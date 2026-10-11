package encryption

import (
	"context"
	"cyber-ai-platform/internal/authorization"
	"errors"
	"testing"
	"time"
)

type admissionDouble func(context.Context, authorization.Execution, authorization.AdmissionStage) error

func (f admissionDouble) Admit(c context.Context, e authorization.Execution, s authorization.AdmissionStage) error {
	return f(c, e, s)
}
func TestCostAdmissionBeforeKMSAndFinalExecution(t *testing.T) {
	for _, mode := range []string{"valid", "preparation denied", "final denied", "slow preparation", "slow final", "KMS failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			plain := []byte("plaintext-secret")
			request := f.request(Encrypt, plain, tenantA)
			var stages []authorization.AdmissionStage
			gate := admissionDouble(func(_ context.Context, _ authorization.Execution, stage authorization.AdmissionStage) error {
				stages = append(stages, stage)
				if mode == "preparation denied" && stage == authorization.PreparationStage || mode == "final denied" && stage == authorization.ExecutionStage {
					return errors.New("private backend")
				}
				if mode == "slow preparation" && stage == authorization.PreparationStage || mode == "slow final" && stage == authorization.ExecutionStage {
					f.now = f.now.Add(time.Hour)
				}
				return nil
			})
			bound, err := authorization.BindAdmission(f.p, gate)
			if err != nil {
				t.Fatal(err)
			}
			f.s.config.PEP = bound
			if mode == "KMS failure" {
				f.kms.failure = errors.New("KMS secret")
			}
			envelope, err := f.s.Encrypt(f.ctx, request, f.store, plain)
			if mode == "valid" {
				if err != nil || len(envelope.Payload.Ciphertext) == 0 || len(stages) != 2 {
					t.Fatal(err)
				}
				return
			}
			if err == nil || len(envelope.Payload.Ciphertext) != 0 || f.boundary.approval.Consumed {
				t.Fatal("failed admission released output/consumed approval")
			}
			if (mode == "preparation denied" || mode == "slow preparation") && f.kms.calls != 0 {
				t.Fatal("KMS reached before positive current admission")
			}
			if mode == "KMS failure" && len(stages) != 1 {
				t.Fatal("KMS failure reached final execution")
			}
		})
	}
}
