package workeridentity

import "errors"

var (
	ErrDenied        = errors.New("worker identity denied")
	ErrDependency    = errors.New("worker identity dependency unavailable")
	ErrConfiguration = errors.New("worker identity configuration invalid")
	ErrAudit         = errors.New("worker identity audit unavailable")
)

// Classify deliberately drops causes. Raw TLS/SDK/source errors may contain
// credential or certificate material and must never enter queue/audit output.
func Classify(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrDenied):
		return ErrDenied
	case errors.Is(err, ErrConfiguration):
		return ErrConfiguration
	case errors.Is(err, ErrAudit):
		return ErrAudit
	default:
		return ErrDependency
	}
}
