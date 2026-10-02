package encryption

import (
	"context"
	"errors"
)

var (
	ErrDenied          = errors.New("encryption operation denied")
	ErrUnavailable     = errors.New("KMS unavailable")
	ErrTimeout         = errors.New("KMS timeout")
	ErrCanceled        = errors.New("encryption operation canceled")
	ErrCorruptResponse = errors.New("invalid encryption dependency response")
	ErrDependency      = errors.New("encryption dependency failed")
)

type FailureKind uint8

const (
	Unavailable FailureKind = iota + 1
	Denied
	Timeout
	CorruptResponse
)

// KMSFailure carries only a safe class. Provider adapters translate SDK errors
// into this type; the core also masks unknown/credential-bearing errors.
type KMSFailure struct{ Kind FailureKind }

func (e KMSFailure) Error() string { return kindError(e.Kind).Error() }

func kindError(kind FailureKind) error {
	switch kind {
	case Unavailable:
		return ErrUnavailable
	case Denied:
		return ErrDenied
	case Timeout:
		return ErrTimeout
	case CorruptResponse:
		return ErrCorruptResponse
	default:
		return ErrDependency
	}
}

func kmsError(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return ErrTimeout
	}
	if errors.Is(err, context.Canceled) {
		return ErrCanceled
	}
	var failure KMSFailure
	if errors.As(err, &failure) {
		return kindError(failure.Kind)
	}
	var pointer *KMSFailure
	if errors.As(err, &pointer) && pointer != nil {
		return kindError(pointer.Kind)
	}
	return ErrDependency
}

func failureClass(err error) string {
	switch err {
	case nil:
		return "none"
	case ErrDenied:
		return "denied"
	case ErrUnavailable:
		return "unavailable"
	case ErrTimeout:
		return "timeout"
	case ErrCanceled:
		return "canceled"
	case ErrCorruptResponse:
		return "corrupt_response"
	default:
		return "dependency"
	}
}
