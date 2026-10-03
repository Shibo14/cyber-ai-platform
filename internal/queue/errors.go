package queue

import (
	"context"
	"errors"

	"cyber-ai-platform/internal/authorization"
	"cyber-ai-platform/internal/encryption"
)

var (
	ErrConfiguration = errors.New("queue configuration required")
	ErrMalformed     = errors.New("invalid queue metadata")
	ErrUnsupported   = errors.New("unsupported queue schema")
	ErrDenied        = errors.New("queue processing denied")
	ErrValidation    = errors.New("queue operation rejected")
	ErrUnavailable   = errors.New("queue dependency unavailable")
	ErrPermission    = errors.New("queue dependency permission denied")
	ErrProtocol      = errors.New("invalid queue dependency response")
	ErrDependency    = errors.New("queue dependency failed")
	ErrStore         = errors.New("queue state unavailable")
	ErrBusy          = errors.New("queue delivery busy")
	ErrDeferred      = errors.New("queue retry deferred")
	ErrACK           = errors.New("queue acknowledgment unconfirmed")
	ErrDLQ           = errors.New("queue dead-letter write unconfirmed")
	ErrAudit         = errors.New("queue audit failed")
)

type Class string

const (
	Permanent Class = "permanent"
	Transient Class = "transient"
	Unknown   Class = "unknown"
)

type Reason string

const (
	Malformed    Reason = "malformed"
	Unsupported  Reason = "unsupported"
	Denied       Reason = "denied"
	Validation   Reason = "validation"
	Unavailable  Reason = "unavailable"
	Timeout      Reason = "timeout"
	Interrupted  Reason = "interrupted"
	Dependency   Reason = "dependency"
	Unclassified Reason = "unclassified"
)

// Classification deliberately has no cause/message field. Raw SDK errors must
// never be returned, serialized or included in audit/DLQ metadata.
type Classification struct {
	Class  Class
	Reason Reason
}

func (c Classification) Error() string { return "queue processing failed" }
func (c Classification) Valid() bool {
	switch c.Class {
	case Permanent:
		return c.Reason == Malformed || c.Reason == Unsupported || c.Reason == Denied || c.Reason == Validation
	case Transient:
		return c.Reason == Unavailable || c.Reason == Timeout || c.Reason == Interrupted || c.Reason == Dependency
	case Unknown:
		return c.Reason == Unclassified
	}
	return false
}

func Classify(err error) Classification {
	var c Classification
	if errors.As(err, &c) && c.Valid() {
		return c
	}
	var cp *Classification
	if errors.As(err, &cp) && cp != nil && cp.Valid() {
		return *cp
	}
	switch {
	case errors.Is(err, ErrMalformed):
		return Classification{Permanent, Malformed}
	case errors.Is(err, ErrUnsupported):
		return Classification{Permanent, Unsupported}
	case errors.Is(err, ErrDenied), errors.Is(err, authorization.ErrDenied), errors.Is(err, encryption.ErrDenied):
		return Classification{Permanent, Denied}
	case errors.Is(err, ErrValidation), errors.Is(err, authorization.ErrState):
		return Classification{Permanent, Validation}
	case errors.Is(err, ErrUnavailable), errors.Is(err, encryption.ErrUnavailable):
		return Classification{Transient, Unavailable}
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, encryption.ErrTimeout):
		return Classification{Transient, Timeout}
	case errors.Is(err, context.Canceled), errors.Is(err, encryption.ErrCanceled):
		return Classification{Transient, Interrupted}
	case errors.Is(err, ErrDependency), errors.Is(err, ErrPermission), errors.Is(err, ErrProtocol),
		errors.Is(err, authorization.ErrDependency), errors.Is(err, encryption.ErrDependency), errors.Is(err, encryption.ErrCorruptResponse):
		return Classification{Transient, Dependency}
	default:
		return Classification{Unknown, Unclassified}
	}
}
