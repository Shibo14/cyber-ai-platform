// Package audit masks secrets before structured data reaches an audit sink.
// It does not select a complete audit schema, retention or PII policy.
package audit

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"unicode"
)

const Redacted = "[REDACTED]"

var ErrEmit = errors.New("audit emission failed")

type Logger struct {
	mu      sync.Mutex
	sink    io.Writer
	allowed map[string]bool
}

// New takes a server-defined top-level field allowlist. Unlisted fields are
// omitted. Never obtain the allowlist from a request or dump full request/auth/
// config structures into events, even when their outer field is allowlisted.
func New(sink io.Writer, allowedFields ...string) *Logger {
	allowed := make(map[string]bool, len(allowedFields))
	for _, field := range allowedFields {
		allowed[field] = true
	}
	return &Logger{sink: sink, allowed: allowed}
}

func (l *Logger) Emit(fields map[string]any) error {
	// Sanitize the complete event first, so a secret copied into an allowed
	// field is still masked even if its original field is not allowlisted.
	clean := Sanitize(fields).(map[string]any)
	filtered := make(map[string]any)
	for key, value := range clean {
		if l.allowed[key] {
			filtered[key] = value
		}
	}
	data, err := json.Marshal(filtered)
	if err != nil || l.sink == nil {
		return ErrEmit
	}
	data = append(data, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	n, err := l.sink.Write(data)
	if err != nil || n != len(data) {
		return ErrEmit // sink errors may contain credentials; never forward them
	}
	return nil
}

// Sanitize copies supported structured fields without invoking Stringer,
// Error, MarshalJSON or reflection on credential-bearing objects. Unsupported
// types and over-deep/cyclic structures are masked. Known secret values are
// masked at every supported nesting level; the input is never mutated.
func Sanitize(value any) any {
	secrets := make(map[string]bool)
	collect(value, 0, false, secrets)
	return sanitize(value, 0, secrets)
}

// Collect only supported data, without inspecting arbitrary objects. This also
// prevents a known secret from leaking under a second, innocuous field/key.
func collect(value any, depth int, secret bool, secrets map[string]bool) {
	if depth >= 16 {
		return
	}
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			collect(item, depth+1, secret || secretField(key), secrets)
		}
	case []any:
		for _, item := range v {
			collect(item, depth+1, secret, secrets)
		}
	case []string:
		for _, item := range v {
			collect(item, depth+1, secret, secrets)
		}
	case string:
		if (secret || secretText(v)) && v != "" {
			secrets[v] = true
		}
		parts := strings.Fields(v)
		for i, part := range parts {
			if (strings.EqualFold(part, "bearer") || strings.EqualFold(part, "basic")) && i+1 < len(parts) {
				secrets[parts[i+1]] = true
			}
		}
	}
}

func containsSecret(value string, secrets map[string]bool) bool {
	if secretText(value) {
		return true
	}
	for secret := range secrets {
		if strings.Contains(value, secret) {
			return true
		}
	}
	return false
}

func sanitize(value any, depth int, secrets map[string]bool) any {
	if depth >= 16 {
		return Redacted
	}
	switch v := value.(type) {
	case map[string]any:
		clean := make(map[string]any, len(v))
		for key, item := range v {
			if containsSecret(key, secrets) {
				clean[Redacted] = Redacted
			} else if secretField(key) {
				clean[key] = Redacted
			} else {
				clean[key] = sanitize(item, depth+1, secrets)
			}
		}
		return clean
	case []any:
		clean := make([]any, len(v))
		for i, item := range v {
			clean[i] = sanitize(item, depth+1, secrets)
		}
		return clean
	case []string:
		clean := make([]any, len(v))
		for i, item := range v {
			clean[i] = sanitize(item, depth+1, secrets)
		}
		return clean
	case string:
		if containsSecret(v, secrets) {
			return Redacted
		}
		return v
	case nil, bool, int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64:
		return v
	default:
		return Redacted
	}
}

func secretField(key string) bool {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToLower(r)
		}
		return -1
	}, key)
	for _, part := range []string{"password", "passwd", "pwd", "token", "bearer", "authorization", "apikey",
		"secret", "cookie", "privatekey", "credential", "signingkey", "encryptionkey"} {
		if strings.Contains(normalized, part) {
			return true
		}
	}
	switch normalized {
	case "session", "sessionid", "authentication", "auth", "request", "httprequest", "config", "environment", "env", "claims",
		"databaseurl", "databaseuri", "dsn", "connectionstring":
		return true
	}
	return false
}

func secretText(value string) bool {
	lower := strings.ToLower(strings.Join(strings.Fields(value), " "))
	return strings.Contains(lower, "bearer ") || strings.Contains(lower, "basic ") ||
		(strings.Contains(lower, "-----begin ") && strings.Contains(lower, "private key-----"))
}
