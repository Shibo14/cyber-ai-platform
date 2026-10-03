package queue

import "strings"

// Field names, supported schema/version and reference syntax are server-injected
// decisions. There is no default message format or production schema version.
type SchemaConfig struct {
	ID, Version                               string
	SchemaField, VersionField, ReferenceField string
	// ValidReference accepts only non-secret, opaque delegation locators.
	// Never use emails, URLs, payloads, tokens or bearer credentials as IDs.
	ValidReference func(string) bool
}
type Schema struct{ config SchemaConfig }

func NewSchema(config SchemaConfig) (*Schema, error) {
	fields := []string{config.SchemaField, config.VersionField, config.ReferenceField}
	seen := map[string]bool{}
	for _, field := range fields {
		if !identifier(field) || seen[field] {
			return nil, ErrConfiguration
		}
		seen[field] = true
	}
	if !identifier(config.ID) || !identifier(config.Version) || config.ValidReference == nil {
		return nil, ErrConfiguration
	}
	return &Schema{config: config}, nil
}

func identifier(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

func (s *Schema) Metadata(reference string) Metadata {
	return Metadata{Schema: s.config.ID, Version: s.config.Version, Reference: reference}
}
func (s *Schema) Validate(m Metadata) error {
	if s == nil || m.Schema == "" || m.Version == "" || strings.TrimSpace(m.Reference) == "" {
		return ErrMalformed
	}
	if m.Schema != s.config.ID || m.Version != s.config.Version {
		return ErrUnsupported
	}
	if !s.config.ValidReference(m.Reference) {
		return ErrMalformed
	}
	return nil
}
func (s *Schema) Encode(m Metadata) (Fields, error) {
	if err := s.Validate(m); err != nil {
		return nil, err
	}
	return Fields{s.config.SchemaField: m.Schema, s.config.VersionField: m.Version, s.config.ReferenceField: m.Reference}, nil
}
func (s *Schema) Decode(fields Fields) (Metadata, error) {
	if s == nil || len(fields) != 3 {
		return Metadata{}, ErrMalformed
	}
	for field := range fields {
		if field != s.config.SchemaField && field != s.config.VersionField && field != s.config.ReferenceField {
			return Metadata{}, ErrMalformed
		}
	}
	m := Metadata{fields[s.config.SchemaField], fields[s.config.VersionField], fields[s.config.ReferenceField]}
	if err := s.Validate(m); err != nil {
		return Metadata{}, err
	}
	return m, nil
}
