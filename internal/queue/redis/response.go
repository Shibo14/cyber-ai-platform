package redis

import (
	"strconv"
	"strings"
)

// rawEntry is private: a malformed entry retains only its validated Redis ID.
// Original fields are never forwarded to DLQ, audit, or error text.
type rawEntry struct {
	id        string
	fields    []string
	malformed bool
}

func validID(id string) bool {
	parts := strings.Split(id, "-")
	if len(parts) != 2 {
		return false
	}
	for _, part := range parts {
		value, err := strconv.ParseUint(part, 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != part {
			return false
		}
	}
	return true
}

func parseEntry(value any) (rawEntry, bool) {
	items, ok := value.([]any)
	if !ok || len(items) != 2 {
		return rawEntry{}, false
	}
	id, ok := items[0].(string)
	if !ok || !validID(id) {
		return rawEntry{}, false
	}
	entry := rawEntry{id: id, malformed: true}
	fields, ok := items[1].([]any)
	if !ok || len(fields) == 0 || len(fields)%2 != 0 {
		return entry, true
	}
	values := make([]string, len(fields))
	names := make(map[string]struct{}, len(fields)/2)
	for i, field := range fields {
		value, ok := field.(string)
		if !ok {
			return entry, true
		}
		if i%2 == 0 {
			if value == "" {
				return entry, true
			}
			if _, duplicate := names[value]; duplicate {
				return entry, true
			}
			names[value] = struct{}{}
		}
		values[i] = value
	}
	entry.fields, entry.malformed = values, false
	return entry, true
}

func parseEntries(value any) ([]rawEntry, bool) {
	items, ok := value.([]any)
	if !ok {
		return nil, false
	}
	entries := make([]rawEntry, len(items))
	seen := make(map[string]struct{}, len(items))
	for i, item := range items {
		entry, ok := parseEntry(item)
		if !ok {
			return nil, false
		}
		if _, duplicate := seen[entry.id]; duplicate {
			return nil, false
		}
		seen[entry.id] = struct{}{}
		entries[i] = entry
	}
	return entries, true
}

func parseRead(value any, stream string) ([]rawEntry, bool) {
	if value == nil {
		return nil, true
	}
	streams, ok := value.([]any)
	if !ok || len(streams) != 1 {
		return nil, false
	}
	items, ok := streams[0].([]any)
	if !ok || len(items) != 2 || items[0] != stream {
		return nil, false
	}
	return parseEntries(items[1])
}
