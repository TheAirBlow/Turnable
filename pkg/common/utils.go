package common

import (
	"strconv"
	"strings"
)

// IsNullOrWhiteSpace checks whether a string is empty with whitespaces removed
func IsNullOrWhiteSpace(s string) bool {
	return len(strings.TrimSpace(s)) == 0
}

// NestedString walks nested maps and returns terminal scalar as string
func NestedString(value map[string]any, keys ...string) (string, bool) {
	var current any = value
	for _, key := range keys {
		next, ok := current.(map[string]any)
		if !ok {
			return "", false
		}
		current = next[key]
	}

	switch typed := current.(type) {
	case string:
		return typed, true
	case float64:
		return strconv.FormatInt(int64(typed), 10), true
	default:
		return "", false
	}
}

// FirstNonEmpty returns first non-empty trimmed string from input list
func FirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// StringifyAny converts supported scalar JSON value into string form
func StringifyAny(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return strconv.FormatInt(int64(typed), 10)
	default:
		return ""
	}
}

// StringSliceAny normalizes a JSON value into a string slice
func StringSliceAny(raw any) []string {
	switch value := raw.(type) {
	case []string:
		return append([]string(nil), value...)
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			text := strings.TrimSpace(StringifyAny(item))
			if text != "" {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}
