package common

import (
	"net/url"
	"strings"
)

// Values is an ordered form-values collection that preserves insertion order when encoding.
// Unlike net/url.Values (which sorts keys alphabetically on Encode), this type encodes
// keys in the order they were first inserted via Set, Add, or NewValues.
type Values struct {
	keys []string
	data map[string][]string
}

// NewValues creates a new Values from alternating key-value pairs.
// Panics if an odd number of arguments is provided.
func NewValues(kvs ...string) *Values {
	v := &Values{data: make(map[string][]string)}
	if len(kvs)%2 != 0 {
		panic("common.NewValues: odd number of arguments")
	}
	for i := 0; i < len(kvs); i += 2 {
		v.Set(kvs[i], kvs[i+1])
	}
	return v
}

// Set sets the key to a single value, replacing any existing values.
// If the key does not exist yet, it is appended in insertion order.
func (v *Values) Set(key, value string) {
	if _, ok := v.data[key]; !ok {
		v.keys = append(v.keys, key)
	}
	v.data[key] = []string{value}
}

// Add appends the value to the list for key.
// If the key does not exist yet, it is appended in insertion order.
func (v *Values) Add(key, value string) {
	if _, ok := v.data[key]; !ok {
		v.keys = append(v.keys, key)
	}
	v.data[key] = append(v.data[key], value)
}

// Get returns the first value associated with key, or "" if none.
func (v *Values) Get(key string) string {
	if vals := v.data[key]; len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// Del removes all values associated with key and drops it from the ordered key list.
func (v *Values) Del(key string) {
	if _, ok := v.data[key]; !ok {
		return
	}
	delete(v.data, key)
	for i, k := range v.keys {
		if k == key {
			v.keys = append(v.keys[:i], v.keys[i+1:]...)
			return
		}
	}
}

// Encode encodes the values into "URL encoded" form ("bar=baz&foo=quux") in insertion order.
// Keys and values are escaped using url.QueryEscape.
func (v *Values) Encode() string {
	if v == nil || len(v.keys) == 0 {
		return ""
	}
	var sb strings.Builder
	first := true
	for _, key := range v.keys {
		vals := v.data[key]
		enc := url.QueryEscape(key)
		for _, val := range vals {
			if !first {
				sb.WriteByte('&')
			}
			first = false
			sb.WriteString(enc)
			sb.WriteByte('=')
			sb.WriteString(url.QueryEscape(val))
		}
	}
	return sb.String()
}
