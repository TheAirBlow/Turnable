package common

import (
	"fmt"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Values is an ordered form-values collection that preserves insertion order when encoding
type Values struct {
	keys []string
	data map[string][]string
}

// NewValues creates a new Values from alternating key-value pairs
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

// Set sets the key to a single value, replacing any existing values
func (v *Values) Set(key, value string) {
	if _, ok := v.data[key]; !ok {
		v.keys = append(v.keys, key)
	}
	v.data[key] = []string{value}
}

// Add appends the value to the list for key
func (v *Values) Add(key, value string) {
	if _, ok := v.data[key]; !ok {
		v.keys = append(v.keys, key)
	}
	v.data[key] = append(v.data[key], value)
}

// Get returns the first value associated with key or "" if none
func (v *Values) Get(key string) string {
	if vals := v.data[key]; len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// Del removes all values associated with key
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

// Encode encodes the values into URL-encoded form in insertion order
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

// Tag format (struct field tag key: "url"):
//	url:"placement,name[,weight][,omitempty]"
//
// Placements:
//	user      - URL user info username
//	pass      - URL user info password
//	host      - URL host field; only one field should use this
//	path      - contributes a path segment; for slices, one segment per element
//	            (the element type's own url tags describe sub-field encoding)
//	query     - URL query parameter
//	fragment  - URL fragment; only one field should use this
//
// name is ignored and not required for all placements except query
// weight controls the relative order within the same placement (lower = first)
// omitempty skips the field when its value is the zero value for its type

const tagKey = "url"

type placement int

const (
	placementUser placement = iota
	placementPass
	placementHost
	placementPath
	placementQuery
	placementFragment
)

// parsePlacement parses the placement from the URL tag
func parsePlacement(s string) (placement, error) {
	switch s {
	case "user":
		return placementUser, nil
	case "pass":
		return placementPass, nil
	case "host":
		return placementHost, nil
	case "path":
		return placementPath, nil
	case "query":
		return placementQuery, nil
	case "fragment":
		return placementFragment, nil
	default:
		return 0, fmt.Errorf("url: unknown placement %q", s)
	}
}

// fieldMeta holds the parsed url tag for one struct field
type fieldMeta struct {
	index     []int
	name      string
	pl        placement
	weight    int
	omitempty bool
	fieldType reflect.Type
}

// parseStructMeta reflects on a struct type and returns its url-tagged fields sorted by placement and weight
func parseStructMeta(t reflect.Type) ([]fieldMeta, error) {
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return nil, fmt.Errorf("url: Marshal/Unmarshal requires a struct, got %s", t.Kind())
	}

	var fields []fieldMeta
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		raw, ok := sf.Tag.Lookup(tagKey)

		if !ok && sf.Anonymous && sf.Type.Kind() == reflect.Struct {
			embeddedType := sf.Type
			for j := 0; j < embeddedType.NumField(); j++ {
				embSf := embeddedType.Field(j)
				embRaw, embOk := embSf.Tag.Lookup(tagKey)
				if !embOk || embRaw == "-" {
					continue
				}

				parentField, ok := t.FieldByName(embSf.Name)
				if !ok {
					continue
				}

				parts := strings.Split(embRaw, ",")
				if len(parts) < 1 {
					return nil, fmt.Errorf("url: field %s: tag %q must have at least a placement", embSf.Name, embRaw)
				}

				plStr := strings.TrimSpace(parts[0])
				pl, err := parsePlacement(plStr)
				if err != nil {
					return nil, fmt.Errorf("url: field %s: %w", embSf.Name, err)
				}

				nameRequired := pl == placementQuery
				var name string
				var remainingParts []string

				if len(parts) > 1 {
					possibleName := strings.TrimSpace(parts[1])
					isWeight := false
					if possibleName != "" {
						_, pErr := strconv.Atoi(possibleName)
						isWeight = pErr == nil
					}
					isOmitEmpty := possibleName == "omitempty"

					if !nameRequired && (isWeight || isOmitEmpty) {
						name = embSf.Name
						remainingParts = parts[1:]
					} else {
						name = possibleName
						remainingParts = parts[2:]
					}
				} else {
					if nameRequired {
						return nil, fmt.Errorf("url: field %s: placement %q requires a target name", embSf.Name, plStr)
					}
					name = embSf.Name
				}

				weight := 0
				omitempty := false

				for _, opt := range remainingParts {
					opt = strings.TrimSpace(opt)
					if opt == "" {
						continue
					}

					if opt == "omitempty" {
						omitempty = true
						continue
					}

					w, err := strconv.Atoi(opt)
					if err != nil {
						return nil, fmt.Errorf("url: field %s: unknown tag option or invalid weight %q: %v", embSf.Name, opt, err)
					}
					weight = w
				}

				fields = append(fields, fieldMeta{
					index:     parentField.Index,
					name:      name,
					pl:        pl,
					weight:    weight,
					omitempty: omitempty,
					fieldType: embSf.Type,
				})
			}
			continue
		}

		if !ok || raw == "-" {
			continue
		}

		if sf.Anonymous && sf.Type.Kind() == reflect.Struct {
			continue
		}

		parts := strings.Split(raw, ",")
		if len(parts) < 1 {
			return nil, fmt.Errorf("url: field %s: tag %q must have at least a placement", sf.Name, raw)
		}

		plStr := strings.TrimSpace(parts[0])
		pl, err := parsePlacement(plStr)
		if err != nil {
			return nil, fmt.Errorf("url: field %s: %w", sf.Name, err)
		}

		nameRequired := pl == placementQuery

		var name string
		var remainingParts []string

		if len(parts) > 1 {
			possibleName := strings.TrimSpace(parts[1])

			isWeight := false
			if possibleName != "" {
				_, pErr := strconv.Atoi(possibleName)
				isWeight = pErr == nil
			}
			isOmitEmpty := possibleName == "omitempty"

			if !nameRequired && (isWeight || isOmitEmpty) {
				name = sf.Name
				remainingParts = parts[1:]
			} else {
				name = possibleName
				remainingParts = parts[2:]
			}
		} else {
			if nameRequired {
				return nil, fmt.Errorf("url: field %s: placement %q requires a target name", sf.Name, plStr)
			}
			name = sf.Name
		}

		weight := 0
		omitempty := false

		for _, opt := range remainingParts {
			opt = strings.TrimSpace(opt)
			if opt == "" {
				continue
			}

			if opt == "omitempty" {
				omitempty = true
				continue
			}

			w, err := strconv.Atoi(opt)
			if err != nil {
				return nil, fmt.Errorf("url: field %s: unknown tag option or invalid weight %q: %v", sf.Name, opt, err)
			}
			weight = w
		}

		fields = append(fields, fieldMeta{
			index:     []int{i},
			name:      name,
			pl:        pl,
			weight:    weight,
			omitempty: omitempty,
			fieldType: sf.Type,
		})
	}

	sort.SliceStable(fields, func(i, j int) bool {
		if fields[i].pl != fields[j].pl {
			return fields[i].pl < fields[j].pl
		}
		return fields[i].weight < fields[j].weight
	})

	return fields, nil
}

// isZero reports whether v is the zero value for its type
func isZero(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.String() == ""
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Slice, reflect.Map:
		return v.Len() == 0
	case reflect.Ptr, reflect.Interface:
		return v.IsNil()
	default:
		return false
	}
}

// valueToString converts a scalar reflect.Value to its string representation
func valueToString(v reflect.Value) (string, error) {
	switch v.Kind() {
	case reflect.String:
		return v.String(), nil
	case reflect.Bool:
		return strconv.FormatBool(v.Bool()), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(v.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return strconv.FormatUint(v.Uint(), 10), nil
	case reflect.Float32:
		return strconv.FormatFloat(v.Float(), 'f', -1, 32), nil
	case reflect.Float64:
		return strconv.FormatFloat(v.Float(), 'f', -1, 64), nil
	default:
		return "", fmt.Errorf("url: unsupported scalar kind %s", v.Kind())
	}
}

// stringToValue parses s into the field described by reflect.Value dst
func stringToValue(s string, dst reflect.Value) error {
	switch dst.Kind() {
	case reflect.String:
		dst.SetString(s)
	case reflect.Bool:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return err
		}
		dst.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return err
		}
		dst.SetInt(n)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		dst.SetUint(n)
	case reflect.Float32, reflect.Float64:
		n, err := strconv.ParseFloat(s, dst.Type().Bits())
		if err != nil {
			return err
		}
		dst.SetFloat(n)
	default:
		return fmt.Errorf("url: unsupported scalar kind %s", dst.Kind())
	}
	return nil
}

// encodePathSegment encodes one element of a path slice into a single URL path segment
func encodePathSegment(elem reflect.Value) (string, error) {
	if elem.Kind() == reflect.Ptr {
		elem = elem.Elem()
	}
	t := elem.Type()
	subFields, err := parseStructMeta(t)
	if err != nil {
		return "", err
	}

	var pathFields []fieldMeta
	for _, sf := range subFields {
		if sf.pl == placementPath {
			pathFields = append(pathFields, sf)
		}
	}

	if len(pathFields) == 0 {
		return "", nil
	}

	tokens := make([]string, len(pathFields))
	for i, sf := range pathFields {
		fv := elem.FieldByIndex(sf.index)

		s, err := valueToString(fv)
		if err != nil {
			return "", fmt.Errorf("url: path sub-field %s: %w", sf.name, err)
		}

		if i > 0 && strings.ContainsRune(s, '-') {
			return "", fmt.Errorf(
				"url: path sub-field %s (position %d): value %q must not contain '-'; "+
					"only the first positional field may contain dashes",
				sf.name, i, s,
			)
		}

		tokens[i] = s
	}

	return strings.Join(tokens, "-"), nil
}

// decodePathSegment parses a dash-delimited path segment back into a struct element whose sub-fields all carry placement
func decodePathSegment(seg string, elemType reflect.Type) (reflect.Value, error) {
	if elemType.Kind() == reflect.Ptr {
		elemType = elemType.Elem()
	}
	elem := reflect.New(elemType).Elem()

	subFields, err := parseStructMeta(elemType)
	if err != nil {
		return elem, err
	}

	var pathFields []fieldMeta
	for _, sf := range subFields {
		if sf.pl == placementPath {
			pathFields = append(pathFields, sf)
		}
	}

	if len(pathFields) == 0 {
		return elem, nil
	}

	n := len(pathFields)

	allParts := strings.Split(seg, "-")

	if len(allParts) < n {
		return elem, fmt.Errorf(
			"url: path segment %q has %d dash-separated parts, need at least %d",
			seg, len(allParts), n,
		)
	}

	tailStart := len(allParts) - (n - 1)
	tokens := make([]string, n)
	tokens[0] = strings.Join(allParts[:tailStart], "-")
	for i := 1; i < n; i++ {
		tokens[i] = allParts[tailStart+i-1]
	}

	for i, sf := range pathFields {
		fv := elem.FieldByIndex(sf.index)
		if err := stringToValue(tokens[i], fv); err != nil {
			return elem, fmt.Errorf("url: path sub-field %s: %w", sf.name, err)
		}
	}

	return elem, nil
}

// MarshalURL encodes v into a URL string using struct field url tags
func MarshalURL(v any, scheme string) (string, error) {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}

	fields, err := parseStructMeta(rv.Type())
	if err != nil {
		return "", err
	}

	type weightedString struct {
		weight int
		value  string
	}

	var (
		userVal      string
		passVal      string
		hostVal      string
		fragmentVal  string
		pathSegments []weightedString
		queryVals    = NewValues()
	)

	for _, fm := range fields {
		fv := rv.FieldByIndex(fm.index)

		if fm.omitempty && isZero(fv) {
			continue
		}

		switch fm.pl {
		case placementUser:
			s, err := valueToString(fv)
			if err != nil {
				return "", fmt.Errorf("url: field %s: %w", fm.name, err)
			}
			userVal = s

		case placementPass:
			s, err := valueToString(fv)
			if err != nil {
				return "", fmt.Errorf("url: field %s: %w", fm.name, err)
			}
			passVal = s

		case placementHost:
			s, err := valueToString(fv)
			if err != nil {
				return "", fmt.Errorf("url: field %s: %w", fm.name, err)
			}
			hostVal = s

		case placementFragment:
			s, err := valueToString(fv)
			if err != nil {
				return "", fmt.Errorf("url: field %s: %w", fm.name, err)
			}
			fragmentVal = s

		case placementPath:
			ft := fv.Type()
			if ft.Kind() == reflect.Slice {
				for i := 0; i < fv.Len(); i++ {
					seg, err := encodePathSegment(fv.Index(i))
					if err != nil {
						return "", fmt.Errorf("url: field %s[%d]: %w", fm.name, i, err)
					}
					if seg != "" {
						pathSegments = append(pathSegments, weightedString{fm.weight*1000 + i, seg})
					}
				}
			} else if ft.Kind() == reflect.Struct {
				seg, err := encodePathSegment(fv)
				if err != nil {
					return "", fmt.Errorf("url: field %s (object): %w", fm.name, err)
				}
				if seg != "" {
					pathSegments = append(pathSegments, weightedString{fm.weight, seg})
				}
			} else {
				s, err := valueToString(fv)
				if err != nil {
					return "", fmt.Errorf("url: field %s: %w", fm.name, err)
				}
				if s != "" {
					pathSegments = append(pathSegments, weightedString{fm.weight, s})
				}
			}

		case placementQuery:
			ft := fv.Type()
			if ft.Kind() == reflect.Slice {
				for i := 0; i < fv.Len(); i++ {
					s, err := valueToString(fv.Index(i))
					if err != nil {
						return "", fmt.Errorf("url: field %s[%d]: %w", fm.name, i, err)
					}
					key := fmt.Sprintf("%s[%d]", fm.name, i+1)
					queryVals.Set(key, s)
				}
			} else {
				s, err := valueToString(fv)
				if err != nil {
					return "", fmt.Errorf("url: field %s: %w", fm.name, err)
				}
				queryVals.Set(fm.name, s)
			}
		}
	}

	sort.SliceStable(pathSegments, func(i, j int) bool {
		return pathSegments[i].weight < pathSegments[j].weight
	})

	rawPath := "/"
	if len(pathSegments) > 0 {
		parts := make([]string, len(pathSegments))
		for i, ws := range pathSegments {
			parts[i] = ws.value
		}
		rawPath = "/" + strings.Join(parts, "/")
	}

	u := &url.URL{
		Scheme:   scheme,
		Host:     hostVal,
		Path:     rawPath,
		Fragment: fragmentVal,
	}

	if userVal != "" || passVal != "" {
		u.User = url.UserPassword(userVal, passVal)
	}

	if enc := queryVals.Encode(); enc != "" {
		u.RawQuery = enc
	}

	if u.Scheme != scheme {
		return "", fmt.Errorf("url: scheme mismatch: struct produced %q but %q was requested", u.Scheme, scheme)
	}

	return u.String(), nil
}

// UnmarshalURL parses rawURL into the struct pointed to by v
func UnmarshalURL(rawURL string, scheme string, v any) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("url: failed to parse URL: %w", err)
	}

	if u.Scheme != scheme {
		return fmt.Errorf("url: scheme mismatch: got %q, want %q", u.Scheme, scheme)
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("url: Unmarshal requires a non-nil pointer")
	}
	rv = rv.Elem()

	fields, err := parseStructMeta(rv.Type())
	if err != nil {
		return err
	}

	queryVals, _ := url.ParseQuery(u.RawQuery)

	rawPathSegs := strings.Split(strings.Trim(u.Path, "/"), "/")
	var pathSegs []string
	for _, s := range rawPathSegs {
		if s != "" {
			pathSegs = append(pathSegs, s)
		}
	}
	pathIdx := 0

	for _, fm := range fields {
		fv := rv.FieldByIndex(fm.index)
		ft := fv.Type()

		switch fm.pl {
		case placementUser:
			if u.User != nil {
				if err := stringToValue(u.User.Username(), fv); err != nil {
					return fmt.Errorf("url: field %s (user): %w", fm.name, err)
				}
			}

		case placementPass:
			if u.User != nil {
				pass, _ := u.User.Password()
				if err := stringToValue(pass, fv); err != nil {
					return fmt.Errorf("url: field %s (pass): %w", fm.name, err)
				}
			}

		case placementHost:
			if err := stringToValue(u.Host, fv); err != nil {
				return fmt.Errorf("url: field %s (host): %w", fm.name, err)
			}

		case placementFragment:
			if err := stringToValue(u.Fragment, fv); err != nil {
				return fmt.Errorf("url: field %s (fragment): %w", fm.name, err)
			}

		case placementPath:
			if ft.Kind() == reflect.Slice {
				elemType := ft.Elem()
				slice := reflect.MakeSlice(ft, 0, len(pathSegs)-pathIdx)
				for pathIdx < len(pathSegs) {
					elem, err := decodePathSegment(pathSegs[pathIdx], elemType)
					if err != nil {
						return fmt.Errorf("url: field %s[%d]: %w", fm.name, pathIdx, err)
					}
					slice = reflect.Append(slice, elem)
					pathIdx++
				}
				fv.Set(slice)
			} else if ft.Kind() == reflect.Struct {
				if pathIdx < len(pathSegs) {
					decodedObj, err := decodePathSegment(pathSegs[pathIdx], ft)
					if err != nil {
						return fmt.Errorf("url: field %s (object): %w", fm.name, err)
					}
					fv.Set(decodedObj)
					pathIdx++
				}
			} else {
				if pathIdx < len(pathSegs) {
					seg, _ := url.PathUnescape(pathSegs[pathIdx])
					if err := stringToValue(seg, fv); err != nil {
						return fmt.Errorf("url: field %s (path): %w", fm.name, err)
					}
					pathIdx++
				}
			}

		case placementQuery:
			if ft.Kind() == reflect.Slice {
				elemType := ft.Elem()
				var slice reflect.Value

				if vals, ok := queryVals[fm.name]; ok {
					for _, val := range vals {
						elem := reflect.New(elemType).Elem()
						if err := stringToValue(val, elem); err != nil {
							return fmt.Errorf("url: field %s (query): %w", fm.name, err)
						}
						slice = reflect.Append(slice, elem)
					}
				} else {
					for i := 1; ; i++ {
						key := fmt.Sprintf("%s[%d]", fm.name, i)
						vals, ok := queryVals[key]
						if !ok || len(vals) == 0 {
							break
						}
						elem := reflect.New(elemType).Elem()
						if err := stringToValue(vals[0], elem); err != nil {
							return fmt.Errorf("url: field %s[%d] (query): %w", fm.name, i, err)
						}
						slice = reflect.Append(slice, elem)
					}
				}

				if slice.IsValid() {
					fv.Set(slice)
				} else {
					fv.Set(reflect.MakeSlice(ft, 0, 0))
				}
			} else {
				vals, ok := queryVals[fm.name]
				if ok && len(vals) > 0 {
					if err := stringToValue(vals[0], fv); err != nil {
						return fmt.Errorf("url: field %s (query %s): %w", fm.name, fm.name, err)
					}
				}
			}
		}
	}

	return nil
}
