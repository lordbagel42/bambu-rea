package cloud

import (
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
)

// unmarshalLenient decodes like json.Unmarshal but tolerates the type
// mismatches Gson silently accepts in the app: numbers or booleans where the
// model declares a string (e.g. `"nozzle_diameter": 0.4`) and numeric strings
// where it declares a number. encoding/json is strict, so on a type error the
// document is re-shaped against the target type and decoded again.
func unmarshalLenient(data []byte, out any) error {
	err := json.Unmarshal(data, out)
	var te *json.UnmarshalTypeError
	if err == nil || !errors.As(err, &te) {
		return err
	}
	var generic any
	if err := json.Unmarshal(data, &generic); err != nil {
		return err
	}
	fixed, err := json.Marshal(coerce(generic, reflect.TypeOf(out)))
	if err != nil {
		return err
	}
	return json.Unmarshal(fixed, out)
}

// coerce walks v alongside the Go type t and converts scalars to the kind t
// expects. Shapes it cannot reconcile are returned unchanged so the strict
// decoder reports them.
func coerce(v any, t reflect.Type) any {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nil || v == nil {
		return v
	}
	if t.Implements(reflect.TypeFor[json.Unmarshaler]()) || reflect.PointerTo(t).Implements(reflect.TypeFor[json.Unmarshaler]()) {
		return v
	}
	switch t.Kind() {
	case reflect.String:
		switch s := v.(type) {
		case float64:
			return strconv.FormatFloat(s, 'f', -1, 64)
		case bool:
			return strconv.FormatBool(s)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Float32, reflect.Float64:
		if s, ok := v.(string); ok {
			if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
				return f
			}
		}
		if b, ok := v.(bool); ok {
			if b {
				return 1
			}
			return 0
		}
	case reflect.Bool:
		switch s := v.(type) {
		case float64:
			return s != 0
		case string:
			if b, err := strconv.ParseBool(s); err == nil {
				return b
			}
		}
	case reflect.Slice, reflect.Array:
		if arr, ok := v.([]any); ok {
			for i := range arr {
				arr[i] = coerce(arr[i], t.Elem())
			}
			return arr
		}
	case reflect.Map:
		if m, ok := v.(map[string]any); ok {
			for k, e := range m {
				m[k] = coerce(e, t.Elem())
			}
			return m
		}
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return v
		}
		fields := jsonFields(t)
		for k, e := range m {
			if ft, ok := fields[k]; ok {
				m[k] = coerce(e, ft)
			} else if ft, ok := fields[strings.ToLower(k)]; ok {
				m[k] = coerce(e, ft)
			}
		}
		return m
	}
	return v
}

// jsonFields maps the JSON key (and its lower-case form, since encoding/json
// matches case-insensitively) of each exported field, including embedded
// structs, to the field's type.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Anonymous {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			if ft.Kind() == reflect.Struct {
				for k, v := range jsonFields(ft) {
					out[k] = v
				}
			}
			continue
		}
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
		out[strings.ToLower(name)] = f.Type
	}
	return out
}
