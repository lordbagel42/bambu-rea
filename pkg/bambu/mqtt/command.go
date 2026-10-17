// Package mqtt implements the printer command channel of the Bambu Handy app:
// the JSON envelope published to device/<sn>/request, the report stream on
// device/<sn>/report, the 90 commands the app can issue (generated into
// commands_gen.go from catalog/mqtt_commands.json) and the optional secure
// channel (RSA-SHA256 signed envelope + RSA-encrypted sensitive fields).
package mqtt

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Command is one printer command before it is wrapped in the MQTT envelope.
type Command struct {
	// Module is the top-level JSON key ("print", "system", "camera", ...).
	Module string
	// Command is the value of the "command" field inside the module object.
	Command string
	// Params are merged into the module object next to sequence_id/command/timestamp.
	Params map[string]any
	// EncryptFields lists "module:field" paths the secure channel RSA-encrypts
	// into "<field>_enc" when a printer certificate is available (e.g. "print:param").
	EncryptFields []string
}

// ParamSpec describes one parameter of a CommandSpec.
type ParamSpec struct {
	Key      string `json:"key"`
	Type     string `json:"type"` // int | long | double | bool | string | string[] | int[] | object[] | any
	Optional bool   `json:"optional"`
	Const    any    `json:"const,omitempty"`   // fixed value the app always sends
	Derived  string `json:"derived,omitempty"` // copy of another param (e.g. target = slot_id)
	Wire     string `json:"wire,omitempty"`    // enable_disable | int01 | upper | gcode
}

// CommandSpec is the machine-readable description of one command, used by the
// generic Build function and by the HTTP API's /v1/commands catalog.
type CommandSpec struct {
	Name          string         `json:"name"`
	Module        string         `json:"module"`
	Command       string         `json:"command"`
	EncryptFields []string       `json:"encryptFields,omitempty"`
	RawParams     bool           `json:"rawParams,omitempty"`    // params are passed through verbatim
	GcodeBuilder  string         `json:"gcodeBuilder,omitempty"` // move_axis | home_axes
	ConstParams   map[string]any `json:"constParams,omitempty"`
	Doc           string         `json:"doc,omitempty"`
	Params        []ParamSpec    `json:"params"`
}

// SpecByName returns the CommandSpec with the given Go name (case-insensitive).
func SpecByName(name string) (*CommandSpec, bool) {
	for i := range Specs {
		if strings.EqualFold(Specs[i].Name, name) {
			return &Specs[i], true
		}
	}
	return nil, false
}

// SpecByWire returns the CommandSpec for a module/command pair. Several specs may
// share a wire command (e.g. print/gcode_line); the first plain one wins.
func SpecByWire(module, command string) (*CommandSpec, bool) {
	var found *CommandSpec
	for i := range Specs {
		s := &Specs[i]
		if s.Module == module && s.Command == command {
			if s.GcodeBuilder == "" && len(s.ConstParams) == 0 {
				return s, true
			}
			if found == nil {
				found = s
			}
		}
	}
	return found, found != nil
}

// Build constructs a Command from a spec and loosely typed parameters (typically
// decoded JSON). It applies the same conversions the typed builders do: constant
// and derived params, enable/disable and 0/1 booleans, upper-casing, G-code
// terminators and the MoveAxis/HomeAxes G-code encoders.
func Build(spec *CommandSpec, params map[string]any) (Command, error) {
	if params == nil {
		params = map[string]any{}
	}
	switch spec.GcodeBuilder {
	case "move_axis":
		var m MoveAxisParams
		var err error
		if m.X, err = optFloat(params, "x"); err != nil {
			return Command{}, err
		}
		if m.Y, err = optFloat(params, "y"); err != nil {
			return Command{}, err
		}
		if m.Z, err = optFloat(params, "z"); err != nil {
			return Command{}, err
		}
		if m.FeedRate, err = optFloat(params, "feed_rate"); err != nil {
			return Command{}, err
		}
		return MoveAxis(m), nil
	case "home_axes":
		x, _ := asBool(params["x"])
		y, _ := asBool(params["y"])
		z, _ := asBool(params["z"])
		return HomeAxes(HomeAxesParams{X: x, Y: y, Z: z}), nil
	}
	p := make(map[string]any, len(params)+len(spec.Params)+len(spec.ConstParams))
	if spec.RawParams {
		for k, v := range params {
			p[k] = v
		}
	}
	for k, v := range spec.ConstParams {
		p[k] = v
	}
	for _, ps := range spec.Params {
		if ps.Const != nil {
			p[ps.Key] = ps.Const
			continue
		}
		if ps.Derived != "" {
			if v, ok := p[ps.Derived]; ok {
				p[ps.Key] = v
			}
			continue
		}
		v, ok := params[ps.Key]
		if !ok || v == nil {
			if ps.Optional {
				continue
			}
			return Command{}, fmt.Errorf("mqtt: %s: missing required param %q", spec.Name, ps.Key)
		}
		cv, err := coerce(ps, v)
		if err != nil {
			return Command{}, fmt.Errorf("mqtt: %s: param %q: %w", spec.Name, ps.Key, err)
		}
		p[ps.Key] = cv
	}
	// Derived params may reference keys defined after them; resolve a second time.
	for _, ps := range spec.Params {
		if ps.Derived != "" {
			if v, ok := p[ps.Derived]; ok {
				p[ps.Key] = v
			}
		}
	}
	if len(p) == 0 {
		p = nil
	}
	return Command{Module: spec.Module, Command: spec.Command, Params: p, EncryptFields: spec.EncryptFields}, nil
}

func coerce(ps ParamSpec, v any) (any, error) {
	switch ps.Wire {
	case "enable_disable":
		b, err := asBool(v)
		if err != nil {
			return nil, err
		}
		return enableDisable(b), nil
	case "int01":
		b, err := asBool(v)
		if err != nil {
			return nil, err
		}
		return boolInt(b), nil
	case "upper":
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("expected string, got %T", v)
		}
		return strings.ToUpper(s), nil
	case "gcode":
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("expected string, got %T", v)
		}
		return ensureGcodeTerminator(s), nil
	}
	switch ps.Type {
	case "int", "long":
		return asInt(v)
	case "double":
		return asFloat(v)
	case "bool":
		return asBool(v)
	case "string":
		switch s := v.(type) {
		case string:
			return s, nil
		case json.Number:
			return s.String(), nil
		case float64, int, int64, bool:
			return fmt.Sprint(s), nil
		}
		return nil, fmt.Errorf("expected string, got %T", v)
	case "string[]":
		arr, ok := v.([]any)
		if !ok {
			if ss, ok := v.([]string); ok {
				return ss, nil
			}
			return nil, fmt.Errorf("expected array of strings, got %T", v)
		}
		out := make([]string, len(arr))
		for i, e := range arr {
			s, ok := e.(string)
			if !ok {
				return nil, fmt.Errorf("element %d: expected string, got %T", i, e)
			}
			out[i] = s
		}
		return out, nil
	case "int[]":
		arr, ok := v.([]any)
		if !ok {
			if is, ok := v.([]int); ok {
				return is, nil
			}
			return nil, fmt.Errorf("expected array of ints, got %T", v)
		}
		out := make([]int, len(arr))
		for i, e := range arr {
			n, err := asInt(e)
			if err != nil {
				return nil, fmt.Errorf("element %d: %w", i, err)
			}
			out[i] = n
		}
		return out, nil
	}
	return v, nil
}

func asInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if n != float64(int64(n)) {
			return 0, fmt.Errorf("expected integer, got %v", n)
		}
		return int(n), nil
	case json.Number:
		i, err := n.Int64()
		return int(i), err
	case bool:
		return boolInt(n), nil
	case string:
		var i int
		_, err := fmt.Sscan(n, &i)
		return i, err
	}
	return 0, fmt.Errorf("expected integer, got %T", v)
}

func asFloat(v any) (float64, error) {
	switch n := v.(type) {
	case float64:
		return n, nil
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case json.Number:
		return n.Float64()
	case string:
		var f float64
		_, err := fmt.Sscan(n, &f)
		return f, err
	}
	return 0, fmt.Errorf("expected number, got %T", v)
}

func optFloat(params map[string]any, key string) (*float64, error) {
	v, ok := params[key]
	if !ok || v == nil {
		return nil, nil
	}
	f, err := asFloat(v)
	if err != nil {
		return nil, fmt.Errorf("mqtt: param %q: %w", key, err)
	}
	return &f, nil
}

func asBool(v any) (bool, error) {
	switch b := v.(type) {
	case bool:
		return b, nil
	case float64:
		return b != 0, nil
	case int:
		return b != 0, nil
	case string:
		switch strings.ToLower(b) {
		case "true", "1", "on", "enable", "yes":
			return true, nil
		case "false", "0", "off", "disable", "no":
			return false, nil
		}
	case nil:
		return false, nil
	}
	return false, fmt.Errorf("expected bool, got %T", v)
}

// enableDisable encodes the camera on/off switches the way the app does.
func enableDisable(b bool) string {
	if b {
		return "enable"
	}
	return "disable"
}

// boolInt encodes buzzer_ctrl/chamber_mode_set style 0/1 flags.
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ensureGcodeTerminator mirrors BblCommandEncoderKt.ensureGcodeLineTerminator:
// G-code without a trailing newline gets " \n" appended.
func ensureGcodeTerminator(g string) string {
	if strings.HasSuffix(g, "\n") {
		return g
	}
	return g + " \n"
}

// Names returns all command names in catalog order.
func Names() []string {
	out := make([]string, len(Specs))
	for i := range Specs {
		out[i] = Specs[i].Name
	}
	return out
}

// Modules returns the distinct module keys used by the commands, sorted.
func Modules() []string {
	seen := map[string]bool{}
	for i := range Specs {
		seen[Specs[i].Module] = true
	}
	out := make([]string, 0, len(seen))
	for m := range seen {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}
