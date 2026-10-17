package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/mqtt"
)

func (a *app) waitQuery() url.Values {
	if a.wait {
		return nil
	}
	return url.Values{"wait": {"0"}}
}

// deviceState mirrors mqtt.DeviceState.
type deviceState struct {
	Serial    string                    `json:"serial"`
	UpdatedAt time.Time                 `json:"updatedAt"`
	Modules   map[string]map[string]any `json:"modules"`
	Print     map[string]any            `json:"print"`
}

func (a *app) targetSerial(args []string) (string, error) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], nil
	}
	return a.printer()
}

func (a *app) cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	refresh := fs.Bool("refresh", false, "ask the printer for a full pushall first")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	sn, err := a.targetSerial(pos)
	if err != nil {
		return err
	}
	base, err := a.printerPath(sn)
	if err != nil {
		return err
	}
	q := url.Values{}
	if *refresh {
		q.Set("refresh", "1")
	}
	var st deviceState
	if err := a.api.do(a.ctx, "GET", base+"/state", q, nil, &st); err != nil {
		return err
	}
	if a.json {
		return a.emit(st)
	}
	renderStatus(a.out, &st)
	return nil
}

func (a *app) cmdWatch(args []string) error {
	sn, err := a.targetSerial(args)
	if err != nil {
		return err
	}
	base, err := a.printerPath(sn)
	if err != nil {
		return err
	}
	if !a.json {
		var st deviceState
		if err := a.api.do(a.ctx, "GET", base+"/state", nil, nil, &st); err == nil {
			renderStatus(a.out, &st)
		}
		fmt.Fprintln(a.out, "--- watching; Ctrl-C to stop")
	}
	last := ""
	return a.api.stream(a.ctx, base+"/events", func(event, data string) bool {
		if a.json {
			fmt.Fprintln(a.out, data)
			return true
		}
		var p map[string]any
		switch event {
		case "state":
			return true
		case "print":
			var env map[string]map[string]any
			if json.Unmarshal([]byte(data), &env) != nil {
				return true
			}
			p = env["print"]
		default:
			if data != "{}" && data != "" {
				fmt.Fprintf(a.out, "%s %s %s\n", time.Now().Format("15:04:05"), event, truncate(data, 200))
			}
			return true
		}
		line := summaryLine(p)
		if line != "" && line != last {
			fmt.Fprintf(a.out, "%s %s\n", time.Now().Format("15:04:05"), line)
			last = line
		}
		return true
	})
}

// summaryLine renders the fields of one incremental print report that a user
// watching a print cares about.
func summaryLine(p map[string]any) string {
	var parts []string
	if v, ok := p["gcode_state"]; ok {
		parts = append(parts, fmt.Sprint(v))
	}
	if v, ok := p["mc_percent"]; ok {
		parts = append(parts, fmt.Sprintf("%v%%", v))
	}
	if v, ok := p["mc_remaining_time"]; ok {
		parts = append(parts, fmt.Sprintf("%v min left", v))
	}
	if v, ok := p["layer_num"]; ok {
		parts = append(parts, fmt.Sprintf("layer %v", v))
	}
	if v, ok := p["nozzle_temper"]; ok {
		parts = append(parts, fmt.Sprintf("nozzle %.1f°C", num(v)))
	}
	if v, ok := p["bed_temper"]; ok {
		parts = append(parts, fmt.Sprintf("bed %.1f°C", num(v)))
	}
	if v, ok := p["print_error"]; ok && num(v) != 0 {
		parts = append(parts, fmt.Sprintf("print_error=0x%08x", int64(num(v))))
	}
	if hms, ok := p["hms"].([]any); ok && len(hms) > 0 {
		parts = append(parts, fmt.Sprintf("%d HMS", len(hms)))
	}
	if cmd, ok := p["command"]; ok && cmd != "push_status" {
		parts = append(parts, fmt.Sprintf("reply %v=%v", cmd, p["result"]))
	}
	return strings.Join(parts, "  ")
}

func renderStatus(w io.Writer, st *deviceState) {
	p := st.Print
	if p == nil {
		p = map[string]any{}
	}
	tw := newTable(w)
	tw.row("printer", st.Serial)
	state := str(p["gcode_state"])
	if sub := str(p["subtask_name"]); sub != "" && state != "IDLE" {
		state += "  " + sub
	}
	tw.row("state", state)
	if pct, ok := p["mc_percent"]; ok {
		prog := fmt.Sprintf("%v%%", pct)
		if rem, ok := p["mc_remaining_time"]; ok {
			prog += fmt.Sprintf("  %s left", minutes(num(rem)))
		}
		if l, ok := p["layer_num"]; ok {
			prog += fmt.Sprintf("  layer %v/%v", l, p["total_layer_num"])
		}
		tw.row("progress", prog)
	}
	if s := temp(p["nozzle_temper"], p["nozzle_target_temper"]); s != "" {
		tw.row("nozzle", s)
	}
	if s := temp(p["bed_temper"], p["bed_target_temper"]); s != "" {
		tw.row("bed", s)
	}
	if _, ok := p["chamber_temper"]; ok {
		tw.row("chamber", fmt.Sprintf("%v°C", p["chamber_temper"]))
	}
	fans := []string{}
	for _, f := range []struct{ key, name string }{{"cooling_fan_speed", "part"}, {"big_fan1_speed", "aux"}, {"big_fan2_speed", "chamber"}, {"heatbreak_fan_speed", "heatbreak"}} {
		if v, ok := p[f.key]; ok {
			fans = append(fans, fmt.Sprintf("%s %d%%", f.name, int(num(v)*100/15+0.5)))
		}
	}
	if len(fans) > 0 {
		tw.row("fans", strings.Join(fans, "  "))
	}
	if v, ok := p["spd_lvl"]; ok {
		tw.row("speed", speedName(int(num(v))))
	}
	if lights, ok := p["lights_report"].([]any); ok {
		var ls []string
		for _, l := range lights {
			if m, ok := l.(map[string]any); ok {
				ls = append(ls, fmt.Sprintf("%v %v", m["node"], m["mode"]))
			}
		}
		if len(ls) > 0 {
			tw.row("lights", strings.Join(ls, "  "))
		}
	}
	if v, ok := p["wifi_signal"]; ok {
		tw.row("wifi", str(v))
	}
	if v, ok := p["sdcard"]; ok {
		tw.row("sdcard", yesNo(v == true))
	}
	if ams, ok := p["ams"].(map[string]any); ok {
		if units, ok := ams["ams"].([]any); ok {
			for _, u := range units {
				um, _ := u.(map[string]any)
				var trays []string
				if ts, ok := um["tray"].([]any); ok {
					for _, t := range ts {
						tm, _ := t.(map[string]any)
						name := str(tm["tray_type"])
						if name == "" {
							name = "empty"
						}
						if c := str(tm["tray_color"]); len(c) >= 6 {
							name += " #" + c[:6]
						}
						trays = append(trays, fmt.Sprintf("[%v] %s", tm["id"], name))
					}
				}
				label := fmt.Sprintf("ams %v", um["id"])
				val := strings.Join(trays, "  ")
				if h := str(um["humidity"]); h != "" {
					val += "  humidity " + h
				}
				tw.row(label, val)
			}
		}
		if now := str(ams["tray_now"]); now != "" && now != "255" {
			tw.row("loaded", "tray "+now)
		}
	}
	if v, ok := p["print_error"]; ok && num(v) != 0 {
		tw.row("print_error", fmt.Sprintf("0x%08x", int64(num(v))))
	}
	if hms, ok := p["hms"].([]any); ok && len(hms) > 0 {
		var codes []string
		for _, h := range hms {
			if m, ok := h.(map[string]any); ok {
				codes = append(codes, fmt.Sprintf("HMS_%04X_%04X_%04X_%04X", int64(num(m["attr"]))>>16, int64(num(m["attr"]))&0xffff, int64(num(m["code"]))>>16, int64(num(m["code"]))&0xffff))
			}
		}
		tw.row("hms", strings.Join(codes, "  "))
	}
	if !st.UpdatedAt.IsZero() {
		tw.row("updated", st.UpdatedAt.Local().Format(time.RFC3339))
	}
	tw.flush()
}

// ---------------------------------------------------------------- controls

func (a *app) cmdPause([]string) error  { return a.send("Pause", nil) }
func (a *app) cmdResume([]string) error { return a.send("Resume", nil) }
func (a *app) cmdStop([]string) error   { return a.send("Stop", nil) }

var speedLevels = map[string]string{"silent": "1", "standard": "2", "sport": "3", "ludicrous": "4", "1": "1", "2": "2", "3": "3", "4": "4"}

func speedName(level int) string {
	for name, v := range speedLevels {
		if v == strconv.Itoa(level) && len(name) > 1 {
			return name
		}
	}
	return strconv.Itoa(level)
}

func (a *app) cmdSpeed(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: bambu speed <silent|standard|sport|ludicrous>")
	}
	code, ok := speedLevels[strings.ToLower(args[0])]
	if !ok {
		return fmt.Errorf("unknown speed %q", args[0])
	}
	return a.send("PrintSpeed", map[string]any{"param": code})
}

func (a *app) cmdLight(args []string) error {
	if len(args) < 1 || (args[0] != "on" && args[0] != "off") {
		return errors.New("usage: bambu light <on|off> [led_node]")
	}
	node := "chamber_light"
	if len(args) > 1 {
		node = args[1]
	}
	// led_on_time/led_off_time/loop_times/interval_time are the app's constants (rpv.java).
	return a.send("LedCtrl", map[string]any{"led_node": node, "led_mode": args[0], "led_on_time": 500, "led_off_time": 500, "loop_times": 0, "interval_time": 0})
}

func (a *app) cmdFan(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: bambu fan <part|aux|chamber|N> <0-100>")
	}
	idx := map[string]int{"part": 1, "aux": 2, "chamber": 3}[strings.ToLower(args[0])]
	if idx == 0 {
		n, err := strconv.Atoi(args[0])
		if err != nil {
			return fmt.Errorf("unknown fan %q", args[0])
		}
		idx = n
	}
	speed, err := strconv.Atoi(strings.TrimSuffix(args[1], "%"))
	if err != nil || speed < 0 || speed > 100 {
		return errors.New("speed must be 0-100")
	}
	return a.send("SetFan", map[string]any{"fan_index": idx, "speed": speed})
}

// cmdTemp sets a heater target. The app sends set_bed_temp/set_nozzle_temp only
// when the printer's capabilities say so (lv2.d) and plain M140/M104 otherwise;
// G-code is the default here because every firmware accepts it.
func (a *app) cmdTemp(args []string) error {
	fs := flag.NewFlagSet("temp", flag.ContinueOnError)
	native := fs.Bool("native", false, "use set_bed_temp/set_nozzle_temp instead of M140/M104")
	args, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(args) < 2 {
		return errors.New("usage: bambu temp <nozzle|bed> <celsius> [extruder] [-native]")
	}
	c, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	ext := 0
	if len(args) > 2 {
		if ext, err = strconv.Atoi(args[2]); err != nil {
			return err
		}
	}
	switch args[0] {
	case "bed":
		if *native {
			return a.send("SetBedTemp", map[string]any{"temp": c})
		}
		return a.send("GcodeLine", map[string]any{"param": fmt.Sprintf("M140 S%d\n", c)})
	case "nozzle":
		if *native {
			return a.send("SetNozzleTemp", map[string]any{"extruder_index": ext, "target_temp": c})
		}
		if ext > 0 {
			return a.send("GcodeLine", map[string]any{"param": fmt.Sprintf("M104 T%d S%d\n", ext, c)})
		}
		return a.send("GcodeLine", map[string]any{"param": fmt.Sprintf("M104 S%d\n", c)})
	}
	return fmt.Errorf("unknown heater %q", args[0])
}

func (a *app) cmdGcode(args []string) error {
	var code string
	if len(args) == 1 && args[0] == "-" {
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		code = string(b)
	} else {
		code = strings.Join(args, "\n")
	}
	if strings.TrimSpace(code) == "" {
		return errors.New("usage: bambu gcode <line>... | -")
	}
	sn, err := a.printer()
	if err != nil {
		return err
	}
	base, err := a.printerPath(sn)
	if err != nil {
		return err
	}
	var res commandResult
	if err := a.api.do(a.ctx, "POST", base+"/gcode", a.waitQuery(), map[string]string{"gcode": code}, &res); err != nil {
		return err
	}
	return a.printResult(&res)
}

func (a *app) cmdMove(args []string) error {
	fs := flag.NewFlagSet("move", flag.ContinueOnError)
	x := fs.Float64("x", 0, "relative X mm")
	y := fs.Float64("y", 0, "relative Y mm")
	z := fs.Float64("z", 0, "relative Z mm")
	f := fs.Float64("f", 0, "feed rate mm/min (default: printer's)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	body := map[string]any{}
	fs.Visit(func(fl *flag.Flag) {
		switch fl.Name {
		case "x":
			body["x"] = *x
		case "y":
			body["y"] = *y
		case "z":
			body["z"] = *z
		case "f":
			body["feed_rate"] = *f
		}
	})
	if len(body) == 0 {
		return errors.New("usage: bambu move [-x N] [-y N] [-z N] [-f feed]")
	}
	sn, err := a.printer()
	if err != nil {
		return err
	}
	base, err := a.printerPath(sn)
	if err != nil {
		return err
	}
	var res commandResult
	if err := a.api.do(a.ctx, "POST", base+"/move", a.waitQuery(), body, &res); err != nil {
		return err
	}
	return a.printResult(&res)
}

func (a *app) cmdHome(args []string) error {
	body := map[string]bool{}
	for _, ax := range args {
		switch strings.ToLower(ax) {
		case "x", "y", "z":
			body[strings.ToLower(ax)] = true
		default:
			return fmt.Errorf("unknown axis %q", ax)
		}
	}
	sn, err := a.printer()
	if err != nil {
		return err
	}
	base, err := a.printerPath(sn)
	if err != nil {
		return err
	}
	var res commandResult
	if err := a.api.do(a.ctx, "POST", base+"/home", a.waitQuery(), body, &res); err != nil {
		return err
	}
	return a.printResult(&res)
}

func (a *app) cmdAMS(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		sn, err := a.printer()
		if err != nil {
			return err
		}
		base, err := a.printerPath(sn)
		if err != nil {
			return err
		}
		var st deviceState
		if err := a.api.do(a.ctx, "GET", base+"/state", nil, nil, &st); err != nil {
			return err
		}
		ams := st.Print["ams"]
		if a.json {
			return a.emit(ams)
		}
		renderStatus(a.out, &deviceState{Serial: st.Serial, Print: map[string]any{"ams": ams, "gcode_state": st.Print["gcode_state"]}})
		return nil
	case "load":
		// Handy sends target == slot_id (rpv.java s72); BambuStudio's target is the
		// global tray index ams*4+slot, which is what we send for both.
		var amsID, tray int
		switch len(args) {
		case 2:
			n, err := strconv.Atoi(args[1])
			if err != nil {
				return err
			}
			amsID, tray = n/4, n
		case 3:
			n1, err1 := strconv.Atoi(args[1])
			n2, err2 := strconv.Atoi(args[2])
			if err1 != nil || err2 != nil || n2 < 0 || n2 > 3 {
				return errors.New("usage: bambu ams load <ams id> <slot 0-3>")
			}
			amsID, tray = n1, n1*4+n2
		default:
			return errors.New("usage: bambu ams load <ams id> <slot 0-3> | <tray index>")
		}
		return a.send("AmsChangeFilament", map[string]any{"ams_id": amsID, "slot_id": tray, "curr_temp": 0, "tar_temp": 0})
	case "unload":
		return a.send("UnloadFilament", nil)
	case "select":
		if len(args) != 3 {
			return errors.New("usage: bambu ams select <ams id> <slot>")
		}
		p, err := kv([]string{"ams_id=" + args[1], "slot_id=" + args[2]})
		if err != nil {
			return err
		}
		return a.send("AmsSelectSlot", p)
	case "retry", "resume", "pause", "done":
		return a.send("AmsControl", map[string]any{"param": args[0]})
	case "drying":
		p, err := kv(args[1:])
		if err != nil {
			return err
		}
		return a.send("AmsFilamentDrying", p)
	case "stop-drying":
		return a.send("AutoStopAmsDry", nil)
	}
	return fmt.Errorf("unknown ams action %q (status|load|unload|select|retry|resume|pause|done|drying|stop-drying)", args[0])
}

func (a *app) cmdPrint(args []string) error {
	fs := flag.NewFlagSet("print", flag.ContinueOnError)
	// The app hard-codes timelapse=false and toolhead_offset_cali=false for
	// gcode_file (CommandSpec consts), so only these four are user choices.
	noLevel := fs.Bool("no-bed-leveling", false, "")
	noFlow := fs.Bool("no-flow-cali", false, "")
	noVib := fs.Bool("no-vibration-cali", false, "")
	noInspect := fs.Bool("no-layer-inspect", false, "")
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: bambu print <path on printer storage, e.g. /sdcard/model.gcode.3mf> [flags]")
	}
	return a.send("GcodeFile", map[string]any{"param": pos[0], "bed_leveling": !*noLevel,
		"flow_cali": !*noFlow, "vibration_cali": !*noVib, "layer_inspect": !*noInspect})
}

func (a *app) cmdSkip(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: bambu skip <object id>...")
	}
	ids := make([]int, 0, len(args))
	for _, s := range args {
		n, err := strconv.Atoi(s)
		if err != nil {
			return err
		}
		ids = append(ids, n)
	}
	return a.send("SkipObjects", map[string]any{"obj_list": ids})
}

func (a *app) cmdCalibrate(args []string) error {
	// Bit flags as in BambuStudio's calibration command: 1 bed leveling, 2 vibration, 4 motor noise, 8 flow (newer firmware).
	opt := 0
	for _, s := range args {
		switch s {
		case "bed-leveling":
			opt |= 1
		case "vibration":
			opt |= 2
		case "motor-noise":
			opt |= 4
		case "flow":
			opt |= 8
		default:
			return fmt.Errorf("unknown calibration %q", s)
		}
	}
	if opt == 0 {
		opt = 1 | 2 | 4
	}
	return a.send("Calibration", map[string]any{"option": opt})
}

func (a *app) cmdCmd(args []string) error {
	if len(args) == 0 || args[0] == "--list" || args[0] == "-l" {
		specs := append([]mqtt.CommandSpec(nil), mqtt.Specs...)
		sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
		if a.json {
			return a.emit(specs)
		}
		tw := newTable(a.out)
		for _, s := range specs {
			var ps []string
			for _, p := range s.Params {
				if p.Const != nil {
					continue
				}
				name := p.Key + ":" + p.Type
				if p.Optional {
					name += "?"
				}
				ps = append(ps, name)
			}
			tw.row(s.Name, s.Module+"/"+s.Command, strings.Join(ps, " "))
		}
		tw.flush()
		return nil
	}
	params, err := kv(args[1:])
	if err != nil {
		return err
	}
	return a.send(args[0], params)
}

func (a *app) cmdRaw(args []string) error {
	if len(args) < 2 {
		return errors.New("usage: bambu raw <module> <command> [key=value]...")
	}
	params, err := kv(args[2:])
	if err != nil {
		return err
	}
	sn, err := a.printer()
	if err != nil {
		return err
	}
	base, err := a.printerPath(sn)
	if err != nil {
		return err
	}
	var res commandResult
	body := map[string]any{"module": args[0], "command": args[1], "params": params}
	if err := a.api.do(a.ctx, "POST", base+"/raw", a.waitQuery(), body, &res); err != nil {
		return err
	}
	return a.printResult(&res)
}

func (a *app) cmdSecurity(args []string) error {
	action := "status"
	if len(args) > 0 {
		action = args[0]
	}
	sn, err := a.printer()
	if err != nil {
		return err
	}
	base, err := a.printerPath(sn)
	if err != nil {
		return err
	}
	var out json.RawMessage
	switch action {
	case "status":
		err = a.api.do(a.ctx, "GET", base+"/security", nil, nil, &out)
	case "exchange":
		err = a.api.do(a.ctx, "POST", base+"/security/exchange", nil, nil, &out)
	case "drop":
		err = a.api.do(a.ctx, "DELETE", base+"/security", nil, nil, nil)
		out = json.RawMessage(`{"secure":false}`)
	default:
		return fmt.Errorf("unknown action %q (status|exchange|drop)", action)
	}
	if err != nil {
		return err
	}
	if a.json {
		fmt.Fprintln(a.out, string(out))
		return nil
	}
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	tw := newTable(a.out)
	for _, k := range []string{"serial", "secure", "installed", "certId", "fieldEncrypt", "certIds"} {
		if v, ok := m[k]; ok {
			tw.row(k, fmt.Sprint(v))
		}
	}
	if pc, _ := m["printerCert"].(string); pc != "" {
		tw.row("printerCert", strings.SplitN(pc, "\n", 2)[0]+" …")
	}
	tw.flush()
	return nil
}

func (a *app) cmdAppCert(_ []string) error {
	var m map[string]any
	if err := a.api.do(a.ctx, "GET", "/v1/appcert", nil, nil, &m); err != nil {
		return err
	}
	if a.json {
		return a.emit(m)
	}
	tw := newTable(a.out)
	for _, k := range []string{"subject", "issuer", "certId", "mqttCertId", "notAfter", "fetchedAt", "keyLayout"} {
		if v, ok := m[k]; ok && v != "" {
			tw.row(k, fmt.Sprint(v))
		}
	}
	tw.flush()
	return nil
}

// ---------------------------------------------------------------- formatting

func str(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}

func num(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case int64:
		return float64(t)
	case json.Number:
		f, _ := t.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(t, 64)
		return f
	}
	return 0
}

func temp(cur, target any) string {
	if cur == nil {
		return ""
	}
	s := fmt.Sprintf("%.1f°C", num(cur))
	if target != nil && num(target) > 0 {
		s += fmt.Sprintf(" → %.0f°C", num(target))
	}
	return s
}

func minutes(m float64) string {
	d := time.Duration(m) * time.Minute
	if d >= time.Hour {
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
	return fmt.Sprintf("%dm", int(d.Minutes()))
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

type table struct {
	w    io.Writer
	rows [][]string
}

func newTable(w io.Writer) *table { return &table{w: w} }

func (t *table) row(cells ...string) { t.rows = append(t.rows, cells) }

func (t *table) flush() {
	widths := []int{}
	for _, r := range t.rows {
		for i, c := range r {
			if i >= len(widths) {
				widths = append(widths, 0)
			}
			if l := len([]rune(c)); l > widths[i] {
				widths[i] = l
			}
		}
	}
	for _, r := range t.rows {
		var b strings.Builder
		for i, c := range r {
			if i == len(r)-1 {
				b.WriteString(c)
				break
			}
			b.WriteString(c)
			b.WriteString(strings.Repeat(" ", widths[i]-len([]rune(c))+2))
		}
		fmt.Fprintln(t.w, strings.TrimRight(b.String(), " "))
	}
}
