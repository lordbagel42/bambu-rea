package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/mqtt"
)

// One registry drives routing, discovery and OpenAPI. Advanced operations keep
// the catalog's parameters; everyday controls hide the Bambu wire vocabulary.
type printerOperation struct {
	Method, Path, Command string
}

var printerOperations = []printerOperation{
	{"PUT", "/lights/{light}", "LedCtrl"},
	{"PUT", "/fans/{fan}", "SetFan"},
	{"PUT", "/temperatures/bed", "SetBedTemp"},
	{"PUT", "/temperatures/nozzle", "SetNozzleTemp"},
	{"PUT", "/job/speed", "PrintSpeed"},
	{"POST", "/job/pause", "Pause"},
	{"POST", "/job/resume", "Resume"},
	{"POST", "/job/stop", "Stop"},
	{"POST", "/job/start", "GcodeFile"},
	{"POST", "/job/project", "ProjectFile"},
	{"POST", "/job/skip-objects", "SkipObjects"},
	{"PUT", "/job/options", "PrintOption"},
	{"POST", "/job/clear-lock", "TaskLockErase"},
	{"POST", "/errors/ignore", "Ignore"},
	{"POST", "/errors/clear", "CleanPrintError"},
	{"POST", "/errors/ignore-idle", "IdleIgnore"},
	{"POST", "/errors/dismiss", "UiopClosePrintError"},
	{"POST", "/motion/move", "MoveAxis"},
	{"POST", "/motion/home", "HomeAxes"},
	{"POST", "/motion/center", "BackToCenter"},
	{"POST", "/motion/capture-position", "MoveToCapture"},
	{"POST", "/motion/control", "XyzCtrl"},
	{"POST", "/gcode", "GcodeLine"},
	{"POST", "/ams/select", "AmsSelectSlot"},
	{"POST", "/ams/load", "AmsChangeFilament"},
	{"POST", "/ams/unload", "UnloadFilament"},
	{"PUT", "/ams/filament", "AmsFilamentSetting"},
	{"PUT", "/ams/settings", "AmsUserSetting"},
	{"POST", "/ams/control", "AmsControl"},
	{"POST", "/ams/read-rfid", "AmsGetRfid"},
	{"POST", "/ams/reset", "AmsReset"},
	{"POST", "/ams/bind", "AutoAmsBind"},
	{"POST", "/ams/drying/start", "AmsFilamentDrying"},
	{"POST", "/ams/drying/stop", "AutoStopAmsDry"},
	{"PUT", "/camera/capture", "CameraCapturePicSet"},
	{"PUT", "/camera/recording", "CameraRecordSet"},
	{"PUT", "/camera/timelapse", "CameraTimelapse"},
	{"PUT", "/camera/resolution", "CameraResolutionSet"},
	{"POST", "/camera/resolution/query", "CameraResolutionGet"},
	{"POST", "/camera/timelapse/delete-oldest", "CameraDeleteOldestTimelapse"},
	{"POST", "/camera/media/query", "CameraGetMediaInfo"},
	{"POST", "/camera/liveview/prepare", "LiveviewPrepare"},
	{"PUT", "/camera/detection", "XcamControlSet"},
	{"POST", "/camera/height/query", "GetHeightFromXcam"},
	{"POST", "/firmware/query", "GetVersion"},
	{"POST", "/firmware/upgrade", "UpgradeStart"},
	{"POST", "/firmware/confirm", "UpgradeConfirm"},
	{"POST", "/firmware/confirm-consistency", "UpgradeConsistencyConfirm"},
	{"POST", "/firmware/history/query", "UpgradeGetHistory"},
	{"POST", "/firmware/history/select", "UpgradeHistory"},
	{"POST", "/firmware/ams/upgrade", "McForAmsFirmwareUpgrade"},
	{"POST", "/calibration/start", "Calibration"},
	{"POST", "/calibration/extrusion/query", "ExtrusionCaliGet"},
	{"PUT", "/calibration/ptc", "SetPtcStep"},
	{"POST", "/calibration/holder", "HolderCali"},
	{"PUT", "/extruders/selection", "SelectExtruder"},
	{"PUT", "/extruders/length", "SetExtrusionLength"},
	{"POST", "/extruders/query", "GetExtruder"},
	{"PUT", "/nozzles/settings", "SetNozzle"},
	{"POST", "/nozzles/refresh", "RefreshNozzle"},
	{"POST", "/nozzles/confirm", "NozzleInfoConfirm"},
	{"POST", "/nozzles/exchange", "NozzleExchange"},
	{"POST", "/nozzles/holder/refresh", "HolderNozzleRefresh"},
	{"POST", "/nozzles/mapping/query", "GetAutoNozzleMapping"},
	{"POST", "/temperatures/nozzle/query", "GetNozzleTemp"},
	{"PUT", "/heating/continuous-protection", "SetAgainstContinuedHeatingMode"},
	{"PUT", "/heating/ctt", "SetCtt"},
	{"PUT", "/buzzer", "BuzzerCtrl"},
	{"POST", "/fire-extinguisher/control", "FireExtCtrl"},
	{"PUT", "/airduct", "SetAirduct"},
	{"POST", "/airduct/query", "GetAirductCfg"},
	{"POST", "/air-filter/close", "CloseAirFilt"},
	{"POST", "/parts/control", "PartControlAps"},
	{"POST", "/fans/query", "GetFan"},
	{"POST", "/filament/refill", "Refill"},
	{"PUT", "/accessories/upgrade-kit", "SetAccessoriesUpgradeKit"},
	{"PUT", "/chamber/mode", "ChamberModeSet"},
	{"PUT", "/door/settings", "SetDoorStat"},
	{"POST", "/door/query", "GetDoorStat"},
	{"PUT", "/print-cache", "PrintCacheSet"},
	{"POST", "/print-cache/query", "PrintCacheGet"},
	{"PUT", "/clock", "Sntp"},
	{"POST", "/access-code/query", "GetAccessCode"},
	{"POST", "/reports/start", "PushingStart"},
	{"POST", "/reports/stop", "PushingStop"},
	{"POST", "/reports/refresh", "PushAll"},
	{"POST", "/diagnostics/upload", "UploadStart"},
	{"POST", "/diagnostics/upload/query", "UploadGetInfo"},
	{"POST", "/security/certificates/query", "AppCertList"},
	{"POST", "/security/certificates/install", "AppCertInstall"},
}

func commandBodySchema(sp *mqtt.CommandSpec) map[string]any {
	props := map[string]any{}
	required := []any{}
	for _, p := range sp.Params {
		if p.Const != nil || p.Derived != "" {
			continue
		}
		sc := paramSchema(p.Type)
		if p.Wire != "" {
			sc["description"] = "wire encoding: " + p.Wire
		}
		props[p.Key] = sc
		if !p.Optional {
			required = append(required, p.Key)
		}
	}
	schema := obj("type", "object", "properties", props, "additionalProperties", sp.RawParams)
	if len(required) > 0 {
		schema["required"] = required
	}
	return schema
}

func (op printerOperation) schema() map[string]any {
	sp, _ := mqtt.SpecByName(op.Command)
	schema := commandBodySchema(sp)
	props := schema["properties"].(map[string]any)
	switch op.Command {
	case "LedCtrl":
		props = obj("on", obj("type", "boolean"))
		schema["required"] = []any{"on"}
		schema["example"] = obj("on", true)
	case "SetFan":
		props = obj("percent", obj("type", "integer", "minimum", 0, "maximum", 100))
		schema["required"] = []any{"percent"}
		schema["example"] = obj("percent", 50)
	case "SetBedTemp", "SetNozzleTemp":
		// Model-specific thermal limits remain the firmware's responsibility.
		props = obj("celsius", obj("type", "integer", "minimum", 0))
		if op.Command == "SetNozzleTemp" {
			props["extruder"] = obj("type", "integer", "minimum", 0, "default", 0)
		}
		schema["required"] = []any{"celsius"}
		schema["example"] = obj("celsius", 0)
	case "PrintSpeed":
		props = obj("mode", obj("type", "string", "enum", []any{"silent", "standard", "sport", "ludicrous"}))
		schema["required"] = []any{"mode"}
		schema["example"] = obj("mode", "standard")
	case "CameraCapturePicSet", "CameraRecordSet", "CameraTimelapse", "BuzzerCtrl":
		props = obj("enabled", obj("type", "boolean"))
		schema["required"] = []any{"enabled"}
	case "GcodeLine":
		props = obj("gcode", obj("type", "string", "pattern", `\S`))
		schema["required"] = []any{"gcode"}
	case "GcodeFile":
		delete(props, "param")
		props["file"] = obj("type", "string", "pattern", `\S`, "description", "Path already on the printer; this does not upload a file.")
		schema["required"] = []any{"file"}
		for _, k := range []string{"bed_leveling", "flow_cali", "vibration_cali", "layer_inspect"} {
			props[k].(map[string]any)["default"] = true
		}
	case "SkipObjects":
		props = obj("ids", obj("type", "array", "minItems", 1, "items", obj("type", "integer", "minimum", 0)))
		schema["required"] = []any{"ids"}
	case "HomeAxes":
		delete(schema, "required")
	case "MoveAxis":
		schema["anyOf"] = []any{obj("required", []any{"x"}), obj("required", []any{"y"}), obj("required", []any{"z"})}
		props["feed_rate"] = obj("type", "number", "exclusiveMinimum", 0)
	}
	schema["properties"] = props
	return schema
}

func (op printerOperation) build(r *http.Request, p map[string]any) (mqtt.Command, error) {
	switch op.Command {
	case "LedCtrl":
		node := map[string]string{"chamber": "chamber_light", "work": "work_light"}[r.PathValue("light")]
		if node == "" {
			return mqtt.Command{}, fmt.Errorf("light must be chamber or work")
		}
		mode := "off"
		if p["on"] == true {
			mode = "on"
		}
		return mqtt.LedCtrl(mqtt.LedCtrlParams{LedNode: node, LedMode: mode}), nil
	case "SetFan":
		index := map[string]int{"part": 1, "aux": 2, "chamber": 3}[r.PathValue("fan")]
		if index == 0 {
			return mqtt.Command{}, fmt.Errorf("fan must be part, aux or chamber")
		}
		return mqtt.SetFan(mqtt.SetFanParams{FanIndex: index, Speed: int(p["percent"].(float64))}), nil
	case "SetBedTemp", "SetNozzleTemp":
		// Match the CLI's firmware-compatible default, not the newer native
		// temperature commands. Explicit native commands remain in /devices.
		gcode := fmt.Sprintf("M140 S%.0f\n", p["celsius"])
		if op.Command == "SetNozzleTemp" {
			gcode = fmt.Sprintf("M104 S%.0f\n", p["celsius"])
			if ext, ok := p["extruder"].(float64); ok && ext > 0 {
				gcode = fmt.Sprintf("M104 T%.0f S%.0f\n", ext, p["celsius"])
			}
		}
		return mqtt.GcodeLine(mqtt.GcodeLineParams{Param: gcode}), nil
	case "PrintSpeed":
		p = obj("param", map[string]string{"silent": "1", "standard": "2", "sport": "3", "ludicrous": "4"}[p["mode"].(string)])
	case "CameraCapturePicSet", "CameraRecordSet", "CameraTimelapse":
		p = obj("control", p["enabled"])
	case "BuzzerCtrl":
		p = obj("mode", p["enabled"])
	case "GcodeLine":
		p = obj("param", p["gcode"])
	case "GcodeFile":
		p["param"] = p["file"]
		delete(p, "file")
		for _, k := range []string{"bed_leveling", "flow_cali", "vibration_cali", "layer_inspect"} {
			if _, ok := p[k]; !ok {
				p[k] = true
			}
		}
	case "SkipObjects":
		p = obj("obj_list", p["ids"])
	case "HomeAxes":
		if len(p) == 0 {
			p = obj("x", true, "y", true, "z", true)
		} else if p["x"] != true && p["y"] != true && p["z"] != true {
			return mqtt.Command{}, fmt.Errorf("select at least one axis, or send {} to home all axes")
		}
	}
	sp, _ := mqtt.SpecByName(op.Command)
	return mqtt.Build(sp, p)
}

func (s *Server) printerRoutes() {
	m := s.mux
	m.HandleFunc("GET /v1/printers", s.withSession(s.handlePrinters))
	m.HandleFunc("GET /v1/printers/{sn}", s.handleState)
	m.HandleFunc("GET /v1/printers/{sn}/events", s.handleEvents)
	m.HandleFunc("GET /v1/printers/{sn}/operations", s.handlePrinterOperations)
	m.HandleFunc("GET /v1/printers/{sn}/security", s.handleSecurityStatus)
	m.HandleFunc("POST /v1/printers/{sn}/security/exchange", s.handleSecurityExchange)
	m.HandleFunc("DELETE /v1/printers/{sn}/security", s.handleSecurityDrop)
	for _, op := range printerOperations {
		var schema jsonschema.Schema
		if err := json.Unmarshal(mustJSON(op.schema()), &schema); err != nil {
			panic(err)
		}
		resolved, err := schema.Resolve(nil)
		if err != nil {
			panic(err)
		}
		m.HandleFunc(op.Method+" /v1/printers/{sn}"+op.Path, func(w http.ResponseWriter, r *http.Request) {
			// Strict single-document JSON: misspelled fields must not silently
			// turn a hardware operation into a different operation.
			data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			if len(strings.TrimSpace(string(data))) == 0 {
				data = []byte("{}")
			}
			var body any
			if err := json.Unmarshal(data, &body); err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			if err := resolved.Validate(body); err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			cmd, err := op.build(r, body.(map[string]any))
			if err != nil {
				writeErr(w, 400, err.Error())
				return
			}
			c, sn, ok := s.printerClient(w, r)
			if ok {
				s.sendCommand(w, r, c, sn, cmd)
			}
		})
	}
}

func (s *Server) handlePrinters(w http.ResponseWriter, r *http.Request, sess *principal) {
	list, err := sess.cloud.GetIotServiceApiUserBind(r.Context(), nil)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	printers := []any{}
	for _, d := range list.Devices {
		sn := d.DeviceId
		if sn == "" {
			sn = d.Sn
		}
		// Deliberately omit the cloud's dev_access_code from discovery.
		printers = append(printers, obj("serial", sn, "name", d.Name, "model", d.ModelName, "online", d.IsOnline, "status", d.PrintStatus))
	}
	writeJSON(w, 200, obj("printers", printers))
}

func (s *Server) handlePrinterOperations(w http.ResponseWriter, r *http.Request) {
	// Like the command catalog, this is static metadata, not printer state.
	ops := []any{}
	for _, op := range printerOperations {
		ops = append(ops, obj("method", op.Method, "path", "/v1/printers/{sn}"+op.Path, "command", op.Command, "description", commandDescriptions[op.Command], "request", op.schema()))
	}
	writeJSON(w, 200, obj("operations", ops, "description", "Replace {sn} with the printer serial. Hardware support varies by model and firmware; listing an operation does not assert support."))
}

func addPrinterOpenAPI(paths map[string]any, security []any, sn, wait map[string]any) {
	// Reuse the existing state, stream and secure-channel contracts verbatim.
	for _, suffix := range []string{"/state", "/events", "/security", "/security/exchange"} {
		entry := map[string]any{}
		for method, v := range paths["/v1/devices/{sn}"+suffix].(map[string]any) {
			op := map[string]any{}
			for k, value := range v.(map[string]any) {
				op[k] = value
			}
			op["tags"] = []any{"printers"}
			entry[method] = op
		}
		if suffix == "/state" {
			suffix = ""
		}
		paths["/v1/printers/{sn}"+suffix] = entry
	}
	response := func(description string, schema map[string]any) map[string]any {
		return obj("description", description, "content", obj("application/json", obj("schema", schema)))
	}
	errorSchema := obj("type", "object", "required", []any{"error"}, "properties", obj("error", obj("type", "string"), "code", obj("type", "integer"), "detail", obj()))
	resultSchema := obj("type", "object", "required", []any{"sequenceId", "module", "command", "sent", "secured"}, "properties", obj(
		"sequenceId", obj("type", "string"), "module", obj("type", "string"), "command", obj("type", "string"),
		"result", obj("type", "string"), "reason", obj("type", "string"), "errno", obj("type", "integer"), "errCode", obj("type", "integer"),
		"reply", obj("type", "object"), "sent", obj("type", "object"), "secured", obj("type", "boolean")))
	printerSchema := obj("type", "object", "required", []any{"serial", "name", "model", "online", "status"}, "properties", obj(
		"serial", obj("type", "string"), "name", obj("type", "string"), "model", obj("type", "string"), "online", obj("type", "boolean"), "status", obj("type", "string")))
	paths["/v1/printers"] = obj("get", obj("tags", []any{"printers"}, "security", security, "operationId", "listPrinters",
		"summary", "List cloud-bound printers", "description", "Discover printers available to the authenticated Bambu account. Start here to obtain the serial used by every printer resource route. Returns {printers: [{serial, name, model, online, status}]} without exposing LAN access codes. LAN-only printers are listed separately in the single-user LAN registry.",
		"responses", obj("200", response("Printers", obj("type", "object", "required", []any{"printers"}, "properties", obj("printers", obj("type", "array", "items", printerSchema)))))))
	paths["/v1/printers/{sn}/operations"] = obj("get", obj("tags", []any{"printers"}, "operationId", "listPrinterOperations", "summary", "Discover all printer operations and request schemas",
		"description", "Discover named operations, their purpose and accepted request bodies. Use this to build API tooling or dynamic control panels without parsing the Bambu wire catalog. This is a static catalog, not a model capability check; no connection or credential is required. Paths are templates. Some operations require specific hardware or firmware.",
		"parameters", []any{sn}, "responses", obj("200", response("Operations", obj("type", "object")))))
	for _, route := range printerOperations {
		params := []any{sn, wait}
		if strings.Contains(route.Path, "{light}") {
			params = append(params, obj("name", "light", "in", "path", "required", true, "schema", obj("type", "string", "enum", []any{"chamber", "work"})))
		}
		if strings.Contains(route.Path, "{fan}") {
			params = append(params, obj("name", "fan", "in", "path", "required", true, "schema", obj("type", "string", "enum", []any{"part", "aux", "chamber"})))
		}
		schema := route.schema()
		if route.Command == "MoveAxis" {
			// OpenAPI 3.0 uses a boolean exclusiveMinimum; validation uses
			// JSON Schema's numeric form. Both describe strictly positive feed.
			schema["properties"].(map[string]any)["feed_rate"] = obj("type", "number", "minimum", 0, "exclusiveMinimum", true)
		}
		sp, _ := mqtt.SpecByName(route.Command)
		description := commandDescriptions[route.Command]
		summary, _, _ := strings.Cut(description, ". ")
		description += "\n\n200 means acknowledged, not necessarily physically completed. wait=0 returns 202 after publishing only. Hardware support varies by model and firmware."
		if route.Command == "SetBedTemp" || route.Command == "SetNozzleTemp" {
			description += " Sets the target in Celsius via M140/M104 for older-firmware compatibility. Zero disables heating; firmware enforces model-specific limits."
		}
		if sp.Doc != "" {
			description += " " + sp.Doc
		}
		required, _ := schema["required"].([]any)
		op := obj("tags", []any{"printers/" + strings.Split(strings.TrimPrefix(route.Path, "/"), "/")[0]}, "security", security,
			"operationId", "printer"+route.Command, "summary", summary, "description", description,
			"parameters", params, "requestBody", obj("required", len(required) > 0 || route.Command == "MoveAxis", "content", obj("application/json", obj("schema", schema))),
			"responses", obj("200", response("Printer acknowledgment", resultSchema), "202", response("Published; not acknowledged", resultSchema),
				"400", response("Invalid request; nothing sent", errorSchema), "401", response("Missing or invalid credential", errorSchema),
				"422", response("Printer rejected the command", resultSchema), "502", response("Upstream connection failed", errorSchema), "504", response("No reply before timeout; command may have executed", errorSchema)))
		entry, _ := paths["/v1/printers/{sn}"+route.Path].(map[string]any)
		if entry == nil {
			entry = map[string]any{}
			paths["/v1/printers/{sn}"+route.Path] = entry
		}
		entry[strings.ToLower(route.Method)] = op
	}
}
