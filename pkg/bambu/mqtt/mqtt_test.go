package mqtt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/secure"
)

func f(v float64) *float64 { return &v }

func TestMoveAxisGcodeMatchesApp(t *testing.T) {
	cases := []struct {
		name string
		p    MoveAxisParams
		want string
	}{
		{"xy uses 9000", MoveAxisParams{X: f(10), Y: f(-5.5)}, "M211 S\nM211 X1 Y1 Z1\nM1002 push_ref_mode\nG91\nG1 X10 Y-5.5 F9000\nM1002 pop_ref_mode\nM211 R \n"},
		{"z only uses 1800", MoveAxisParams{Z: f(1)}, "M211 S\nM211 X1 Y1 Z1\nM1002 push_ref_mode\nG91\nG1 Z1 F1800\nM1002 pop_ref_mode\nM211 R \n"},
		{"xz uses 9000", MoveAxisParams{X: f(1), Z: f(1)}, "M211 S\nM211 X1 Y1 Z1\nM1002 push_ref_mode\nG91\nG1 X1 Z1 F9000\nM1002 pop_ref_mode\nM211 R \n"},
		{"explicit feed", MoveAxisParams{Z: f(0.1), FeedRate: f(600)}, "M211 S\nM211 X1 Y1 Z1\nM1002 push_ref_mode\nG91\nG1 Z0.1 F600\nM1002 pop_ref_mode\nM211 R \n"},
		{"no axes no feed", MoveAxisParams{}, "M211 S\nM211 X1 Y1 Z1\nM1002 push_ref_mode\nG91\nG1 \nM1002 pop_ref_mode\nM211 R \n"},
	}
	for _, c := range cases {
		got := MoveAxis(c.p)
		if got.Module != "print" || got.Command != "gcode_line" || got.Params["param"] != c.want {
			t.Errorf("%s: got %q", c.name, got.Params["param"])
		}
		if len(got.EncryptFields) != 1 || got.EncryptFields[0] != "print:param" {
			t.Errorf("%s: encrypt fields %v", c.name, got.EncryptFields)
		}
	}
	if got := HomeAxes(HomeAxesParams{X: true, Z: true}).Params["param"]; got != "G28 X Z \n" {
		t.Errorf("home: %q", got)
	}
	if got := GcodeLine(GcodeLineParams{Param: "M104 S200\n"}).Params["param"]; got != "M104 S200\n" {
		t.Errorf("existing newline must not be doubled: %q", got)
	}
}

func TestBuildAppliesWireEncodings(t *testing.T) {
	spec, _ := SpecByName("CameraCapturePicSet")
	cmd, err := Build(spec, map[string]any{"control": false})
	if err != nil || cmd.Params["control"] != "disable" {
		t.Fatalf("enable_disable: %v %v", cmd.Params, err)
	}
	spec, _ = SpecByName("BuzzerCtrl")
	cmd, _ = Build(spec, map[string]any{"mode": true})
	if cmd.Params["mode"] != 1 {
		t.Fatalf("int01: %v", cmd.Params)
	}
	spec, _ = SpecByName("AmsChangeFilament")
	cmd, err = Build(spec, map[string]any{"ams_id": float64(0), "slot_id": float64(3)})
	if err != nil || cmd.Params["target"] != 3 || cmd.Params["slot_id"] != 3 {
		t.Fatalf("derived target: %v %v", cmd.Params, err)
	}
	if _, ok := cmd.Params["curr_temp"]; ok {
		t.Fatal("optional param must be omitted when absent")
	}
	if _, err := Build(spec, map[string]any{"ams_id": 0}); err == nil || !strings.Contains(err.Error(), "slot_id") {
		t.Fatalf("missing required param must fail, got %v", err)
	}
	spec, _ = SpecByName("Refill")
	cmd, _ = Build(spec, nil)
	if cmd.Params["refill_command"] != 5 || cmd.Params["version"] != 0 {
		t.Fatalf("const params: %v", cmd.Params)
	}
	spec, _ = SpecByName("MoveAxis")
	cmd, err = Build(spec, map[string]any{"z": float64(-2)})
	if err != nil || !strings.Contains(cmd.Params["param"].(string), "G1 Z-2 F1800") {
		t.Fatalf("gcode builder via Build: %v %v", cmd.Params, err)
	}
	spec, _ = SpecByName("PrintOption")
	cmd, _ = Build(spec, map[string]any{"auto_recovery": true, "sound_enable": false})
	if cmd.Params["auto_recovery"] != true || cmd.Params["sound_enable"] != false {
		t.Fatalf("raw params passthrough: %v", cmd.Params)
	}
}

func TestEnvelopeShape(t *testing.T) {
	env := Envelope("42", "2001", Command{Module: "print", Command: "pause", Params: map[string]any{"sequence_id": "evil", "foo": nil}})
	if env["user_id"] != "42" {
		t.Fatal("user_id missing")
	}
	mod := env["print"].(map[string]any)
	if mod["sequence_id"] != "2001" || mod["command"] != "pause" {
		t.Fatalf("reserved keys must come from the envelope, got %v", mod)
	}
	if _, ok := mod["timestamp"].(int64); !ok {
		t.Fatalf("timestamp must be epoch millis, got %T", mod["timestamp"])
	}
	if v, ok := mod["foo"]; !ok || v != nil {
		t.Fatal("nil params are sent as JSON null, as in the app")
	}
	b, _ := json.Marshal(env)
	if !strings.Contains(string(b), `"foo":null`) {
		t.Fatalf("%s", b)
	}
}

func TestSecureChannelSignAndEncrypt(t *testing.T) {
	appKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	printerKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	sc := &SecureChannel{Key: appKey, CertID: "CN=BBL CA:abc123", PrinterCert: &printerKey.PublicKey}

	payload, err := Encode("7", "2005", GcodeLine(GcodeLineParams{Param: "G28"}), sc)
	if err != nil {
		t.Fatal(err)
	}
	s := string(payload)
	if !strings.HasSuffix(s, "}}") || !strings.Contains(s, `,"header":{"cert_id":"CN=BBL CA:abc123","payload_len":`) {
		t.Fatalf("header must be appended last: %s", s)
	}
	// Body before the header must be canonical and signed as-is.
	idx := strings.Index(s, `,"header":`)
	body := s[:idx] + "}"
	var env map[string]any
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatal(err)
	}
	hdr := env["header"].(map[string]any)
	sig, _ := base64.StdEncoding.DecodeString(hdr["sign_string"].(string))
	h := sha256.Sum256([]byte(body))
	if err := rsa.VerifyPKCS1v15(&appKey.PublicKey, 5, h[:], sig); err != nil {
		t.Fatalf("signature does not verify over the emitted body: %v", err)
	}
	if int(hdr["payload_len"].(float64)) != len(body) {
		t.Fatalf("payload_len %v != %d", hdr["payload_len"], len(body))
	}
	if hdr["sign_ver"] != "v1.0" || hdr["sign_alg"] != "RSA_SHA256" {
		t.Fatalf("header %v", hdr)
	}
	pr := env["print"].(map[string]any)
	if _, ok := pr["param"]; ok {
		t.Fatal("plaintext param must be removed")
	}
	enc, _ := base64.StdEncoding.DecodeString(pr["param_enc"].(string))
	plain, err := rsa.DecryptPKCS1v15(nil, printerKey, enc)
	if err != nil || string(plain) != "G28 \n" {
		t.Fatalf("param_enc did not decrypt to the gcode: %q %v", plain, err)
	}
	canon, _ := secure.CanonicalJSON(map[string]any{"a": 1})
	if string(canon) != `{"a":1}` {
		t.Fatal(canon)
	}
}

func TestEncodeWithoutSecureChannelIsPlainJSON(t *testing.T) {
	payload, err := Encode("", "2001", PushAll(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	_ = json.Unmarshal(payload, &env)
	if _, ok := env["user_id"]; ok {
		t.Fatal("LAN envelopes have no user_id")
	}
	p := env["pushing"].(map[string]any)
	if p["command"] != "pushall" || p["version"] != float64(1) || p["sequence_id"] != "2001" {
		t.Fatalf("%v", p)
	}
}

func TestDeviceStateDeepMerge(t *testing.T) {
	st := newDeviceState("SN")
	st.apply("print", map[string]any{"gcode_state": "RUNNING", "ams": map[string]any{"ams": []any{"a"}, "tray_now": "1"}}, st.UpdatedAt)
	st.apply("print", map[string]any{"ams": map[string]any{"tray_now": "2"}}, st.UpdatedAt)
	ams := st.Print["ams"].(map[string]any)
	if ams["tray_now"] != "2" || ams["ams"] == nil || st.Print["gcode_state"] != "RUNNING" {
		t.Fatalf("merge lost data: %v", st.Print)
	}
	st.apply("print", map[string]any{"command": "pause", "result": "success", "sequence_id": "2002"}, st.UpdatedAt)
	if _, ok := st.Print["result"]; ok {
		t.Fatal("command acks must not be merged into the status snapshot")
	}
	if st.Replies["print"]["pause"]["result"] != "success" {
		t.Fatalf("ack not recorded: %v", st.Replies)
	}
}
