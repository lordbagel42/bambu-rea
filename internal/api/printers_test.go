package api

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/eclipse/paho.mqtt.golang/packets"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
)

// A local TLS MQTT peer exercises the public HTTP API down to the actual wire.
// It acknowledges commands, except pause, which simulates a printer rejection.
func printerPeer(t *testing.T) (string, <-chan map[string]any) {
	t.Helper()
	certServer := httptest.NewTLSServer(http.NotFoundHandler())
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	received := make(chan map[string]any, 64)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
		for {
			packet, err := packets.ReadPacket(conn)
			if err != nil {
				return
			}
			switch p := packet.(type) {
			case *packets.ConnectPacket:
				_ = packets.NewControlPacket(packets.Connack).Write(conn)
			case *packets.SubscribePacket:
				ack := packets.NewControlPacket(packets.Suback).(*packets.SubackPacket)
				ack.MessageID, ack.ReturnCodes = p.MessageID, []byte{0}
				_ = ack.Write(conn)
			case *packets.PublishPacket:
				var envelope map[string]any
				if err := json.Unmarshal(p.Payload, &envelope); err != nil {
					return
				}
				if p.Qos == 1 {
					ack := packets.NewControlPacket(packets.Puback).(*packets.PubackPacket)
					ack.MessageID = p.MessageID
					_ = ack.Write(conn)
				}
				for _, value := range envelope {
					if body, ok := value.(map[string]any); ok {
						body["result"] = "success"
						if body["command"] == "pause" {
							body["result"], body["reason"] = "fail", "not printing"
						}
					}
				}
				reply := packets.NewControlPacket(packets.Publish).(*packets.PublishPacket)
				reply.TopicName = strings.Replace(p.TopicName, "/request", "/report", 1)
				reply.Payload, _ = json.Marshal(envelope)
				received <- envelope
				_ = reply.Write(conn)
			case *packets.PingreqPacket:
				_ = packets.NewControlPacket(packets.Pingresp).Write(conn)
			case *packets.DisconnectPacket:
				return
			}
		}
	}()
	return ln.Addr().String(), received
}

func TestPrinterResourcesSendExpectedCommands(t *testing.T) {
	hs, _ := newTestServer(t, false)
	addr, received := printerPeer(t)
	if r := do(t, hs, "POST", "/v1/lan/devices", "", obj("ip", addr, "serial", "TEST", "accessCode", "test", "insecure", true)); r.status != 201 {
		t.Fatalf("register peer: %d %s", r.status, r.raw)
	}
	cases := []struct {
		method, path, body, module, command string
		want                                map[string]any
		status                              int
	}{
		{"PUT", "/lights/chamber", `{"on":true}`, "system", "ledctrl", obj("led_node", "chamber_light", "led_mode", "on", "led_on_time", float64(500)), 200},
		{"PUT", "/lights/work?wait=0", `{"on":false}`, "system", "ledctrl", obj("led_node", "work_light", "led_mode", "off"), 202},
		{"PUT", "/fans/aux", `{"percent":37}`, "print", "set_fan", obj("fan_index", float64(2), "speed", float64(37)), 200},
		{"PUT", "/fans/part", `{"percent":0}`, "print", "set_fan", obj("fan_index", float64(1), "speed", float64(0)), 200},
		{"PUT", "/fans/chamber", `{"percent":100}`, "print", "set_fan", obj("fan_index", float64(3), "speed", float64(100)), 200},
		{"PUT", "/temperatures/bed", `{"celsius":0}`, "print", "gcode_line", obj("param", "M140 S0\n"), 200},
		{"PUT", "/temperatures/nozzle", `{"celsius":215,"extruder":1}`, "print", "gcode_line", obj("param", "M104 T1 S215\n"), 200},
		{"PUT", "/job/speed", `{"mode":"sport"}`, "print", "print_speed", obj("param", "3"), 200},
		{"POST", "/job/start", `{"file":"/sdcard/model.3mf","bed_leveling":false}`, "print", "gcode_file", obj("param", "/sdcard/model.3mf", "bed_leveling", false, "flow_cali", true), 200},
		{"PUT", "/camera/recording", `{"enabled":false}`, "camera", "ipcam_record_set", obj("control", "disable"), 200},
		{"POST", "/ams/load", `{"ams_id":1,"slot_id":6}`, "print", "ams_change_filament", obj("ams_id", float64(1), "slot_id", float64(6), "target", float64(6)), 200},
		{"POST", "/motion/home", `{}`, "print", "gcode_line", obj("param", "G28 X Y Z \n"), 200},
		{"POST", "/motion/home", `{"z":true}`, "print", "gcode_line", obj("param", "G28 Z \n"), 200},
		{"POST", "/motion/move", `{"z":-1.5}`, "print", "gcode_line", obj("param", "M211 S\nM211 X1 Y1 Z1\nM1002 push_ref_mode\nG91\nG1 Z-1.5 F1800\nM1002 pop_ref_mode\nM211 R \n"), 200},
		{"POST", "/job/pause", `{}`, "print", "pause", obj(), 422},
	}
	for _, tc := range cases {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			var body any
			_ = json.Unmarshal([]byte(tc.body), &body)
			r := do(t, hs, tc.method, "/v1/printers/TEST"+tc.path, "", body)
			if r.status != tc.status || r.body["sequenceId"] == "" || r.body["command"] != tc.command {
				t.Fatalf("response: %d %s", r.status, r.raw)
			}
			select {
			case envelope := <-received:
				p, _ := envelope[tc.module].(map[string]any)
				if p["command"] != tc.command {
					t.Fatalf("wire command: %v", envelope)
				}
				for k, want := range tc.want {
					if p[k] != want {
						t.Errorf("wire %s = %v, want %v", k, p[k], want)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("no MQTT command received")
			}
		})
	}
	// The old API still works against the same printer connection.
	if r := do(t, hs, "POST", "/v1/devices/TEST/commands/Resume", "", obj()); r.status != 200 {
		t.Fatalf("legacy command: %d %s", r.status, r.raw)
	}
}

func TestPrinterResourcesRejectInvalidInput(t *testing.T) {
	hs, _ := newTestServer(t, false)
	for _, tc := range []struct{ method, path, body string }{
		{"PUT", "/lights/chamber", `{}`},
		{"PUT", "/lights/chamber", `{"on":"false"}`},
		{"PUT", "/lights/chamber", `{"on":null}`},
		{"PUT", "/lights/chamber", `{"on":true,"onn":false}`},
		{"PUT", "/lights/missing", `{"on":true}`},
		{"PUT", "/fans/aux", `{"percent":101}`},
		{"PUT", "/fans/aux", `{"percent":-1}`},
		{"PUT", "/fans/aux", `{"percent":1.5}`},
		{"PUT", "/fans/missing", `{"percent":50}`},
		{"PUT", "/temperatures/bed", `{"celsius":-1}`},
		{"PUT", "/job/speed", `{"mode":"fast"}`},
		{"POST", "/motion/move", `{"feed_rate":300}`},
		{"POST", "/motion/move", `{"x":1,"feed_rate":0}`},
		{"POST", "/motion/home", `{"z":false}`},
		{"POST", "/gcode", `{"gcode":"  "}`},
		{"POST", "/job/start", `{"file":""}`},
		{"POST", "/job/pause", `null`},
		{"POST", "/job/pause", `[]`},
		{"POST", "/job/pause", `{} {}`},
	} {
		t.Run(tc.path+tc.body, func(t *testing.T) {
			req, _ := http.NewRequest(tc.method, hs.URL+"/v1/printers/UNKNOWN"+tc.path, strings.NewReader(tc.body))
			res, err := hs.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()
			if res.StatusCode != 400 {
				t.Fatalf("status = %d; expected rejection before connecting", res.StatusCode)
			}
		})
	}
	if r := do(t, hs, "PUT", "/v1/printers/UNKNOWN/lights/chamber", "", obj("on", true)); r.status != 401 {
		t.Fatalf("valid input must require authentication: %d %s", r.status, r.raw)
	}
}

func TestPrinterDiscoveryAndOpenAPI(t *testing.T) {
	hs, _ := newTestServer(t, false)
	catalog := do(t, hs, "GET", "/v1/printers/TEST/operations", "", nil)
	if catalog.status != 200 {
		t.Fatalf("catalog: %d %s", catalog.status, catalog.raw)
	}
	// Verify coverage against the public, existing command catalog rather than
	// the implementation's route table, so omissions are visible to consumers.
	commands := do(t, hs, "GET", "/v1/catalog/commands", "", nil)
	var specs []struct{ Name string }
	_ = json.Unmarshal(commands.raw, &specs)
	seen := map[string]bool{}
	doc := do(t, hs, "GET", "/openapi.json", "", nil)
	if doc.status != 200 {
		t.Fatalf("OpenAPI: %d %s", doc.status, doc.raw)
	}
	paths := doc.body["paths"].(map[string]any)
	for _, item := range catalog.body["operations"].([]any) {
		op := item.(map[string]any)
		seen[op["command"].(string)] = true
		entry, ok := paths[op["path"].(string)].(map[string]any)
		if !ok || entry[strings.ToLower(op["method"].(string))] == nil {
			t.Fatalf("missing OpenAPI operation: %v", op)
		}
	}
	for _, sp := range specs {
		if !seen[sp.Name] {
			t.Errorf("command %s has no resource endpoint", sp.Name)
		}
	}
}

func TestPrinterListUsesFriendlyFieldsWithoutAccessCodes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/iot-service/api/user/bind" || r.Header.Get("Authorization") != "Bearer "+fakeJWT("42") {
			t.Errorf("unexpected upstream request: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"devices":[{"dev_id":"SERIAL1","sn":"other","name":"Workshop","dev_model_name":"P1P","online":true,"print_status":"RUNNING","dev_access_code":"secret"},{"sn":"SERIAL2","name":"Desk","dev_model_name":"A1 mini","online":false,"print_status":"IDLE"}]}`))
	}))
	defer upstream.Close()
	region := cloud.RegionIntl
	region.APIBaseURL = upstream.URL + "/v1/"
	s := New(Config{Region: region})
	defer s.Close()
	hs := httptest.NewServer(s)
	defer hs.Close()
	r := do(t, hs, "GET", "/v1/printers", fakeJWT("42"), nil)
	want := obj("printers", []any{
		obj("serial", "SERIAL1", "name", "Workshop", "model", "P1P", "online", true, "status", "RUNNING"),
		obj("serial", "SERIAL2", "name", "Desk", "model", "A1 mini", "online", false, "status", "IDLE"),
	})
	if r.status != 200 || !reflect.DeepEqual(r.body, want) {
		t.Fatalf("list: %d %s", r.status, r.raw)
	}
}
