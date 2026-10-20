package liveview

import (
	"net/url"
	"testing"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud/model"
)

func TestCapabilitiesFromReport(t *testing.T) {
	cases := []struct {
		name  string
		print map[string]any
		want  Capabilities
	}{
		{"no ipcam", map[string]any{}, Capabilities{}},
		{"camera unplugged", map[string]any{"ipcam": map[string]any{"ipcam_dev": "0"}}, Capabilities{Camera: false, TUTK: false}},
		{"a1 mini without liveview.remote", map[string]any{"ipcam": map[string]any{"ipcam_dev": "1", "tutk_server": "enable", "resolution": "1080p"}},
			Capabilities{Camera: true, TUTK: true, TUTKServer: "enable", Resolution: "1080p"}},
		{"home_flag agora bit", map[string]any{"ipcam": map[string]any{"ipcam_dev": "1"}, "home_flag": float64(1 << 30)},
			Capabilities{Camera: true, TUTK: true, Agora: true}},
		{"explicit remote wins over home_flag", map[string]any{"ipcam": map[string]any{"ipcam_dev": "1", "liveview": map[string]any{"remote": "tutk"}}, "home_flag": float64(1 << 30)},
			Capabilities{Camera: true, TUTK: true, Remote: "tutk"}},
		{"remote tutk_agora", map[string]any{"ipcam": map[string]any{"ipcam_dev": "1", "liveview": map[string]any{"remote": "tutk_agora"}}},
			Capabilities{Camera: true, TUTK: true, Agora: true, Remote: "tutk_agora"}},
		{"remote none", map[string]any{"ipcam": map[string]any{"ipcam_dev": "1", "liveview": map[string]any{"remote": "none"}}},
			Capabilities{Camera: true, Remote: "none"}},
	}
	for _, tc := range cases {
		if got := CapabilitiesFromReport(tc.print); got != tc.want {
			t.Errorf("%s: got %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestFromResponse(t *testing.T) {
	code := 0
	tutk, err := fromResponse(&model.FetchTTCodeResponse{Code: &code, Ttcode: "UID", Authkey: "AK", Passwd: "PW", Region: "us"})
	if err != nil || tutk.Type != TransportTUTK || tutk.TUTK == nil || tutk.TUTK.UID != "UID" || tutk.Agora != nil {
		t.Fatalf("tutk: %+v %v", tutk, err)
	}
	agora, err := fromResponse(&model.FetchTTCodeResponse{Type: "agora", AppId: "APP", ChannelName: "CH", Region: "us",
		Streams: []model.AgoraStreamToken{{Uid: 42, Token: "TOK"}}, StreamKey: "K", StreamSalt: "S="})
	if err != nil || agora.Type != TransportAgora || agora.Agora == nil || agora.Agora.UID != 42 || agora.Agora.Token != "TOK" {
		t.Fatalf("agora: %+v %v", agora, err)
	}
	if _, err := fromResponse(&model.FetchTTCodeResponse{Type: "agora", AppId: "APP"}); err == nil {
		t.Error("agora without channel/streams should fail")
	}
	bad := 1
	if _, err := fromResponse(&model.FetchTTCodeResponse{Code: &bad, Error: "nope", Ttcode: "UID"}); err == nil {
		t.Error("non-zero code should fail")
	}
}

func TestTunnelURL(t *testing.T) {
	cred := &Credentials{Type: TransportTUTK, Region: "us", TUTK: &TUTK{UID: "UID", Authkey: "A K", Passwd: "P&W"}}
	raw, err := cred.TunnelURL(Viewer{Serial: "SN", DeviceVersion: "01.04.00.00", NetVersion: PluginVersion})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "bambu" || u.Host != "" || u.Path != "/tutk" {
		t.Fatalf("bad tunnel url %q: %v", raw, err)
	}
	q := u.Query()
	for k, want := range map[string]string{"uid": "UID", "authkey": "A K", "passwd": "P&W", "region": "us", "device": "SN", "dev_ver": "01.04.00.00", "net_ver": PluginVersion} {
		if q.Get(k) != want {
			t.Errorf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if q.Has("cli_id") {
		t.Error("empty viewer fields must be omitted")
	}
	if _, err := (&Credentials{Type: TransportTUTK}).TunnelURL(Viewer{}); err == nil {
		t.Error("missing credentials should fail")
	}
}

func TestLANURL(t *testing.T) {
	if got := LANURL("10.0.0.5", "a b", false); got != "bambu:///local/10.0.0.5.?port=6000&user=bblp&passwd=a+b" {
		t.Errorf("mjpeg: %q", got)
	}
	if got := LANURL("10.0.0.5", "12345678", true); got != "bambu:///rtsps___bblp:12345678@10.0.0.5/streaming/live/1?proto=rtsps" {
		t.Errorf("rtsps: %q", got)
	}
}
