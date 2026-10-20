// Package liveview obtains camera live-view credentials for a printer and
// turns them into the bambu:/// tunnel URLs understood by Bambu Studio's
// network plugin (libBambuSource.so), which cmd/bambu-tunnel drives.
//
// Remote live view goes through one of two relays chosen by the printer
// firmware: TUTK (P1, A1 and X1 before Agora firmware) or Agora (X1, H2 and
// newer firmware). The cloud issues short-lived credentials for either through
// POST iot-service/api/user/ttcode; TUTK additionally needs a liveview/prepare
// MQTT command so the printer starts its TUTK server.
package liveview

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud/model"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/mqtt"
)

// PluginVersion is the Bambu Studio network plugin release this package was
// verified against (the libBambuSource.so bundle cmd/bambu-tunnel loads).
const PluginVersion = "02.08.04.60"

// Transport is a remote camera relay.
type Transport string

const (
	TransportTUTK  Transport = "tutk"
	TransportAgora Transport = "agora"
)

// Capabilities is what a printer's status report says about its camera.
type Capabilities struct {
	// Camera is false when the report shows no camera module at all.
	Camera bool `json:"camera"`
	// TUTK and Agora report which remote relays the printer offers.
	TUTK  bool `json:"tutk"`
	Agora bool `json:"agora"`
	// Remote is the raw ipcam.liveview.remote value when the firmware reports
	// one ("none", "tutk", "agora", "tutk_agora").
	Remote string `json:"remote,omitempty"`
	// TUTKServer is the raw ipcam.tutk_server state ("enable"/"disable").
	TUTKServer string `json:"tutkServer,omitempty"`
	// Resolution is the configured camera resolution ("720p", "1080p").
	Resolution string `json:"resolution,omitempty"`
}

// Preferred is the relay to try first: Agora when offered (it carries H.264
// instead of TUTK's low-rate MJPEG on the models that support both).
func (c Capabilities) Preferred() (Transport, bool) {
	switch {
	case c.Agora:
		return TransportAgora, true
	case c.TUTK:
		return TransportTUTK, true
	}
	return "", false
}

// homeFlagAgora is the home_flag bit newer firmware sets when Agora live view
// is supported (BambuStudio DeviceManager: is_support_agora).
const homeFlagAgora = 1 << 30

// CapabilitiesFromReport reads the camera facts from a printer's print report
// (the DeviceState.Print map). Firmware that omits ipcam.liveview.remote is
// assumed to support TUTK whenever it has a camera, which matches every
// shipped P1/A1/X1 firmware.
func CapabilitiesFromReport(print map[string]any) Capabilities {
	var c Capabilities
	ipcam, _ := print["ipcam"].(map[string]any)
	if ipcam == nil {
		return c
	}
	c.Camera = true
	if dev, ok := ipcam["ipcam_dev"].(string); ok && dev == "0" {
		c.Camera = false
	}
	c.TUTKServer, _ = ipcam["tutk_server"].(string)
	c.Resolution, _ = ipcam["resolution"].(string)
	if lv, ok := ipcam["liveview"].(map[string]any); ok {
		c.Remote, _ = lv["remote"].(string)
	}
	if c.Remote != "" {
		c.TUTK = strings.Contains(c.Remote, "tutk")
		c.Agora = strings.Contains(c.Remote, "agora") || strings.Contains(c.Remote, "agaro")
		return c
	}
	c.TUTK = c.Camera
	if hf, ok := print["home_flag"].(float64); ok && int64(hf)&homeFlagAgora != 0 {
		c.Agora = true
	}
	return c
}

// Credentials are the cloud-issued live-view credentials for one printer.
// They are short-lived; fetch them for every viewer.
type Credentials struct {
	Type   Transport `json:"type"`
	Region string    `json:"region"`
	TUTK   *TUTK     `json:"tutk,omitempty"`
	Agora  *Agora    `json:"agora,omitempty"`
}

// TUTK is the IOTC session triple the printer and viewer share.
type TUTK struct {
	UID     string `json:"uid"`
	Authkey string `json:"authkey"`
	Passwd  string `json:"passwd"`
}

// Agora is a token for the printer's Agora RTC channel.
type Agora struct {
	AppID   string `json:"appId"`
	Channel string `json:"channel"`
	// UID and Token are the viewer's own RTC identity (streams[0]).
	UID   int64  `json:"uid"`
	Token string `json:"token"`
	// StreamKey and StreamSalt configure AES-256-GCM2 channel encryption;
	// the salt is base64.
	StreamKey  string `json:"streamKey,omitempty"`
	StreamSalt string `json:"streamSalt,omitempty"`
	// Peers are the printer-side RTC uids.
	Peers []model.AgoraDevicePeer `json:"peers,omitempty"`
	RTM   *model.AgoraRtmConfig   `json:"rtm,omitempty"`
}

// Fetch asks the cloud for live-view credentials. protocols lists the relays
// the caller can drive; the cloud answers with one of them (Type). The client
// must carry a user token and a signer (ttcode is an IoT-signed endpoint).
func Fetch(ctx context.Context, c *cloud.Client, serial string, protocols ...Transport) (*Credentials, error) {
	req := &model.FetchTTCodeRequest{DevId: serial}
	for _, p := range protocols {
		req.Protocols = append(req.Protocols, string(p))
	}
	resp, err := c.PostIotServiceApiUserTtcode(ctx, req, nil)
	if err != nil {
		return nil, err
	}
	return fromResponse(&resp)
}

func fromResponse(resp *model.FetchTTCodeResponse) (*Credentials, error) {
	if resp.Code != nil && *resp.Code != 0 {
		return nil, fmt.Errorf("ttcode: %s (code %d)", firstNonEmpty(resp.Error, resp.Message), *resp.Code)
	}
	cred := &Credentials{Region: resp.Region}
	switch {
	case resp.Type == string(TransportAgora) || (resp.Type == "" && resp.ChannelName != ""):
		if resp.AppId == "" || resp.ChannelName == "" || len(resp.Streams) == 0 {
			return nil, errors.New("ttcode: agora response is missing app_id, channel_name or streams")
		}
		cred.Type = TransportAgora
		cred.Agora = &Agora{
			AppID: resp.AppId, Channel: resp.ChannelName,
			UID: resp.Streams[0].Uid, Token: resp.Streams[0].Token,
			StreamKey: resp.StreamKey, StreamSalt: resp.StreamSalt,
			Peers: resp.Peers, RTM: resp.Rtm,
		}
	case resp.Ttcode != "":
		cred.Type = TransportTUTK
		cred.TUTK = &TUTK{UID: resp.Ttcode, Authkey: resp.Authkey, Passwd: resp.Passwd}
	default:
		return nil, fmt.Errorf("ttcode: no credentials in response (type %q)", resp.Type)
	}
	return cred, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// PrepareTimeout bounds how long Prepare waits for the printer to report its
// TUTK server up; Bambu Handy uses five seconds.
var PrepareTimeout = 8 * time.Second

// Prepare starts the printer's TUTK server for these credentials and waits
// until the printer reports ipcam.tutk_server = "enable". Agora needs no
// preparation. The MQTT client must already be subscribed to the printer.
func Prepare(ctx context.Context, mc *mqtt.Client, serial string, cred *Credentials) error {
	if cred.Type != TransportTUTK {
		return nil
	}
	reports, stop := mc.Watch(serial, 32)
	defer stop()
	region := cred.Region
	if _, err := mc.Send(ctx, serial, mqtt.LiveviewPrepare(mqtt.LiveviewPrepareParams{Ttcode: cred.TUTK.UID, Passwd: cred.TUTK.Passwd, Authkey: cred.TUTK.Authkey, Region: &region})); err != nil {
		return fmt.Errorf("liveview/prepare: %w", err)
	}
	if st := mc.Snapshot(serial); st != nil && CapabilitiesFromReport(st.Print).TUTKServer == "enable" {
		return nil
	}
	timer := time.NewTimer(PrepareTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			// The printer did not confirm; the relay may still accept us.
			return nil
		case <-reports:
			if st := mc.Snapshot(serial); st != nil && CapabilitiesFromReport(st.Print).TUTKServer == "enable" {
				return nil
			}
		}
	}
}

// Viewer identifies the viewing client inside the tunnel URL. Bambu Studio
// sends its own serial/version fields; the plugin reports them to the printer.
type Viewer struct {
	Serial string
	// DeviceVersion is the printer's firmware (ota) version, e.g. "01.04.00.00".
	DeviceVersion string
	// NetVersion is the network plugin version (libBambuSource.so).
	NetVersion string
	// ClientID and ClientVersion identify this viewer.
	ClientID, ClientVersion string
}

// TunnelURL builds the bambu:/// URL that libBambuSource.so opens for these
// credentials.
//
// The TUTK grammar is confirmed against the A1 mini. The Agora grammar is
// what the plugin's StaticAgoraLib::initAgora/joinChannel read back out
// (app, region, channel, user, token, streamKey, streamSalt; see
// docs/liveview.md) but has not been exercised against hardware yet.
func (c *Credentials) TunnelURL(v Viewer) (string, error) {
	q := url.Values{}
	switch c.Type {
	case TransportTUTK:
		if c.TUTK == nil {
			return "", errors.New("missing tutk credentials")
		}
		q.Set("uid", c.TUTK.UID)
		q.Set("authkey", c.TUTK.Authkey)
		q.Set("passwd", c.TUTK.Passwd)
	case TransportAgora:
		if c.Agora == nil {
			return "", errors.New("missing agora credentials")
		}
		q.Set("app", c.Agora.AppID)
		q.Set("channel", c.Agora.Channel)
		q.Set("user", fmt.Sprint(c.Agora.UID))
		q.Set("token", c.Agora.Token)
		if c.Agora.StreamKey != "" {
			q.Set("streamKey", c.Agora.StreamKey)
			q.Set("streamSalt", c.Agora.StreamSalt)
		}
	default:
		return "", fmt.Errorf("unsupported transport %q", c.Type)
	}
	q.Set("region", c.Region)
	q.Set("device", v.Serial)
	if v.DeviceVersion != "" {
		q.Set("dev_ver", v.DeviceVersion)
	}
	if v.NetVersion != "" {
		q.Set("net_ver", v.NetVersion)
	}
	if v.ClientID != "" {
		q.Set("cli_id", v.ClientID)
	}
	if v.ClientVersion != "" {
		q.Set("cli_ver", v.ClientVersion)
	}
	return "bambu:///" + string(c.Type) + "?" + q.Encode(), nil
}

// LANURL is the plugin URL for a printer on the local network: P1/A1 serve
// MJPEG on port 6000 with the access code; X1 serves RTSPS.
func LANURL(ip, accessCode string, rtsps bool) string {
	if rtsps {
		return "bambu:///rtsps___bblp:" + accessCode + "@" + ip + "/streaming/live/1?proto=rtsps"
	}
	return "bambu:///local/" + ip + ".?port=6000&user=bblp&passwd=" + url.QueryEscape(accessCode)
}
