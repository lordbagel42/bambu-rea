package mqtt

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
)

// LocalCAPEM is res/raw/bbl_local_ca.pem from the APK: the "BBL CA2 RSA" root that
// signs printer certificates for LAN-mode MQTT (and the printer's FTPS/camera ports).
//
//go:embed bbl_local_ca.pem
var LocalCAPEM []byte

// Defaults taken from hhp.java / BblBrokerConfig.
const (
	DefaultTimeout     = 10 * time.Second
	FirstSequenceID    = 2001
	DefaultKeepAlive   = 60 * time.Second
	LocalUsername      = "bblp"
	CloudUsernamePfx   = "u_"
	ClientPlatform     = "android"
	PortSSL            = 8883
	topicRequestSuffix = "/request"
	topicReportSuffix  = "/report"
)

// Config describes one broker connection.
type Config struct {
	// Host is "host:port"; port defaults to 8883.
	Host string
	// ClientID must be unique per connection. The cloud broker kicks the previous
	// session that reused an id, so each API instance should use its own hardware id.
	ClientID string
	Username string
	Password string
	// TLS enables TLS (always true for Bambu brokers). Nil uses system roots plus
	// the embedded Bambu LAN CA; LAN printers present certs for their serial, so
	// LANConfig sets InsecureSkipVerify + manual chain verification instead.
	TLS *tls.Config
	// UserID is written as "user_id" in each envelope (cloud uid, empty on LAN).
	UserID string
	// KeepAlive defaults to 60s, Timeout (per command ack) to 10s.
	KeepAlive time.Duration
	Timeout   time.Duration
}

// CloudConfig builds the connection the app opens to the regional EMQX broker:
// username "u_<uid>", password = cloud access token, client id "android:<uid>:<hw>".
func CloudConfig(host, userID, accessToken, hardwareID string) Config {
	return Config{
		Host:     withDefaultPort(host),
		ClientID: ClientPlatform + ":" + userID + ":" + hardwareID,
		Username: CloudUsernamePfx + userID,
		Password: accessToken,
		UserID:   userID,
		TLS:      &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// LANConfig builds the LAN-mode connection: user "bblp", password = the printer's
// access code, TLS validated against the embedded BBL CA (the printer cert's CN is
// its serial, not the IP, so hostname verification is replaced by chain + SN checks).
// Pass extra PEM roots to also trust other CAs (custom firmware, test brokers).
func LANConfig(ip, serial, accessCode string, extraRootsPEM ...[]byte) Config {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(LocalCAPEM)
	for _, r := range extraRootsPEM {
		pool.AppendCertsFromPEM(r)
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // verified in VerifyPeerCertificate against the pinned Bambu CA
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("mqtt: printer sent no certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			inter := x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				if c, err := x509.ParseCertificate(raw); err == nil {
					inter.AddCert(c)
				}
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter}); err != nil {
				return fmt.Errorf("mqtt: printer certificate not signed by Bambu LAN CA: %w", err)
			}
			if serial != "" && leaf.Subject.CommonName != serial {
				return fmt.Errorf("mqtt: printer certificate CN %q does not match serial %q", leaf.Subject.CommonName, serial)
			}
			return nil
		},
	}
	return Config{
		Host:     withDefaultPort(ip),
		ClientID: "bambu-rea-" + strconv.FormatInt(time.Now().UnixNano()%1_000_000, 10),
		Username: LocalUsername,
		Password: accessCode,
		TLS:      tlsCfg,
	}
}

func withDefaultPort(host string) string {
	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(PortSSL))
}

// Report is one message received on device/<sn>/report.
type Report struct {
	Serial     string
	Topic      string
	Payload    []byte
	ReceivedAt time.Time
	// Module/Command/SequenceID are filled when the payload is a command reply.
	Module     string
	Command    string
	SequenceID string
	Result     string
	Reason     string
	// Errno/ErrCode are the numeric error fields some replies carry
	// (BblCommandReceipt); 0 when absent.
	Errno   int
	ErrCode int
}

// Response is the printer's reply to a command, matched on sequence_id.
type Response struct {
	Report
	// Body is the module object of the reply (e.g. the "print" object).
	Body map[string]any
}

// Err returns a non-nil error when the printer reported result != "success".
func (r *Response) Err() error {
	if r == nil {
		return errors.New("mqtt: nil response")
	}
	if r.Errno != 0 || r.ErrCode != 0 {
		return fmt.Errorf("mqtt: %s/%s failed: errno=%d err_code=%d %s %s", r.Module, r.Command, r.Errno, r.ErrCode, r.Result, r.Reason)
	}
	if r.Result == "" || r.Result == "success" || r.Result == "SUCCESS" {
		return nil
	}
	if r.Reason != "" {
		return fmt.Errorf("mqtt: %s/%s failed: %s (%s)", r.Module, r.Command, r.Result, r.Reason)
	}
	return fmt.Errorf("mqtt: %s/%s failed: %s", r.Module, r.Command, r.Result)
}

// Client is a connected MQTT session that can control any number of printers.
type Client struct {
	cfg  Config
	paho paho.Client
	seq  atomic.Int64

	mu       sync.Mutex
	pending  map[string]chan *Response // sequence_id -> waiter
	subs     map[string]bool           // serials with an active report subscription
	state    map[string]*DeviceState
	watchers map[string]map[int]chan Report
	nextW    int
	secure   map[string]*SecureChannel // serial -> established secure channel
}

// Secure returns the secure channel established for serial, or nil.
func (c *Client) Secure(serial string) *SecureChannel {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.secure[serial]
}

// SetSecure installs (or, with nil, removes) the secure channel used for every
// command sent to serial.
func (c *Client) SetSecure(serial string, sc *SecureChannel) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if sc == nil {
		delete(c.secure, serial)
		return
	}
	c.secure[serial] = sc
}

// Connect opens the broker session and blocks until CONNACK or ctx is done.
func Connect(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = DefaultKeepAlive
	}
	if cfg.TLS == nil {
		cfg.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	c := &Client{
		cfg:      cfg,
		pending:  map[string]chan *Response{},
		subs:     map[string]bool{},
		state:    map[string]*DeviceState{},
		watchers: map[string]map[int]chan Report{},
		secure:   map[string]*SecureChannel{},
	}
	c.seq.Store(FirstSequenceID)
	opts := paho.NewClientOptions().
		AddBroker("ssl://" + cfg.Host).
		SetClientID(cfg.ClientID).
		SetUsername(cfg.Username).
		SetPassword(cfg.Password).
		SetTLSConfig(cfg.TLS).
		SetProtocolVersion(4). // MQTT 3.1.1, as BblBrokerConfig
		SetCleanSession(true).
		SetKeepAlive(cfg.KeepAlive).
		SetAutoReconnect(true).
		SetConnectRetry(false).
		SetOrderMatters(false).
		SetDefaultPublishHandler(c.onMessage).
		SetOnConnectHandler(func(pc paho.Client) {
			// Re-subscribe after reconnects.
			c.mu.Lock()
			serials := make([]string, 0, len(c.subs))
			for sn := range c.subs {
				serials = append(serials, sn)
			}
			c.mu.Unlock()
			for _, sn := range serials {
				pc.Subscribe("device/"+sn+topicReportSuffix, 0, c.onMessage)
			}
		})
	c.paho = paho.NewClient(opts)
	tok := c.paho.Connect()
	if err := waitToken(ctx, tok); err != nil {
		return nil, fmt.Errorf("mqtt: connect %s: %w", cfg.Host, err)
	}
	return c, nil
}

func waitToken(ctx context.Context, tok paho.Token) error {
	select {
	case <-tok.Done():
		return tok.Error()
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close disconnects from the broker.
func (c *Client) Close() {
	c.paho.Disconnect(250)
}

// IsConnected reports the broker connection status.
func (c *Client) IsConnected() bool { return c.paho.IsConnectionOpen() }

// Subscribe starts receiving device/<sn>/report for a printer and keeps the
// subscription across reconnects. It is idempotent.
func (c *Client) Subscribe(ctx context.Context, serial string) error {
	c.mu.Lock()
	already := c.subs[serial]
	c.subs[serial] = true
	if _, ok := c.state[serial]; !ok {
		c.state[serial] = newDeviceState(serial)
	}
	c.mu.Unlock()
	if already {
		return nil
	}
	tok := c.paho.Subscribe("device/"+serial+topicReportSuffix, 0, c.onMessage)
	if err := waitToken(ctx, tok); err != nil {
		c.mu.Lock()
		delete(c.subs, serial)
		c.mu.Unlock()
		return fmt.Errorf("mqtt: subscribe %s: %w", serial, err)
	}
	return nil
}

// Unsubscribe stops the report stream for a printer.
func (c *Client) Unsubscribe(ctx context.Context, serial string) error {
	c.mu.Lock()
	delete(c.subs, serial)
	c.mu.Unlock()
	return waitToken(ctx, c.paho.Unsubscribe("device/"+serial+topicReportSuffix))
}

// NextSequenceID returns the next sequence id (the app starts at 2001).
func (c *Client) NextSequenceID() string {
	return strconv.FormatInt(c.seq.Add(1)-1, 10)
}

// Envelope builds the JSON the app publishes for cmd, without signing.
// Params named sequence_id/command/timestamp are ignored, as in hhp.java.
func Envelope(userID, sequenceID string, cmd Command) map[string]any {
	mod := map[string]any{
		"sequence_id": sequenceID,
		"timestamp":   time.Now().UnixMilli(),
	}
	if cmd.Command != "" {
		mod["command"] = cmd.Command
	}
	for k, v := range cmd.Params {
		switch k {
		case "sequence_id", "command", "timestamp":
			continue
		}
		mod[k] = v
	}
	env := map[string]any{}
	if userID != "" {
		env["user_id"] = userID
	}
	env[cmd.Module] = mod
	return env
}

// Encode serializes a command the way the client would publish it: plain JSON,
// or the secure-channel form (encrypted fields + signature header) when sc is set.
func Encode(userID, sequenceID string, cmd Command, sc *SecureChannel) ([]byte, error) {
	env := Envelope(userID, sequenceID, cmd)
	if sc != nil && sc.Key != nil {
		if err := sc.EncryptFields(env, cmd.EncryptFields); err != nil {
			return nil, err
		}
		return sc.Sign(env)
	}
	return json.Marshal(env)
}

// Publish sends cmd to device/<sn>/request without waiting for a reply and
// returns the sequence id used.
func (c *Client) Publish(ctx context.Context, serial string, cmd Command) (string, error) {
	seq := c.NextSequenceID()
	payload, err := Encode(c.cfg.UserID, seq, cmd, c.Secure(serial))
	if err != nil {
		return "", err
	}
	tok := c.paho.Publish("device/"+serial+topicRequestSuffix, 0, false, payload)
	if err := waitToken(ctx, tok); err != nil {
		return "", fmt.Errorf("mqtt: publish %s/%s: %w", cmd.Module, cmd.Command, err)
	}
	return seq, nil
}

// Send publishes cmd and waits for the reply with the same sequence_id, or until
// the configured timeout / ctx expires. The report subscription is created if missing.
func (c *Client) Send(ctx context.Context, serial string, cmd Command) (*Response, error) {
	if err := c.Subscribe(ctx, serial); err != nil {
		return nil, err
	}
	seq := c.NextSequenceID()
	payload, err := Encode(c.cfg.UserID, seq, cmd, c.Secure(serial))
	if err != nil {
		return nil, err
	}
	ch := make(chan *Response, 1)
	c.mu.Lock()
	c.pending[seq] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, seq)
		c.mu.Unlock()
	}()
	tok := c.paho.Publish("device/"+serial+topicRequestSuffix, 0, false, payload)
	if err := waitToken(ctx, tok); err != nil {
		return nil, fmt.Errorf("mqtt: publish %s/%s: %w", cmd.Module, cmd.Command, err)
	}
	timer := time.NewTimer(c.cfg.Timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r, nil
	case <-timer.C:
		return nil, fmt.Errorf("mqtt: %s/%s: no reply within %s (sequence_id %s)", cmd.Module, cmd.Command, c.cfg.Timeout, seq)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Watch returns a channel that receives every report for serial until cancel is
// called. Slow consumers drop messages rather than block the MQTT reader.
func (c *Client) Watch(serial string, buffer int) (<-chan Report, func()) {
	if buffer <= 0 {
		buffer = 64
	}
	ch := make(chan Report, buffer)
	c.mu.Lock()
	id := c.nextW
	c.nextW++
	if c.watchers[serial] == nil {
		c.watchers[serial] = map[int]chan Report{}
	}
	c.watchers[serial][id] = ch
	c.mu.Unlock()
	return ch, func() {
		c.mu.Lock()
		if m := c.watchers[serial]; m != nil {
			if w, ok := m[id]; ok {
				delete(m, id)
				close(w)
			}
		}
		c.mu.Unlock()
	}
}

// State returns the cached, merged report state for serial (nil if never subscribed).
func (c *Client) State(serial string) *DeviceState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state[serial]
}

func intOf(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case string:
		var i int
		if _, err := fmt.Sscanf(n, "%d", &i); err == nil {
			return i
		}
	}
	return 0
}

func (c *Client) onMessage(_ paho.Client, m paho.Message) {
	topic := m.Topic()
	serial := serialFromTopic(topic)
	rep := Report{Serial: serial, Topic: topic, Payload: m.Payload(), ReceivedAt: time.Now()}
	var env map[string]json.RawMessage
	var body map[string]any
	if json.Unmarshal(rep.Payload, &env) == nil {
		for k, raw := range env {
			if k == "user_id" || k == "header" {
				continue
			}
			var mod map[string]any
			if json.Unmarshal(raw, &mod) != nil {
				continue
			}
			rep.Module = k
			body = mod
			rep.Command, _ = mod["command"].(string)
			rep.SequenceID = stringify(mod["sequence_id"])
			rep.Result, _ = mod["result"].(string)
			rep.Reason, _ = mod["reason"].(string)
			rep.Errno = intOf(mod["errno"])
			rep.ErrCode = intOf(mod["err_code"])
			break
		}
	}
	c.mu.Lock()
	if st := c.state[serial]; st != nil && body != nil {
		st.apply(rep.Module, body, rep.ReceivedAt)
	}
	var waiter chan *Response
	if rep.SequenceID != "" {
		waiter = c.pending[rep.SequenceID]
	}
	var fanout []chan Report
	for _, w := range c.watchers[serial] {
		fanout = append(fanout, w)
	}
	for _, w := range c.watchers["*"] {
		fanout = append(fanout, w)
	}
	c.mu.Unlock()
	if waiter != nil {
		select {
		case waiter <- &Response{Report: rep, Body: body}:
		default:
		}
	}
	for _, w := range fanout {
		select {
		case w <- rep:
		default:
		}
	}
}

func serialFromTopic(topic string) string {
	const pfx = "device/"
	if len(topic) <= len(pfx) || topic[:len(pfx)] != pfx {
		return ""
	}
	rest := topic[len(pfx):]
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			return rest[:i]
		}
	}
	return rest
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return strconv.FormatInt(int64(t), 10)
	default:
		return fmt.Sprint(t)
	}
}

// DeviceState is the merged view of everything a printer has reported. The
// printer sends full "pushall" snapshots and incremental diffs on the same
// topic; both are deep-merged per module, like the app's BblPrinterChannel.
type DeviceState struct {
	Serial    string                    `json:"serial"`
	UpdatedAt time.Time                 `json:"updatedAt"`
	Modules   map[string]map[string]any `json:"modules"`
	// Print is a shortcut to Modules["print"], the main status object (temps,
	// progress, AMS, HMS errors, gcode_state ...).
	Print map[string]any `json:"print"`
	// Replies keeps the latest command acknowledgement per module/command
	// (anything carrying a "result"), so e.g. get_access_code or get_fan answers
	// stay available without polluting the status snapshot.
	Replies map[string]map[string]map[string]any `json:"replies,omitempty"`
}

func newDeviceState(serial string) *DeviceState {
	return &DeviceState{Serial: serial, Modules: map[string]map[string]any{}, Replies: map[string]map[string]map[string]any{}}
}

func (s *DeviceState) apply(module string, body map[string]any, at time.Time) {
	if module == "" {
		return
	}
	s.UpdatedAt = at
	if _, isAck := body["result"]; isAck {
		cmd, _ := body["command"].(string)
		if s.Replies[module] == nil {
			s.Replies[module] = map[string]map[string]any{}
		}
		s.Replies[module][cmd] = body
		return
	}
	cur := s.Modules[module]
	if cur == nil {
		cur = map[string]any{}
		s.Modules[module] = cur
	}
	deepMerge(cur, body)
	if module == "print" {
		s.Print = cur
	}
}

// Snapshot returns a JSON-safe copy of the state (safe to marshal concurrently).
func (c *Client) Snapshot(serial string) *DeviceState {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.state[serial]
	if st == nil {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return nil
	}
	var out DeviceState
	if json.Unmarshal(b, &out) != nil {
		return nil
	}
	return &out
}

func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if sv, ok := v.(map[string]any); ok {
			if dv, ok := dst[k].(map[string]any); ok {
				deepMerge(dv, sv)
				continue
			}
		}
		dst[k] = v
	}
}
