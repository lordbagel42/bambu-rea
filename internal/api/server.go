// Package api is the HTTP front end of bambu-api. Cloud calls are made with the
// caller's Bambu access token (Authorization: Bearer ...), so the server holds no
// credentials of its own; LAN printers are registered with their access code.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/mqtt"
)

// Config configures a Server.
type Config struct {
	Region     cloud.Region
	APIKey     string // optional shared secret required in X-API-Key
	HardwareID string
	AppCert    *cloud.AppCert // optional captured app certificate for IoT-signed endpoints
	IdleAfter  time.Duration
	// LANExtraRoots are additional PEM CA bundles trusted for LAN printers.
	LANExtraRoots [][]byte
	Logger        *log.Logger
}

// Server is the HTTP handler.
type Server struct {
	cfg  Config
	mux  *http.ServeMux
	anon *cloud.Client
	log  *log.Logger

	// appCert is the shared, cloud-issued app certificate used for IoT-signed
	// HTTP endpoints and the MQTT secure channel. The cert endpoint needs no
	// user token and returns the same certificate for every caller.
	appCert *cloud.AppCertSigner

	mu       sync.Mutex
	sessions map[string]*session
	lan      map[string]*lanPrinter
	done     chan struct{}
}

// New builds the server and starts its idle reaper.
func New(cfg Config) *Server {
	if cfg.IdleAfter <= 0 {
		cfg.IdleAfter = 15 * time.Minute
	}
	if cfg.HardwareID == "" {
		cfg.HardwareID = "bambu-rea"
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	s := &Server{
		cfg:      cfg,
		mux:      http.NewServeMux(),
		anon:     cloud.New(cfg.Region, cloud.WithDeviceInfo(cloud.DeviceInfo{DeviceID: cfg.HardwareID, Brand: "google", Model: "Pixel 8", OSVersion: "15", Language: "en"})),
		log:      cfg.Logger,
		sessions: map[string]*session{},
		lan:      map[string]*lanPrinter{},
		done:     make(chan struct{}),
	}
	if cfg.AppCert != nil {
		s.appCert = cloud.NewAppCertSigner(nil, cfg.AppCert)
	} else {
		s.appCert = cloud.NewAppCertSigner(s.anon, nil)
	}
	s.routes()
	go s.reap()
	return s
}

// Close shuts down all MQTT sessions.
func (s *Server) Close() {
	close(s.done)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sess := range s.sessions {
		sess.mu.Lock()
		if sess.mqtt != nil {
			sess.mqtt.Close()
		}
		sess.mu.Unlock()
	}
	for _, p := range s.lan {
		p.mu.Lock()
		if p.mqtt != nil {
			p.mqtt.Close()
		}
		p.mu.Unlock()
	}
}

// CommandCount is the number of printer commands exposed.
func (s *Server) CommandCount() int { return len(mqtt.Specs) }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s.cfg.APIKey != "" && r.Header.Get("X-API-Key") != s.cfg.APIKey && r.URL.Path != "/v1/healthz" {
		writeErr(w, http.StatusUnauthorized, "missing or invalid X-API-Key")
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	m.HandleFunc("GET /openapi.json", s.handleOpenAPI)
	m.HandleFunc("GET /v1/catalog/endpoints", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, cloud.Endpoints) })
	m.HandleFunc("GET /v1/catalog/commands", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, mqtt.Specs) })
	m.HandleFunc("GET /v1/catalog/region", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.cfg.Region) })

	// Account
	m.HandleFunc("GET /v1/auth/pubkey", s.handlePubKey)
	m.HandleFunc("POST /v1/auth/login", s.handleLogin)
	m.HandleFunc("POST /v1/auth/tfa", s.handleTFA)
	m.HandleFunc("POST /v1/auth/email-code", s.handleEmailCode)
	m.HandleFunc("POST /v1/auth/logout", s.withSession(s.handleLogout))
	m.HandleFunc("GET /v1/me", s.withSession(s.handleMe))

	// Printers (cloud-bound or LAN-registered)
	m.HandleFunc("GET /v1/devices", s.withSession(s.handleDevices))
	m.HandleFunc("GET /v1/devices/{sn}/state", s.handleState)
	m.HandleFunc("GET /v1/devices/{sn}/events", s.handleEvents)
	m.HandleFunc("POST /v1/devices/{sn}/commands/{name}", s.handleCommand)
	m.HandleFunc("POST /v1/devices/{sn}/raw", s.handleRaw)
	m.HandleFunc("POST /v1/devices/{sn}/gcode", s.handleGcode)
	m.HandleFunc("POST /v1/devices/{sn}/move", s.handleMove)
	m.HandleFunc("POST /v1/devices/{sn}/home", s.handleHome)
	m.HandleFunc("GET /v1/devices/{sn}/security", s.handleSecurityStatus)
	m.HandleFunc("POST /v1/devices/{sn}/security/exchange", s.handleSecurityExchange)
	m.HandleFunc("DELETE /v1/devices/{sn}/security", s.handleSecurityDrop)
	m.HandleFunc("GET /v1/appcert", s.handleAppCert)

	// LAN registry
	m.HandleFunc("GET /v1/lan/devices", s.handleLANList)
	m.HandleFunc("POST /v1/lan/devices", s.handleLANAdd)
	m.HandleFunc("DELETE /v1/lan/devices/{sn}", s.handleLANDelete)

	// Raw cloud passthrough
	m.HandleFunc("/v1/cloud/{path...}", s.withSession(s.handleCloud))
}

// ---------------------------------------------------------------- helpers

type apiError struct {
	Error  string `json:"error"`
	Code   int    `json:"code,omitempty"`
	Detail any    `json:"detail,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

// writeCallErr maps cloud/MQTT errors onto HTTP statuses.
func writeCallErr(w http.ResponseWriter, err error) {
	var ae *cloud.APIError
	if errors.As(err, &ae) {
		var detail any
		if len(ae.Body) > 0 && json.Valid(ae.Body) {
			detail = json.RawMessage(ae.Body)
		}
		writeJSON(w, ae.StatusCode, apiError{Error: ae.Message, Code: ae.Code, Detail: detail})
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "no reply within") {
		writeErr(w, http.StatusGatewayTimeout, err.Error())
		return
	}
	writeErr(w, http.StatusBadGateway, err.Error())
}

func decodeBody(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		return err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.UseNumber()
	return dec.Decode(v)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if t := r.Header.Get("X-Bambu-Token"); t != "" {
		return t
	}
	return ""
}

type sessionHandler func(w http.ResponseWriter, r *http.Request, sess *session)

func (s *Server) withSession(h sessionHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if tok == "" {
			writeErr(w, http.StatusUnauthorized, "Authorization: Bearer <bambu access token> required")
			return
		}
		sess, err := s.sessionFor(r.Context(), tok)
		if err != nil {
			writeCallErr(w, err)
			return
		}
		h(w, r, sess)
	}
}

// printerClient resolves the MQTT client for a serial: a registered LAN printer
// wins, otherwise the caller's cloud session.
func (s *Server) printerClient(w http.ResponseWriter, r *http.Request) (*mqtt.Client, string, bool) {
	sn := r.PathValue("sn")
	s.mu.Lock()
	lp := s.lan[sn]
	s.mu.Unlock()
	if lp != nil {
		c, err := lp.MQTT(r.Context())
		if err != nil {
			writeCallErr(w, err)
			return nil, sn, false
		}
		return c, sn, true
	}
	tok := bearer(r)
	if tok == "" {
		writeErr(w, http.StatusUnauthorized, "printer is not registered for LAN mode; send Authorization: Bearer <bambu access token> for cloud control")
		return nil, sn, false
	}
	sess, err := s.sessionFor(r.Context(), tok)
	if err != nil {
		writeCallErr(w, err)
		return nil, sn, false
	}
	c, err := sess.MQTT(r.Context(), s.cfg.Region, s.cfg.HardwareID)
	if err != nil {
		writeCallErr(w, err)
		return nil, sn, false
	}
	return c, sn, true
}

// ---------------------------------------------------------------- auth

func (s *Server) handlePubKey(w http.ResponseWriter, r *http.Request) {
	pk, err := s.anon.PubKey(r.Context())
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, pk)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req cloud.LoginRequest
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Account == "" || (req.Password == "" && req.Code == "" && req.Token == "" && req.OneClickToken == "") {
		writeErr(w, 400, "account plus password, code or token required")
		return
	}
	// Each login gets a fresh anonymous client so tokens never leak between callers.
	c := s.anon.WithToken("")
	res, err := c.LoginWith(r.Context(), &req)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleTFA(w http.ResponseWriter, r *http.Request) {
	var req struct {
		TfaKey  string `json:"tfaKey"`
		TfaCode string `json:"tfaCode"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	res, err := s.anon.WithToken("").LoginTFA(r.Context(), req.TfaKey, req.TfaCode)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleEmailCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Type  string `json:"type"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Type == "" {
		req.Type = "codeLogin"
	}
	if err := s.anon.WithToken("").SendEmailCode(r.Context(), req.Email, req.Type); err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *session) {
	err := sess.cloud.Logout(r.Context())
	s.mu.Lock()
	delete(s.sessions, tokenKey(sess.token))
	s.mu.Unlock()
	sess.mu.Lock()
	if sess.mqtt != nil {
		sess.mqtt.Close()
	}
	sess.mu.Unlock()
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, sess *session) {
	me, err := sess.cloud.GetUserServiceMyProfile(r.Context(), nil)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, me)
}

// ---------------------------------------------------------------- devices

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, sess *session) {
	list, err := sess.cloud.GetIotServiceApiUserBind(r.Context(), nil)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, list)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	c, sn, ok := s.printerClient(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := c.Subscribe(ctx, sn); err != nil {
		writeCallErr(w, err)
		return
	}
	st := c.Snapshot(sn)
	refresh := r.URL.Query().Get("refresh") == "1" || st == nil || len(st.Print) == 0
	if refresh {
		// pushing/pushall makes the printer send a full status snapshot.
		if _, err := c.Send(ctx, sn, mqtt.PushAll()); err != nil {
			// Older firmware acks pushall on the print module instead; fall back to a short wait.
			time.Sleep(1500 * time.Millisecond)
		}
		st = c.Snapshot(sn)
	}
	if st == nil {
		writeErr(w, http.StatusGatewayTimeout, "no report received from printer yet")
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	c, sn, ok := s.printerClient(w, r)
	if !ok {
		return
	}
	if err := c.Subscribe(r.Context(), sn); err != nil {
		writeCallErr(w, err)
		return
	}
	fl, canFlush := w.(http.Flusher)
	if !canFlush {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	if st := c.Snapshot(sn); st != nil {
		b, _ := json.Marshal(st)
		fmt.Fprintf(w, "event: state\ndata: %s\n\n", b)
	}
	fl.Flush()
	ch, cancel := c.Watch(sn, 256)
	defer cancel()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		case rep, ok := <-ch:
			if !ok {
				return
			}
			ev := "report"
			if rep.Module != "" {
				ev = rep.Module
			}
			fmt.Fprintf(w, "event: %s\nid: %s\ndata: %s\n\n", ev, rep.SequenceID, bytesOneLine(rep.Payload))
			fl.Flush()
		}
	}
}

func bytesOneLine(b []byte) string {
	return strings.ReplaceAll(strings.ReplaceAll(string(b), "\r", ""), "\n", "")
}

type commandResult struct {
	SequenceID string         `json:"sequenceId"`
	Module     string         `json:"module"`
	Command    string         `json:"command"`
	Result     string         `json:"result,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Errno      int            `json:"errno,omitempty"`
	ErrCode    int            `json:"errCode,omitempty"`
	Reply      map[string]any `json:"reply,omitempty"`
	Sent       map[string]any `json:"sent"`
	// Secured is true when the command went out signed through the secure channel.
	Secured bool `json:"secured"`
}

func (s *Server) sendCommand(w http.ResponseWriter, r *http.Request, c *mqtt.Client, sn string, cmd mqtt.Command) {
	wait := r.URL.Query().Get("wait") != "0"
	sent := mqtt.Envelope("", "<n>", cmd)
	if !wait {
		seq, err := c.Publish(r.Context(), sn, cmd)
		if err != nil {
			writeCallErr(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, commandResult{SequenceID: seq, Module: cmd.Module, Command: cmd.Command, Sent: sent})
		return
	}
	resp, err := c.Send(r.Context(), sn, cmd)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	secured := false
	if mqtt.IsSecurityError(resp) {
		// Mirror pv9: refresh the app cert, run the exchange, retry signed.
		if _, xerr := s.establishSecure(r.Context(), c, sn); xerr != nil {
			s.log.Printf("secure exchange with %s failed: %v", sn, xerr)
		} else if retry, rerr := c.Send(r.Context(), sn, cmd); rerr == nil {
			resp, secured = retry, true
		}
	}
	status := 200
	if resp.Err() != nil {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, commandResult{SequenceID: resp.SequenceID, Module: resp.Module, Command: resp.Command, Result: resp.Result, Reason: resp.Reason, Errno: resp.Errno, ErrCode: resp.ErrCode, Reply: resp.Body, Sent: sent, Secured: secured || c.Secure(sn) != nil})
}

// establishSecure fetches the shared app certificate and runs the
// app_cert_list / app_cert_install exchange with the printer.
func (s *Server) establishSecure(ctx context.Context, c *mqtt.Client, sn string) (*mqtt.SecureStatus, error) {
	cert, err := s.appCert.Cert(ctx)
	if err != nil {
		return nil, fmt.Errorf("app certificate: %w", err)
	}
	return c.EstablishSecure(ctx, sn, mqtt.AppCertMaterial{CertPEM: cert.CertPEM, CRLPEM: cert.CRLPEM, MQTTCertID: cert.MQTTCertID, Key: cert.Key})
}

type securityStatus struct {
	Serial       string `json:"serial"`
	Secure       bool   `json:"secure"`
	CertID       string `json:"certId,omitempty"`
	FieldEncrypt bool   `json:"fieldEncrypt"`
	PrinterCert  string `json:"printerCert,omitempty"`
}

func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	c, sn, ok := s.printerClient(w, r)
	if !ok {
		return
	}
	st := securityStatus{Serial: sn}
	if sc := c.Secure(sn); sc != nil {
		st.Secure, st.CertID, st.FieldEncrypt, st.PrinterCert = true, sc.CertID, sc.PrinterCert != nil, sc.PrinterCertPEM
	}
	writeJSON(w, 200, st)
}

func (s *Server) handleSecurityExchange(w http.ResponseWriter, r *http.Request) {
	c, sn, ok := s.printerClient(w, r)
	if !ok {
		return
	}
	st, err := s.establishSecure(r.Context(), c, sn)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, st)
}

func (s *Server) handleSecurityDrop(w http.ResponseWriter, r *http.Request) {
	c, sn, ok := s.printerClient(w, r)
	if !ok {
		return
	}
	c.SetSecure(sn, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleAppCert reports the shared app certificate (never its private key).
func (s *Server) handleAppCert(w http.ResponseWriter, r *http.Request) {
	cert, err := s.appCert.Cert(r.Context())
	if err != nil {
		writeCallErr(w, err)
		return
	}
	leaf, err := cert.LeafCert()
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"certId":     cert.CertID,
		"mqttCertId": cert.MQTTCertID,
		"subject":    leaf.Subject.CommonName,
		"issuer":     leaf.Issuer.CommonName,
		"notAfter":   leaf.NotAfter,
		"keyLayout":  cert.KeyLayout,
		"fetchedAt":  cert.FetchedAt,
		"cert":       cert.CertPEM,
		"crl":        cert.CRLPEM,
	})
}

func (s *Server) handleCommand(w http.ResponseWriter, r *http.Request) {
	spec, ok := mqtt.SpecByName(r.PathValue("name"))
	if !ok {
		writeErr(w, 404, "unknown command; see /v1/catalog/commands")
		return
	}
	params := map[string]any{}
	if err := decodeBody(r, &params); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	normalizeNumbers(params)
	cmd, err := mqtt.Build(spec, params)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	c, sn, ok := s.printerClient(w, r)
	if !ok {
		return
	}
	s.sendCommand(w, r, c, sn, cmd)
}

func (s *Server) handleRaw(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Module        string         `json:"module"`
		Command       string         `json:"command"`
		Params        map[string]any `json:"params"`
		EncryptFields []string       `json:"encryptFields"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.Module == "" {
		writeErr(w, 400, "module required")
		return
	}
	normalizeNumbers(req.Params)
	c, sn, ok := s.printerClient(w, r)
	if !ok {
		return
	}
	s.sendCommand(w, r, c, sn, mqtt.Command{Module: req.Module, Command: req.Command, Params: req.Params, EncryptFields: req.EncryptFields})
}

func (s *Server) handleGcode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Gcode string `json:"gcode"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if strings.TrimSpace(req.Gcode) == "" {
		writeErr(w, 400, "gcode required")
		return
	}
	c, sn, ok := s.printerClient(w, r)
	if !ok {
		return
	}
	s.sendCommand(w, r, c, sn, mqtt.GcodeLine(mqtt.GcodeLineParams{Param: req.Gcode}))
}

func (s *Server) handleMove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		X, Y, Z  *float64
		FeedRate *float64 `json:"feed_rate"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	c, sn, ok := s.printerClient(w, r)
	if !ok {
		return
	}
	s.sendCommand(w, r, c, sn, mqtt.MoveAxis(mqtt.MoveAxisParams{X: req.X, Y: req.Y, Z: req.Z, FeedRate: req.FeedRate}))
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	var req struct {
		X, Y, Z *bool
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	all := req.X == nil && req.Y == nil && req.Z == nil
	p := mqtt.HomeAxesParams{X: all || (req.X != nil && *req.X), Y: all || (req.Y != nil && *req.Y), Z: all || (req.Z != nil && *req.Z)}
	c, sn, ok := s.printerClient(w, r)
	if !ok {
		return
	}
	s.sendCommand(w, r, c, sn, mqtt.HomeAxes(p))
}

// normalizeNumbers converts json.Number (from UseNumber) into int/float64 so the
// command builders and encoding/json treat them like ordinary JSON numbers.
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			t[k] = normalizeNumbers(e)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = normalizeNumbers(e)
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			if int64(int(i)) == i {
				return int(i)
			}
			return i
		}
		f, _ := t.Float64()
		return f
	}
	return v
}

// ---------------------------------------------------------------- LAN

func (s *Server) handleLANList(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := make([]*lanPrinter, 0, len(s.lan))
	for _, p := range s.lan {
		out = append(out, p)
	}
	s.mu.Unlock()
	writeJSON(w, 200, out)
}

func (s *Server) handleLANAdd(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP         string `json:"ip"`
		Serial     string `json:"serial"`
		AccessCode string `json:"accessCode"`
		Name       string `json:"name"`
		Insecure   bool   `json:"insecure"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if req.IP == "" || req.Serial == "" || req.AccessCode == "" {
		writeErr(w, 400, "ip, serial and accessCode required")
		return
	}
	p := &lanPrinter{IP: req.IP, Serial: req.Serial, AccessCode: req.AccessCode, Name: req.Name, Insecure: req.Insecure, extraRoots: s.cfg.LANExtraRoots}
	if _, err := p.MQTT(r.Context()); err != nil {
		writeCallErr(w, err)
		return
	}
	s.mu.Lock()
	if old := s.lan[req.Serial]; old != nil && old.mqtt != nil {
		old.mqtt.Close()
	}
	s.lan[req.Serial] = p
	s.mu.Unlock()
	writeJSON(w, 201, p)
}

func (s *Server) handleLANDelete(w http.ResponseWriter, r *http.Request) {
	sn := r.PathValue("sn")
	s.mu.Lock()
	p := s.lan[sn]
	delete(s.lan, sn)
	s.mu.Unlock()
	if p == nil {
		writeErr(w, 404, "not registered")
		return
	}
	p.mu.Lock()
	if p.mqtt != nil {
		p.mqtt.Close()
	}
	p.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- cloud passthrough

// handleCloud forwards /v1/cloud/<service path> to the Bambu cloud with the
// caller's token and the app's standard headers. Query string and JSON body are
// passed through; IoT-signed endpoints get the certificate headers automatically.
func (s *Server) handleCloud(w http.ResponseWriter, r *http.Request, sess *session) {
	path := r.PathValue("path")
	if path == "" {
		writeErr(w, 400, "service path required, e.g. /v1/cloud/iot-service/api/user/bind")
		return
	}
	signed := r.Header.Get("X-Bambu-Signed") == "1"
	for _, ep := range cloud.Endpoints {
		if ep.Method == r.Method && pathMatches(ep.Path, path) {
			signed = signed || ep.Signed
			break
		}
	}
	var body any
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.ContentLength != 0 {
		data, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		if len(data) > 0 {
			if !json.Valid(data) && strings.Contains(r.Header.Get("Content-Type"), "json") {
				writeErr(w, 400, "body is not valid JSON")
				return
			}
			if json.Valid(data) {
				var generic any
				_ = json.Unmarshal(data, &generic)
				body = generic // re-encoded; lets the password rewrite hook run for login-type bodies
			} else {
				body = data
			}
		}
	}
	h := http.Header{}
	for k, vs := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-bbl-") || lk == "content-type" {
			for _, v := range vs {
				h.Add(k, v)
			}
		}
	}
	q := url.Values(r.URL.Query())
	var raw []byte
	err := sess.cloud.Do(r.Context(), cloud.Request{Method: r.Method, Path: path, Query: q, Headers: h, Body: body, Signed: signed}, &raw)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(raw)))
	w.WriteHeader(200)
	_, _ = w.Write(raw)
}

// pathMatches compares a Retrofit template (with {params}) against a concrete path.
func pathMatches(tmpl, actual string) bool {
	ts := strings.Split(strings.Trim(tmpl, "/"), "/")
	as := strings.Split(strings.Trim(actual, "/"), "/")
	if len(ts) != len(as) {
		return false
	}
	for i := range ts {
		if strings.HasPrefix(ts[i], "{") && strings.HasSuffix(ts[i], "}") {
			continue
		}
		if ts[i] != as[i] {
			return false
		}
	}
	return true
}
