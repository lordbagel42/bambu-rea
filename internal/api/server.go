// Package api is the HTTP front end of bambu-api. Cloud calls are made with the
// caller's Bambu access token (Authorization: Bearer ...) or with an API key
// that maps to a Bambu session stored at login; LAN printers are registered
// with their access code.
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
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lordbagel42/bambu-rea/internal/store"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/mqtt"
)

// Config configures a Server.
type Config struct {
	Region     cloud.Region
	APIKey     string // optional shared secret required in X-API-Key on top of per-user auth
	HardwareID string
	AppCert    *cloud.AppCert // optional captured app certificate for IoT-signed endpoints
	IdleAfter  time.Duration
	// RecheckEvery is how often an open event stream re-authenticates its
	// credential on a hosted server (default 30s).
	RecheckEvery time.Duration
	// LANExtraRoots are additional PEM CA bundles trusted for LAN printers.
	LANExtraRoots [][]byte
	Logger        *log.Logger
	// Store persists accounts and API keys. Without it logins are not
	// remembered and the key, account and MCP routes are unavailable.
	Store *store.Store
	// PublicURL is the externally visible base URL (for the OpenAPI servers
	// list and MCP metadata); empty means "same origin".
	PublicURL string
	// CORSOrigins are browser origins allowed to call the API; "*" allows any.
	CORSOrigins []string
}

// Server is the HTTP handler.
type Server struct {
	cfg        Config
	mux        *http.ServeMux
	anon       *cloud.Client
	httpClient *http.Client
	store      *store.Store
	log        *log.Logger

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
	if cfg.RecheckEvery <= 0 {
		cfg.RecheckEvery = 30 * time.Second
	}
	if cfg.HardwareID == "" {
		cfg.HardwareID = "bambu-rea"
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}
	hc := &http.Client{Timeout: 60 * time.Second}
	s := &Server{
		cfg:        cfg,
		mux:        http.NewServeMux(),
		anon:       cloud.New(cfg.Region, cloud.WithHTTPClient(hc), cloud.WithDeviceInfo(deviceInfo(cfg.HardwareID))),
		httpClient: hc,
		store:      cfg.Store,
		log:        cfg.Logger,
		sessions:   map[string]*session{},
		lan:        map[string]*lanPrinter{},
		done:       make(chan struct{}),
	}
	if cfg.AppCert != nil {
		s.appCert = cloud.NewAppCertSigner(nil, cfg.AppCert)
	} else {
		s.appCert = cloud.NewAppCertSigner(s.anon, nil)
	}
	s.anon.Signer = s.appCert
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
		sess.closeMQTT()
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
	if s.cors(w, r) {
		return
	}
	if s.cfg.APIKey != "" && r.Header.Get("X-API-Key") != s.cfg.APIKey && r.URL.Path != "/v1/healthz" {
		writeErr(w, http.StatusUnauthorized, "missing or invalid X-API-Key")
		return
	}
	s.mux.ServeHTTP(w, r)
}

// cors answers browser preflights and stamps allowed origins on every response.
// It returns true when the request was a preflight and has been answered.
func (s *Server) cors(w http.ResponseWriter, r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" || len(s.cfg.CORSOrigins) == 0 {
		return false
	}
	allowed := false
	for _, o := range s.cfg.CORSOrigins {
		if o == "*" || strings.EqualFold(o, origin) {
			allowed = true
			break
		}
	}
	if !allowed {
		return false
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Add("Vary", "Origin")
	h.Set("Access-Control-Expose-Headers", "Content-Type, Mcp-Session-Id")
	if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
		h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key, X-Bambu-Token, X-Bambu-Signed, X-BBL-Client-Type, X-BBL-Client-Version, Mcp-Session-Id, Mcp-Protocol-Version, Last-Event-ID")
		h.Set("Access-Control-Max-Age", "600")
		w.WriteHeader(http.StatusNoContent)
		return true
	}
	return false
}

func (s *Server) routes() {
	m := s.mux
	m.HandleFunc("GET /v1/healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	m.HandleFunc("GET /openapi.json", s.handleOpenAPI)
	m.HandleFunc("GET /docs", s.handleDocs)
	m.HandleFunc("GET /login", s.handleLoginPage)
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/docs", http.StatusFound) })
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

	// Hosted accounts and API keys (need a Store)
	m.HandleFunc("GET /v1/account", s.withSession(s.handleAccount))
	m.HandleFunc("GET /v1/keys", s.withSession(s.handleKeysList))
	m.HandleFunc("POST /v1/keys", s.withSession(s.handleKeysCreate))
	m.HandleFunc("DELETE /v1/keys/{id}", s.withSession(s.handleKeysDelete))
	m.Handle("/mcp", s.mcpHandler())

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

	// LAN registry: a single-user feature. It is global and unauthenticated
	// (it lets the caller dial arbitrary hosts and then drive those printers),
	// so a hosted multi-account server does not offer it.
	if s.store == nil {
		m.HandleFunc("GET /v1/lan/devices", s.handleLANList)
		m.HandleFunc("POST /v1/lan/devices", s.handleLANAdd)
		m.HandleFunc("DELETE /v1/lan/devices/{sn}", s.handleLANDelete)
	}

	// Raw cloud passthrough
	m.HandleFunc("/v1/cloud/{path...}", s.withSession(s.handleCloud))
}

// ---------------------------------------------------------------- helpers

type apiError struct {
	Error  string `json:"error"`
	Code   int    `json:"code,omitempty"`
	Detail any    `json:"detail,omitempty"`
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
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
	var ua errUnauthorized
	if errors.As(err, &ua) {
		writeErr(w, http.StatusUnauthorized, ua.Error())
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var ae *cloud.APIError
	if errors.As(err, &ae) {
		var detail any
		if len(ae.Body) > 0 && json.Valid(ae.Body) {
			detail = json.RawMessage(ae.Body)
		}
		writeJSON(w, ae.StatusCode, apiError{Error: ae.Message, Code: ae.Code, Detail: detail})
		return
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errNoReport) || strings.Contains(err.Error(), "no reply within") {
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

type sessionHandler func(w http.ResponseWriter, r *http.Request, sess *principal)

func (s *Server) withSession(h sessionHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := s.authenticate(r.Context(), credential(r))
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
	cred := credential(r)
	if cred == "" {
		writeErr(w, http.StatusUnauthorized, "printer is not registered for LAN mode; send Authorization: Bearer <bambu access token or API key> for cloud control")
		return nil, sn, false
	}
	sess, err := s.authenticate(r.Context(), cred)
	if err != nil {
		writeCallErr(w, err)
		return nil, sn, false
	}
	c, err := sess.MQTT(r.Context(), s.cfg.Region)
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
	if err := s.rememberLogin(r.Context(), req.Account, res); err != nil {
		s.loginNotStored(w, r, res, err)
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
	if err := s.rememberLogin(r.Context(), "", res); err != nil {
		s.loginNotStored(w, r, res, err)
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

// handleLogout invalidates the Bambu token at the cloud and, when the account
// is stored here, forgets its session so its API keys stop working. Keys
// themselves may not sign the account out.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, sess *principal) {
	if sess.key != nil {
		writeErr(w, http.StatusForbidden, "API keys cannot sign the account out; use a Bambu login session")
		return
	}
	if !s.requireLiveToken(w, r, sess) {
		return
	}
	// The stored session goes first, on a context the client cannot cancel
	// half-way: once the caller hears "ok" the account's keys must be off.
	if s.store != nil && sess.account != nil {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		if err := s.store.ClearSession(ctx, sess.userID); err != nil && !errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusInternalServerError, "could not sign out the stored session: "+err.Error())
			return
		}
	}
	s.dropSessions(sess.userID, sess.token)
	if err := sess.cloud.Logout(r.Context()); err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// isLogoutPath recognises the cloud's logout endpoint in a passthrough request
// (after cleanCloudPath), so it cannot be used to skip handleLogout's rules.
func isLogoutPath(method, path string) bool {
	return method == http.MethodPost && path == "user-service/user/logout"
}

// cleanCloudPath normalises a passthrough service path the way the cloud's web
// server would ("..", "." and "//" resolved, no leading slash), so rules keyed
// on a path cannot be dodged by spelling it differently. Escapes, queries and
// fragments are refused: queries go in the query string.
func cleanCloudPath(in string) (string, error) {
	if strings.ContainsAny(in, "?#%") {
		return "", errors.New("service path must not contain '?', '#' or '%'")
	}
	p := strings.TrimPrefix(path.Clean("/"+in), "/")
	if p == "" {
		return "", errors.New("service path required, e.g. iot-service/api/user/bind")
	}
	return p, nil
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, sess *principal) {
	me, err := sess.cloud.GetUserServiceMyProfile(r.Context(), nil)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, me)
}

// ---------------------------------------------------------------- devices

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, sess *principal) {
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
	st, err := s.printerState(r.Context(), c, sn, r.URL.Query().Get("refresh") == "1")
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, st)
}

// printerState subscribes to the printer and returns its merged report
// snapshot, asking for a full pushall when none (or a refresh) is wanted.
func (s *Server) printerState(ctx context.Context, c *mqtt.Client, sn string, refresh bool) (*mqtt.DeviceState, error) {
	if err := c.Subscribe(ctx, sn); err != nil {
		return nil, err
	}
	st := c.Snapshot(sn)
	if refresh || st == nil || len(st.Print) == 0 {
		// pushing/pushall makes the printer send a full status snapshot.
		if _, err := c.Send(ctx, sn, mqtt.PushAll()); err != nil {
			// Older firmware acks pushall on the print module instead; fall back to a short wait.
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		st = c.Snapshot(sn)
	}
	if st == nil {
		return nil, errNoReport
	}
	return st, nil
}

// errNoReport is returned when the printer has not reported anything yet.
var errNoReport = errors.New("no report received from printer yet")

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
	// A stream outlives the request that opened it, so on a hosted server the
	// credential is checked again periodically: a revoked key or a signed-out
	// account loses the stream within a recheck interval.
	var recheck <-chan time.Time
	if s.store != nil {
		t := time.NewTicker(s.cfg.RecheckEvery)
		defer t.Stop()
		recheck = t.C
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case <-recheck:
			if _, err := s.authenticate(r.Context(), credential(r)); err != nil {
				fmt.Fprintf(w, "event: error\ndata: %s\n\n", bytesOneLine(mustJSON(apiError{Error: err.Error(), Code: http.StatusUnauthorized})))
				fl.Flush()
				return
			}
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

// failed reports whether the printer rejected the command (mqtt.Response.Err).
func (r *commandResult) failed() bool {
	return r.Errno != 0 || r.ErrCode != 0 || (r.Result != "" && !strings.EqualFold(r.Result, "success"))
}

func (s *Server) sendCommand(w http.ResponseWriter, r *http.Request, c *mqtt.Client, sn string, cmd mqtt.Command) {
	if r.URL.Query().Get("wait") == "0" {
		seq, err := c.Publish(r.Context(), sn, cmd)
		if err != nil {
			writeCallErr(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, commandResult{SequenceID: seq, Module: cmd.Module, Command: cmd.Command, Sent: mqtt.Envelope("", "<n>", cmd)})
		return
	}
	res, err := s.execCommand(r.Context(), c, sn, cmd)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	status := 200
	if res.failed() {
		status = http.StatusUnprocessableEntity
	}
	writeJSON(w, status, res)
}

// execCommand publishes a command, waits for the printer's reply and, on the
// app's "verification failed" errnos, establishes the secure channel and
// retries signed. The result carries the printer's verdict; err is transport.
func (s *Server) execCommand(ctx context.Context, c *mqtt.Client, sn string, cmd mqtt.Command) (*commandResult, error) {
	sent := mqtt.Envelope("", "<n>", cmd)
	resp, err := c.Send(ctx, sn, cmd)
	if err != nil {
		return nil, err
	}
	secured := false
	if mqtt.IsSecurityError(resp) {
		// Mirror pv9: refresh the app cert, run the exchange, retry signed.
		if _, xerr := s.establishSecure(ctx, c, sn); xerr != nil {
			s.log.Printf("secure exchange with %s failed: %v", sn, xerr)
		} else if retry, rerr := c.Send(ctx, sn, cmd); rerr == nil {
			resp, secured = retry, true
		}
	}
	return &commandResult{SequenceID: resp.SequenceID, Module: resp.Module, Command: resp.Command, Result: resp.Result, Reason: resp.Reason, Errno: resp.Errno, ErrCode: resp.ErrCode, Reply: resp.Body, Sent: sent, Secured: secured || c.Secure(sn) != nil}, nil
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
func (s *Server) handleCloud(w http.ResponseWriter, r *http.Request, sess *principal) {
	path, err := cleanCloudPath(r.PathValue("path"))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if isLogoutPath(r.Method, path) {
		s.handleLogout(w, r, sess)
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
	err = sess.cloud.Do(r.Context(), cloud.Request{Method: r.Method, Path: path, Query: q, Headers: h, Body: body, Signed: signed}, &raw)
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
