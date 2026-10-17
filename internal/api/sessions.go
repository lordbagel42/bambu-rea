package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lordbagel42/bambu-rea/internal/store"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/mqtt"
)

// session is the per-credential state: a cloud client bound to a Bambu access
// token and a lazily opened MQTT connection to the regional broker. Raw-token
// callers get one session per token; API keys share one session per account,
// which follows the account's latest login.
type session struct {
	token      string
	userID     string
	hardwareID string
	cloud      *cloud.Client
	// account is set when the session was resolved through the store (an API
	// key, or a Bambu token whose owner has logged in here before).
	account *store.Account
	// viaKey is the API key that authenticated the request, if any.
	viaKey *store.APIKey

	mu       sync.Mutex
	mqtt     *mqtt.Client
	lastUsed time.Time
}

// lanPrinter is a printer reachable directly over the LAN (no cloud account).
type lanPrinter struct {
	IP         string `json:"ip"`
	Serial     string `json:"serial"`
	AccessCode string `json:"-"`
	Name       string `json:"name,omitempty"`
	// Insecure disables TLS certificate verification for this printer (custom
	// firmware or a printer whose cert is not signed by the Bambu LAN CA).
	Insecure bool `json:"insecure,omitempty"`

	extraRoots [][]byte

	mu   sync.Mutex
	mqtt *mqtt.Client
}

func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:8])
}

// userIDFromJWT extracts the numeric uid from the cloud access token without
// verifying it; the broker and envelope only need the id, and the cloud rejects
// forged tokens anyway. Bambu tokens carry "username": "u_<uid>" and/or "sub".
func userIDFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return ""
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	if u, _ := claims["username"].(string); strings.HasPrefix(u, "u_") {
		return strings.TrimPrefix(u, "u_")
	}
	switch s := claims["sub"].(type) {
	case string:
		return strings.TrimPrefix(s, "u_")
	case float64:
		return fmt.Sprintf("%.0f", s)
	}
	return ""
}

// errUnauthorized carries a 401 reason out of credential resolution.
type errUnauthorized string

func (e errUnauthorized) Error() string { return string(e) }

// credential pulls the caller's credential out of the request: a Bambu access
// token or an API key, in Authorization: Bearer, X-API-Key or X-Bambu-Token.
func credential(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	if k := r.Header.Get("X-API-Key"); k != "" {
		return k
	}
	if t := r.Header.Get("X-Bambu-Token"); t != "" {
		return t
	}
	return ""
}

// authenticate resolves the request's credential to a session.
func (s *Server) authenticate(ctx context.Context, cred string) (*session, error) {
	if cred == "" {
		return nil, errUnauthorized("Authorization: Bearer <bambu access token or API key> required")
	}
	if store.IsKey(cred) {
		if s.store == nil {
			return nil, errUnauthorized("API keys are not enabled on this server")
		}
		key, err := s.store.ResolveKey(ctx, cred)
		if errors.Is(err, store.ErrNotFound) {
			return nil, errUnauthorized("unknown API key")
		}
		if err != nil {
			return nil, err
		}
		sess, err := s.sessionForAccount(ctx, key.AccountUID)
		if err != nil {
			return nil, err
		}
		sess.viaKey = key
		return sess, nil
	}
	return s.sessionFor(ctx, cred)
}

// sessionForAccount returns the shared session for a stored account, replacing
// it when the account has logged in again since.
func (s *Server) sessionForAccount(ctx context.Context, uid string) (*session, error) {
	stored, err := s.store.Session(ctx, uid)
	if errors.Is(err, store.ErrSignedOut) {
		return nil, errUnauthorized("account is signed out; log in again to reactivate its API keys")
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, errUnauthorized("account no longer exists")
	}
	if err != nil {
		return nil, err
	}
	key := "acct:" + uid
	s.mu.Lock()
	sess, ok := s.sessions[key]
	if ok && sess.token != stored.Token {
		delete(s.sessions, key)
		go sess.closeMQTT()
		ok = false
	}
	if !ok {
		sess = s.newSession(stored.Token, uid, stored.HardwareID)
		s.sessions[key] = sess
	}
	sess.account = &stored.Account
	sess.lastUsed = time.Now()
	s.mu.Unlock()
	return sess, nil
}

// sessionFor returns the session for a raw Bambu access token.
func (s *Server) sessionFor(ctx context.Context, token string) (*session, error) {
	key := tokenKey(token)
	s.mu.Lock()
	sess, ok := s.sessions[key]
	if !ok {
		sess = s.newSession(token, userIDFromJWT(token), s.cfg.HardwareID)
		s.sessions[key] = sess
	}
	sess.lastUsed = time.Now()
	s.mu.Unlock()
	if sess.userID == "" {
		me, err := sess.cloud.GetUserServiceMyProfile(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("resolve user id: %w", err)
		}
		if me.Uid == nil {
			return nil, errors.New("profile has no uid")
		}
		sess.userID = fmt.Sprint(*me.Uid)
		sess.cloud.UserID = sess.userID
	}
	if s.store != nil && sess.account == nil {
		// A token whose owner has logged in here before may manage that account.
		if acct, err := s.store.Account(ctx, sess.userID); err == nil {
			sess.account = acct
		}
	}
	return sess, nil
}

func (s *Server) newSession(token, userID, hardwareID string) *session {
	c := cloud.New(s.cfg.Region, cloud.WithHTTPClient(s.httpClient), cloud.WithDeviceInfo(deviceInfo(hardwareID)), cloud.WithSigner(s.appCert), cloud.WithToken(token))
	c.UserID = userID
	return &session{token: token, userID: userID, hardwareID: hardwareID, cloud: c}
}

func deviceInfo(hardwareID string) cloud.DeviceInfo {
	return cloud.DeviceInfo{DeviceID: hardwareID, Brand: "google", Model: "Pixel 8", OSVersion: "15", Language: "en"}
}

// MQTT returns the session's broker connection, dialling on first use.
func (sess *session) MQTT(ctx context.Context, region cloud.Region) (*mqtt.Client, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.mqtt != nil && sess.mqtt.IsConnected() {
		return sess.mqtt, nil
	}
	if sess.mqtt != nil {
		sess.mqtt.Close()
		sess.mqtt = nil
	}
	cfg := mqtt.CloudConfig(region.MQTTHost, sess.userID, sess.token, sess.hardwareID)
	c, err := mqtt.Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	sess.mqtt = c
	return c, nil
}

func (sess *session) closeMQTT() {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.mqtt != nil {
		sess.mqtt.Close()
		sess.mqtt = nil
	}
}

func (p *lanPrinter) MQTT(ctx context.Context) (*mqtt.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.mqtt != nil && p.mqtt.IsConnected() {
		return p.mqtt, nil
	}
	if p.mqtt != nil {
		p.mqtt.Close()
	}
	cfg := mqtt.LANConfig(p.IP, p.Serial, p.AccessCode, p.extraRoots...)
	if p.Insecure {
		cfg.TLS.VerifyPeerCertificate = nil
	}
	c, err := mqtt.Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	p.mqtt = c
	return c, nil
}

// dropSessions forgets every cached session for an account and for a token.
func (s *Server) dropSessions(uid, token string) {
	s.mu.Lock()
	var closing []*session
	for k, sess := range s.sessions {
		if (uid != "" && sess.userID == uid) || (token != "" && sess.token == token) {
			delete(s.sessions, k)
			closing = append(closing, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range closing {
		sess.closeMQTT()
	}
}

// reap closes MQTT sessions that have been idle longer than cfg.IdleAfter.
func (s *Server) reap() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-t.C:
		}
		s.mu.Lock()
		var idle []*session
		for k, sess := range s.sessions {
			if time.Since(sess.lastUsed) > s.cfg.IdleAfter {
				delete(s.sessions, k)
				idle = append(idle, sess)
			}
		}
		s.mu.Unlock()
		for _, sess := range idle {
			sess.closeMQTT()
		}
	}
}
