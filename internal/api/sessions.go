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

	mu       sync.Mutex
	mqtt     *mqtt.Client
	lastUsed time.Time
}

// principal is what one request authenticated as: the shared session plus the
// request's own view of the stored account it is verified to own and the API
// key it used, if any. Sessions are shared between requests (and between all
// keys of an account), so per-request facts never live on the session itself.
type principal struct {
	*session
	// account is the stored account behind the credential: the key's account,
	// or the verified owner of a Bambu token who has logged in here before.
	account *store.Account
	// key is the API key that authenticated the request, if any.
	key *store.APIKey
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
	return hex.EncodeToString(h[:])
}

// userIDFromJWT extracts the numeric uid from the cloud access token without
// verifying it. It is only a hint: nothing that grants access to stored state
// trusts it (see session.verify). Bambu tokens carry "username": "u_<uid>"
// and/or "sub".
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

// authenticate resolves the request's credential to a principal.
func (s *Server) authenticate(ctx context.Context, cred string) (*principal, error) {
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
		p, err := s.sessionForAccount(ctx, key.AccountUID)
		if err != nil {
			return nil, err
		}
		p.key = key
		return p, nil
	}
	return s.sessionFor(ctx, cred)
}

// sessionForAccount returns the shared session for a stored account, replacing
// it when the account has logged in again since.
func (s *Server) sessionForAccount(ctx context.Context, uid string) (*principal, error) {
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
		// The store only holds tokens this server received from a login.
		sess = s.newSession(stored.Token, uid, stored.HardwareID)
		s.sessions[key] = sess
	}
	sess.lastUsed = time.Now()
	s.mu.Unlock()
	return &principal{session: sess, account: &stored.Account}, nil
}

// sessionFor returns the principal for a raw Bambu access token.
func (s *Server) sessionFor(ctx context.Context, token string) (*principal, error) {
	key := tokenKey(token)
	s.mu.Lock()
	sess, ok := s.sessions[key]
	if ok {
		sess.lastUsed = time.Now()
	}
	s.mu.Unlock()
	if !ok {
		// A new session is verified before it is shared, so a rejected token
		// never enters the cache and its userID is settled before any other
		// goroutine can read it. Without a store there is nothing local a
		// forged token could reach and the cloud rejects it on first use, so
		// only a token with no uid claim costs a profile call there; with a
		// store, every token is verified before it can be linked to an account.
		sess = s.newSession(token, userIDFromJWT(token), s.cfg.HardwareID)
		if err := sess.verify(ctx, s.store != nil); err != nil {
			return nil, err
		}
		s.mu.Lock()
		if cur, ok := s.sessions[key]; ok {
			sess = cur // a concurrent request verified the same token first
		} else {
			s.sessions[key] = sess
		}
		sess.lastUsed = time.Now()
		s.mu.Unlock()
	}
	p := &principal{session: sess}
	if s.store != nil {
		// A token whose owner has logged in here before may manage that account.
		acct, err := s.store.Account(ctx, sess.userID)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
		p.account = acct
	}
	return p, nil
}

// verify asks the cloud whose token this is, before the session is shared. A
// token's uid claim is never trusted on its own when the answer grants access
// to stored state: the cloud must accept the token and report the same uid.
func (sess *session) verify(ctx context.Context, always bool) error {
	if !always && sess.userID != "" {
		return nil
	}
	me, err := sess.cloud.GetUserServiceMyProfile(ctx, nil)
	if err != nil {
		var ae *cloud.APIError
		if errors.As(err, &ae) && (ae.StatusCode == http.StatusUnauthorized || ae.StatusCode == http.StatusForbidden) {
			return errUnauthorized("the Bambu cloud rejected this access token")
		}
		return fmt.Errorf("verify token: %w", err)
	}
	if me.Uid == nil {
		return errors.New("verify token: profile has no uid")
	}
	uid := fmt.Sprint(*me.Uid)
	if sess.userID != "" && sess.userID != uid {
		return errUnauthorized("access token does not belong to the user it claims")
	}
	sess.userID = uid
	sess.cloud.UserID = uid
	return nil
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
