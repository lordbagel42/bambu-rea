package api

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/mqtt"
)

// session is the per-access-token state: a cloud client bound to the token and
// a lazily opened MQTT connection to the regional broker.
type session struct {
	token  string
	userID string
	cloud  *cloud.Client

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

func (s *Server) sessionFor(ctx context.Context, token string) (*session, error) {
	key := tokenKey(token)
	s.mu.Lock()
	sess, ok := s.sessions[key]
	if !ok {
		sess = &session{token: token, cloud: s.anon.WithToken(token)}
		sess.cloud.Signer = s.appCert
		s.sessions[key] = sess
	}
	sess.lastUsed = time.Now()
	s.mu.Unlock()
	if sess.userID == "" {
		sess.userID = userIDFromJWT(token)
	}
	if sess.userID == "" {
		me, err := sess.cloud.GetUserServiceMyProfile(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("resolve user id: %w", err)
		}
		if me.Uid == nil {
			return nil, errors.New("profile has no uid")
		}
		sess.userID = fmt.Sprint(*me.Uid)
	}
	sess.cloud.UserID = sess.userID
	return sess, nil
}

// MQTT returns the session's broker connection, dialling on first use.
func (sess *session) MQTT(ctx context.Context, region cloud.Region, hardwareID string) (*mqtt.Client, error) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.mqtt != nil && sess.mqtt.IsConnected() {
		return sess.mqtt, nil
	}
	if sess.mqtt != nil {
		sess.mqtt.Close()
		sess.mqtt = nil
	}
	cfg := mqtt.CloudConfig(region.MQTTHost, sess.userID, sess.token, hardwareID)
	c, err := mqtt.Connect(ctx, cfg)
	if err != nil {
		return nil, err
	}
	sess.mqtt = c
	return c, nil
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
		for k, sess := range s.sessions {
			if time.Since(sess.lastUsed) > s.cfg.IdleAfter {
				sess.mu.Lock()
				if sess.mqtt != nil {
					sess.mqtt.Close()
				}
				sess.mu.Unlock()
				delete(s.sessions, k)
			}
		}
		s.mu.Unlock()
	}
}
