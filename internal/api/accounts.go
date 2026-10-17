package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lordbagel42/bambu-rea/internal/store"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
)

// rememberLogin persists the Bambu session a successful login produced, so API
// keys for that account act with the freshest token. It is best effort: the
// login response is returned to the caller whether or not storage succeeded.
func (s *Server) rememberLogin(ctx context.Context, account string, res *cloud.LoginResult) {
	if s.store == nil || res == nil || res.AccessToken == "" {
		return
	}
	uid := userIDFromJWT(res.AccessToken)
	c := s.anon.WithToken(res.AccessToken)
	// One profile call gives the uid when the token does not carry it and the
	// account email after a TFA step, where the request has none.
	if uid == "" || account == "" {
		me, err := c.GetUserServiceMyProfile(ctx, nil)
		if err != nil {
			s.log.Printf("remember login: profile: %v", err)
		} else {
			if uid == "" && me.Uid != nil {
				uid = fmt.Sprint(*me.Uid)
			}
			if account == "" {
				account = me.Account
			}
		}
	}
	if uid == "" {
		s.log.Printf("remember login: could not determine uid; session not stored")
		return
	}
	var exp time.Time
	if res.ExpiresIn != nil && *res.ExpiresIn > 0 {
		exp = time.Now().Add(time.Duration(*res.ExpiresIn) * time.Second)
	}
	if _, err := s.store.SaveLogin(ctx, store.Login{UID: uid, Email: account, Token: res.AccessToken, RefreshToken: res.RefreshToken, ExpiresAt: exp}); err != nil {
		s.log.Printf("remember login for %s: %v", uid, err)
		return
	}
	// Any cached session for this account now holds a stale token.
	s.dropSessions(uid, "")
}

// requireStore rejects account routes on servers without persistence.
func (s *Server) requireStore(w http.ResponseWriter) bool {
	if s.store == nil {
		writeErr(w, http.StatusNotImplemented, "this server has no account store (start bambu-api with -db)")
		return false
	}
	return true
}

// requireLoginSession limits key management to callers holding a Bambu token
// for an account that has logged in here, so a leaked API key cannot mint more.
func (s *Server) requireLoginSession(w http.ResponseWriter, sess *session) bool {
	if sess.viaKey != nil {
		writeErr(w, http.StatusForbidden, "API keys cannot manage keys; authenticate with the Bambu access token from /v1/auth/login")
		return false
	}
	if sess.account == nil {
		writeErr(w, http.StatusForbidden, "this account has not logged in through this server; call /v1/auth/login here first")
		return false
	}
	return true
}

type accountView struct {
	store.Account
	ViaKey *store.APIKey `json:"viaKey,omitempty"`
	Keys   int           `json:"keys"`
}

// handleAccount describes the stored account behind the credential.
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireStore(w) {
		return
	}
	if sess.account == nil {
		writeErr(w, http.StatusNotFound, "no stored account for this token; log in through /v1/auth/login to create one")
		return
	}
	keys, err := s.store.ListKeys(r.Context(), sess.userID)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, accountView{Account: *sess.account, ViaKey: sess.viaKey, Keys: len(keys)})
}

func (s *Server) handleKeysList(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireStore(w) || !s.requireLoginSession(w, sess) {
		return
	}
	keys, err := s.store.ListKeys(r.Context(), sess.userID)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"keys": keys})
}

type createdKey struct {
	store.APIKey
	Key string `json:"key"`
}

func (s *Server) handleKeysCreate(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireStore(w) || !s.requireLoginSession(w, sess) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if len(req.Name) > 100 {
		writeErr(w, 400, "name too long (max 100)")
		return
	}
	secret, k, err := s.store.CreateKey(r.Context(), sess.userID, req.Name)
	if err != nil {
		writeCallErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, createdKey{APIKey: *k, Key: secret})
}

func (s *Server) handleKeysDelete(w http.ResponseWriter, r *http.Request, sess *session) {
	if !s.requireStore(w) || !s.requireLoginSession(w, sess) {
		return
	}
	err := s.store.DeleteKey(r.Context(), sess.userID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "no such key")
		return
	}
	if err != nil {
		writeCallErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
