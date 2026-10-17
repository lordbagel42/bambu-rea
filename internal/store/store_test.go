package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T, key []byte) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestKeysActAsTheAccountAndFollowReLogin(t *testing.T) {
	ctx := context.Background()
	s := openTest(t, bytes.Repeat([]byte{7}, 32))
	acct, err := s.SaveLogin(ctx, Login{UID: "42", Email: "me@example.com", Token: "tok-1", RefreshToken: "rt-1", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if acct.HardwareID == "" || !acct.SignedIn {
		t.Fatalf("account not initialised: %+v", acct)
	}

	secret, k, err := s.CreateKey(ctx, "42", "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if !IsKey(secret) || k.Prefix != secret[:11] || k.Name != "laptop" {
		t.Fatalf("bad key %q %+v", secret, k)
	}
	got, err := s.ResolveKey(ctx, secret)
	if err != nil || got.AccountUID != "42" {
		t.Fatalf("resolve: %v %+v", err, got)
	}
	if _, err := s.ResolveKey(ctx, secret[:len(secret)-1]+"x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tampered key resolved: %v", err)
	}
	if _, err := s.ResolveKey(ctx, "not-a-key"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bambu token treated as key: %v", err)
	}

	// Logging in again rotates the token every key uses, but keeps the hardware id.
	again, err := s.SaveLogin(ctx, Login{UID: "42", Token: "tok-2"})
	if err != nil {
		t.Fatal(err)
	}
	if again.HardwareID != acct.HardwareID || again.Email != "me@example.com" {
		t.Fatalf("re-login changed identity: %+v vs %+v", again, acct)
	}
	sess, err := s.Session(ctx, "42")
	if err != nil || sess.Token != "tok-2" || sess.RefreshToken != "" {
		t.Fatalf("session after re-login: %v %+v", err, sess)
	}

	// Tokens are not stored in clear.
	var raw []byte
	if err := s.db.QueryRow(`SELECT token FROM accounts WHERE uid = '42'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("tok-2")) {
		t.Fatal("token stored in clear despite data key")
	}

	// Signing out keeps the account and its keys but makes sessions unusable.
	if err := s.ClearSession(ctx, "42"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Session(ctx, "42"); !errors.Is(err, ErrSignedOut) {
		t.Fatalf("expected ErrSignedOut, got %v", err)
	}
	keys, err := s.ListKeys(ctx, "42")
	if err != nil || len(keys) != 1 || keys[0].LastUsedAt == nil {
		t.Fatalf("keys after sign-out: %v %+v", err, keys)
	}
	if err := s.DeleteKey(ctx, "other", k.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account deleted the key: %v", err)
	}
	if err := s.DeleteKey(ctx, "42", k.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveKey(ctx, secret); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted key still resolves: %v", err)
	}
}

func TestEncryptedTokensNeedTheKey(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "enc.sqlite")
	s, err := Open(path, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SaveLogin(ctx, Login{UID: "1", Token: "secret"}); err != nil {
		t.Fatal(err)
	}
	s.Close()

	plain, err := Open(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	if _, err := plain.Session(ctx, "1"); err == nil || errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected a decrypt error without the key, got %v", err)
	}
	if _, err := Open(path, []byte("short")); err == nil {
		t.Fatal("accepted a non-32-byte key")
	}
}
