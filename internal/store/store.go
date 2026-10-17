// Package store persists the hosted service's state: one Bambu session per
// account (access token, refresh token, hardware id) and the API keys that act
// as that account. It is a single SQLite file; tokens are encrypted at rest when
// a data key is supplied.
package store

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// KeyPrefix starts every API key so callers can tell one from a Bambu token.
const KeyPrefix = "bk_"

var (
	// ErrNotFound is returned for unknown accounts and keys.
	ErrNotFound = errors.New("store: not found")
	// ErrSignedOut is returned when an account exists but holds no session.
	ErrSignedOut = errors.New("store: account is signed out; log in again")
)

// Account is what the service knows about one Bambu user.
type Account struct {
	UID            string    `json:"uid"`
	Email          string    `json:"email,omitempty"`
	HardwareID     string    `json:"hardwareId"`
	TokenExpiresAt time.Time `json:"tokenExpiresAt,omitempty"`
	CreatedAt      time.Time `json:"createdAt"`
	LastLoginAt    time.Time `json:"lastLoginAt"`
	SignedIn       bool      `json:"signedIn"`
}

// Session is an account together with its cloud tokens.
type Session struct {
	Account
	Token        string
	RefreshToken string
}

// Login is what a successful cloud login yields and what gets persisted.
type Login struct {
	UID          string
	Email        string
	Token        string
	RefreshToken string
	ExpiresAt    time.Time
}

// APIKey is the public view of a key; the secret is only ever returned by CreateKey.
type APIKey struct {
	ID         string     `json:"id"`
	AccountUID string     `json:"-"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt,omitempty"`
}

// Store is the SQLite-backed persistence layer.
type Store struct {
	db   *sql.DB
	aead cipher.AEAD // nil = tokens stored in clear
}

// Open opens (and migrates) the database at path. dataKey, when non-empty, must
// be 32 bytes and is used to encrypt tokens at rest.
func Open(path string, dataKey []byte) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: path required")
	}
	var aead cipher.AEAD
	if len(dataKey) > 0 {
		if len(dataKey) != 32 {
			return nil, fmt.Errorf("store: data key must be 32 bytes, got %d", len(dataKey))
		}
		block, err := aes.NewCipher(dataKey)
		if err != nil {
			return nil, err
		}
		if aead, err = cipher.NewGCM(block); err != nil {
			return nil, err
		}
	}
	dsn := path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, aead: aead}
	if err := s.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS accounts (
	uid              TEXT PRIMARY KEY,
	email            TEXT NOT NULL DEFAULT '',
	hardware_id      TEXT NOT NULL,
	token            BLOB,
	refresh_token    BLOB,
	encrypted        INTEGER NOT NULL DEFAULT 0,
	token_expires_at INTEGER NOT NULL DEFAULT 0,
	created_at       INTEGER NOT NULL,
	last_login_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
	id           TEXT PRIMARY KEY,
	account_uid  TEXT NOT NULL REFERENCES accounts(uid) ON DELETE CASCADE,
	name         TEXT NOT NULL DEFAULT '',
	prefix       TEXT NOT NULL,
	key_hash     BLOB NOT NULL UNIQUE,
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER
);
CREATE INDEX IF NOT EXISTS api_keys_account ON api_keys(account_uid);
`)
	return err
}

// ---------------------------------------------------------------- accounts

// SaveLogin upserts the account's session after a successful cloud login. A new
// account gets a random, stable hardware id that its MQTT client id and
// X-BBL-Device-ID will use from then on.
func (s *Store) SaveLogin(ctx context.Context, l Login) (*Account, error) {
	if l.UID == "" || l.Token == "" {
		return nil, errors.New("store: uid and token required")
	}
	tok, err := s.seal(l.Token)
	if err != nil {
		return nil, err
	}
	rt, err := s.seal(l.RefreshToken)
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	_, err = s.db.ExecContext(ctx, `
INSERT INTO accounts (uid, email, hardware_id, token, refresh_token, encrypted, token_expires_at, created_at, last_login_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(uid) DO UPDATE SET
	email = CASE WHEN excluded.email <> '' THEN excluded.email ELSE accounts.email END,
	token = excluded.token, refresh_token = excluded.refresh_token, encrypted = excluded.encrypted,
	token_expires_at = excluded.token_expires_at, last_login_at = excluded.last_login_at`,
		l.UID, l.Email, "bambu-api-"+randomHex(8), tok, rt, boolInt(s.aead != nil), unixOrZero(l.ExpiresAt), now, now)
	if err != nil {
		return nil, err
	}
	return s.Account(ctx, l.UID)
}

// Account returns the public view of an account.
func (s *Store) Account(ctx context.Context, uid string) (*Account, error) {
	sess, err := s.Session(ctx, uid)
	if err != nil && !errors.Is(err, ErrSignedOut) {
		return nil, err
	}
	return &sess.Account, nil
}

// Session returns the account and its decrypted tokens. ErrSignedOut is
// returned (with the Account still filled in) when the token has been cleared.
func (s *Store) Session(ctx context.Context, uid string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `SELECT uid, email, hardware_id, token, refresh_token, encrypted, token_expires_at, created_at, last_login_at FROM accounts WHERE uid = ?`, uid)
	var (
		sess      Session
		tok, rt   []byte
		enc       int
		exp, c, l int64
	)
	if err := row.Scan(&sess.UID, &sess.Email, &sess.HardwareID, &tok, &rt, &enc, &exp, &c, &l); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	sess.CreatedAt, sess.LastLoginAt = time.Unix(c, 0), time.Unix(l, 0)
	if exp > 0 {
		sess.TokenExpiresAt = time.Unix(exp, 0)
	}
	if len(tok) == 0 {
		return &sess, ErrSignedOut
	}
	var err error
	if sess.Token, err = s.open(tok, enc == 1); err != nil {
		return nil, err
	}
	if sess.RefreshToken, err = s.open(rt, enc == 1); err != nil {
		return nil, err
	}
	sess.SignedIn = true
	return &sess, nil
}

// ClearSession forgets the account's tokens; its keys stay but stop working
// until the next login.
func (s *Store) ClearSession(ctx context.Context, uid string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE accounts SET token = NULL, refresh_token = NULL WHERE uid = ?`, uid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---------------------------------------------------------------- keys

// CreateKey mints a key for the account and returns the secret exactly once.
func (s *Store) CreateKey(ctx context.Context, uid, name string) (string, *APIKey, error) {
	if _, err := s.Account(ctx, uid); err != nil {
		return "", nil, err
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	secret := KeyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	k := &APIKey{ID: randomHex(8), AccountUID: uid, Name: strings.TrimSpace(name), Prefix: secret[:len(KeyPrefix)+8], CreatedAt: time.Now().Truncate(time.Second)}
	h := hashKey(secret)
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_keys (id, account_uid, name, prefix, key_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		k.ID, uid, k.Name, k.Prefix, h[:], k.CreatedAt.Unix())
	if err != nil {
		return "", nil, err
	}
	return secret, k, nil
}

// ResolveKey looks a secret up and records its use. Unknown keys yield ErrNotFound.
func (s *Store) ResolveKey(ctx context.Context, secret string) (*APIKey, error) {
	if !IsKey(secret) {
		return nil, ErrNotFound
	}
	h := hashKey(secret)
	row := s.db.QueryRowContext(ctx, `SELECT id, account_uid, name, prefix, key_hash, created_at, last_used_at FROM api_keys WHERE key_hash = ?`, h[:])
	k, stored, err := scanKey(row)
	if err != nil {
		return nil, err
	}
	// The index already matched; the constant-time compare keeps the lookup
	// honest should the hash column ever be truncated.
	if subtle.ConstantTimeCompare(stored, h[:]) != 1 {
		return nil, ErrNotFound
	}
	now := time.Now()
	if k.LastUsedAt == nil || now.Sub(*k.LastUsedAt) > time.Minute {
		_, _ = s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, now.Unix(), k.ID)
		k.LastUsedAt = &now
	}
	return k, nil
}

// ListKeys returns the account's keys, newest first.
func (s *Store) ListKeys(ctx context.Context, uid string) ([]APIKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, account_uid, name, prefix, key_hash, created_at, last_used_at FROM api_keys WHERE account_uid = ? ORDER BY created_at DESC, id`, uid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIKey{}
	for rows.Next() {
		k, _, err := scanKey(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *k)
	}
	return out, rows.Err()
}

// DeleteKey revokes one of the account's keys.
func (s *Store) DeleteKey(ctx context.Context, uid, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ? AND account_uid = ?`, id, uid)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// IsKey reports whether a credential is an API key rather than a Bambu token.
func IsKey(credential string) bool {
	return strings.HasPrefix(credential, KeyPrefix) && len(credential) > len(KeyPrefix)+8
}

type scanner interface{ Scan(dest ...any) error }

func scanKey(sc scanner) (*APIKey, []byte, error) {
	var (
		k    APIKey
		h    []byte
		c    int64
		last sql.NullInt64
	)
	if err := sc.Scan(&k.ID, &k.AccountUID, &k.Name, &k.Prefix, &h, &c, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	k.CreatedAt = time.Unix(c, 0)
	if last.Valid {
		t := time.Unix(last.Int64, 0)
		k.LastUsedAt = &t
	}
	return &k, h, nil
}

func hashKey(secret string) [32]byte { return sha256.Sum256([]byte(secret)) }

// ---------------------------------------------------------------- crypto

func (s *Store) seal(plain string) ([]byte, error) {
	if plain == "" {
		return nil, nil
	}
	if s.aead == nil {
		return []byte(plain), nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, []byte(plain), nil), nil
}

func (s *Store) open(blob []byte, encrypted bool) (string, error) {
	if len(blob) == 0 {
		return "", nil
	}
	if !encrypted {
		return string(blob), nil
	}
	if s.aead == nil {
		return "", errors.New("store: tokens are encrypted but no data key is configured")
	}
	ns := s.aead.NonceSize()
	if len(blob) < ns {
		return "", errors.New("store: corrupt token")
	}
	plain, err := s.aead.Open(nil, blob[:ns], blob[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("store: decrypt token: %w", err)
	}
	return string(plain), nil
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}
