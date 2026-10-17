package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud/model"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/secure"
)

// passwordEndpoints mirrors PasswordBodyRewriter.PASSWORD_ENDPOINTS: on these paths the
// app replaces the `password` field with `encryptedPassword` when the server's pubkey
// endpoint reports needEncrypt.
var passwordEndpoints = map[string]bool{
	"user-service/user/login":         true,
	"user-service/user/signup":        true,
	"user-service/user/resetpassword": true,
	"user-service/my/password/verify": true,
	"user-service/my/identity/verify": true,
}

// PubKey fetches GET user-service/user/security/pubkey.
func (c *Client) PubKey(ctx context.Context) (*model.NetworkPasswordPubKeyResp, error) {
	var out model.NetworkPasswordPubKeyResp
	err := c.call(ctx, &Endpoint{Name: "pubkey", Method: http.MethodGet, Path: "user-service/user/security/pubkey"},
		"user-service/user/security/pubkey", nil, nil, nil, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// EncryptPassword builds the `encryptedPassword` value exactly like PasswordEncryptor.build:
// base64(RSA-OAEP-SHA256(pubkey, `{"pwd":<password>,"challenge":<challenge>}`)).
func EncryptPassword(password, publicKeyPEM, challenge string) (string, error) {
	if password == "" || publicKeyPEM == "" || challenge == "" {
		return "", errors.New("cloud: password, public key and challenge are required")
	}
	pub, err := secure.ParsePublicKey(publicKeyPEM)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]string{"pwd": password, "challenge": challenge})
	if err != nil {
		return "", err
	}
	ct, err := secure.EncryptOAEPSHA256(pub, payload)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// rewritePasswordBody implements PasswordBodyRewriter: for password endpoints, fetch the
// pubkey and swap the plaintext password for encryptedPassword. Returns nil when the body
// should be sent unchanged (no password field, pubkey fetch failed → plaintext fallback,
// or needEncrypt=false).
func (c *Client) rewritePasswordBody(ctx context.Context, path string, body []byte) ([]byte, error) {
	if !passwordEndpoints[path] {
		return nil, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, nil
	}
	var plain string
	if raw, ok := obj["password"]; !ok || json.Unmarshal(raw, &plain) != nil || plain == "" {
		return nil, nil
	}
	pk, err := c.PubKey(ctx)
	if err != nil {
		return nil, nil // app falls back to plaintext when the pubkey fetch fails
	}
	if pk.NeedEncrypt == nil || !*pk.NeedEncrypt || pk.PublicKey == "" || pk.Challenge == "" {
		return nil, nil
	}
	enc, err := EncryptPassword(plain, pk.PublicKey, pk.Challenge)
	if err != nil {
		return nil, fmt.Errorf("cloud: password encrypt failed when needEncrypt=true: %w", err)
	}
	delete(obj, "password")
	encJSON, _ := json.Marshal(enc)
	obj["encryptedPassword"] = encJSON
	return json.Marshal(obj)
}

// LoginRequest is the body of POST user-service/user/login (com.bbl.mobile.auth.model.LoginRequest).
type LoginRequest = model.AuthModelLoginRequest

// LoginResult is the response of the login endpoints.
type LoginResult = model.AuthModelLoginResult

// Login performs a password login. If the account has 2FA enabled the result has
// LoginType "tfa" and TfaKey set; follow up with LoginTFA. If the server demands an email
// verification code the result has LoginType "verifyCode"; send one with SendEmailCode and
// retry Login with Code set.
func (c *Client) Login(ctx context.Context, account, password string) (*LoginResult, error) {
	return c.LoginWith(ctx, &LoginRequest{Account: account, Password: password})
}

// LoginWith sends an arbitrary login request (verification code, one-click token, ...).
func (c *Client) LoginWith(ctx context.Context, req *LoginRequest) (*LoginResult, error) {
	var out LoginResult
	if err := c.call(ctx, &Endpoint{Name: "login", Method: http.MethodPost, Path: "user-service/user/login"},
		"user-service/user/login", nil, nil, req, &out); err != nil {
		return nil, err
	}
	if out.AccessToken != "" {
		c.SetToken(out.AccessToken)
	}
	return &out, nil
}

// LoginTFA completes a two-factor login with the tfaKey from Login and the TOTP code.
func (c *Client) LoginTFA(ctx context.Context, tfaKey, tfaCode string) (*LoginResult, error) {
	var out LoginResult
	body := map[string]string{"tfaKey": tfaKey, "tfaCode": tfaCode}
	if err := c.call(ctx, &Endpoint{Name: "tfaLogin", Method: http.MethodPost, Path: "user-service/user/tfa/login"},
		"user-service/user/tfa/login", nil, nil, body, &out); err != nil {
		return nil, err
	}
	if out.AccessToken != "" {
		c.SetToken(out.AccessToken)
	}
	return &out, nil
}

// SendEmailCode requests a verification code (codeType is e.g. "codeLogin").
func (c *Client) SendEmailCode(ctx context.Context, email, codeType string) error {
	body := model.AuthModelCodeRequest{Email: email, Type: codeType}
	return c.call(ctx, &Endpoint{Name: "sendEmailCode", Method: http.MethodPost, Path: "user-service/user/sendemail/code"},
		"user-service/user/sendemail/code", nil, nil, body, nil)
}

// Logout calls POST user-service/user/logout and clears the local token.
func (c *Client) Logout(ctx context.Context) error {
	err := c.call(ctx, &Endpoint{Name: "logout", Method: http.MethodPost, Path: "user-service/user/logout"},
		"user-service/user/logout", url.Values{}, nil, nil, nil)
	c.SetToken("")
	return err
}

// Login result types that need a follow-up step.
const (
	LoginTypeTFA        = model.AuthModelLoginTypeTfa
	LoginTypeVerifyCode = model.AuthModelLoginTypeVerifyCode
)
