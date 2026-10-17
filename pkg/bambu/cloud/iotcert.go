package cloud

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/secure"
)

// IoT app-certificate constants recovered from the APK.
const (
	// IoTAppIDPrefix prefixes the app key before it is AES-encrypted into the
	// {appKey} path segment (IotCertManager.fetchAppCertFromNetwork).
	IoTAppIDPrefix = "GLOF3813734089-"
	// IoTAndroidAppKey is BuildConfig.IOT_ANDROID_APP_KEY (Virbox string table, defpackage/s9e.java).
	IoTAndroidAppKey = "af70cf3b000006c7d872272593fe"
	// AppCertCacheTTL mirrors IotCertManager.APP_CERT_CACHE_TTL_MS: how long a
	// fetched certificate is reused before it is fetched again.
	AppCertCacheTTL = 600 * time.Second
	// SigningSessionTTL mirrors IotCertManager.SIGNING_SESSION_TTL_MS.
	SigningSessionTTL = 300 * time.Second
)

// IoTServiceCertPEM is the pinned "service.bambulab.com" certificate the app
// RSA-wraps its ephemeral AES key to (IotCertManager.exportWrappedAesKey).
const IoTServiceCertPEM = `-----BEGIN CERTIFICATE-----
MIIDeTCCAmGgAwIBAgIUGpX26HEycYnaaCUFwJr8F/UPCZIwDQYJKoZIhvcNAQEL
BQAwKDEmMCQGA1UEAwwdYXBwbGljYXRpb25fcm9vdC5iYW1idWxhYi5jb20wHhcN
MjQwNzI2MDE1MjI3WhcNMzQwNzI0MDE1MjI3WjAfMR0wGwYDVQQDDBRzZXJ2aWNl
LmJhbWJ1bGFiLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ2z
wQvNAjA9lQe06o/Vv6JULHLn25NK706myDa4i9lmb3wqARNVi6aSWfxO3Cz9NklC
4dYAdFbgcEUXuJIcJBBZdgPO2GhnaeCUVWz/ucW2GCdPaBAkXZNDK56aPqfYwltI
sNJcUIvq0OmbFsI90l8zKTQzd8/zJcfm8lOBpAberwbEeHCQfDxUWpNyrAuGJlkD
cmxraAjzBXQjAyMT+kK+KPOqhJICu5SXP87WGlzw8sfrdLl7J2vhtXpzRC67vtv6
uD6aqq5f2OaRxHRUyqeDY/adiWE9Qeb9amkRMcQiUJ0IQJZ4wDSMNpZe0guXLkl5
LPdPU249Bu86H5eDf5ECAwEAAaOBozCBoDAJBgNVHRMEAjAAMAsGA1UdDwQEAwID
uDAdBgNVHQ4EFgQUb/FHYnyT++aiAcbhmQsDIMw/C+kwZwYDVR0jBGAwXqFGpEQw
QjELMAkGA1UEBhMCQ04xIjAgBgNVBAoMGUJCTCBUZWNobm9sb2dpZXMgQ28uLCBM
dGQxDzANBgNVBAMMBkJCTCBDQYIUGpX26HEycYnaaCUFwJr8F/UPCYgwDQYJKoZI
hvcNAQELBQADggEBAK3n3LsRPiT9dEKrteCvBhaO/nAhc3Ogpi5iw4yiSB6abIHy
a36oGCA7RDMaMizDxbmWqooasA3xWnWLaf83FPt8KTnG72hmRb/usjc8sqFQQPPX
/VZf8ITAILx7Nrh1yLKI31UtYLMgeGNA8sifQUVJFOLqcwEpqUvII5ZK1YZ/27lM
gmscseUC5s4MTVf+aT5Gxg/v8MI0kgzNKCUELx7HuMfz/Og7+BSS58piZ1vt8Mgq
VvhUVmCS9SnCnvkM57zOumHHlvoSf7u6eq7YQd6spdJBYS1Yf2KGxKG2uooT9VlX
Gq8Fcpo0F9pzYXX3kKeBJo1vl1/R54eAgd82rNg=
-----END CERTIFICATE-----`

// iotServiceCertPEM is what FetchAppCert actually wraps to; tests swap it.
var iotServiceCertPEM = IoTServiceCertPEM

// WrapPadding selects how the ephemeral AES key is RSA-wrapped for the cert
// endpoint. The scheme lives in the Virbox-packed libbbl_crypto.so
// (bbl_crypto_ephemeral_aes_export_wrapped); the desktop plugin, which calls
// the same endpoint, uses RSAES-PKCS1-v1_5 (open-bamboo-networking
// research/10.02-secrets.md), so that is tried first with OAEP-SHA256 as the
// fallback.
type WrapPadding string

const (
	WrapPKCS1v15   WrapPadding = "pkcs1v15"
	WrapOAEPSHA256 WrapPadding = "oaep-sha256"
)

// AppCert is the app certificate + private key the IoT service issues per user.
type AppCert struct {
	CertPEM string
	CRLPEM  string // joined CRL PEM blocks (may be empty)
	Key     *rsa.PrivateKey
	// CertID is IotAppCert.joinedCertId, "CN=<issuer CN>:<serial hex lowercase>",
	// the x-bbl-app-certification-id header value.
	CertID string
	// MQTTCertID is IotAppCert.certId, "<serial hex lowercase>CN=<issuer CN>",
	// the cert_id carried in signed MQTT envelopes.
	MQTTCertID string
	// KeyLayout names the key-blob layout that decrypted successfully
	// (see appcertblob.go); empty for user-supplied material.
	KeyLayout string
	FetchedAt time.Time
}

// certIDsFromPEM reproduces IotAppCert.joinedCertId and IotAppCert.certId from
// the first certificate of the returned chain.
func certIDsFromPEM(certPEM string) (joined, mqtt string, err error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return "", "", errors.New("iotcert: app cert is not PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("iotcert: parse app cert: %w", err)
	}
	serial := strings.ToLower(c.SerialNumber.Text(16))
	if len(serial)%2 == 1 {
		serial = "0" + serial
	}
	return "CN=" + c.Issuer.CommonName + ":" + serial, serial + "CN=" + c.Issuer.CommonName, nil
}

// LeafCert parses the first certificate in CertPEM.
func (a *AppCert) LeafCert() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(a.CertPEM))
	if block == nil {
		return nil, errors.New("iotcert: app cert is not PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

// ParseAppCert builds an AppCert from user-supplied PEM material (e.g. captured
// from a rooted phone), bypassing the network fetch entirely.
func ParseAppCert(certPEM, keyPEM, crlPEM string) (*AppCert, error) {
	key, err := secure.ParsePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	id, mid, err := certIDsFromPEM(certPEM)
	if err != nil {
		return nil, err
	}
	return &AppCert{CertPEM: certPEM, CRLPEM: crlPEM, Key: key, CertID: id, MQTTCertID: mid, FetchedAt: time.Now()}, nil
}

// aesGCMSeal encodes IV(12) || ciphertext || tag(16), the layout implied by the
// app's `key.length > 28` check and GCM_IV_LENGTH = 12.
func aesGCMSeal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return gcm.Seal(iv, iv, plaintext, nil), nil
}

func aesGCMOpen(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) <= gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("iotcert: encrypted key payload too short")
	}
	return gcm.Open(nil, blob[:gcm.NonceSize()], blob[gcm.NonceSize():], nil)
}

// FetchAppCert performs GET iot-service/api/user/applications/{appKey}/cert.
func (c *Client) FetchAppCert(ctx context.Context, padding WrapPadding) (*AppCert, error) {
	servicePub, err := secure.ParsePublicKey(iotServiceCertPEM)
	if err != nil {
		return nil, err
	}
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}
	appKeyCT, err := aesGCMSeal(aesKey, []byte(IoTAppIDPrefix+IoTAndroidAppKey))
	if err != nil {
		return nil, err
	}
	var wrapped []byte
	switch padding {
	case WrapPKCS1v15:
		wrapped, err = secure.EncryptPKCS1v15(servicePub, aesKey)
	default:
		wrapped, err = secure.EncryptOAEPSHA256(servicePub, aesKey)
	}
	if err != nil {
		return nil, err
	}
	// Base64.URL_SAFE | NO_WRAP (flag 10) in the app: padding is kept.
	appKey := base64.URLEncoding.EncodeToString(appKeyCT)
	q := url.Values{"aes256": {base64.URLEncoding.EncodeToString(wrapped)}}
	var resp struct {
		Code    *int            `json:"code"`
		Message string          `json:"message"`
		Cert    string          `json:"cert"`
		Key     string          `json:"key"`
		CRL     json.RawMessage `json:"crl"`
	}
	// The path segment is @Path(encoded = true): base64url is URL-safe already.
	path := "iot-service/api/user/applications/" + appKey + "/cert"
	if err := c.call(ctx, &Endpoint{Name: "FetchAppCert", Method: "GET", Path: path}, path, q, nil, nil, &resp); err != nil {
		return nil, err
	}
	if resp.Code == nil || *resp.Code != 0 {
		code := -1
		if resp.Code != nil {
			code = *resp.Code
		}
		return nil, fmt.Errorf("iotcert: getAppCert failed: code %d %s", code, resp.Message)
	}
	if resp.Cert == "" || resp.Key == "" {
		return nil, errors.New("iotcert: getAppCert: missing cert/key field")
	}
	blob, err := base64.StdEncoding.DecodeString(resp.Key)
	if err != nil {
		return nil, fmt.Errorf("iotcert: key is not base64: %w", err)
	}
	if len(blob) <= 28 {
		return nil, errors.New("iotcert: invalid encrypted key payload")
	}
	key, layout, err := unwrapAppKeyBlob(aesKey, blob)
	if err != nil {
		return nil, fmt.Errorf("iotcert: unwrap private key (padding %s): %w", padding, err)
	}
	id, mid, err := certIDsFromPEM(resp.Cert)
	if err != nil {
		return nil, err
	}
	cert := &AppCert{CertPEM: resp.Cert, CRLPEM: joinCRL(resp.CRL), Key: key, CertID: id, MQTTCertID: mid, KeyLayout: layout, FetchedAt: time.Now()}
	leaf, err := cert.LeafCert()
	if err != nil {
		return nil, err
	}
	if pub, ok := leaf.PublicKey.(*rsa.PublicKey); !ok || pub.N.Cmp(key.N) != 0 {
		return nil, errors.New("iotcert: decrypted private key does not match the app certificate")
	}
	return cert, nil
}

// parseAnyPrivateKey accepts SKEY, PEM, PKCS#8 DER or PKCS#1 DER and names the
// format it recognised.
func parseAnyPrivateKey(der []byte) (*rsa.PrivateKey, string, error) {
	if k, err := parseSKEY(der); err == nil {
		return k, "skey", nil
	}
	if strings.HasPrefix(strings.TrimSpace(string(der)), "-----") {
		k, err := secure.ParsePrivateKey(string(der))
		return k, "pem", err
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		if rk, ok := k.(*rsa.PrivateKey); ok {
			return rk, "pkcs8", nil
		}
		return nil, "", errors.New("iotcert: private key is not RSA")
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, "pkcs1", nil
	}
	return nil, "", errors.New("iotcert: private key is neither SKEY, PEM, PKCS#8 nor PKCS#1")
}

// joinCRL mirrors IotAppCertCrl.joinCrlPems: a JSON array of PEM strings joined by "\n".
func joinCRL(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var arr []string
	if json.Unmarshal(raw, &arr) != nil {
		var single string
		if json.Unmarshal(raw, &single) == nil {
			return strings.TrimSpace(single)
		}
		return ""
	}
	var parts []string
	for _, s := range arr {
		if t := strings.TrimSpace(s); t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "\n")
}

// AppCertSigner implements IoTSigner with a cached AppCert, fetching it on first
// use and refreshing the signing session every SigningSessionTTL like the app.
type AppCertSigner struct {
	client *Client

	mu        sync.Mutex
	cert      *AppCert
	fetchedAt time.Time
	// Padding, when non-empty, pins the RSA wrap scheme; otherwise both are tried.
	Padding WrapPadding
}

// NewAppCertSigner returns a signer bound to client's token. If cert is non-nil
// it is used as-is and never fetched.
func NewAppCertSigner(client *Client, cert *AppCert) *AppCertSigner {
	s := &AppCertSigner{client: client, cert: cert}
	if cert != nil {
		s.fetchedAt = time.Now()
	}
	return s
}

// Cert returns the cached certificate, fetching it when missing or stale.
func (s *AppCertSigner) Cert(ctx context.Context) (*AppCert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cert != nil && (s.cert.Key != nil) && time.Since(s.fetchedAt) < AppCertCacheTTL {
		return s.cert, nil
	}
	if s.cert != nil && s.client == nil {
		// User-supplied material never expires on our side.
		return s.cert, nil
	}
	if s.client == nil {
		return nil, errors.New("iotcert: no client to fetch app cert with")
	}
	paddings := []WrapPadding{WrapPKCS1v15, WrapOAEPSHA256}
	if s.Padding != "" {
		paddings = []WrapPadding{s.Padding}
	}
	var errs []error
	for _, p := range paddings {
		cert, err := s.client.FetchAppCert(ctx, p)
		if err == nil {
			s.cert = cert
			s.fetchedAt = time.Now()
			s.Padding = p
			return cert, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", p, err))
	}
	return nil, errors.Join(errs...)
}

// SignedHeaders implements IoTSigner.
func (s *AppCertSigner) SignedHeaders(ctx context.Context) (string, string, error) {
	cert, err := s.Cert(ctx)
	if err != nil {
		return "", "", err
	}
	ts := fmt.Sprint(time.Now().UnixMilli())
	sig, err := secure.PrivateEncryptPKCS1v15(cert.Key, []byte(ts))
	if err != nil {
		return "", "", err
	}
	return cert.CertID, base64.StdEncoding.EncodeToString(sig), nil
}
