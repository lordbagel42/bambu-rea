package cloud

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud/model"
)

func testClient(t *testing.T, h http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	region := RegionIntl
	region.APIBaseURL = srv.URL + "/v1/"
	region.MallAPIBaseURL = srv.URL + "/mall"
	return New(region, WithHTTPClient(srv.Client())), srv
}

func TestLoginEncryptsPasswordLikeTheApp(t *testing.T) {
	serverKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKIXPublicKey(&serverKey.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	var seenLogin map[string]any
	var seenHeaders http.Header
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/user-service/user/security/pubkey", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"publicKey": pubPEM, "challenge": "chal-1", "keyId": "k1", "needEncrypt": true})
	})
	mux.HandleFunc("POST /v1/user-service/user/login", func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&seenLogin)
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "tok", "loginType": "verifyCode", "expiresIn": 3600})
	})
	c, _ := testClient(t, mux)
	res, err := c.Login(context.Background(), "me@example.com", "hunter2")
	if err != nil {
		t.Fatal(err)
	}
	if res.AccessToken != "tok" || c.Token() != "tok" {
		t.Fatalf("token not installed: %+v", res)
	}
	if _, ok := seenLogin["password"]; ok {
		t.Fatal("plaintext password must be removed when needEncrypt=true")
	}
	ct, err := base64.StdEncoding.DecodeString(seenLogin["encryptedPassword"].(string))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), nil, serverKey, ct, nil)
	if err != nil {
		t.Fatalf("not RSA-OAEP-SHA256: %v", err)
	}
	var payload map[string]string
	_ = json.Unmarshal(plain, &payload)
	if payload["pwd"] != "hunter2" || payload["challenge"] != "chal-1" {
		t.Fatalf("payload %s", plain)
	}
	for k, v := range map[string]string{
		"User-Agent": "Handy/4.2.2", "X-Bbl-Client-Name": "BambuHandy", "X-Bbl-Client-Version": "4.2.2",
		"X-Bbl-Client-Release-Code": "40202", "X-Bbl-Os-Type": "android", "X-Bbl-Client-Type": "app",
	} {
		if got := seenHeaders.Get(k); got != v {
			t.Errorf("header %s = %q, want %q", k, got, v)
		}
	}
	if seenHeaders.Get("Authorization") != "" {
		t.Error("login must be anonymous")
	}
}

func TestPasswordSentPlainWhenPubkeyUnavailable(t *testing.T) {
	var seen map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/user-service/user/security/pubkey", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) })
	mux.HandleFunc("POST /v1/user-service/user/login", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&seen)
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "t"})
	})
	c, _ := testClient(t, mux)
	if _, err := c.Login(context.Background(), "a", "pw"); err != nil {
		t.Fatal(err)
	}
	if seen["password"] != "pw" {
		t.Fatalf("expected plaintext fallback, got %v", seen)
	}
}

func TestAPIErrorParsingAndSignedHeaders(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/iot-service/api/user/ttcode", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-bbl-app-certification-id") != "CN=X:1" || r.Header.Get("x-bbl-device-security-sign") != "sig" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"code":403,"error":"unsigned"}`))
			return
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`{"code":"1","message":"bad token"}`))
			return
		}
		_, _ = w.Write([]byte(`{"ttcode":"T"}`))
	})
	c, _ := testClient(t, mux)
	c.SetToken("tok")
	ctx := context.Background()
	_, err := c.PostIotServiceApiUserTtcode(ctx, &model.FetchTTCodeRequest{DevId: "SN"}, nil)
	var ae *APIError
	if !errors.As(err, &ae) || ae.StatusCode != 403 || ae.Message != "unsigned" || ae.Code != 403 {
		t.Fatalf("expected parsed 403 APIError, got %v", err)
	}
	c.Signer = fakeSigner{}
	out, err := c.PostIotServiceApiUserTtcode(ctx, &model.FetchTTCodeRequest{DevId: "SN"}, nil)
	if err != nil || out.Ttcode != "T" {
		t.Fatalf("signed call failed: %v %+v", err, out)
	}
	c.SetToken("")
	_, err = c.PostIotServiceApiUserTtcode(ctx, &model.FetchTTCodeRequest{DevId: "SN"}, nil)
	if !IsUnauthorized(err) || !errors.As(err, &ae) || ae.Code != 1 {
		t.Fatalf("expected 401 with string code parsed, got %v", err)
	}
}

type fakeSigner struct{}

func (fakeSigner) SignedHeaders(context.Context) (string, string, error) { return "CN=X:1", "sig", nil }

func TestMallPathsUseMallHost(t *testing.T) {
	var gotHost []string
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotHost = append(gotHost, r.URL.Path)
		_, _ = w.Write([]byte(`{}`))
	})
	c, _ := testClient(t, mux)
	_ = c.Do(context.Background(), Request{Method: "GET", Path: "mall-app-bff/x"}, nil)
	_ = c.Do(context.Background(), Request{Method: "GET", Path: "user-service/my/profile"}, nil)
	if len(gotHost) != 2 || gotHost[0] != "/mall/mall-app-bff/x" || gotHost[1] != "/v1/user-service/my/profile" {
		t.Fatalf("paths %v", gotHost)
	}
}

// TestFetchAppCertRoundTrip models the server side of the cert endpoint the way
// the desktop plugin research documents it (PKCS#1 v1.5 wrapped AES key,
// padded base64url, SKEY blob under the fixed custom-AES key).
func TestFetchAppCertRoundTrip(t *testing.T) {
	serviceKey := mustServiceKeyPair(t)
	appKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(0xBEEF), Subject: pkix.Name{CommonName: "u_1"}, Issuer: pkix.Name{CommonName: "BBL App CA"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "BBL App CA"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, caTmpl, &appKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/iot-service/api/user/applications/{appKey}/cert", func(w http.ResponseWriter, r *http.Request) {
		wrapped, err := base64.URLEncoding.DecodeString(r.URL.Query().Get("aes256"))
		if err != nil {
			t.Errorf("aes256 not padded base64url: %v", err)
		}
		aesKey, err := rsa.DecryptPKCS1v15(nil, serviceKey, wrapped)
		if err != nil {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"code":1,"message":"bad wrap"}`))
			return
		}
		appKeyBlob, err := base64.URLEncoding.DecodeString(r.PathValue("appKey"))
		if err != nil {
			t.Errorf("appKey not padded base64url: %v", err)
		}
		blk, _ := aes.NewCipher(aesKey)
		gcm, _ := cipher.NewGCM(blk)
		plain, err := gcm.Open(nil, appKeyBlob[:12], appKeyBlob[12:], nil)
		if err != nil || string(plain) != IoTAppIDPrefix+IoTAndroidAppKey {
			t.Errorf("appKey plaintext %q err %v", plain, err)
		}
		blob := skeyBlob(appKey)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "cert": certPEM, "key": base64.StdEncoding.EncodeToString(blob), "crl": []string{" -----BEGIN X509 CRL-----\nAA==\n-----END X509 CRL----- "}})
	})
	c, _ := testClient(t, mux)
	c.SetToken("tok")
	signer := NewAppCertSigner(c, nil)
	certID, sig, err := signer.SignedHeaders(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if certID != "CN=BBL App CA:beef" {
		t.Fatalf("cert id %q", certID)
	}
	raw, _ := base64.StdEncoding.DecodeString(sig)
	em := new(big.Int).Exp(new(big.Int).SetBytes(raw), big.NewInt(int64(appKey.E)), appKey.N).Bytes()
	ts := string(em[strings.LastIndexByte(string(em), 0)+1:])
	if len(ts) != 13 || !strings.HasPrefix(ts, "17") {
		t.Fatalf("signature plaintext %q is not epoch millis", ts)
	}
	if signer.Padding != WrapPKCS1v15 {
		t.Fatalf("padding %q", signer.Padding)
	}
	cert, _ := signer.Cert(context.Background())
	if cert.KeyLayout != "custom-ctr-fixed/skey" || cert.MQTTCertID != "beefCN=BBL App CA" {
		t.Fatalf("layout %q mqtt id %q", cert.KeyLayout, cert.MQTTCertID)
	}
	if cert.CRLPEM != "-----BEGIN X509 CRL-----\nAA==\n-----END X509 CRL-----" {
		t.Fatalf("crl %q", cert.CRLPEM)
	}
}

// skeyBlob encodes key the way the cert endpoint's `key` field is observed on
// the wire: nonce‖tag‖u32le(len)‖custom-AES-CTR("SKEY"‖v1‖bits‖lens‖p‖q‖dp‖dq‖qinv).
func skeyBlob(key *rsa.PrivateKey) []byte {
	key.Precompute()
	limb := key.N.BitLen() / 16
	pt := make([]byte, 32, 32+5*limb)
	copy(pt, skeyMagic)
	binary.LittleEndian.PutUint32(pt[4:], 1)
	binary.LittleEndian.PutUint32(pt[8:], uint32(key.N.BitLen()))
	for i := 0; i < 5; i++ {
		binary.LittleEndian.PutUint32(pt[12+4*i:], uint32(limb))
	}
	for _, v := range []*big.Int{key.Primes[0], key.Primes[1], key.Precomputed.Dp, key.Precomputed.Dq, key.Precomputed.Qinv} {
		pt = append(pt, v.FillBytes(make([]byte, limb))...)
	}
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce)
	blob := append([]byte{}, nonce...)
	blob = append(blob, make([]byte, 16)...)
	blob = binary.LittleEndian.AppendUint32(blob, uint32(len(pt)))
	return append(blob, customAESCTR(appCertFixedKey, nonce, pt)...)
}

// TestCustomAESKnownAnswers checks the custom-S-box cipher against the public
// vectors in open-bamboo-networking tools/fetch_slicer_credentials.py self_test.
func TestCustomAESKnownAnswers(t *testing.T) {
	nonce, _ := hex.DecodeString("303c8f522a171b9a40dc8901")
	rk := customAESExpand(appCertFixedKey)
	ks := func(ctr uint32) string {
		b := make([]byte, 16)
		copy(b, nonce)
		binary.BigEndian.PutUint32(b[12:], ctr)
		out := customAESEncryptBlock(&rk, b)
		return hex.EncodeToString(out[:])
	}
	for ctr, want := range map[uint32]string{
		2: "c6bf1cc1b40dcc16443034d6dabe7b81",
		3: "a5dee6b960b56cf67aa24081f505a4b8",
		4: "a155d92625a1eb00d8901fef52a8f105",
	} {
		if got := ks(ctr); got != want {
			t.Errorf("keystream ctr=%d: got %s want %s", ctr, got, want)
		}
	}
	ct, _ := hex.DecodeString("9ffa5792b50dcc16443834d65abe7b8125dee6b9e0b56cf6faa240817505a4b8")
	want := "59454b5301000000000800008000000080000000800000008000000080000000"
	if got := hex.EncodeToString(customAESCTR(appCertFixedKey, nonce, ct)); got != want {
		t.Errorf("SKEY header: got %s want %s", got, want)
	}
}

// mustServiceKeyPair swaps the pinned service certificate for a test one.
func mustServiceKeyPair(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "service.test"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	old := iotServiceCertPEM
	iotServiceCertPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	t.Cleanup(func() { iotServiceCertPEM = old })
	return key
}

func TestUnmarshalLenientCoercesGsonShapes(t *testing.T) {
	// The live bind list sends nozzle_diameter as a number although the app's
	// model declares a String (Gson coerces); encoding/json must not fail.
	var dm model.DeviceModel
	data := []byte(`{"devices":[{"dev_id":"01P","nozzle_diameter":0.4,"online":1,"print_job":"7"}],"message":"success"}`)
	if err := unmarshalLenient(data, &dm); err != nil {
		t.Fatal(err)
	}
	d := dm.Devices[0]
	if d.NozzleDiameter != "0.4" || !d.IsOnline || d.PrintJob == nil || *d.PrintJob != 7 {
		t.Fatalf("coerced badly: %+v", d)
	}
	var strict struct {
		N int `json:"n"`
	}
	if err := unmarshalLenient([]byte(`{"n":"abc"}`), &strict); err == nil {
		t.Fatal("expected a type error for a non-numeric string")
	}
}
