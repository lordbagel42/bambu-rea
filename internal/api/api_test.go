package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lordbagel42/bambu-rea/internal/store"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
)

// fakeCloud is enough of the Bambu cloud for the account flow: password login
// (first a verifyCode step, then a token), TFA, profile and logout.
func fakeCloud(t *testing.T) (*httptest.Server, *[]string) {
	t.Helper()
	var calls []string
	var mu sync.Mutex
	issued := map[string]bool{} // tokens this cloud handed out; the profile rejects all others
	issue := func(uid string) string {
		tok := fakeJWT(uid)
		mu.Lock()
		issued[tok] = true
		mu.Unlock()
		return tok
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/user-service/user/security/pubkey", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"needEncrypt": false})
	})
	mux.HandleFunc("POST /v1/user-service/user/login", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch {
		case req["code"] == "123456":
			_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": issue("42"), "refreshToken": "rt", "expiresIn": 3600})
		case req["password"] == "tfa":
			_ = json.NewEncoder(w).Encode(map[string]any{"loginType": "tfa", "tfaKey": "tfa-key"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"loginType": "verifyCode"})
		}
	})
	mux.HandleFunc("POST /v1/user-service/user/tfa/login", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": issue("43"), "expiresIn": 3600})
	})
	mux.HandleFunc("POST /v1/user-service/user/sendemail/code", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("POST /v1/user-service/user/logout", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("GET /v1/user-service/my/profile", func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Header.Get("Authorization")+" "+r.Header.Get("X-BBL-Device-ID"))
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		mu.Lock()
		ok := issued[tok]
		mu.Unlock()
		uid := userIDFromJWT(tok)
		if uid == "" || !ok {
			w.WriteHeader(401)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 401, "message": "bad token"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"uid": json.Number(uid), "account": "u" + uid + "@example.com", "name": "tester"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &calls
}

func fakeJWT(uid string) string {
	payload, _ := json.Marshal(map[string]any{"username": "u_" + uid, "exp": 9999999999})
	return "eyJhbGciOiJIUzI1NiJ9." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

// forgedJWT claims a uid but was never issued by the cloud.
func forgedJWT(uid string) string {
	return strings.TrimSuffix(fakeJWT(uid), ".sig") + ".forged"
}

func newTestServer(t *testing.T, withStore bool) (*httptest.Server, *Server) {
	t.Helper()
	bambu, _ := fakeCloud(t)
	region := cloud.RegionIntl
	region.APIBaseURL = bambu.URL + "/v1/"
	region.MallAPIBaseURL = bambu.URL + "/mall"
	cfg := Config{Region: region, Logger: log.New(io.Discard, "", 0), CORSOrigins: []string{"https://app.example"}}
	if withStore {
		st, err := store.Open(filepath.Join(t.TempDir(), "api.sqlite"), bytes.Repeat([]byte{9}, 32))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { st.Close() })
		cfg.Store = st
	}
	s := New(cfg)
	t.Cleanup(s.Close)
	hs := httptest.NewServer(s)
	t.Cleanup(hs.Close)
	return hs, s
}

type call struct {
	status int
	body   map[string]any
	raw    []byte
	header http.Header
}

func do(t *testing.T, hs *httptest.Server, method, path, cred string, body any) call {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, hs.URL+path, rdr)
	if cred != "" {
		req.Header.Set("Authorization", "Bearer "+cred)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := hs.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	c := call{status: res.StatusCode, raw: raw, header: res.Header}
	_ = json.Unmarshal(raw, &c.body)
	return c
}

func TestLoginPersistsSessionAndKeysActAsTheAccount(t *testing.T) {
	hs, _ := newTestServer(t, true)

	// Password login asks for an emailed code first, exactly like the app.
	r := do(t, hs, "POST", "/v1/auth/login", "", map[string]string{"account": "me@example.com", "password": "pw"})
	if r.status != 200 || r.body["loginType"] != "verifyCode" {
		t.Fatalf("first login step: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "POST", "/v1/auth/email-code", "", map[string]string{"email": "me@example.com"}); r.status != 200 {
		t.Fatalf("email code: %d %s", r.status, r.raw)
	}
	r = do(t, hs, "POST", "/v1/auth/login", "", map[string]string{"account": "me@example.com", "code": "123456"})
	token, _ := r.body["accessToken"].(string)
	if r.status != 200 || token == "" {
		t.Fatalf("code login: %d %s", r.status, r.raw)
	}

	// The login was remembered for uid 42.
	acct := do(t, hs, "GET", "/v1/account", token, nil)
	if acct.status != 200 || acct.body["uid"] != "42" || acct.body["email"] != "me@example.com" || acct.body["signedIn"] != true {
		t.Fatalf("account: %d %s", acct.status, acct.raw)
	}

	created := do(t, hs, "POST", "/v1/keys", token, map[string]string{"name": "laptop"})
	key, _ := created.body["key"].(string)
	if created.status != 201 || !strings.HasPrefix(key, "bk_") {
		t.Fatalf("create key: %d %s", created.status, created.raw)
	}

	// The key reaches the cloud as the account and reports itself on /v1/account.
	me := do(t, hs, "GET", "/v1/me", key, nil)
	if me.status != 200 || me.body["account"] != "u42@example.com" {
		t.Fatalf("me via key: %d %s", me.status, me.raw)
	}
	via := do(t, hs, "GET", "/v1/account", key, nil)
	if via.status != 200 || via.body["viaKey"] == nil || via.body["keys"] != float64(1) {
		t.Fatalf("account via key: %d %s", via.status, via.raw)
	}

	// Keys may not mint keys or sign the account out.
	if r := do(t, hs, "POST", "/v1/keys", key, map[string]string{"name": "evil"}); r.status != 403 {
		t.Fatalf("key minted a key: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "POST", "/v1/auth/logout", key, nil); r.status != 403 {
		t.Fatalf("key signed out: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "GET", "/v1/me", "bk_definitely-not-a-real-key-000000", nil); r.status != 401 {
		t.Fatalf("bogus key accepted: %d %s", r.status, r.raw)
	}

	// Signing out keeps the key but disables it until the next login.
	if r := do(t, hs, "POST", "/v1/auth/logout", token, nil); r.status != 200 {
		t.Fatalf("logout: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "GET", "/v1/me", key, nil); r.status != 401 || !strings.Contains(r.body["error"].(string), "signed out") {
		t.Fatalf("key after logout: %d %s", r.status, r.raw)
	}
	r = do(t, hs, "POST", "/v1/auth/login", "", map[string]string{"account": "me@example.com", "code": "123456"})
	if r.status != 200 {
		t.Fatalf("re-login: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "GET", "/v1/me", key, nil); r.status != 200 {
		t.Fatalf("key after re-login: %d %s", r.status, r.raw)
	}
	keys := do(t, hs, "GET", "/v1/keys", token, nil)
	list, _ := keys.body["keys"].([]any)
	if keys.status != 200 || len(list) != 1 {
		t.Fatalf("list keys: %d %s", keys.status, keys.raw)
	}
	id := list[0].(map[string]any)["id"].(string)
	if r := do(t, hs, "DELETE", "/v1/keys/"+id, token, nil); r.status != 204 {
		t.Fatalf("delete key: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "GET", "/v1/me", key, nil); r.status != 401 {
		t.Fatalf("revoked key accepted: %d %s", r.status, r.raw)
	}
}

func TestForgedTokenCannotReachAStoredAccount(t *testing.T) {
	hs, _ := newTestServer(t, true)
	if r := do(t, hs, "POST", "/v1/auth/login", "", map[string]string{"account": "me@example.com", "code": "123456"}); r.status != 200 {
		t.Fatalf("login: %d %s", r.status, r.raw)
	}
	forged := forgedJWT("42") // the victim's uid, a signature the cloud never made
	for _, c := range []struct{ method, path string }{
		{"GET", "/v1/account"}, {"GET", "/v1/keys"}, {"POST", "/v1/keys"}, {"POST", "/v1/auth/logout"}, {"GET", "/v1/me"},
	} {
		body := map[string]string(nil)
		if c.method == "POST" {
			body = map[string]string{"name": "evil"}
		}
		if r := do(t, hs, c.method, c.path, forged, body); r.status != 401 {
			t.Errorf("%s %s with a forged token: %d %s", c.method, c.path, r.status, r.raw)
		}
	}
	// The real owner is unaffected: still signed in, still no keys.
	r := do(t, hs, "GET", "/v1/account", fakeJWT("42"), nil)
	if r.status != 200 || r.body["signedIn"] != true || r.body["keys"] != float64(0) {
		t.Fatalf("victim account after forgery attempt: %d %s", r.status, r.raw)
	}
}

func TestHostedServerHasNoLANRegistryAndKeysCannotLogOutViaPassthrough(t *testing.T) {
	hs, _ := newTestServer(t, true)
	if r := do(t, hs, "POST", "/v1/lan/devices", "", map[string]string{"ip": "127.0.0.1", "serial": "X", "accessCode": "1"}); r.status != 404 {
		t.Fatalf("LAN registration on a hosted server: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "GET", "/openapi.json", "", nil); strings.Contains(string(r.raw), "/v1/lan/") {
		t.Fatal("hosted OpenAPI still documents /v1/lan")
	}
	r := do(t, hs, "POST", "/v1/auth/login", "", map[string]string{"account": "me@example.com", "code": "123456"})
	token := r.body["accessToken"].(string)
	key := do(t, hs, "POST", "/v1/keys", token, map[string]string{"name": "k"}).body["key"].(string)
	for _, p := range []string{"/v1/cloud/user-service/user/logout", "/v1/cloud/x/%2e%2e/user-service/user/logout", "/v1/cloud/user-service%2F%2Fuser/logout"} {
		if r := do(t, hs, "POST", p, key, nil); r.status != 403 {
			t.Fatalf("key logout through the passthrough as %s: %d %s", p, r.status, r.raw)
		}
	}
	if r := do(t, hs, "GET", "/v1/me", key, nil); r.status != 200 {
		t.Fatalf("key still works after the blocked logout: %d %s", r.status, r.raw)
	}
	// The owner's token through the passthrough signs out for real, keys included.
	if r := do(t, hs, "POST", "/v1/cloud/user-service/user/logout", token, nil); r.status != 200 {
		t.Fatalf("token logout through the passthrough: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "GET", "/v1/me", key, nil); r.status != 401 {
		t.Fatalf("key after passthrough logout: %d %s", r.status, r.raw)
	}
}

func TestTFALoginIsRememberedWithTheProfileEmail(t *testing.T) {
	hs, _ := newTestServer(t, true)
	r := do(t, hs, "POST", "/v1/auth/login", "", map[string]string{"account": "two@example.com", "password": "tfa"})
	if r.body["loginType"] != "tfa" || r.body["tfaKey"] != "tfa-key" {
		t.Fatalf("tfa step: %s", r.raw)
	}
	r = do(t, hs, "POST", "/v1/auth/tfa", "", map[string]string{"tfaKey": "tfa-key", "tfaCode": "000000"})
	token, _ := r.body["accessToken"].(string)
	if token == "" {
		t.Fatalf("tfa login: %s", r.raw)
	}
	acct := do(t, hs, "GET", "/v1/account", token, nil)
	if acct.body["uid"] != "43" || acct.body["email"] != "u43@example.com" {
		t.Fatalf("account after tfa: %s", acct.raw)
	}
}

func TestWithoutAStoreAccountsAreUnavailable(t *testing.T) {
	hs, _ := newTestServer(t, false)
	if r := do(t, hs, "GET", "/v1/account", fakeJWT("1"), nil); r.status != 501 {
		t.Fatalf("account without store: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "GET", "/v1/me", "bk_somekeythatisnotvalidxxxxxxxx", nil); r.status != 401 {
		t.Fatalf("key without store: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "POST", "/mcp", "bk_somekeythatisnotvalidxxxxxxxx", map[string]any{}); r.status != 501 {
		t.Fatalf("mcp without store: %d %s", r.status, r.raw)
	}
}

func TestCORSAllowsOnlyConfiguredOrigins(t *testing.T) {
	hs, _ := newTestServer(t, true)
	req, _ := http.NewRequest(http.MethodOptions, hs.URL+"/v1/keys", nil)
	req.Header.Set("Origin", "https://app.example")
	req.Header.Set("Access-Control-Request-Method", "POST")
	res, err := hs.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 204 || res.Header.Get("Access-Control-Allow-Origin") != "https://app.example" || !strings.Contains(res.Header.Get("Access-Control-Allow-Headers"), "Authorization") {
		t.Fatalf("preflight: %d %v", res.StatusCode, res.Header)
	}
	req.Header.Set("Origin", "https://evil.example")
	res, _ = hs.Client().Do(req)
	if res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("foreign origin allowed: %v", res.Header)
	}
}

func TestMCPToolsRunAsTheKeyOwner(t *testing.T) {
	hs, _ := newTestServer(t, true)
	r := do(t, hs, "POST", "/v1/auth/login", "", map[string]string{"account": "me@example.com", "code": "123456"})
	token := r.body["accessToken"].(string)
	key := do(t, hs, "POST", "/v1/keys", token, map[string]string{"name": "agent"}).body["key"].(string)

	ctx := context.Background()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	hc := &http.Client{Transport: &bearerTransport{token: key, next: http.DefaultTransport}}
	sess, err := client.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: hs.URL + "/mcp", HTTPClient: hc}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, tl := range tools.Tools {
		names[tl.Name] = true
	}
	for _, want := range []string{"whoami", "list_printers", "printer_status", "list_commands", "send_command", "send_gcode", "print_history", "cloud_request"} {
		if !names[want] {
			t.Fatalf("tool %s missing from %v", want, names)
		}
	}
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{Name: "whoami"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || len(res.Content) == 0 || !strings.Contains(res.Content[0].(*mcp.TextContent).Text, "u42@example.com") {
		t.Fatalf("whoami: %+v", res)
	}

	// A Bambu token is not accepted on the MCP endpoint, nor is a missing key.
	if r := do(t, hs, "POST", "/mcp", token, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); r.status != 401 {
		t.Fatalf("mcp with bambu token: %d %s", r.status, r.raw)
	}
	if r := do(t, hs, "POST", "/mcp", "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "ping"}); r.status != 401 {
		t.Fatalf("mcp without auth: %d %s", r.status, r.raw)
	}
}

type bearerTransport struct {
	token string
	next  http.RoundTripper
}

func (b *bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}
