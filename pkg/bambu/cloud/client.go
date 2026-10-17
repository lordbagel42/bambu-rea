// Package cloud is a Go client for the Bambu Lab cloud HTTP API as used by the
// Bambu Handy 4.2.2 Android app. Endpoint methods and models are generated from the
// decompiled Retrofit interfaces (see tools/gen_go.py and catalog/).
package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// App identity constants from the APK (BblHeaderInterceptor / BuildConfig).
const (
	AppVersionName = "4.2.2"
	AppVersionCode = "40202"
	AppPackage     = "bbl.intl.bambulab.com"
	UserAgent      = "Handy/" + AppVersionName
)

// ParamSpec describes one Retrofit parameter of an endpoint.
type ParamSpec struct {
	Kind     string `json:"kind"` // path | query | querymap | body | header
	Name     string `json:"name,omitempty"`
	JavaType string `json:"javaType"`
}

// Endpoint is the static description of one cloud API call.
type Endpoint struct {
	Name     string      `json:"name"`
	Method   string      `json:"method"`
	Path     string      `json:"path"`
	Service  string      `json:"service"`
	Response string      `json:"response"`
	Signed   bool        `json:"signed"` // carries x-bbl-app-certification-id / x-bbl-device-security-sign
	Params   []ParamSpec `json:"params"`
}

// IoTSigner produces the app-certificate headers the IoT service requires on
// print-job creation, printer unbind, TT-code (live view) and bind-confirm calls.
type IoTSigner interface {
	// SignedHeaders returns (x-bbl-app-certification-id, x-bbl-device-security-sign).
	SignedHeaders(ctx context.Context) (certID, sign string, err error)
}

// DeviceInfo is what the app reports about the phone in the X-BBL-* headers.
type DeviceInfo struct {
	DeviceID  string // X-BBL-Device-ID (app installation id)
	Brand     string // X-BBL-Device-Brand
	Model     string // X-BBL-Device-Model
	OSVersion string // X-BBL-OS-Version
	Language  string // X-BBL-Language, e.g. "en"
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the underlying http.Client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.http = h } }

// WithDeviceInfo overrides the fake phone identity sent in headers.
func WithDeviceInfo(d DeviceInfo) Option { return func(c *Client) { c.device = d } }

// WithSigner installs an IoTSigner used for Endpoint.Signed calls.
func WithSigner(s IoTSigner) Option { return func(c *Client) { c.Signer = s } }

// WithToken sets the initial bearer token.
func WithToken(t string) Option { return func(c *Client) { c.SetToken(t) } }

// Client talks to one region of the Bambu cloud on behalf of one user.
type Client struct {
	Region Region
	Signer IoTSigner
	// UserID is the numeric cloud uid of the token owner. When set, signed
	// requests carry X-BBL-Client-ID = "android:<uid>:<deviceID>" like Handy
	// (LiveviewRepository.buildTtCodeHeaders).
	UserID string

	http   *http.Client
	device DeviceInfo

	mu    sync.RWMutex
	token string
}

// ClientID returns the X-BBL-Client-ID value for this user, or "" if the uid is unknown.
func (c *Client) ClientID() string {
	if c.UserID == "" {
		return ""
	}
	return "android:" + c.UserID + ":" + c.device.DeviceID
}

// New creates a client for region. Tokens are set via Login or SetToken.
func New(region Region, opts ...Option) *Client {
	c := &Client{
		Region: region,
		http:   &http.Client{Timeout: 60 * time.Second},
		device: DeviceInfo{DeviceID: "bambu-rea", Brand: "google", Model: "Pixel 8", OSVersion: "15", Language: "en"},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// SetToken installs the access token used as `Authorization: Bearer`.
func (c *Client) SetToken(t string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.token = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "Bearer "))
}

// Token returns the current access token.
func (c *Client) Token() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// WithToken returns a shallow copy of the client bound to another user's token.
// It shares the HTTP transport, region, device identity and signer.
func (c *Client) WithToken(token string) *Client {
	n := &Client{Region: c.Region, Signer: c.Signer, UserID: c.UserID, http: c.http, device: c.device}
	n.SetToken(token)
	return n
}

// BaseURL returns the base URL for a service path (mall-app-bff goes to the mall host).
func (c *Client) BaseURL(path string) string {
	if strings.HasPrefix(path, "mall-app-bff/") {
		return strings.TrimSuffix(c.Region.MallAPIBaseURL, "/") + "/"
	}
	return c.Region.APIBaseURL
}

// APIError is a non-2xx response from the cloud, parsed like the app's ApiErrorBody.
type APIError struct {
	StatusCode int
	Code       int    `json:"code"`
	Message    string `json:"message"`
	CaptchaID  string `json:"captchaId,omitempty"`
	Body       []byte `json:"-"`
	Method     string `json:"-"`
	Path       string `json:"-"`
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	return fmt.Sprintf("bambu cloud: %s %s -> %d (code %d): %s", e.Method, e.Path, e.StatusCode, e.Code, msg)
}

// IsUnauthorized reports whether err is a 401 from the cloud (token expired or invalid).
func IsUnauthorized(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.StatusCode == http.StatusUnauthorized
}

func parseAPIError(method, path string, status int, body []byte) *APIError {
	e := &APIError{StatusCode: status, Body: body, Method: method, Path: path}
	var raw map[string]json.RawMessage
	if json.Unmarshal(body, &raw) == nil {
		if v, ok := raw["code"]; ok {
			var n json.Number
			if json.Unmarshal(v, &n) == nil {
				if i, err := n.Int64(); err == nil {
					e.Code = int(i)
				}
			} else {
				var s string
				if json.Unmarshal(v, &s) == nil {
					fmt.Sscan(s, &e.Code)
				}
			}
		}
		for _, k := range []string{"message", "msg", "error"} {
			if v, ok := raw[k]; ok {
				var s string
				if json.Unmarshal(v, &s) == nil && s != "" {
					e.Message = s
					break
				}
			}
		}
		if v, ok := raw["captchaId"]; ok {
			_ = json.Unmarshal(v, &e.CaptchaID)
		}
	}
	if e.Message == "" {
		e.Message = strings.TrimSpace(string(body))
		if len(e.Message) > 200 {
			e.Message = e.Message[:200]
		}
	}
	return e
}

// Request is a fully generic cloud call (used by the passthrough API).
type Request struct {
	Method  string
	Path    string // service path relative to the base URL, e.g. "iot-service/api/user/bind"
	Query   url.Values
	Headers http.Header
	Body    any // marshalled as JSON unless nil or []byte / io.Reader
	Signed  bool
}

// Do performs a generic request and decodes a JSON response into out (if non-nil).
// A nil out with a non-empty body is ignored. If out is *[]byte the raw body is returned.
func (c *Client) Do(ctx context.Context, r Request, out any) error {
	ep := &Endpoint{Name: "raw", Method: r.Method, Path: r.Path, Signed: r.Signed}
	return c.call(ctx, ep, r.Path, r.Query, r.Headers, r.Body, out)
}

func (c *Client) call(ctx context.Context, ep *Endpoint, path string, q url.Values, h http.Header, body any, out any) error {
	u := c.BaseURL(path) + strings.TrimPrefix(path, "/")
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rdr io.Reader
	contentType := ""
	switch b := body.(type) {
	case nil:
	case []byte:
		rdr = bytes.NewReader(b)
		contentType = "application/json; charset=utf-8"
	case io.Reader:
		rdr = b
	default:
		buf, err := json.Marshal(b)
		if err != nil {
			return fmt.Errorf("cloud: encode body: %w", err)
		}
		if rewritten, err := c.rewritePasswordBody(ctx, path, buf); err != nil {
			return err
		} else if rewritten != nil {
			buf = rewritten
		}
		rdr = bytes.NewReader(buf)
		contentType = "application/json; charset=utf-8"
	}
	req, err := http.NewRequestWithContext(ctx, ep.Method, u, rdr)
	if err != nil {
		return err
	}
	c.applyStandardHeaders(req)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, vs := range h {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	if ep.Signed && c.Signer != nil && req.Header.Get("x-bbl-device-security-sign") == "" {
		certID, sign, err := c.Signer.SignedHeaders(ctx)
		if err != nil {
			return fmt.Errorf("cloud: iot signing: %w", err)
		}
		req.Header.Set("x-bbl-app-certification-id", certID)
		req.Header.Set("x-bbl-device-security-sign", sign)
	}
	if ep.Signed && req.Header.Get("X-BBL-Client-ID") == "" {
		if id := c.ClientID(); id != "" {
			req.Header.Set("X-BBL-Client-ID", id)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseAPIError(ep.Method, path, resp.StatusCode, data)
	}
	if out == nil {
		return nil
	}
	if raw, ok := out.(*[]byte); ok {
		*raw = data
		return nil
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if err := unmarshalLenient(data, out); err != nil {
		return fmt.Errorf("cloud: decode %s %s response: %w", ep.Method, path, err)
	}
	return nil
}

func (c *Client) applyStandardHeaders(req *http.Request) {
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("accept", "application/json")
	req.Header.Set("X-BBL-Client-Type", "app")
	req.Header.Set("X-BBL-Client-Name", "BambuHandy")
	req.Header.Set("X-BBL-Client-Version", AppVersionName)
	req.Header.Set("X-BBL-Client-Release-Code", AppVersionCode)
	req.Header.Set("X-BBL-OS-Type", "android")
	req.Header.Set("X-BBL-OS-Version", c.device.OSVersion)
	req.Header.Set("X-BBL-Device-Brand", c.device.Brand)
	req.Header.Set("X-BBL-Device-Model", c.device.Model)
	req.Header.Set("X-BBL-Language", c.device.Language)
	req.Header.Set("X-BBL-Device-ID", c.device.DeviceID)
	if t := c.Token(); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
}

// EndpointByName looks up a generated endpoint by its Go name.
func EndpointByName(name string) (*Endpoint, bool) {
	for _, e := range Endpoints {
		if e.Name == name {
			return e, true
		}
	}
	return nil, false
}
