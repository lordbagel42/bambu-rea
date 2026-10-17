package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lordbagel42/bambu-rea/internal/api"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
)

// apiClient talks to a bambu-api server over HTTP. Without --server it starts
// the server in-process on a loopback port, so the CLI needs nothing running
// and still exercises the exact HTTP contract a remote deployment would.
type apiClient struct {
	base   string
	apiKey string
	token  string
	http   *http.Client

	srv  *api.Server
	hsrv *http.Server
}

func newAPIClient(cfg *Config, server, apiKey string, timeout time.Duration) (*apiClient, error) {
	c := &apiClient{apiKey: apiKey, token: cfg.Token, http: &http.Client{Timeout: timeout}}
	if server != "" {
		c.base = strings.TrimRight(server, "/")
		return c, nil
	}
	reg, ok := cloud.RegionByName(cfg.Region)
	if !ok {
		return nil, fmt.Errorf("unknown region %q", cfg.Region)
	}
	c.srv = api.New(api.Config{Region: reg, HardwareID: cfg.HardwareID, Logger: log.New(io.Discard, "", 0)})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	c.hsrv = &http.Server{Handler: c.srv}
	go func() { _ = c.hsrv.Serve(ln) }()
	c.base = "http://" + ln.Addr().String()
	return c, nil
}

func (c *apiClient) close() {
	if c.hsrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = c.hsrv.Shutdown(ctx)
	}
	if c.srv != nil {
		c.srv.Close()
	}
}

// apiError is a non-2xx answer from bambu-api (which mirrors the cloud's error body).
type apiError struct {
	Status int
	Msg    string          `json:"error"`
	Code   int             `json:"code,omitempty"`
	Detail json.RawMessage `json:"detail,omitempty"`
}

func (e *apiError) Error() string {
	s := fmt.Sprintf("HTTP %d: %s", e.Status, e.Msg)
	if e.Code != 0 {
		s += fmt.Sprintf(" (code %d)", e.Code)
	}
	return s
}

func (c *apiClient) newRequest(ctx context.Context, method, path string, q url.Values, body any) (*http.Request, error) {
	u := c.base + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rdr io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		rdr = bytes.NewReader(b)
	case string:
		rdr = strings.NewReader(b)
	default:
		data, err := json.Marshal(b)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rdr)
	if err != nil {
		return nil, err
	}
	if rdr != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	return req, nil
}

// do performs a JSON call and decodes the response into out (which may be nil
// or a *json.RawMessage to keep the body verbatim).
func (c *apiClient) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	req, err := c.newRequest(ctx, method, path, q, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		ae := &apiError{Status: resp.StatusCode}
		if json.Unmarshal(data, ae) != nil || ae.Msg == "" {
			ae.Msg = strings.TrimSpace(string(data))
			if ae.Msg == "" {
				ae.Msg = http.StatusText(resp.StatusCode)
			}
		}
		return ae
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = append((*raw)[:0], data...)
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // keep ids like uid 1242808761 intact when decoding into map[string]any
	return dec.Decode(out)
}

// stream opens a server-sent-events endpoint and calls fn for every event
// until ctx ends or fn returns false.
func (c *apiClient) stream(ctx context.Context, path string, fn func(event, data string) bool) error {
	req, err := c.newRequest(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := (&http.Client{}).Do(req) // no timeout: the stream is long-lived
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		ae := &apiError{Status: resp.StatusCode}
		if json.Unmarshal(data, ae) != nil || ae.Msg == "" {
			ae.Msg = strings.TrimSpace(string(data))
		}
		return ae
	}
	var event string
	var data strings.Builder
	buf := make([]byte, 0, 64<<10)
	rd := newLineReader(resp.Body)
	for {
		line, err := rd.readLine(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return nil
			}
			return err
		}
		switch {
		case line == "":
			if data.Len() > 0 || event != "" {
				if !fn(event, strings.TrimSuffix(data.String(), "\n")) {
					return nil
				}
			}
			event = ""
			data.Reset()
		case strings.HasPrefix(line, ":"):
		case strings.HasPrefix(line, "event:"):
			event = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "data:"):
			data.WriteString(strings.TrimPrefix(line[5:], " "))
			data.WriteByte('\n')
		}
	}
}

// lineReader splits a stream into lines without a maximum token size.
type lineReader struct {
	r   io.Reader
	buf []byte
}

func newLineReader(r io.Reader) *lineReader { return &lineReader{r: r} }

func (l *lineReader) readLine(scratch []byte) (string, error) {
	for {
		if i := bytes.IndexByte(l.buf, '\n'); i >= 0 {
			line := strings.TrimRight(string(l.buf[:i]), "\r")
			l.buf = l.buf[i+1:]
			return line, nil
		}
		n, err := l.r.Read(scratch[:cap(scratch)])
		l.buf = append(l.buf, scratch[:n]...)
		if err != nil {
			if len(l.buf) > 0 && errors.Is(err, io.EOF) {
				line := string(l.buf)
				l.buf = nil
				return line, nil
			}
			return "", err
		}
	}
}
