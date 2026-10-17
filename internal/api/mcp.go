package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lordbagel42/bambu-rea/internal/store"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/mqtt"
)

// mcpHandler serves the Model Context Protocol over streamable HTTP at /mcp.
// Clients authenticate with an API key as a bearer token; every tool then acts
// as the Bambu account behind that key. Sessions are stateless so a plain
// POST per call works through any proxy.
func (s *Server) mcpHandler() http.Handler {
	if s.store == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeErr(w, http.StatusNotImplemented, "MCP needs the account store (start bambu-api with -db)")
		})
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "bambu-api", Title: "Bambu Lab printers", Version: cloud.AppVersionName, WebsiteURL: s.cfg.PublicURL}, &mcp.ServerOptions{
		Instructions: "Tools act as the Bambu Lab account that owns the API key. Use list_printers to find serial numbers, printer_status for live state, and send_command / send_gcode only when the user explicitly asks to change something on a printer.",
	})
	s.addMCPTools(server)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{Stateless: true})
	return auth.RequireBearerToken(s.verifyMCPKey, nil)(h)
}

// verifyMCPKey resolves an API key for the MCP transport.
func (s *Server) verifyMCPKey(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	if !store.IsKey(token) {
		return nil, fmt.Errorf("%w: MCP requires an API key from /login, not a Bambu token", auth.ErrInvalidToken)
	}
	key, err := s.store.ResolveKey(ctx, token)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: unknown API key", auth.ErrInvalidToken)
	}
	if err != nil {
		return nil, err
	}
	sess, err := s.store.Session(ctx, key.AccountUID)
	if errors.Is(err, store.ErrSignedOut) {
		return nil, fmt.Errorf("%w: account is signed out; log in again", auth.ErrInvalidToken)
	}
	if err != nil {
		return nil, err
	}
	exp := sess.TokenExpiresAt
	if exp.IsZero() || exp.After(time.Now().Add(24*time.Hour)) {
		// Keys have no expiry of their own; the transport only needs a bound.
		exp = time.Now().Add(24 * time.Hour)
	}
	return &auth.TokenInfo{UserID: key.AccountUID, Expiration: exp, Extra: map[string]any{"key": key.ID}}, nil
}

// mcpSession is the account session behind a tool call.
func (s *Server) mcpSession(ctx context.Context, req *mcp.CallToolRequest) (*session, error) {
	if req.Extra == nil || req.Extra.TokenInfo == nil || req.Extra.TokenInfo.UserID == "" {
		return nil, errors.New("unauthenticated MCP request")
	}
	return s.sessionForAccount(ctx, req.Extra.TokenInfo.UserID)
}

func (s *Server) mcpPrinter(ctx context.Context, req *mcp.CallToolRequest, serial string) (*mqtt.Client, error) {
	if strings.TrimSpace(serial) == "" {
		return nil, errors.New("serial is required; call list_printers first")
	}
	sess, err := s.mcpSession(ctx, req)
	if err != nil {
		return nil, err
	}
	return sess.MQTT(ctx, s.cfg.Region)
}

func boolPtr(b bool) *bool { return &b }

type serialArgs struct {
	Serial string `json:"serial" jsonschema:"printer serial number, from list_printers"`
}

type statusArgs struct {
	Serial  string `json:"serial" jsonschema:"printer serial number, from list_printers"`
	Refresh bool   `json:"refresh,omitempty" jsonschema:"ask the printer for a full report before answering"`
}

type commandsArgs struct {
	Module string `json:"module,omitempty" jsonschema:"only commands of this module (print, system, camera, upgrade, ...)"`
}

type commandArgs struct {
	Serial string         `json:"serial" jsonschema:"printer serial number"`
	Name   string         `json:"name" jsonschema:"command name from list_commands, e.g. Pause, Resume, Stop, SetFan, LedCtrl, PrintSpeed"`
	Params map[string]any `json:"params,omitempty" jsonschema:"command parameters keyed as list_commands describes"`
}

type gcodeArgs struct {
	Serial string `json:"serial" jsonschema:"printer serial number"`
	Gcode  string `json:"gcode" jsonschema:"G-code to run, one or more lines"`
}

type historyArgs struct {
	Limit int `json:"limit,omitempty" jsonschema:"number of print tasks to return (default 20)"`
}

type cloudArgs struct {
	Method string            `json:"method" jsonschema:"HTTP method"`
	Path   string            `json:"path" jsonschema:"service path as in the Handy app, e.g. iot-service/api/user/bind or user-service/my/tasks"`
	Query  map[string]string `json:"query,omitempty" jsonschema:"query parameters"`
	Body   any               `json:"body,omitempty" jsonschema:"JSON body for POST/PUT/PATCH"`
}

func (s *Server) addMCPTools(server *mcp.Server) {
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true, OpenWorldHint: boolPtr(true)}
	mutating := &mcp.ToolAnnotations{DestructiveHint: boolPtr(true), OpenWorldHint: boolPtr(true)}

	mcp.AddTool(server, &mcp.Tool{Name: "whoami", Description: "Profile of the Bambu account this key belongs to.", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			sess, err := s.mcpSession(ctx, req)
			if err != nil {
				return nil, nil, err
			}
			me, err := sess.cloud.GetUserServiceMyProfile(ctx, nil)
			return nil, me, err
		})

	mcp.AddTool(server, &mcp.Tool{Name: "list_printers", Description: "Printers bound to the account: serial (dev_id), name, model, online flag and print status.", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			sess, err := s.mcpSession(ctx, req)
			if err != nil {
				return nil, nil, err
			}
			list, err := sess.cloud.GetIotServiceApiUserBind(ctx, nil)
			return nil, list, err
		})

	mcp.AddTool(server, &mcp.Tool{Name: "printer_status", Description: "Live state of a printer from its MQTT report stream: gcode_state, progress (mc_percent, mc_remaining_time, layer_num/total_layer_num), temperatures, fans, speed, lights, AMS, HMS errors, current job.", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, in statusArgs) (*mcp.CallToolResult, any, error) {
			c, err := s.mcpPrinter(ctx, req, in.Serial)
			if err != nil {
				return nil, nil, err
			}
			st, err := s.printerState(ctx, c, in.Serial, in.Refresh)
			if err != nil {
				return nil, nil, err
			}
			return nil, map[string]any{"serial": st.Serial, "updatedAt": st.UpdatedAt, "print": st.Print}, nil
		})

	mcp.AddTool(server, &mcp.Tool{Name: "list_commands", Description: "Catalog of printer commands (module, command, parameters) the Handy app can send; names are what send_command expects.", Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *mcp.CallToolRequest, in commandsArgs) (*mcp.CallToolResult, any, error) {
			type param struct {
				Key      string `json:"key"`
				Type     string `json:"type"`
				Optional bool   `json:"optional,omitempty"`
				Wire     string `json:"wire,omitempty"`
			}
			type entry struct {
				Name    string  `json:"name"`
				Module  string  `json:"module"`
				Command string  `json:"command"`
				Doc     string  `json:"doc,omitempty"`
				Params  []param `json:"params"`
			}
			var out []entry
			for i := range mqtt.Specs {
				sp := &mqtt.Specs[i]
				if in.Module != "" && !strings.EqualFold(sp.Module, in.Module) {
					continue
				}
				e := entry{Name: sp.Name, Module: sp.Module, Command: sp.Command, Doc: sp.Doc, Params: []param{}}
				for _, p := range sp.Params {
					if p.Const != nil || p.Derived != "" {
						continue
					}
					e.Params = append(e.Params, param{Key: p.Key, Type: p.Type, Optional: p.Optional, Wire: p.Wire})
				}
				out = append(out, e)
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
			return nil, out, nil
		})

	mcp.AddTool(server, &mcp.Tool{Name: "send_command", Description: "Send a catalogued command to a printer and wait for its reply. Changes printer state (pause, resume, stop, temperatures, fans, lights, speed, AMS, start a print) — only use when the user explicitly asks.", Annotations: mutating},
		func(ctx context.Context, req *mcp.CallToolRequest, in commandArgs) (*mcp.CallToolResult, any, error) {
			spec, ok := mqtt.SpecByName(in.Name)
			if !ok {
				return nil, nil, fmt.Errorf("unknown command %q; see list_commands", in.Name)
			}
			params := in.Params
			if params == nil {
				params = map[string]any{}
			}
			cmd, err := mqtt.Build(spec, params)
			if err != nil {
				return nil, nil, err
			}
			c, err := s.mcpPrinter(ctx, req, in.Serial)
			if err != nil {
				return nil, nil, err
			}
			res, err := s.execCommand(ctx, c, in.Serial, cmd)
			if err != nil {
				return nil, nil, err
			}
			if res.failed() {
				return nil, nil, fmt.Errorf("printer rejected %s: result=%s reason=%s errno=%d err_code=%d", in.Name, res.Result, res.Reason, res.Errno, res.ErrCode)
			}
			return nil, res, nil
		})

	mcp.AddTool(server, &mcp.Tool{Name: "send_gcode", Description: "Run raw G-code on a printer (print/gcode_line). Changes printer state — only use when the user explicitly asks.", Annotations: mutating},
		func(ctx context.Context, req *mcp.CallToolRequest, in gcodeArgs) (*mcp.CallToolResult, any, error) {
			if strings.TrimSpace(in.Gcode) == "" {
				return nil, nil, errors.New("gcode is required")
			}
			c, err := s.mcpPrinter(ctx, req, in.Serial)
			if err != nil {
				return nil, nil, err
			}
			res, err := s.execCommand(ctx, c, in.Serial, mqtt.GcodeLine(mqtt.GcodeLineParams{Param: in.Gcode}))
			if err != nil {
				return nil, nil, err
			}
			if res.failed() {
				return nil, nil, fmt.Errorf("printer rejected the G-code: result=%s reason=%s errno=%d", res.Result, res.Reason, res.Errno)
			}
			return nil, res, nil
		})

	mcp.AddTool(server, &mcp.Tool{Name: "print_history", Description: "Recent print jobs of the account (user-service/my/tasks): model, printer, status, timings, cost.", Annotations: readOnly},
		func(ctx context.Context, req *mcp.CallToolRequest, in historyArgs) (*mcp.CallToolResult, any, error) {
			sess, err := s.mcpSession(ctx, req)
			if err != nil {
				return nil, nil, err
			}
			limit := in.Limit
			if limit <= 0 {
				limit = 20
			}
			var raw []byte
			err = sess.cloud.Do(ctx, cloud.Request{Method: http.MethodGet, Path: "user-service/my/tasks", Query: url.Values{"limit": {fmt.Sprint(limit)}}}, &raw)
			return nil, json.RawMessage(raw), err
		})

	mcp.AddTool(server, &mcp.Tool{Name: "cloud_request", Description: "Call any Bambu cloud endpoint as the account, with the app's headers (see GET /v1/catalog/endpoints for the 396 known paths). Prefer the specific tools; non-GET methods change account state.", Annotations: &mcp.ToolAnnotations{OpenWorldHint: boolPtr(true)}},
		func(ctx context.Context, req *mcp.CallToolRequest, in cloudArgs) (*mcp.CallToolResult, any, error) {
			method := strings.ToUpper(strings.TrimSpace(in.Method))
			if method == "" {
				method = http.MethodGet
			}
			path := strings.TrimPrefix(strings.TrimSpace(in.Path), "/")
			if path == "" {
				return nil, nil, errors.New("path is required")
			}
			sess, err := s.mcpSession(ctx, req)
			if err != nil {
				return nil, nil, err
			}
			q := url.Values{}
			for k, v := range in.Query {
				q.Set(k, v)
			}
			signed := false
			for _, ep := range cloud.Endpoints {
				if ep.Method == method && pathMatches(ep.Path, path) {
					signed = ep.Signed
					break
				}
			}
			var raw []byte
			err = sess.cloud.Do(ctx, cloud.Request{Method: method, Path: path, Query: q, Body: in.Body, Signed: signed}, &raw)
			if err != nil {
				return nil, nil, err
			}
			if len(raw) == 0 || !json.Valid(raw) {
				return nil, map[string]any{"ok": true, "body": string(raw)}, nil
			}
			return nil, json.RawMessage(raw), nil
		})
}
