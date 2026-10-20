package api

import (
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/cloud"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/mqtt"
)

var (
	openAPIOnce sync.Once
	openAPIDoc  map[string]any
)

func (s *Server) handleOpenAPI(w http.ResponseWriter, _ *http.Request) {
	openAPIOnce.Do(func() { openAPIDoc = buildOpenAPI(s.cfg.Region, s.cfg.PublicURL, s.store != nil) })
	writeJSON(w, 200, openAPIDoc)
}

func obj(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		m[kv[i].(string)] = kv[i+1]
	}
	return m
}

func paramSchema(t string) map[string]any {
	switch t {
	case "int", "long":
		return obj("type", "integer")
	case "double":
		return obj("type", "number")
	case "bool":
		return obj("type", "boolean")
	case "string":
		return obj("type", "string")
	case "string[]":
		return obj("type", "array", "items", obj("type", "string"))
	case "int[]":
		return obj("type", "array", "items", obj("type", "integer"))
	case "object[]":
		return obj("type", "array", "items", obj("type", "object"))
	case "object":
		return obj("type", "object")
	}
	return map[string]any{}
}

func javaSchema(jt string) map[string]any {
	switch strings.TrimSpace(jt) {
	case "int", "Integer", "long", "Long", "short":
		return obj("type", "integer")
	case "double", "Double", "float", "Float":
		return obj("type", "number")
	case "boolean", "Boolean":
		return obj("type", "boolean")
	case "String":
		return obj("type", "string")
	}
	return obj("type", "string")
}

// buildOpenAPI renders an OpenAPI 3.0 description of the server, including one
// operation per cloud endpoint and per printer command, from the catalogs.
func buildOpenAPI(region cloud.Region, publicURL string, hosted bool) map[string]any {
	paths := map[string]any{}
	bearerSec := []any{obj("bearer", []any{}), obj("apiKeyHeader", []any{})}
	loginSec := []any{obj("bearer", []any{})}
	jsonResp := func(desc string) map[string]any {
		return obj("200", obj("description", desc, "content", obj("application/json", obj("schema", obj("type", "object")))))
	}
	jsonBody := func(schema map[string]any) map[string]any {
		return obj("required", true, "content", obj("application/json", obj("schema", schema)))
	}
	snParam := obj("name", "sn", "in", "path", "required", true, "schema", obj("type", "string"), "description", "printer serial number")
	waitParam := obj("name", "wait", "in", "query", "schema", obj("type", "string", "enum", []any{"0", "1"}), "description", "wait=0 publishes without waiting for the printer's reply")

	paths["/v1/healthz"] = obj("get", obj("tags", []any{"meta"}, "summary", "Liveness check", "responses", jsonResp("ok")))
	paths["/v1/catalog/endpoints"] = obj("get", obj("tags", []any{"meta"}, "summary", "List all cloud endpoints the Handy app can call", "responses", jsonResp("endpoint catalog")))
	paths["/v1/catalog/commands"] = obj("get", obj("tags", []any{"meta"}, "summary", "List all printer MQTT commands", "responses", jsonResp("command catalog")))
	paths["/v1/catalog/region"] = obj("get", obj("tags", []any{"meta"}, "summary", "Active cloud region and hosts", "responses", jsonResp("region")))

	paths["/v1/auth/pubkey"] = obj("get", obj("tags", []any{"auth"}, "summary", "Fetch the password-encryption public key", "responses", jsonResp("pubkey")))
	paths["/v1/auth/login"] = obj("post", obj("tags", []any{"auth"}, "summary", "Log in with account + password (RSA-OAEP encrypted like the app) or email code",
		"requestBody", jsonBody(obj("type", "object", "required", []any{"account"}, "properties", obj(
			"account", obj("type", "string"), "password", obj("type", "string"), "code", obj("type", "string"),
			"tfaKey", obj("type", "string"), "tfaCode", obj("type", "string"), "token", obj("type", "string")))),
		"responses", jsonResp("LoginResult with accessToken, or tfaKey when 2FA is required")))
	paths["/v1/auth/tfa"] = obj("post", obj("tags", []any{"auth"}, "summary", "Complete a two-factor login",
		"requestBody", jsonBody(obj("type", "object", "required", []any{"tfaKey", "tfaCode"}, "properties", obj("tfaKey", obj("type", "string"), "tfaCode", obj("type", "string")))),
		"responses", jsonResp("LoginResult")))
	paths["/v1/auth/email-code"] = obj("post", obj("tags", []any{"auth"}, "summary", "Send a login verification code to an email address",
		"requestBody", jsonBody(obj("type", "object", "required", []any{"email"}, "properties", obj("email", obj("type", "string"), "type", obj("type", "string", "default", "codeLogin")))),
		"responses", jsonResp("ok")))
	paths["/v1/auth/logout"] = obj("post", obj("tags", []any{"auth"}, "security", loginSec, "summary", "Invalidate the Bambu token and sign the stored account out",
		"description", "Also forgets the session stored for the account, so its API keys stop working until the next login. API keys may not call this.", "responses", jsonResp("ok")))
	paths["/v1/me"] = obj("get", obj("tags", []any{"auth"}, "security", bearerSec, "summary", "Current user profile", "responses", jsonResp("User")))

	if hosted {
		keySchema := obj("type", "object", "properties", obj("id", obj("type", "string"), "name", obj("type", "string"), "prefix", obj("type", "string", "description", "first characters of the key, for display"),
			"createdAt", obj("type", "string", "format", "date-time"), "lastUsedAt", obj("type", "string", "format", "date-time")))
		paths["/v1/account"] = obj("get", obj("tags", []any{"account"}, "security", bearerSec, "summary", "The stored account behind the credential",
			"description", "Accounts are created by a successful /v1/auth/login or /v1/auth/tfa on this server. With an API key, viaKey names the key used.",
			"responses", obj("200", obj("description", "account", "content", obj("application/json", obj("schema", obj("type", "object", "properties", obj(
				"uid", obj("type", "string"), "email", obj("type", "string"), "hardwareId", obj("type", "string"), "signedIn", obj("type", "boolean"),
				"tokenExpiresAt", obj("type", "string", "format", "date-time"), "lastLoginAt", obj("type", "string", "format", "date-time"), "keys", obj("type", "integer"), "viaKey", keySchema))))))))
		paths["/v1/keys"] = obj(
			"get", obj("tags", []any{"account"}, "security", loginSec, "summary", "List the account's API keys (Bambu token required, not a key)",
				"responses", obj("200", obj("description", "keys", "content", obj("application/json", obj("schema", obj("type", "object", "properties", obj("keys", obj("type", "array", "items", keySchema)))))))),
			"post", obj("tags", []any{"account"}, "security", loginSec, "summary", "Create an API key that acts as this account (Bambu token required, not a key)",
				"description", "The secret is returned once. Send it as Authorization: Bearer or X-API-Key on every route, including /mcp. Keys follow the account's latest login and stop working after /v1/auth/logout.",
				"requestBody", obj("content", obj("application/json", obj("schema", obj("type", "object", "properties", obj("name", obj("type", "string", "maxLength", 100)))))),
				"responses", obj("201", obj("description", "created", "content", obj("application/json", obj("schema", obj("allOf", []any{keySchema, obj("type", "object", "required", []any{"key"}, "properties", obj("key", obj("type", "string", "description", "the secret, shown once")))})))))))
		paths["/v1/keys/{id}"] = obj("delete", obj("tags", []any{"account"}, "security", loginSec, "summary", "Revoke an API key",
			"parameters", []any{obj("name", "id", "in", "path", "required", true, "schema", obj("type", "string"))}, "responses", obj("204", obj("description", "revoked"))))
		paths["/mcp"] = obj("post", obj("tags", []any{"mcp"}, "security", []any{obj("apiKey", []any{})}, "summary", "Model Context Protocol endpoint (streamable HTTP)",
			"description", "Connect an MCP client here with an API key as the bearer token. Tools: whoami, list_printers, printer_status, list_commands, send_command, send_gcode, print_history, cloud_request.",
			"requestBody", obj("content", obj("application/json", obj("schema", obj("type", "object", "description", "JSON-RPC 2.0 message")))),
			"responses", obj("200", obj("description", "JSON-RPC response (application/json or text/event-stream)"))))
	}

	paths["/v1/devices"] = obj("get", obj("tags", []any{"printer"}, "security", bearerSec, "summary", "Printers bound to the account", "responses", jsonResp("DeviceModel")))
	paths["/v1/devices/{sn}/state"] = obj("get", obj("tags", []any{"printer"}, "security", bearerSec, "summary", "Merged live state from the printer's report stream",
		"parameters", []any{snParam, obj("name", "refresh", "in", "query", "schema", obj("type", "string", "enum", []any{"1"}), "description", "force a pushall before answering")},
		"responses", jsonResp("DeviceState")))
	paths["/v1/devices/{sn}/events"] = obj("get", obj("tags", []any{"printer"}, "security", bearerSec, "summary", "Server-sent events: every MQTT report for the printer",
		"parameters", []any{snParam}, "responses", obj("200", obj("description", "text/event-stream"))))
	paths["/v1/devices/{sn}/raw"] = obj("post", obj("tags", []any{"printer"}, "security", bearerSec, "summary", "Send an arbitrary module/command/params envelope",
		"parameters", []any{snParam, waitParam},
		"requestBody", jsonBody(obj("type", "object", "required", []any{"module"}, "properties", obj("module", obj("type", "string"), "command", obj("type", "string"), "params", obj("type", "object"), "encryptFields", obj("type", "array", "items", obj("type", "string"))))),
		"responses", jsonResp("commandResult")))
	paths["/v1/devices/{sn}/gcode"] = obj("post", obj("tags", []any{"printer"}, "security", bearerSec, "summary", "Run raw G-code (print/gcode_line)",
		"parameters", []any{snParam, waitParam}, "requestBody", jsonBody(obj("type", "object", "required", []any{"gcode"}, "properties", obj("gcode", obj("type", "string")))), "responses", jsonResp("commandResult")))
	paths["/v1/devices/{sn}/move"] = obj("post", obj("tags", []any{"printer"}, "security", bearerSec, "summary", "Relative jog, encoded exactly like the app's jog pad",
		"parameters", []any{snParam, waitParam}, "requestBody", jsonBody(obj("type", "object", "properties", obj("x", obj("type", "number"), "y", obj("type", "number"), "z", obj("type", "number"), "feed_rate", obj("type", "number")))), "responses", jsonResp("commandResult")))
	paths["/v1/devices/{sn}/home"] = obj("post", obj("tags", []any{"printer"}, "security", bearerSec, "summary", "Home axes (all when body is empty)",
		"parameters", []any{snParam, waitParam}, "requestBody", obj("content", obj("application/json", obj("schema", obj("type", "object", "properties", obj("x", obj("type", "boolean"), "y", obj("type", "boolean"), "z", obj("type", "boolean")))))), "responses", jsonResp("commandResult")))

	paths["/v1/devices/{sn}/security"] = obj(
		"get", obj("tags", []any{"security"}, "security", bearerSec, "summary", "Secure-channel status for the printer (cert id, printer cert, field encryption)",
			"parameters", []any{snParam}, "responses", jsonResp("SecureStatus")),
		"delete", obj("tags", []any{"security"}, "security", bearerSec, "summary", "Forget the secure channel; later commands go out unsigned until the next exchange",
			"parameters", []any{snParam}, "responses", obj("204", obj("description", "dropped"))))
	paths["/v1/devices/{sn}/security/exchange"] = obj("post", obj("tags", []any{"security"}, "security", bearerSec,
		"summary", "Run the app-certificate exchange (security/app_cert_list, then app_cert_install) and sign every later command",
		"description", "The app does this only for printers whose capabilities report security=true; this server also runs it automatically when a reply carries errno 84033543/44/45/47/48 and retries the command signed.",
		"parameters", []any{snParam}, "responses", jsonResp("SecureStatus")))
	paths["/v1/appcert"] = obj("get", obj("tags", []any{"security"}, "security", bearerSec,
		"summary", "The IoT app certificate in use (chain, CRL, ids, validity). The private key is never returned.",
		"responses", jsonResp("AppCertInfo")))

	if !hosted {
		// The LAN registry is global and unauthenticated: single-user servers only.
		paths["/v1/lan/devices"] = obj(
			"get", obj("tags", []any{"lan"}, "summary", "Registered LAN printers", "responses", jsonResp("list")),
			"post", obj("tags", []any{"lan"}, "summary", "Register a LAN-mode printer (ip, serial, access code) and connect to it",
				"requestBody", jsonBody(obj("type", "object", "required", []any{"ip", "serial", "accessCode"}, "properties", obj("ip", obj("type", "string"), "serial", obj("type", "string"), "accessCode", obj("type", "string"), "name", obj("type", "string")))),
				"responses", obj("201", obj("description", "registered"))))
		paths["/v1/lan/devices/{sn}"] = obj("delete", obj("tags", []any{"lan"}, "summary", "Forget a LAN printer", "parameters", []any{snParam}, "responses", obj("204", obj("description", "removed"))))
	}

	// Printer commands, one operation each.
	for i := range mqtt.Specs {
		sp := &mqtt.Specs[i]
		schema := commandBodySchema(sp)
		props := schema["properties"].(map[string]any)
		if sp.GcodeBuilder == "move_axis" {
			props = obj("x", obj("type", "number"), "y", obj("type", "number"), "z", obj("type", "number"), "feed_rate", obj("type", "number"))
			schema["properties"] = props
			delete(schema, "required")
		}
		summary := sp.Module + "/" + sp.Command
		if sp.Doc != "" {
			summary += " — " + sp.Doc
		}
		op := obj("tags", []any{"commands", "module:" + sp.Module}, "security", bearerSec, "summary", summary, "operationId", "cmd"+sp.Name,
			"description", commandDescriptions[sp.Name]+"\n\nLow-level compatibility route using the catalog's Bambu parameter names. Prefer the resource-oriented printer API for ordinary application controls.",
			"parameters", []any{snParam, waitParam}, "responses", jsonResp("commandResult"))
		if len(props) > 0 || sp.RawParams {
			op["requestBody"] = obj("content", obj("application/json", obj("schema", schema)))
		}
		paths["/v1/devices/{sn}/commands/"+sp.Name] = obj("post", op)
	}

	// Cloud passthrough, one operation per catalogued endpoint.
	for _, ep := range cloud.Endpoints {
		p := "/v1/cloud/" + ep.Path
		entry, _ := paths[p].(map[string]any)
		if entry == nil {
			entry = map[string]any{}
			paths[p] = entry
		}
		var params []any
		var bodySchema map[string]any
		for _, ps := range ep.Params {
			switch ps.Kind {
			case "path":
				params = append(params, obj("name", ps.Name, "in", "path", "required", true, "schema", javaSchema(ps.JavaType)))
			case "query":
				params = append(params, obj("name", ps.Name, "in", "query", "schema", javaSchema(ps.JavaType)))
			case "querymap":
				params = append(params, obj("name", "<any>", "in", "query", "description", "free-form query map", "schema", obj("type", "string")))
			case "header":
				if strings.EqualFold(ps.Name, "Authorization") {
					continue
				}
				params = append(params, obj("name", ps.Name, "in", "header", "schema", obj("type", "string")))
			case "body":
				bodySchema = obj("type", "object", "description", "Java type "+ps.JavaType)
			}
		}
		op := obj("tags", []any{"cloud", "service:" + ep.Service}, "security", bearerSec, "operationId", ep.Name,
			"summary", ep.Method+" "+ep.Path+" → "+ep.Response, "description", cloudEndpointDescription(ep), "responses", jsonResp(ep.Response))
		if ep.Signed {
			op["description"] = op["description"].(string) + " The wrapper adds x-bbl-app-certification-id / x-bbl-device-security-sign automatically; supply -app-cert/-app-key or let the server fetch its app certificate."
		}
		if isLogoutPath(ep.Method, ep.Path) {
			op["description"] = "Compatibility alias for POST /v1/auth/logout: signs the stored account out and invalidates its Bambu token. API keys cannot call this route; use a Bambu login token. This is not a raw passthrough around the wrapper's logout rules."
		}
		if len(params) > 0 {
			op["parameters"] = params
		}
		if bodySchema != nil {
			op["requestBody"] = obj("content", obj("application/json", obj("schema", bodySchema)))
		}
		entry[strings.ToLower(ep.Method)] = op
	}

	for path, entry := range paths {
		for method, operation := range entry.(map[string]any) {
			if description := routeDescriptions[strings.ToUpper(method)+" "+path]; description != "" {
				operation.(map[string]any)["description"] = description
			}
		}
	}
	addPrinterOpenAPI(paths, bearerSec, snParam, waitParam)
	tags := []any{"printers"}
	printerTags := []any{"printers"}
	groups := map[string]bool{}
	for _, op := range printerOperations {
		group := "printers/" + strings.Split(strings.TrimPrefix(op.Path, "/"), "/")[0]
		if !groups[group] {
			tags = append(tags, group)
			printerTags = append(printerTags, group)
			groups[group] = true
		}
	}
	tags = append(tags, "meta", "auth", "account", "mcp", "printer", "security", "lan", "commands", "cloud")
	advancedTags := []any{"printer", "commands", "cloud", "security", "meta"}
	if hosted {
		tags = slices.DeleteFunc(tags, func(t any) bool { return t == "lan" })
	} else {
		advancedTags = append(advancedTags, "lan")
	}
	mods := mqtt.Modules()
	sort.Strings(mods)
	for _, m := range mods {
		tags = append(tags, "module:"+m)
	}
	displayNames := map[string]string{
		"printers": "Overview", "auth": "Sign in", "account": "Account & API keys", "mcp": "MCP",
		"printer": "Legacy printer API", "commands": "MQTT commands", "cloud": "Cloud passthrough",
		"security": "Low-level security", "meta": "Catalogs & health", "lan": "LAN registry",
	}
	tagObjs := make([]any, 0, len(tags))
	for _, t := range tags {
		name := t.(string)
		label := displayNames[name]
		if strings.HasPrefix(name, "printers/") {
			label = strings.ReplaceAll(strings.TrimPrefix(name, "printers/"), "-", " ")
		}
		tag := obj("name", name)
		if label != "" {
			tag["x-displayName"] = label
		}
		tagObjs = append(tagObjs, tag)
	}
	via := "cloud broker " + region.MQTTHost + " or LAN"
	if hosted {
		via = "cloud broker " + region.MQTTHost
	}
	desc := "Start with `GET /v1/printers`, then control a printer through its resources: `PUT /v1/printers/{sn}/lights/chamber` with `{\"on\":true}`, " +
		"`PUT /v1/printers/{sn}/fans/part` with `{\"percent\":50}`, or `POST /v1/printers/{sn}/job/pause`. " +
		"`GET /v1/printers/{sn}/operations` lists every named operation and its request schema. Existing `/v1/devices` and `/v1/cloud` routes remain available for low-level access.\n\n" +
		"Everything Bambu Handy " + cloud.AppVersionName + " can do, as HTTP. Printers are controlled over MQTT (" + via + ").\n\n" +
		"**Authentication.** Every route takes `Authorization: Bearer <credential>`, where the credential is either the Bambu access token returned by `/v1/auth/login` (or `/v1/auth/tfa`) " +
		"or an API key (`bk_…`) minted at [/login](/login) or `POST /v1/keys`. An API key acts as the Bambu account that created it, using the session stored at that account's latest login here. " +
		"Key management and logout need the Bambu token.\n\n**MCP.** `/mcp` speaks the Model Context Protocol over streamable HTTP with the same API keys."
	servers := []any{obj("url", "/")}
	if publicURL != "" {
		servers = []any{obj("url", publicURL)}
	}
	return obj(
		"openapi", "3.0.3",
		"info", obj("title", "bambu-api", "version", cloud.AppVersionName, "description", desc),
		"servers", servers,
		"tags", tagObjs,
		// Module/service tags remain in the document for other consumers, but
		// Scalar shows each low-level operation once under commands or cloud.
		"x-tagGroups", []any{
			obj("name", "Printer API", "tags", printerTags),
			obj("name", "Account", "tags", []any{"auth", "account", "mcp"}),
			obj("name", "Advanced", "tags", advancedTags),
		},
		"components", obj("securitySchemes", obj(
			"bearer", obj("type", "http", "scheme", "bearer", "description", "Bambu cloud access token from /v1/auth/login, or an API key (bk_…)"),
			"apiKeyHeader", obj("type", "apiKey", "in", "header", "name", "X-API-Key", "description", "API key (bk_…) as an alternative to the Authorization header"),
			"apiKey", obj("type", "http", "scheme", "bearer", "description", "API key (bk_…) from /login"))),
		"paths", paths,
	)
}
