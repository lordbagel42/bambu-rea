# bambu-rea

Bambu Handy 4.2.2 (Android) reverse-engineered into a Go library, an HTTP/JSON
API and a CLI that expose everything the app can do: cloud login, the whole cloud
REST surface (396 endpoints), and printer control over MQTT (90 commands, live
state, event stream) in cloud or LAN mode.

Nothing here talks to Bambu's servers or to a printer until you give it credentials.
Run as a hosted service (`-db`), the server remembers each account's Bambu session
at login and hands out API keys that act as that account, over REST and MCP. The
hosted instance is at <https://bambuapi.raygen.dev> ([docs](https://bambuapi.raygen.dev/docs),
[sign in](https://bambuapi.raygen.dev/login), MCP at `/mcp`).

## Layout

| Path | What |
|---|---|
| `cmd/bambu-api` | the HTTP server |
| `cmd/bambu` | the CLI (talks to the HTTP API, in-process by default) |
| `internal/api` | routes, per-credential sessions, OpenAPI document, Scalar docs + login page, MCP server |
| `internal/store` | SQLite persistence: accounts (Bambu session per uid) and API keys |
| `pkg/bambu/cloud` | REST client: auth, regions, generated models + endpoint catalog, IoT app-cert signing |
| `pkg/bambu/mqtt` | MQTT client (cloud + LAN), generated command catalog, G-code builders, secure channel signing, device state merge |
| `pkg/bambu/secure` | RSA / canonical-JSON helpers shared by both |
| `catalog/*.json` | endpoints, models and MQTT commands extracted from the decompiled app |
| `tools/` | extraction scripts and `gen_go.py`, which regenerates the `*_gen.go` files from `catalog/` |
| `.amp/in/artifacts/` (git-excluded) | REA outputs: split APKs, jadx trees, decrypted strings, `REPORT.md` |

## CLI

```sh
go build ./cmd/bambu
bambu login                     # password (no echo) → emailed code → 2FA, like the app
bambu printers                  # cloud-bound printers; `bambu use <serial>` picks the default
bambu status                    # state, progress/ETA/layers, temps, fans, speed, lights, AMS, HMS
bambu watch                     # live tail of the printer's reports
bambu pause | resume | stop
bambu speed sport               # silent|standard|sport|ludicrous
bambu light off                 # chamber light
bambu fan part 50               # part|aux|chamber, percent
bambu temp bed 60               # M140/M104 (what the app sends on older firmware); -native for set_*_temp
bambu gcode "G28"               # or `bambu gcode -` to read stdin
bambu move -x 10 -f 3000        # relative jog; bambu home x y
bambu ams status | load 0 2 | unload
bambu print /sdcard/model.gcode.3mf     # print a file already on the printer (gcode_file)
bambu cmd GetVersion            # any catalogued command, key=value params; `bambu cmd --list`
bambu raw system get_access_code
bambu tasks -n 20               # print history
bambu cloud GET user-service/my/profile          # any catalogued endpoint; -d json|@file, -q k=v
bambu lan add 192.168.1.50 01P00A... 12345678    # LAN mode, no cloud account needed
bambu security exchange         # MQTT secure channel; bambu appcert shows the app certificate
```

`--json` on any command prints the API's JSON; `-p <serial>` overrides the default
printer. State is kept in `~/.config/bambu/config.json` (0600; `BAMBU_CONFIG`
overrides). Without `--server` the CLI runs `internal/api` in-process on a
loopback port; `bambu config server https://host` (or `BAMBU_SERVER` /
`BAMBU_API_KEY`) points it at a deployed `bambu-api` instead. `BAMBU_EMAIL` /
`BAMBU_PASSWORD` let `bambu login` run non-interactively.

## Run the server

```sh
go build ./cmd/bambu-api
./bambu-api -addr :8080                      # intl region, no persistence: bring your own Bambu token
./bambu-api -region china                    # api.lunkuocorp.cn / cn.mqtt
./bambu-api -db /data/bambu-api.sqlite -data-key $(openssl rand -hex 32) \
            -public-url https://bambuapi.example.com -cors-origins https://app.example.com
```

`-db` turns on the hosted mode below (accounts, API keys, `/login`, `/mcp`);
`-data-key` (32 bytes, hex) encrypts the stored Bambu tokens at rest. Flags also
read `BAMBU_API_ADDR`, `BAMBU_REGION`, `BAMBU_DB`, `BAMBU_DATA_KEY`, `BAMBU_PUBLIC_URL`,
`BAMBU_CORS_ORIGINS`, `BAMBU_API_KEY` (a static `X-API-Key` gate on top of per-user
auth; leave it unset on a hosted server, where `X-API-Key` carries per-account keys),
`BAMBU_HARDWARE_ID`, `BAMBU_APP_CERT`, `BAMBU_APP_KEY`, `BAMBU_LAN_CA`; `BAMBU_ENV_FILE`
names a dotenv file loaded first, for secrets a scheduler should not see. Secrets
are read from the environment after flag parsing, so `-h` never prints them.
`GET /openapi.json` describes every route, including one operation per MQTT command
and per cloud endpoint, and `GET /docs` renders it with Scalar. The `Dockerfile`
builds a static binary on a distroless image that expects `/data` as a volume.

## Auth model

Every route takes `Authorization: Bearer <credential>` (or `X-API-Key`). The
credential is one of two things:

- **A Bambu access token**, straight from the login endpoints below. The server
  is multi-tenant by token; sessions (cloud client, MQTT connection) are created
  lazily per token and dropped after `-mqtt-idle`. With `-db`, a token the server
  has not seen is first checked against the cloud (`user-service/my/profile`): the
  uid in the JWT is never trusted on its own, and a token the cloud rejects gets
  `401` before it can reach any stored account.
- **An API key** (`bk_` + 32 url-safe characters), which acts as the Bambu account
  that created it. The key is a handle on the server-side session stored at that
  account's latest login, so it never expires on its own and follows re-logins.

Both kinds work on every `/v1/...` route (including `/v1/devices/{sn}/events` and
`/v1/cloud/...`) and on `/mcp` (keys only). Only key management and logout need the
Bambu token.

### Login

`POST /v1/auth/login` returns the app's login response verbatim: `accessToken`
(plus `refreshToken`, `expiresIn`) when done, or `loginType` for a second step.
The password is RSA-OAEP-SHA256-encrypted with Bambu's published key exactly like
the app does. The state machine the Handy app, the CLI and `/login` all follow:

1. `POST /v1/auth/login {"account": email, "password": pw}`
2. If `loginType == "verifyCode"` (new device/location): `POST /v1/auth/email-code
   {"email": email, "type": "codeLogin"}`, then repeat step 1 as
   `{"account": email, "code": "<emailed code>"}`.
3. If `loginType == "tfa"`: `POST /v1/auth/tfa {"tfaKey": <from step 1>, "tfaCode": "<TOTP>"}`.
4. Anything with `accessToken` set is a success. Errors come back with the cloud's
   status and `{"error", "code", "detail"}`.

With `-db`, every successful login/TFA on this server also **stores the session**
(uid, account email, token, refresh token, expiry) under the Bambu uid, creating
the account on first login with a stable random hardware id that its MQTT client
id and `X-BBL-Device-ID` use from then on. Logging in again replaces the token;
all of the account's keys switch to it immediately. If the server cannot store
the session, the login answers `500` (the Bambu token was issued, but no key will
use it) and should be retried.

```sh
curl -X POST $API/v1/auth/login -d '{"account":"me@example.com","password":"..."}'
curl -X POST $API/v1/auth/email-code -d '{"email":"me@example.com","type":"codeLogin"}'
curl -X POST $API/v1/auth/login -d '{"account":"me@example.com","code":"123456"}'
curl -X POST $API/v1/auth/tfa   -d '{"tfaKey":"...","tfaCode":"123456"}'
curl -H 'Authorization: Bearer TOKEN' $API/v1/me
```

### API keys

Key management needs the **Bambu token** of an account that has logged in here
(a key cannot mint keys or sign the account out):

| Route | Does |
|---|---|
| `GET /v1/account` | the stored account behind the credential: `uid`, `email`, `hardwareId`, `signedIn`, `tokenExpiresAt`, `lastLoginAt`, `keys` (count), `viaKey` when called with a key |
| `GET /v1/keys` | `{"keys": [{id, name, prefix, createdAt, lastUsedAt}]}` |
| `POST /v1/keys {"name"}` | `201` with the same fields plus `key` — the secret, returned once |
| `DELETE /v1/keys/{id}` | `204`; the key stops working immediately |
| `POST /v1/auth/logout` | **clears the stored session** (every key of the account answers `401 … signed out` until the next login), then invalidates the token at the cloud. `POST /v1/cloud/user-service/user/logout` is routed here too |

Statuses: `401` unknown/revoked key or signed-out account, `403` a key tried to
manage keys or log out (also through the cloud passthrough or MCP `cloud_request`),
`501` the server runs without `-db`. Revoking a key or signing out ends the
account's open event streams within 30 s: the stream re-checks its credential,
sends `event: error` with the `401` body and closes. The browser flow at
`/login` does all of this (sign in with code/2FA, create, list, revoke, sign out);
a web app does the same calls cross-origin when its origin is in `-cors-origins`.

```sh
curl -H "Authorization: Bearer $TOKEN" -X POST $API/v1/keys -d '{"name":"laptop"}'
# {"id":"…","name":"laptop","prefix":"bk_AbCdEfGh","createdAt":"…","key":"bk_AbCdEfGh…"}
curl -H "Authorization: Bearer bk_AbCdEfGh…" $API/v1/devices
bambu config server https://bambuapi.raygen.dev && bambu config apiKey bk_AbCdEfGh…
```

## MCP

`/mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) server over
streamable HTTP (stateless; one POST per call). It authenticates with an API key
as the bearer token and every tool acts as that key's account:

| Tool | Does |
|---|---|
| `whoami` | account profile |
| `list_printers` | bound printers (serial, name, model, online, status) |
| `printer_status {serial, refresh?}` | merged live `print.*` state |
| `list_commands {module?}` | the command catalog with parameters |
| `send_command {serial, name, params}` | any catalogued command, waits for the ack (destructive) |
| `send_gcode {serial, gcode}` | raw G-code (destructive) |
| `print_history {limit?}` | `user-service/my/tasks` |
| `cloud_request {method, path, query?, body?}` | any cloud endpoint, signed when the catalog says so |

```json
{ "mcpServers": { "bambu": { "type": "http", "url": "https://bambuapi.raygen.dev/mcp",
                             "headers": { "Authorization": "Bearer bk_…" } } } }
```

## Printer control

Commands are named as in the app's catalog (`GET /v1/catalog/commands`): e.g.
`Pause`, `Resume`, `Stop`, `SetFan`, `SetNozzleTemp`, `SetBedTemp`, `PrintSpeed`,
`LedCtrl`, `AmsFilamentSetting`, `AmsChangeFilament`, `ProjectFile` (start a print),
`PushAll`, `GetAccessCode`, `GetVersion`, `UpgradeStart`, `Calibration`, ...

```sh
B='-H Authorization:Bearer\ TOKEN'
curl $B localhost:8080/v1/devices/SN/state                     # merged status (print.*), replies[module][command]
curl $B localhost:8080/v1/devices/SN/events                    # SSE stream of every report
curl $B -X POST localhost:8080/v1/devices/SN/commands/SetFan -d '{"fan_index":2,"speed":128}'
curl $B -X POST localhost:8080/v1/devices/SN/commands/Pause?wait=0 -d '{}'   # 202, don't wait for the ack
curl $B -X POST localhost:8080/v1/devices/SN/gcode -d '{"gcode":"M140 S60"}'
curl $B -X POST localhost:8080/v1/devices/SN/move  -d '{"z":-1}'                # x/y/z mm, optional feed_rate
curl $B -X POST localhost:8080/v1/devices/SN/home  -d '{}'
curl $B -X POST localhost:8080/v1/devices/SN/raw   -d '{"module":"print","command":"gcode_line","params":{"param":"G28\n"}}'
```

Parameter values are encoded the way the app encodes them (`enable_disable`,
`int01`, upper-cased enums, G-code builders with the app's `M211`/`M1002` wrapper
and feed rates); missing required parameters are rejected with 400 before anything
is published. Replies are matched by `sequence_id` with the app's 10 s timeout; a
printer `result != success` yields 422 with the full reply.

### LAN mode

Single-user servers only: the LAN registry is global and unauthenticated, so a
server started with `-db` (the hosted mode) has no `/v1/lan/...` routes. LAN
printers are registered with their access code and are reachable under the same
`/v1/devices/{sn}/...` routes:

```sh
curl $B -X POST localhost:8080/v1/lan/devices -d '{"ip":"192.168.1.50","serial":"01P00A...","accessCode":"12345678"}'
```

TLS is verified against the app's bundled `bbl_local_ca.pem` and the certificate's
CN must equal the serial; `"insecure":true` skips verification for printers with
replaced certificates. `-lan-ca` adds extra trusted roots.

### Secure channel

`pkg/bambu/mqtt.SecureChannel` implements the app's v1.0 signed envelope (RSA-SHA256
over the canonical sorted JSON, `header` appended last) and per-field RSA encryption
(`param_enc`, `url_enc`, `ttcode_enc`) with the printer certificate obtained from
`security/app_cert_install`.

The app only signs for printers whose capabilities report `security=true`; that
bit comes from a native layer this repository could not read, so the server uses
two triggers instead: `POST /v1/devices/{sn}/security/exchange` runs the exchange
explicitly, and any reply carrying errno `84033543/44/45/47/48` (the app's own
"verification failed" set) runs it automatically and retries the command signed.
`GET /v1/devices/{sn}/security` shows the state; `DELETE` forgets it.

## Cloud passthrough

Every catalogued endpoint can be called under `/v1/cloud/<path>` with the same
method, query and body as the app, and the standard app headers (`User-Agent:
Handy/4.2.2`, `X-BBL-Client-*`, ...) are added for you:

```sh
curl $B 'localhost:8080/v1/cloud/iot-service/api/user/bind'
curl $B 'localhost:8080/v1/cloud/user-service/my/tasks?limit=20'
curl $B 'localhost:8080/v1/cloud/mall-app-bff/...'        # routed to ap-store-api.bambulab.com
```

Endpoints the app signs with its IoT app certificate are signed automatically
(`x-bbl-app-certification-id`, `x-bbl-device-security-sign`, `X-BBL-Client-ID`)
using the fetched or supplied app certificate; `X-Bambu-Signed: 1` forces signing
on any other endpoint.

## Known limitations

- **IoT app certificate.** Five endpoints (`DELETE iot-service/api/user/bind`,
  `POST iot-service/api/user/ttcode`, `POST user-service/my/pincode/{pincode}`,
  `POST user-service/my/task`, `POST user-service/my/ticket/{ticket}`) and the MQTT
  secure channel use a per-app certificate fetched from
  `iot-service/api/user/applications/{appKey}/cert`. `cloud.FetchAppCert`
  reproduces the app's request (AES-256-GCM `{appKey}` path segment under a
  session key that is RSA-PKCS1v15-wrapped to the pinned `service.bambulab.com`
  certificate) and has been verified against the live service: the response
  `key` decrypts under the session key to a PEM private key whose modulus matches
  the leaf (`CN=GLOF3813734089-af70cf3b0000`, issuer `GLOF3813734089.bambulab.com`,
  valid to 2028-01-25). The fetch needs no user token and the certificate is
  shared, so the server fetches one on first use (cache 600 s like the app) or
  takes `-app-cert`/`-app-key`/`-app-crl`. The signed endpoints themselves have
  not been called against the cloud from this repository; `GET /v1/appcert`
  shows what would be used.
- `X-BBL-Client-ID` is sent on signed requests as `android:<uid>:<hardware-id>`,
  which is what `LiveviewRepository.buildTtCodeHeaders` builds; the app's
  per-call `clientIdKey:` prefix variant is not exposed.
- Live-verified against a real account (A1 mini + P1P over cloud MQTT): login,
  bind list, print history, state/`watch`, `ledctrl`, `get_version`, and the
  signed `iot-service/api/user/ttcode` endpoint (the cloud accepted the
  certificate headers and returned TUTK credentials). The secure-channel
  exchange, signed envelopes and `param_enc` were validated only against a local
  broker with a fake printer that verifies the signatures; no real printer has
  had `security/app_cert_install` sent to it from here.
- Cloud responses do not always match the app's declared types (Gson coerces,
  e.g. `nozzle_diameter` arrives as a number for a `String` field); the client
  re-shapes such scalars instead of failing, but other mismatches may still
  surface as decode errors on endpoints that have not been exercised. Cloud request shapes come from the decompiled app and its
  decrypted string table, not from live traffic.
- Camera/live-view (WebRTC/TUTK streams in the app) is not exposed.

## Deploying

The homelab instance runs on Nomad from `pulumi-homelab/nomad/bambu-api`: a
`docker build` of this repository, `docker save | docker load` onto the Nomad
client, a hardened allocation (read-only root, no capabilities, uid 1000) with
`/data` on a host volume and the data key in a read-only env file, and Traefik
routing on `bambuapi.raygen.dev` via Consul tags.

## Regenerating

```sh
python3 tools/gen_go.py   # rewrites pkg/bambu/cloud/{models_gen,endpoints_gen}.go and pkg/bambu/mqtt/commands_gen.go
go build ./... && go vet ./... && go test ./...
```
