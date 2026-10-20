# Camera live view

How `bambu-api` streams a printer's camera, what was recovered from where,
and what is still unverified.

## Why the closed plugin

Remote live view never touches Bambu's cloud: the printer and the viewer meet
on one of two third-party relays and the cloud only hands out credentials.

| Relay | Printers | Codec | Client library |
|---|---|---|---|
| TUTK (ThroughTek Kalay IOTC/AV) | P1P, P1S, A1, A1 mini, X1 before Agora firmware | MJPEG, ~0.5 fps | `libIOTCAPIs`/`libAVAPIs`, statically linked into Bambu's plugin |
| Agora RTC | X1C/X1E with recent firmware, H2D/H2S | H.264 (Annex B) | `libagora_rtc_sdk.so` (closed) |

The Handy APK carries both as native libraries wrapped by Virbox, and the
protocols underneath are proprietary: IOTC does UDP hole punching through
ThroughTek's master servers with an obfuscated handshake, and Agora RTC is a
closed SFU protocol. Reimplementing either from the decompiled app was judged
infeasible for this project, so `bambu-api` drives the one public binary that
speaks both: Bambu Studio's network plugin, `libBambuSource.so`.

The plugin is downloaded at image build time from Bambu's CDN
(`public-cdn.bblmw.com/upgrade/studio/plugins/02.08.04.60/fd41e5cc78/linux_02.08.04.60.zip`,
sha256 `f73d12ec8a179160b78bc58e28dcb71f04bbee3669f3ef45375164ae7d3b8c59`) and
never committed; `liveview.PluginVersion` records the release the code was
verified against.

## Process layout

```diagram
┌─────────────┐  HTTP   ┌───────────────┐ stdin: bambu:/// URL  ┌──────────────────┐
│ viewer      │────────▶│ bambu-api     │──────────────────────▶│ bambu-tunnel     │
│ <img>/<video>│◀────────│ internal/api/ │◀──────────────────────│ dlopen(          │
└─────────────┘ mjpeg/  │ camera.go     │ stdout: header + frames│  libBambuSource) │
                h264    └───────────────┘                        └────────┬─────────┘
                                                                    TUTK / Agora
                                                                          ▼
                                                                      printer
```

`cmd/bambu-tunnel` is a small cgo program that `dlopen`s the plugin and calls
its exported C API in the order Bambu Studio does: `Bambu_Create(url)` →
`Bambu_Open` → `Bambu_StartStream` → `Bambu_GetStreamInfo` →
`Bambu_ReadSample` in a loop → `Bambu_Close`/`Bambu_Destroy`. It writes one
JSON header line describing the tracks, then length-prefixed samples
(`pkg/bambu/liveview/tunnel/proto.go`). Keeping the plugin out of the API
process means a crash in the closed code only kills one printer's feed.

`internal/api/camera.go` keeps one feed per printer serial, fans frames out
to every subscriber, caches the last JPEG for `/snapshot.jpg`, and closes the
tunnel 5 s after the last viewer leaves. A closing feed stays registered until
its helper process is reaped, so a reconnecting viewer never races the
printer's single remote session; server shutdown cancels feeds that are still
opening and waits for every helper.

Access control: feeds are keyed by serial, so before a caller may look one up
it must obtain the printer's report through its own MQTT session (the broker
only delivers reports for printers bound to the account). Browser `<img>`
tags use a 60 s ticket from `POST /camera/ticket`, bound to one serial and the
issuing credential, instead of putting the account token in the URL; open
streams re-authenticate every `RecheckEvery` (30 s) like `/events`, and each
frame write has a 15 s deadline so a stalled viewer cannot pin the feed.

## Credentials and preparation

1. `POST iot-service/api/user/ttcode` with `{"dev_id": sn, "protocols": [...]}`
   (an IoT-signed endpoint, so the server must hold an app certificate). The
   reply's `type` says which relay the printer chose:
   * TUTK: `ttcode` (the IOTC UID), `passwd`, `authkey`, `region`.
   * Agora: `app_id`, `channel_name`, `streams[].{uid,token}` (the viewer's RTC
     identity; the app joins with `streams[0]`), `peers[]` (the printer's
     uids), `stream_key`, `stream_salt` (base64), `rtm`.
2. TUTK only: send `liveview/prepare` over MQTT with the same triple. The
   printer starts its TUTK server and reports `ipcam.tutk_server: "enable"`;
   `liveview.Prepare` waits for that (up to 8 s, Handy waits 5). A reply with
   `err_code 84033543` is normal here and does not mean failure.
3. Build the tunnel URL and hand it to the plugin.

Capabilities come from the printer's last report
(`liveview.CapabilitiesFromReport`): `ipcam.ipcam_dev == "0"` means no
camera; `ipcam.liveview.remote` is `none|tutk|agora|tutk_agora` on firmware
that reports it; older firmware is assumed TUTK, with `home_flag` bit 30
marking Agora support (Bambu Studio's `is_support_agora`).

## Tunnel URL grammar

`BambuTunnel::create` (plugin, Ghidra at 0x242e40 with image base 0x100000)
matches the URL against `logo/`, `debug/`, `camera/`, `rtsp___`, `rtsps___`,
`local/`, `tutk`, `agora`, then `set_path_query` splits `?k=v&…` with
`url_decode`.

### TUTK (verified on the A1 mini)

```
bambu:///tutk?uid=<ttcode>&authkey=<authkey>&passwd=<passwd>&region=<region>
             &device=<sn>&dev_ver=<ota version>&net_ver=<plugin version>
             [&cli_id=…&cli_ver=…]
```

Observed: 1680×1080 MJPEG (`format_type` 2), frames start `ff d8 ff e0`, the
first two frames share a decode time, prepare ≈2.8 s and open ≈1.9 s. The
plugin connects in LAN mode when the printer is on the same network.

### Agora (recovered, not exercised)

Query keys and defaults read straight from the decompiled plugin
(`.amp` scratch output of Ghidra 12.1.4 headless on `libBambuSource.so`):

| Function | `BambuTunnel::query(key, default)` | Used as |
|---|---|---|
| `StaticAgoraLib::initAgora` @ 0x24f8f0 | `app`, `region` (`""`) | `RtcEngineContext.appId`; region → Agora area code: `all`→GLOBAL (0xffffffff), `cn`→1, `na`→2, `eu`→4, `asia`→8, `us`→0x800 |
| `StaticAgoraLib::joinChannel` @ 0x250000 | `channel` (`""`), `user` (`"0"`, `stoul`), `token`, `streamKey` (`""`), `streamSalt` (`""`, base64 → `EVP_DecodeBlock`) | `joinChannelEx(token, channel, uid)`; `enableEncryptionEx` is always called with mode 8 (`AES_256_GCM2`), key and 32-byte salt |
| `StaticAgoraLib::refreshToken` @ 0x250bf0 | `auxiliary_enable` (`"0"`), `refresh_url`, `channel`, `dev_ver`, `device` | token refresh; see below |

So `liveview.Credentials.TunnelURL` emits

```
bambu:///agora?app=<app_id>&channel=<channel_name>&user=<streams[0].uid>
              &token=<streams[0].token>&streamKey=<stream_key>&streamSalt=<stream_salt>
              &region=<region>&device=<sn>&dev_ver=…&net_ver=…
```

which matches Handy's own join (`LiveviewRepositoryKt.parseAgoraCredentials`
joins `channel_name` with `streams[0].uid/token`, encryption `AES_256_GCM2`
with `stream_key`/`stream_salt`). The mapping is consistent on both ends but
no Agora-capable printer was available, so this path is untested.

**Token refresh is not wired.** When `auxiliary_enable` is `0` the plugin
treats `refresh_url` as a hexadecimal function pointer supplied by Bambu
Studio's host process (`strtoll(…, 16)` → call), and returns without doing
anything when it is absent; `auxiliary_enable=1` uses the plugin's built-in
HTTP refresher aimed at Bambu Suite's endpoints. `bambu-api` passes neither,
so an Agora feed ends when its token expires and the next viewer opens a new
one. Handy's own ttcode tokens last long enough for a viewing session.

## LAN mode

Registered LAN printers skip the cloud entirely:

* P1/A1: `bambu:///local/<ip>.?port=6000&user=bblp&passwd=<access code>`
  (the plugin's own MJPEG-over-TLS client, same as Studio's LAN live view).
* X1-series (serial starts `00`): `bambu:///rtsps___bblp:<access code>@<ip>/streaming/live/1?proto=rtsps`,
  decoded by the bundled live555.

## Runtime requirements

`libagora_rtc_sdk.so` links X11, libdrm, zlib and friends even when no window
is ever created, so the runtime image is `debian:bookworm-slim` plus those
libraries rather than distroless. The helper needs `BAMBU_SOURCE_LIB` (or
`-tunnel-lib`) pointing at `libBambuSource.so` and the plugin's sibling
libraries on `LD_LIBRARY_PATH`/rpath; the Dockerfile installs the bundle at
`/opt/bambu-plugin`.

## Known limitations

* Only TUTK has been exercised (A1 mini). Agora is implemented from the
  decompiled grammar above; expect to debug it on first contact with an X1/H2.
* `/camera/snapshot.jpg` needs an MJPEG camera; H.264 cameras answer 400
  (decoding H.264 to JPEG would need ffmpeg or similar in the image).
* No Agora token refresh (above).
* The plugin is closed source and pinned to one version; a new Studio release
  may change the exported API or URL grammar.
