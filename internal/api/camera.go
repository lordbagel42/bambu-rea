package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/liveview"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/liveview/tunnel"
	"github.com/lordbagel42/bambu-rea/pkg/bambu/mqtt"
)

// Camera streaming runs Bambu Studio's network plugin in a bambu-tunnel child
// process per printer and fans its frames out to every viewer. A printer
// accepts one remote session at a time, so viewers of the same printer share
// a feed; the feed closes a few seconds after the last viewer leaves.
//
// Feeds are keyed by serial, so every caller proves it can reach the printer
// through its own account (the printer's report arrives on the caller's MQTT
// session, which the broker only allows for bound printers) before it may
// look the feed up.

// cameraIdleGrace keeps a feed alive briefly after its last viewer leaves so
// a reconnecting browser does not pay the TUTK handshake again.
const cameraIdleGrace = 5 * time.Second

// cameraSubBuffer is how many frames a slow viewer may lag before it is
// dropped; dropping frames would corrupt H.264 for that viewer anyway.
const cameraSubBuffer = 64

// cameraWriteTimeout bounds one frame write to a viewer so a stalled
// connection cannot pin its handler (and the shared feed) forever.
const cameraWriteTimeout = 15 * time.Second

// cameraTicketTTL is how long a stream ticket opens the camera routes.
const cameraTicketTTL = 60 * time.Second

type cameraFeed struct {
	serial    string
	transport string
	source    string // "cloud" or "lan"

	ready  chan struct{} // closed once open finished (header or err set)
	gone   chan struct{} // closed once the tunnel process is reaped
	cancel context.CancelFunc
	err    error
	sess   *tunnel.Session
	hdr    tunnel.Header

	mu       sync.Mutex
	subs     map[chan tunnel.Frame]struct{}
	latest   []byte // most recent sync frame (JPEG only)
	latestAt time.Time
	closed   bool
	idle     *time.Timer
	startAt  time.Time
	frames   int64
}

// cameraInfo is the JSON view of a printer's camera.
type cameraInfo struct {
	Serial       string                `json:"serial"`
	Capabilities liveview.Capabilities `json:"capabilities"`
	// Transport is the relay a stream would use (or is using).
	Transport string `json:"transport,omitempty"`
	// Supported reports whether this server can open tunnels at all
	// (bambu-tunnel and libBambuSource.so installed).
	Supported bool `json:"supported"`
	// Active describes the running feed, if any.
	Active *cameraActive `json:"active,omitempty"`
}

type cameraActive struct {
	Transport string        `json:"transport"`
	Source    string        `json:"source"`
	Stream    tunnel.Stream `json:"stream"`
	Viewers   int           `json:"viewers"`
	Frames    int64         `json:"frames"`
	Since     time.Time     `json:"since"`
}

// cameraTicket is a short-lived, camera-only stand-in for a credential so
// <img> and <video> elements, which cannot set headers, can open a stream
// without putting the account's token in a URL (and in proxy access logs).
type cameraTicket struct {
	serial     string
	credential string
	expires    time.Time
}

// cameraTicketResponse is the JSON view of a freshly issued ticket.
type cameraTicketResponse struct {
	Ticket    string    `json:"ticket"`
	ExpiresAt time.Time `json:"expiresAt"`
	Stream    string    `json:"stream"`
	Snapshot  string    `json:"snapshot"`
}

// cameraCredential resolves ?ticket= to the credential it was issued for; a
// ticket is bound to one printer serial. The usual headers still win.
func (s *Server) cameraCredential(r *http.Request) {
	if credential(r) != "" {
		return
	}
	tk := r.URL.Query().Get("ticket")
	if tk == "" {
		return
	}
	now := time.Now()
	s.camMu.Lock()
	s.purgeTicketsLocked(now)
	t, ok := s.tickets[tk]
	s.camMu.Unlock()
	if ok && t.serial == r.PathValue("sn") {
		r.Header.Set("Authorization", "Bearer "+t.credential)
	}
}

// purgeTicketsLocked drops expired tickets; camMu held.
func (s *Server) purgeTicketsLocked(now time.Time) {
	for k, v := range s.tickets {
		if now.After(v.expires) {
			delete(s.tickets, k)
		}
	}
}

// issueTicket records a ticket for the caller's credential and printer.
func (s *Server) issueTicket(serial, cred string) (string, time.Time) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	tk := base64.RawURLEncoding.EncodeToString(raw)
	now := time.Now()
	exp := now.Add(cameraTicketTTL)
	s.camMu.Lock()
	s.purgeTicketsLocked(now)
	s.tickets[tk] = cameraTicket{serial: serial, credential: cred, expires: exp}
	s.camMu.Unlock()
	return tk, exp
}

// cameraStreamingAvailable reports whether the helper can be started.
func (s *Server) cameraStreamingAvailable() bool {
	helper := s.cfg.TunnelHelper
	if helper == "" {
		helper = "bambu-tunnel"
	}
	_, err := exec.LookPath(helper)
	return err == nil
}

// cameraTarget resolves everything a feed needs: the printer's MQTT client,
// the cloud client issuing credentials (nil for LAN printers) and the LAN
// registration (nil for cloud printers).
type cameraTarget struct {
	serial string
	mqtt   *mqtt.Client
	sess   *principal
	lan    *lanPrinter
	// cred is the credential the caller presented (empty for LAN printers).
	cred string
}

func (s *Server) cameraTarget(w http.ResponseWriter, r *http.Request) (*cameraTarget, bool) {
	s.cameraCredential(r)
	sn := r.PathValue("sn")
	s.mu.Lock()
	lp := s.lan[sn]
	s.mu.Unlock()
	if lp != nil {
		c, err := lp.MQTT(r.Context())
		if err != nil {
			writeCallErr(w, err)
			return nil, false
		}
		return &cameraTarget{serial: sn, mqtt: c, lan: lp}, true
	}
	cred := credential(r)
	if cred == "" {
		writeErr(w, http.StatusUnauthorized, "printer is not registered for LAN mode; send Authorization: Bearer <bambu access token or API key> (or ?ticket= from POST …/camera/ticket) for cloud camera access")
		return nil, false
	}
	sess, err := s.authenticate(r.Context(), cred)
	if err != nil {
		writeCallErr(w, err)
		return nil, false
	}
	c, err := sess.MQTT(r.Context(), s.cfg.Region)
	if err != nil {
		writeCallErr(w, err)
		return nil, false
	}
	return &cameraTarget{serial: sn, mqtt: c, sess: sess, cred: cred}, true
}

// cameraState is the printer report the caller's own session can see; it is
// the proof of access to a serial and the source of camera capabilities.
func (s *Server) cameraState(ctx context.Context, t *cameraTarget) (*mqtt.DeviceState, liveview.Capabilities, error) {
	st, err := s.printerState(ctx, t.mqtt, t.serial, false)
	if err != nil {
		return nil, liveview.Capabilities{}, err
	}
	if len(st.Print) == 0 {
		return nil, liveview.Capabilities{}, errNoReport
	}
	return st, liveview.CapabilitiesFromReport(st.Print), nil
}

func (s *Server) handleCameraInfo(w http.ResponseWriter, r *http.Request) {
	t, ok := s.cameraTarget(w, r)
	if !ok {
		return
	}
	info := cameraInfo{Serial: t.serial, Supported: s.cameraStreamingAvailable()}
	st, caps, err := s.cameraState(r.Context(), t)
	if err != nil && !errors.Is(err, errNoReport) {
		writeCallErr(w, err)
		return
	}
	if st != nil {
		info.Capabilities = caps
	}
	if t.lan != nil {
		info.Transport = "lan"
	} else if tr, ok := info.Capabilities.Preferred(); ok {
		info.Transport = string(tr)
	}
	s.camMu.Lock()
	f := s.feeds[t.serial]
	s.camMu.Unlock()
	// Only a caller who can see the printer learns about its feed.
	if f != nil && (t.lan != nil || st != nil) {
		select {
		case <-f.ready:
			if f.err == nil {
				f.mu.Lock()
				if !f.closed {
					v, _ := f.hdr.Video()
					info.Active = &cameraActive{Transport: f.transport, Source: f.source, Stream: v, Viewers: len(f.subs), Frames: f.frames, Since: f.startAt}
				}
				f.mu.Unlock()
			}
		default:
		}
	}
	writeJSON(w, 200, info)
}

// handleCameraTicket issues a stream ticket for the caller's printer.
func (s *Server) handleCameraTicket(w http.ResponseWriter, r *http.Request) {
	// Only a real credential may mint tickets; a ticket cannot renew itself.
	if credential(r) == "" && r.URL.Query().Get("ticket") != "" {
		writeErr(w, http.StatusUnauthorized, "tickets are issued to the Authorization header credential, not to another ticket")
		return
	}
	t, ok := s.cameraTarget(w, r)
	if !ok {
		return
	}
	if t.lan != nil {
		writeErr(w, http.StatusBadRequest, "LAN printers need no ticket; the camera routes are open for them")
		return
	}
	if _, _, err := s.cameraState(r.Context(), t); err != nil {
		writeCameraErr(w, err)
		return
	}
	tk, exp := s.issueTicket(t.serial, t.cred)
	base := "/v1/devices/" + t.serial + "/camera"
	writeJSON(w, 200, cameraTicketResponse{
		Ticket: tk, ExpiresAt: exp,
		Stream:   base + "/stream?ticket=" + tk,
		Snapshot: base + "/snapshot.jpg?ticket=" + tk,
	})
}

// errCameraUnsupported means the server cannot stream (helper missing).
var errCameraUnsupported = errors.New("camera streaming is not enabled on this server: bambu-tunnel and libBambuSource.so are not installed")

// errNoCamera means the printer reports no camera module.
var errNoCamera = errors.New("printer reports no camera")

// errNotMJPEG means a snapshot was asked of an H.264-only camera.
var errNotMJPEG = errors.New("snapshots need an MJPEG camera; this stream is H.264 (use /camera/stream)")

// openFeed returns the shared feed for a printer, starting one when needed.
// The returned subscriber channel receives frames until it is closed; call
// release when done.
func (s *Server) openFeed(ctx context.Context, t *cameraTarget, transport string) (*cameraFeed, chan tunnel.Frame, error) {
	if !s.cameraStreamingAvailable() {
		return nil, nil, errCameraUnsupported
	}
	// Prove access and read capabilities through the caller's own session
	// before touching the shared feed table.
	var st *mqtt.DeviceState
	var caps liveview.Capabilities
	if t.lan == nil {
		var err error
		if st, caps, err = s.cameraState(ctx, t); err != nil {
			return nil, nil, err
		}
		if !caps.Camera {
			return nil, nil, errNoCamera
		}
	}

	for {
		s.camMu.Lock()
		select {
		case <-s.done:
			// Checked under camMu so a feed cannot be registered after
			// closeFeeds took its snapshot.
			s.camMu.Unlock()
			return nil, nil, errors.New("server is shutting down")
		default:
		}
		f := s.feeds[t.serial]
		if f == nil {
			fctx, cancel := context.WithCancel(context.Background())
			f = &cameraFeed{serial: t.serial, ready: make(chan struct{}), gone: make(chan struct{}), cancel: cancel, subs: map[chan tunnel.Frame]struct{}{}}
			s.feeds[t.serial] = f
			go s.startFeed(fctx, t, st, caps, transport, f)
		}
		s.camMu.Unlock()

		select {
		case <-f.ready:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
		if f.err != nil {
			return nil, nil, f.err
		}
		f.mu.Lock()
		if f.closed {
			f.mu.Unlock()
			// The feed is being torn down and stays registered until its
			// tunnel process is gone; wait, then start a fresh one.
			select {
			case <-f.gone:
				continue
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			}
		}
		ch := make(chan tunnel.Frame, cameraSubBuffer)
		f.subs[ch] = struct{}{}
		if f.idle != nil {
			f.idle.Stop()
			f.idle = nil
		}
		f.mu.Unlock()
		return f, ch, nil
	}
}

// release drops a subscriber and schedules the feed to close when idle.
func (s *Server) release(f *cameraFeed, ch chan tunnel.Frame) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.subs[ch]; ok {
		delete(f.subs, ch)
		close(ch)
	}
	s.scheduleIdle(f)
}

// scheduleIdle arms the idle close when the feed has no viewers; f.mu held.
// The timer decides under f.mu whether it is still the current one and
// whether the feed is still empty, so a viewer arriving in between keeps the
// feed.
func (s *Server) scheduleIdle(f *cameraFeed) {
	if len(f.subs) != 0 || f.closed || f.idle != nil {
		return
	}
	var tm *time.Timer
	tm = time.AfterFunc(cameraIdleGrace, func() {
		f.mu.Lock()
		if f.idle != tm || len(f.subs) != 0 || f.closed {
			f.mu.Unlock()
			return
		}
		f.idle = nil
		s.closeFeedLocked(f)
		s.log.Printf("camera %s: closed (idle)", f.serial)
	})
	f.idle = tm
}

// startFeed fetches credentials, opens the tunnel and pumps frames. ctx is
// the feed's own lifetime; server shutdown cancels it.
func (s *Server) startFeed(ctx context.Context, t *cameraTarget, st *mqtt.DeviceState, caps liveview.Capabilities, transport string, f *cameraFeed) {
	openCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	url, err := s.tunnelURL(openCtx, t, st, caps, transport, f)
	if err == nil {
		f.sess, err = tunnel.Open(openCtx, url, tunnel.Options{Helper: s.cfg.TunnelHelper, Lib: s.cfg.TunnelLib, Log: func(line string) {
			if s.cfg.TunnelLogs {
				s.log.Printf("camera %s: %s", t.serial, line)
			}
		}})
	}
	cancel()
	if err != nil {
		f.err = err
		s.log.Printf("camera %s: open failed: %v", t.serial, err)
		s.camMu.Lock()
		if s.feeds[t.serial] == f {
			delete(s.feeds, t.serial)
		}
		s.camMu.Unlock()
		close(f.ready)
		close(f.gone)
		return
	}
	f.hdr = f.sess.Header()
	f.startAt = time.Now()
	v, _ := f.hdr.Video()
	s.log.Printf("camera %s: streaming %s %dx%d via %s (%s)", t.serial, v.Codec, v.Width, v.Height, f.transport, f.source)
	close(f.ready)
	// The opener may have gone away before subscribing; do not leak the tunnel.
	f.mu.Lock()
	s.scheduleIdle(f)
	f.mu.Unlock()
	// Shutdown ends the stream through the feed context.
	go func() {
		<-ctx.Done()
		s.closeFeed(f, ctx.Err())
	}()

	for {
		fr, err := f.sess.Read()
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.log.Printf("camera %s: stream ended: %v", t.serial, err)
			}
			s.closeFeed(f, err)
			return
		}
		f.mu.Lock()
		f.frames++
		if v.Codec == "jpeg" && fr.Sync() {
			f.latest, f.latestAt = fr.Payload, time.Now()
		}
		for ch := range f.subs {
			select {
			case ch <- fr:
			default:
				// A viewer that cannot keep up is dropped; its handler sees
				// the closed channel once its blocked write times out.
				delete(f.subs, ch)
				close(ch)
			}
		}
		s.scheduleIdle(f)
		f.mu.Unlock()
	}
}

// tunnelURL decides the relay and builds the plugin URL for a target.
func (s *Server) tunnelURL(ctx context.Context, t *cameraTarget, st *mqtt.DeviceState, caps liveview.Capabilities, transport string, f *cameraFeed) (string, error) {
	if t.lan != nil {
		f.source, f.transport = "lan", "local"
		// X1-series serials start with "00" and serve RTSPS; P1/A1 serve
		// MJPEG on port 6000.
		rtsps := transport == "rtsps" || (transport == "" && strings.HasPrefix(t.serial, "00"))
		if rtsps {
			f.transport = "rtsps"
		}
		return liveview.LANURL(t.lan.IP, t.lan.AccessCode, rtsps), nil
	}
	f.source = "cloud"
	var tr liveview.Transport
	switch transport {
	case "":
		var ok bool
		if tr, ok = caps.Preferred(); !ok {
			return "", errors.New("printer offers no remote camera relay (ipcam.liveview.remote is none)")
		}
	case string(liveview.TransportTUTK), string(liveview.TransportAgora):
		tr = liveview.Transport(transport)
	default:
		return "", fmt.Errorf("unknown transport %q (tutk, agora)", transport)
	}
	f.transport = string(tr)
	cred, err := liveview.Fetch(ctx, t.sess.cloud, t.serial, tr)
	if err != nil {
		return "", fmt.Errorf("live-view credentials: %w", err)
	}
	f.transport = string(cred.Type)
	if err := liveview.Prepare(ctx, t.mqtt, t.serial, cred); err != nil {
		return "", err
	}
	return cred.TunnelURL(liveview.Viewer{
		Serial:        t.serial,
		DeviceVersion: firmwareVersion(st),
		NetVersion:    s.cfg.PluginVersion,
		ClientID:      s.cfg.HardwareID,
		ClientVersion: s.cfg.PluginVersion,
	})
}

// firmwareVersion finds the printer's ota version in its info module report
// when one has been received; empty otherwise.
func firmwareVersion(st *mqtt.DeviceState) string {
	info := st.Modules["info"]
	mods, _ := info["module"].([]any)
	for _, m := range mods {
		mm, _ := m.(map[string]any)
		if name, _ := mm["name"].(string); name == "ota" {
			v, _ := mm["sw_ver"].(string)
			return v
		}
	}
	return ""
}

// closeFeed ends a feed and its subscribers. The feed stays in the table,
// marked closed, until its tunnel process is reaped so a reopen cannot race
// the printer's single remote session; f.gone signals that.
func (s *Server) closeFeed(f *cameraFeed, cause error) {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	s.closeFeedLocked(f)
	if cause == nil {
		s.log.Printf("camera %s: closed", f.serial)
	}
}

// closeFeedLocked is closeFeed for a caller holding f.mu with f.closed still
// false; it marks the feed closed before releasing the lock so no viewer can
// subscribe in between, then tears the tunnel down and unregisters the feed.
func (s *Server) closeFeedLocked(f *cameraFeed) {
	f.closed = true
	if f.idle != nil {
		f.idle.Stop()
		f.idle = nil
	}
	for ch := range f.subs {
		delete(f.subs, ch)
		close(ch)
	}
	f.mu.Unlock()
	f.cancel()
	if f.sess != nil {
		f.sess.Close()
	}
	s.camMu.Lock()
	if s.feeds[f.serial] == f {
		delete(s.feeds, f.serial)
	}
	s.camMu.Unlock()
	close(f.gone)
}

// closeFeeds stops every camera feed, including ones still opening (server
// shutdown), and waits for their tunnel processes.
func (s *Server) closeFeeds() {
	s.camMu.Lock()
	feeds := make([]*cameraFeed, 0, len(s.feeds))
	for _, f := range s.feeds {
		feeds = append(feeds, f)
	}
	s.camMu.Unlock()
	for _, f := range feeds {
		f.cancel()
	}
	for _, f := range feeds {
		<-f.ready
		if f.err == nil {
			s.closeFeed(f, errors.New("server shutting down"))
		}
		<-f.gone
	}
}

func writeCameraErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errCameraUnsupported), errors.Is(err, tunnel.ErrNoHelper):
		writeErr(w, http.StatusNotImplemented, err.Error())
	case errors.Is(err, errNoCamera):
		writeErr(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errNotMJPEG):
		writeErr(w, http.StatusBadRequest, err.Error())
	default:
		writeCallErr(w, err)
	}
}

// viewerWriter writes frames to one viewer with a per-write deadline.
type viewerWriter struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (v viewerWriter) write(p []byte) error {
	_ = v.rc.SetWriteDeadline(time.Now().Add(cameraWriteTimeout))
	if _, err := v.w.Write(p); err != nil {
		return err
	}
	return v.rc.Flush()
}

// handleCameraStream streams the camera: multipart/x-mixed-replace JPEG for
// MJPEG cameras (P1/A1, LAN port 6000), which <img src> renders directly, or
// a raw H.264 Annex B byte stream (video/h264) for X1/H2 relays.
func (s *Server) handleCameraStream(w http.ResponseWriter, r *http.Request) {
	t, ok := s.cameraTarget(w, r)
	if !ok {
		return
	}
	f, ch, err := s.openFeed(r.Context(), t, r.URL.Query().Get("transport"))
	if err != nil {
		writeCameraErr(w, err)
		return
	}
	defer s.release(f, ch)
	// A stream outlives the request that opened it, so on a hosted server the
	// credential is checked again periodically (as /events does): a revoked
	// key or a signed-out account loses the picture within an interval.
	var recheck <-chan time.Time
	if s.store != nil && t.sess != nil {
		tk := time.NewTicker(s.cfg.RecheckEvery)
		defer tk.Stop()
		recheck = tk.C
	}
	stillAllowed := func() bool {
		_, err := s.authenticate(r.Context(), t.cred)
		return err == nil
	}
	v, _ := f.hdr.Video()
	vw := viewerWriter{w: w, rc: http.NewResponseController(w)}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Camera-Codec", v.Codec)
	w.Header().Set("X-Camera-Transport", f.transport)
	switch v.Codec {
	case "jpeg":
		w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary="+mjpegBoundary)
		w.WriteHeader(http.StatusOK)
		// Start with the last frame so the viewer shows a picture at once.
		f.mu.Lock()
		first := f.latest
		f.mu.Unlock()
		if first != nil {
			if err := vw.write(jpegPart(first)); err != nil {
				return
			}
		}
		for {
			select {
			case fr, ok := <-ch:
				if !ok {
					_ = vw.write([]byte("\r\n--" + mjpegBoundary + "--\r\n"))
					return
				}
				if err := vw.write(jpegPart(fr.Payload)); err != nil {
					return
				}
			case <-recheck:
				if !stillAllowed() {
					return
				}
			case <-r.Context().Done():
				return
			}
		}
	default:
		w.Header().Set("Content-Type", "video/h264")
		w.WriteHeader(http.StatusOK)
		// Decoders need a sync frame first.
		synced := false
		for {
			select {
			case fr, ok := <-ch:
				if !ok {
					return
				}
				if !synced && !fr.Sync() {
					continue
				}
				synced = true
				if err := vw.write(fr.Payload); err != nil {
					return
				}
			case <-recheck:
				if !stillAllowed() {
					return
				}
			case <-r.Context().Done():
				return
			}
		}
	}
}

// mjpegBoundary separates frames in multipart/x-mixed-replace responses.
const mjpegBoundary = "bambuframe"

// jpegPart frames one JPEG as a multipart part, the way <img> expects it.
func jpegPart(jpeg []byte) []byte {
	var b strings.Builder
	b.Grow(len(jpeg) + 128)
	b.WriteString("\r\n--" + mjpegBoundary + "\r\n")
	b.WriteString("Content-Type: image/jpeg\r\nContent-Length: " + fmt.Sprint(len(jpeg)) + "\r\n\r\n")
	b.Write(jpeg)
	return []byte(b.String())
}

// snapshotTimeout bounds waiting for a fresh frame; MJPEG printers send one
// frame every two seconds or so.
const snapshotTimeout = 15 * time.Second

// cameraSnapshot returns the latest JPEG from the printer, opening the feed
// when needed.
func (s *Server) cameraSnapshot(ctx context.Context, t *cameraTarget, transport string) ([]byte, error) {
	f, ch, err := s.openFeed(ctx, t, transport)
	if err != nil {
		return nil, err
	}
	defer s.release(f, ch)
	v, _ := f.hdr.Video()
	if v.Codec != "jpeg" {
		return nil, errNotMJPEG
	}
	f.mu.Lock()
	latest, at := f.latest, f.latestAt
	f.mu.Unlock()
	if latest != nil && time.Since(at) < 5*time.Second {
		return latest, nil
	}
	timer := time.NewTimer(snapshotTimeout)
	defer timer.Stop()
	for {
		select {
		case fr, ok := <-ch:
			if !ok {
				return nil, errors.New("camera feed ended before a frame arrived")
			}
			if fr.Sync() {
				return fr.Payload, nil
			}
		case <-timer.C:
			return nil, errors.New("no frame from the camera")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *Server) handleCameraSnapshot(w http.ResponseWriter, r *http.Request) {
	t, ok := s.cameraTarget(w, r)
	if !ok {
		return
	}
	jpeg, err := s.cameraSnapshot(r.Context(), t, r.URL.Query().Get("transport"))
	if err != nil {
		writeCameraErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", fmt.Sprint(len(jpeg)))
	w.WriteHeader(http.StatusOK)
	w.Write(jpeg)
}
