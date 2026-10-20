//go:build cgo && linux

// Command bambu-tunnel opens one Bambu camera tunnel through Bambu Studio's
// closed-source network plugin (libBambuSource.so) and writes the encoded
// frames to stdout. bambu-api runs it as a child process per viewer so the
// proprietary library never shares an address space with the API.
//
// Protocol: the tunnel URL is read from the first line of stdin (never argv,
// which is world-readable). stdout carries one JSON header line describing the
// streams, then frames as [u32 BE payload size][u8 track][u8 flags][u64 BE
// decode time][payload]. Library log lines go to stderr. EOF on stdin, or a
// closed stdout, ends the stream.
package main

/*
#cgo LDFLAGS: -ldl
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void *Bambu_Tunnel;
typedef void (*Bambu_Logger)(void *context, int level, char const *msg);

typedef struct {
	int type;
	int sub_type;
	union {
		struct { int width, height, frame_rate; } video;
		struct { int sample_rate, channel_count, sample_size; } audio;
	} format;
	int format_type;
	int format_size;
	int max_frame_size;
	unsigned char const *format_buffer;
} Bambu_StreamInfo;

typedef struct {
	int itrack;
	int size;
	int flags;
	unsigned char const *buffer;
	unsigned long long decode_time;
} Bambu_Sample;

typedef struct {
	void *handle;
	int (*Create)(Bambu_Tunnel *, char const *);
	void (*SetLogger)(Bambu_Tunnel, Bambu_Logger, void *);
	int (*Open)(Bambu_Tunnel);
	int (*StartStream)(Bambu_Tunnel, int);
	int (*GetStreamCount)(Bambu_Tunnel);
	int (*GetStreamInfo)(Bambu_Tunnel, int, Bambu_StreamInfo *);
	int (*ReadSample)(Bambu_Tunnel, Bambu_Sample *);
	void (*Close)(Bambu_Tunnel);
	void (*Destroy)(Bambu_Tunnel);
	int (*Init)(void);
	void (*Deinit)(void);
	void (*FreeLogMsg)(char const *);
} bambu_lib;

// The one library table lives in C storage for the process lifetime: the
// plugin keeps its address as logger context, which cgo forbids for Go memory.
static bambu_lib g_lib;
static bambu_lib *lib_ptr(void) { return &g_lib; }

static void *must_sym(void *h, char const *name, char const **missing) {
	void *p = dlsym(h, name);
	if (!p && !*missing) *missing = name;
	return p;
}

// bambu_load resolves every entry point; it returns the first missing symbol
// name (static storage) or NULL on success.
static char const *bambu_load(bambu_lib *lib, char const *path) {
	char const *missing = NULL;
	lib->handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!lib->handle) return dlerror();
	*(void **)&lib->Create = must_sym(lib->handle, "Bambu_Create", &missing);
	*(void **)&lib->SetLogger = must_sym(lib->handle, "Bambu_SetLogger", &missing);
	*(void **)&lib->Open = must_sym(lib->handle, "Bambu_Open", &missing);
	*(void **)&lib->StartStream = must_sym(lib->handle, "Bambu_StartStream", &missing);
	*(void **)&lib->GetStreamCount = must_sym(lib->handle, "Bambu_GetStreamCount", &missing);
	*(void **)&lib->GetStreamInfo = must_sym(lib->handle, "Bambu_GetStreamInfo", &missing);
	*(void **)&lib->ReadSample = must_sym(lib->handle, "Bambu_ReadSample", &missing);
	*(void **)&lib->Close = must_sym(lib->handle, "Bambu_Close", &missing);
	*(void **)&lib->Destroy = must_sym(lib->handle, "Bambu_Destroy", &missing);
	*(void **)&lib->Init = must_sym(lib->handle, "Bambu_Init", &missing);
	*(void **)&lib->Deinit = must_sym(lib->handle, "Bambu_Deinit", &missing);
	*(void **)&lib->FreeLogMsg = must_sym(lib->handle, "Bambu_FreeLogMsg", &missing);
	return missing;
}

static void c_logger(void *ctx, int level, char const *msg) {
	bambu_lib *lib = (bambu_lib *)ctx;
	fprintf(stderr, "[lib %d] %s\n", level, msg);
	if (lib->FreeLogMsg) lib->FreeLogMsg(msg);
}

static void bambu_set_logger(bambu_lib *lib, Bambu_Tunnel t) { lib->SetLogger(t, c_logger, lib); }
static int call_init(bambu_lib *l) { return l->Init(); }
static void call_deinit(bambu_lib *l) { l->Deinit(); }
static int call_create(bambu_lib *l, Bambu_Tunnel *t, char const *url) { return l->Create(t, url); }
static int call_open(bambu_lib *l, Bambu_Tunnel t) { return l->Open(t); }
static int call_start_stream(bambu_lib *l, Bambu_Tunnel t, int video) { return l->StartStream(t, video); }
static int call_stream_count(bambu_lib *l, Bambu_Tunnel t) { return l->GetStreamCount(t); }
static int call_stream_info(bambu_lib *l, Bambu_Tunnel t, int i, Bambu_StreamInfo *info) { return l->GetStreamInfo(t, i, info); }
static int call_read_sample(bambu_lib *l, Bambu_Tunnel t, Bambu_Sample *s) { return l->ReadSample(t, s); }
static void call_close(bambu_lib *l, Bambu_Tunnel t) { l->Close(t); }
static void call_destroy(bambu_lib *l, Bambu_Tunnel t) { l->Destroy(t); }
*/
import "C"

import (
	"bufio"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/lordbagel42/bambu-rea/pkg/bambu/liveview/tunnel"
)

// Return codes of the Bambu_* functions (BambuTunnel.h).
const (
	bambuOK          = 0
	bambuStreamEnd   = 1
	bambuWouldBlock  = 2
	bambuBufferLimit = 3
)

func main() {
	libPath := flag.String("lib", envOr("BAMBU_SOURCE_LIB", "libBambuSource.so"), "path to libBambuSource.so")
	openTimeout := flag.Duration("open-timeout", 30*time.Second, "time allowed for the tunnel to connect and start streaming")
	idleTimeout := flag.Duration("idle-timeout", 30*time.Second, "exit when no frame arrives for this long")
	flag.Parse()

	if err := run(*libPath, *openTimeout, *idleTimeout); err != nil {
		fmt.Fprintln(os.Stderr, "bambu-tunnel:", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run(libPath string, openTimeout, idleTimeout time.Duration) error {
	url, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read url: %w", err)
	}
	url = strings.TrimSpace(url)
	if !strings.HasPrefix(url, "bambu:///") {
		return errors.New("expected a bambu:/// tunnel URL on stdin")
	}

	lib := C.lib_ptr()
	cpath := C.CString(libPath)
	defer C.free(unsafe.Pointer(cpath))
	if missing := C.bambu_load(lib, cpath); missing != nil {
		return fmt.Errorf("load %s: %s", libPath, C.GoString(missing))
	}
	if rc := C.call_init(lib); rc != 0 {
		return fmt.Errorf("Bambu_Init: %d", rc)
	}
	defer C.call_deinit(lib)

	var t C.Bambu_Tunnel
	curl := C.CString(url)
	rc := C.call_create(lib, &t, curl)
	C.free(unsafe.Pointer(curl))
	if rc != 0 {
		return fmt.Errorf("Bambu_Create: %d", rc)
	}
	defer C.call_destroy(lib, t)
	C.bambu_set_logger(lib, t)

	// Stop on SIGTERM/SIGINT or when the parent closes stdin.
	stop := make(chan struct{})
	var stopOnce sync.Once
	requestStop := func() { stopOnce.Do(func() { close(stop) }) }
	go func() {
		io.Copy(io.Discard, os.Stdin)
		requestStop()
	}()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; requestStop() }()

	deadline := time.Now().Add(openTimeout)
	if rc := C.call_open(lib, t); rc != bambuOK && rc != bambuWouldBlock {
		return fmt.Errorf("Bambu_Open: %d", rc)
	}
	defer C.call_close(lib, t)
	for {
		rc := C.call_start_stream(lib, t, 1)
		if rc == bambuOK {
			break
		}
		if rc != bambuWouldBlock {
			return fmt.Errorf("Bambu_StartStream: %d", rc)
		}
		if time.Now().After(deadline) {
			return errors.New("timed out waiting for the printer to start streaming")
		}
		select {
		case <-stop:
			return nil
		case <-time.After(100 * time.Millisecond):
		}
	}

	out := bufio.NewWriterSize(os.Stdout, 1<<20)
	defer out.Flush()
	hdr := tunnel.Header{}
	n := int(C.call_stream_count(lib, t))
	for i := 0; i < n; i++ {
		var info C.Bambu_StreamInfo
		if rc := C.call_stream_info(lib, t, C.int(i), &info); rc != 0 {
			return fmt.Errorf("Bambu_GetStreamInfo(%d): %d", i, rc)
		}
		hdr.Streams = append(hdr.Streams, streamFromInfo(&info))
	}
	if err := tunnel.WriteHeader(out, hdr); err != nil {
		return err
	}
	if err := out.Flush(); err != nil {
		return err
	}

	lastFrame := time.Now()
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		var s C.Bambu_Sample
		rc := C.call_read_sample(lib, t, &s)
		switch rc {
		case bambuOK:
			f := tunnel.Frame{Track: int(s.itrack), Flags: int(s.flags), DecodeTime: uint64(s.decode_time), Payload: unsafe.Slice((*byte)(unsafe.Pointer(s.buffer)), int(s.size))}
			if err := tunnel.WriteFrame(out, f); err != nil {
				return nil // parent went away
			}
			if err := out.Flush(); err != nil {
				return nil
			}
			lastFrame = time.Now()
		case bambuWouldBlock, bambuBufferLimit:
			if time.Since(lastFrame) > idleTimeout {
				return errors.New("no frames received from the printer")
			}
			time.Sleep(10 * time.Millisecond)
		case bambuStreamEnd:
			return nil
		default:
			return fmt.Errorf("Bambu_ReadSample: %d", rc)
		}
	}
}

func streamFromInfo(info *C.Bambu_StreamInfo) tunnel.Stream {
	st := tunnel.Stream{FormatType: int(info.format_type)}
	switch info._type {
	case 0:
		st.Type = "video"
		v := (*[3]C.int)(unsafe.Pointer(&info.format))
		st.Width, st.Height, st.FrameRate = int(v[0]), int(v[1]), int(v[2])
		switch info.sub_type {
		case 0:
			st.Codec = "h264"
		case 1:
			st.Codec = "jpeg"
		default:
			st.Codec = "unknown"
		}
	case 1:
		st.Type = "audio"
		st.Codec = "unknown"
	default:
		st.Type = "unknown"
		st.Codec = "unknown"
	}
	if info.format_size > 0 && info.format_buffer != nil {
		raw := unsafe.Slice((*byte)(unsafe.Pointer(info.format_buffer)), int(info.format_size))
		st.Format = base64.StdEncoding.EncodeToString(raw)
	}
	return st
}
