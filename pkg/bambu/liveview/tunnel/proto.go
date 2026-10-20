// Package tunnel runs cmd/bambu-tunnel (the libBambuSource.so wrapper) as a
// child process and decodes its frame stream. The wire protocol between the
// two lives here so both sides derive from one definition:
//
//	stdin:  one line, the bambu:/// URL
//	stdout: one JSON Header line, then frames of
//	        [u32 BE payload size][u8 track][u8 flags][u64 BE decode time][payload]
//	stderr: library log lines
package tunnel

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Stream describes one track of the tunnel.
type Stream struct {
	Type       string `json:"type"`  // "video" or "audio"
	Codec      string `json:"codec"` // "h264", "jpeg" or "unknown"
	Width      int    `json:"width,omitempty"`
	Height     int    `json:"height,omitempty"`
	FrameRate  int    `json:"frameRate,omitempty"`
	FormatType int    `json:"formatType"`
	// Format is base64 codec-private data (e.g. avcC) when the plugin
	// provides one; empty for Annex B H.264 and JPEG.
	Format string `json:"format,omitempty"`
}

// Header is the first stdout line.
type Header struct {
	Streams []Stream `json:"streams"`
}

// Video returns the first video stream.
func (h Header) Video() (Stream, bool) {
	for _, s := range h.Streams {
		if s.Type == "video" {
			return s, true
		}
	}
	return Stream{}, false
}

// FlagSync marks a sync sample (JPEG frame or H.264 IDR).
const FlagSync = 1

// Frame is one encoded sample.
type Frame struct {
	Track int
	Flags int
	// DecodeTime is in 100 ns ticks, as the plugin reports it.
	DecodeTime uint64
	Payload    []byte
}

// Sync reports whether the frame can start decoding.
func (f Frame) Sync() bool { return f.Flags&FlagSync != 0 }

// MaxFrameSize bounds one payload so a corrupt stream cannot allocate
// unbounded memory; 1080p H.264 IDR frames are well under a megabyte.
const MaxFrameSize = 16 << 20

const frameHeaderSize = 4 + 1 + 1 + 8

// WriteHeader writes the header line.
func WriteHeader(w io.Writer, h Header) error {
	return json.NewEncoder(w).Encode(h)
}

// ReadHeader reads the header line.
func ReadHeader(r *bufio.Reader) (Header, error) {
	line, err := r.ReadBytes('\n')
	if err != nil {
		return Header{}, err
	}
	var h Header
	if err := json.Unmarshal(line, &h); err != nil {
		return Header{}, fmt.Errorf("tunnel header: %w", err)
	}
	return h, nil
}

// WriteFrame writes one frame.
func WriteFrame(w io.Writer, f Frame) error {
	var hdr [frameHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(f.Payload)))
	hdr[4] = byte(f.Track)
	hdr[5] = byte(f.Flags)
	binary.BigEndian.PutUint64(hdr[6:14], f.DecodeTime)
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(f.Payload)
	return err
}

// ReadFrame reads one frame. It returns io.EOF at a clean end of stream.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [frameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return Frame{}, io.EOF
		}
		return Frame{}, err
	}
	size := binary.BigEndian.Uint32(hdr[0:4])
	if size > MaxFrameSize {
		return Frame{}, fmt.Errorf("tunnel frame of %d bytes exceeds limit", size)
	}
	f := Frame{Track: int(hdr[4]), Flags: int(hdr[5]), DecodeTime: binary.BigEndian.Uint64(hdr[6:14]), Payload: make([]byte, size)}
	if _, err := io.ReadFull(r, f.Payload); err != nil {
		return Frame{}, fmt.Errorf("tunnel frame truncated: %w", err)
	}
	return f, nil
}
