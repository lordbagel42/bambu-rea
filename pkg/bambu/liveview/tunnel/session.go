package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Options configure one tunnel process.
type Options struct {
	// Helper is the bambu-tunnel executable; empty looks it up on PATH.
	Helper string
	// Lib is the libBambuSource.so path handed to the helper (BAMBU_SOURCE_LIB);
	// empty leaves the helper's own default.
	Lib string
	// OpenTimeout bounds connecting and the first frame; zero means 30 s.
	OpenTimeout time.Duration
	// Log receives the helper's stderr lines; nil discards them.
	Log func(line string)
}

// Session is one running tunnel.
type Session struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	outR   *os.File
	out    *bufio.Reader
	header Header

	closeOnce sync.Once
	done      chan struct{}
	waitErr   error
}

// ErrNoHelper is returned when the bambu-tunnel executable cannot be found.
var ErrNoHelper = errors.New("bambu-tunnel helper is not installed")

// Open starts the helper for url and waits for its stream header. The
// returned session must be closed; ctx only bounds the open phase.
func Open(ctx context.Context, url string, o Options) (*Session, error) {
	helper := o.Helper
	if helper == "" {
		helper = "bambu-tunnel"
	}
	path, err := exec.LookPath(helper)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoHelper, err)
	}
	timeout := o.OpenTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	cmd := exec.Command(path, "-open-timeout", timeout.String())
	cmd.Env = helperEnv(o.Lib)
	// The plugin writes agora_log/ and tutk_log/ into its working directory.
	cmd.Dir = os.TempDir()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	// The read ends are owned here rather than by exec.Cmd: cmd.Wait closes
	// pipes it created as soon as the child exits, which could drop the
	// last frames or the stderr line explaining a failed start.
	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		outR.Close()
		outW.Close()
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = outW, errW
	err = cmd.Start()
	outW.Close()
	errW.Close()
	if err != nil {
		outR.Close()
		errR.Close()
		return nil, fmt.Errorf("start %s: %w", path, err)
	}
	s := &Session{cmd: cmd, stdin: stdin, outR: outR, out: bufio.NewReaderSize(outR, 1<<20), done: make(chan struct{})}

	var lastLog strings.Builder
	var logMu sync.Mutex
	go func() {
		defer errR.Close()
		sc := bufio.NewScanner(errR)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Text()
			logMu.Lock()
			if lastLog.Len() < 4096 {
				lastLog.WriteString(line)
				lastLog.WriteByte('\n')
			}
			logMu.Unlock()
			if o.Log != nil {
				o.Log(line)
			}
		}
	}()
	go func() {
		s.waitErr = cmd.Wait()
		close(s.done)
	}()

	if _, err := io.WriteString(stdin, url+"\n"); err != nil {
		s.Close()
		return nil, err
	}

	type result struct {
		h   Header
		err error
	}
	hdrCh := make(chan result, 1)
	go func() {
		h, err := ReadHeader(s.out)
		hdrCh <- result{h, err}
	}()
	select {
	case r := <-hdrCh:
		if r.err != nil {
			s.Close()
			logMu.Lock()
			tail := strings.TrimSpace(lastLog.String())
			logMu.Unlock()
			return nil, openError(r.err, s.waitErr, tail)
		}
		s.header = r.h
		return s, nil
	case <-ctx.Done():
		s.Close()
		return nil, ctx.Err()
	}
}

// openError folds the helper's exit status and last stderr lines into a
// readable reason for a failed open.
func openError(readErr, waitErr error, stderrTail string) error {
	msg := "tunnel did not start"
	if waitErr != nil {
		msg += " (" + waitErr.Error() + ")"
	}
	if i := strings.LastIndex(stderrTail, "bambu-tunnel: "); i >= 0 {
		return fmt.Errorf("%s: %s", msg, strings.TrimSpace(stderrTail[i+len("bambu-tunnel: "):]))
	}
	if errors.Is(readErr, io.EOF) {
		return errors.New(msg)
	}
	return fmt.Errorf("%s: %w", msg, readErr)
}

// Header is the stream description read at open.
func (s *Session) Header() Header { return s.header }

// Read returns the next frame; io.EOF when the helper ends the stream.
func (s *Session) Read() (Frame, error) {
	return ReadFrame(s.out)
}

// Close ends the stream and reaps the helper.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		s.stdin.Close()
		select {
		case <-s.done:
		case <-time.After(2 * time.Second):
			s.cmd.Process.Kill()
			<-s.done
		}
		s.outR.Close()
	})
	return nil
}

// helperEnv is the environment the helper runs with: only what the dynamic
// loader and the plugin need, so the API's own secrets (data key, tokens)
// never reach the closed library.
func helperEnv(lib string) []string {
	env := []string{}
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "LD_LIBRARY_PATH", "BAMBU_SOURCE_LIB"} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	if lib != "" {
		env = append(env, "BAMBU_SOURCE_LIB="+lib)
	}
	return env
}
