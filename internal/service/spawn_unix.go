//go:build unix

package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// readyFDEnv tells the child which inherited file descriptor to report on.
const readyFDEnv = "TAILPROXY_READY_FD"

// Supported reports whether background mode works on this platform.
const Supported = true

// Spawn starts exe with args as a detached background process (new session,
// no controlling terminal, stdin from /dev/null, stdout/stderr appended to
// logPath, working directory /) and waits up to timeout for its Ready report.
// Paths in args must be absolute.
func Spawn(exe string, args []string, logPath string, timeout time.Duration) (Ready, error) {
	logf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return Ready{}, err
	}
	defer logf.Close()
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return Ready{}, err
	}
	defer devnull.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		return Ready{}, err
	}
	defer pr.Close()

	cmd := exec.Command(exe, args...)
	cmd.Stdin = devnull
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.Dir = "/"
	cmd.ExtraFiles = []*os.File{pw} // fd 3 in the child
	cmd.Env = append(childEnv(), readyFDEnv+"=3")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		pw.Close()
		return Ready{}, err
	}
	pw.Close() // the child holds the only write end now

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	pr.SetReadDeadline(time.Now().Add(timeout))
	data, rerr := io.ReadAll(pr)
	var ready Ready
	if len(data) > 0 {
		if err := json.Unmarshal(data, &ready); err != nil {
			return Ready{}, fmt.Errorf("background process sent an invalid ready report: %w", err)
		}
		if ready.OK {
			return ready, nil // leave the child running
		}
		return ready, errors.New(ready.Error)
	}
	if errors.Is(rerr, os.ErrDeadlineExceeded) {
		cmd.Process.Kill()
		return Ready{}, fmt.Errorf("background process did not become ready within %s (see %s)", timeout, logPath)
	}
	select {
	case werr := <-exited:
		return Ready{}, fmt.Errorf("background process exited during startup (%v); see %s", werr, logPath)
	case <-time.After(time.Second):
		cmd.Process.Kill()
		return Ready{}, fmt.Errorf("background process closed its ready pipe without reporting; see %s", logPath)
	}
}

// ReadyWriter returns the pipe to report readiness on when this process was
// started by Spawn, or nil when running in the foreground.
func ReadyWriter() *os.File {
	fd, err := strconv.Atoi(os.Getenv(readyFDEnv))
	if err != nil || fd < 3 {
		return nil
	}
	os.Unsetenv(readyFDEnv)
	return os.NewFile(uintptr(fd), "ready")
}

// Report writes r to w (from ReadyWriter) and closes it.
func Report(w *os.File, r Ready) error {
	defer w.Close()
	return json.NewEncoder(w).Encode(r)
}

// Terminate asks the process to shut down gracefully.
func Terminate(pid int) error {
	return syscall.Kill(pid, syscall.SIGTERM)
}

func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	if err != nil && !errors.Is(err, syscall.EPERM) {
		return false
	}
	// A killed process that its parent (often init) has not reaped yet still
	// answers kill(pid, 0). On Linux, treat such a zombie as dead.
	if stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		if i := bytes.LastIndexByte(stat, ')'); i >= 0 && i+2 < len(stat) && stat[i+2] == 'Z' {
			return false
		}
	}
	return true
}
