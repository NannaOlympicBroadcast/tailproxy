// Package service runs tailproxy as a background process: it spawns a
// detached child, waits until the child's panel is listening, and keeps a
// small state directory (default ~/.lighthousepro) with the running
// instance's state, log and, optionally, its panel token.
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// DefaultDirName is the state directory under the user's home.
const DefaultDirName = ".lighthousepro"

// Paths are the files tailproxy keeps in its state directory.
type Paths struct {
	Dir   string
	State string // tailproxy.json: the running instance
	Log   string // tailproxy.log: output of the background process
	Token string // tailproxy.token: persisted panel token (kept across restarts)
}

// DefaultDir returns ~/.lighthousepro.
func DefaultDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, DefaultDirName), nil
}

// NewPaths returns the file paths inside dir.
func NewPaths(dir string) Paths {
	return Paths{
		Dir:   dir,
		State: filepath.Join(dir, "tailproxy.json"),
		Log:   filepath.Join(dir, "tailproxy.log"),
		Token: filepath.Join(dir, "tailproxy.token"),
	}
}

// Ensure creates the state directory, readable only by the current user.
func (p Paths) Ensure() error {
	if err := os.MkdirAll(p.Dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(p.Dir, 0o700)
}

// State describes a running tailproxy instance.
type State struct {
	PID       int       `json:"pid"`
	URL       string    `json:"url"`
	Config    string    `json:"config"`
	Log       string    `json:"log,omitempty"`        // empty when running in the foreground
	TokenFile string    `json:"token_file,omitempty"` // persisted token file; empty for env or one-off tokens
	TokenEnv  string    `json:"token_env,omitempty"`
	Started   time.Time `json:"started"`
	Manager   string    `json:"manager,omitempty"` // "systemd" when run as a systemd unit
	UserUnit  bool      `json:"user_unit,omitempty"`
}

// ReadState returns the recorded instance, or (nil, nil) if there is none.
func (p Paths) ReadState() (*State, error) {
	data, err := os.ReadFile(p.State)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("%s: %w", p.State, err)
	}
	return &st, nil
}

// Running returns the recorded instance if its process is still alive. A
// stale state file (process gone) is removed.
func (p Paths) Running() (*State, error) {
	st, err := p.ReadState()
	if err != nil || st == nil {
		return nil, err
	}
	if st.PID > 0 && processAlive(st.PID) {
		return st, nil
	}
	p.Cleanup(st.PID)
	return nil, nil
}

// WriteState records st atomically with mode 0600.
func (p Paths) WriteState(st State) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFile0600(p.State, append(data, '\n'))
}

// Cleanup removes the state file if it belongs to pid (or to a process that
// no longer exists). It never touches another live instance's state. The
// persisted token file is kept on purpose.
func (p Paths) Cleanup(pid int) {
	st, err := p.ReadState()
	if err != nil || st == nil {
		return
	}
	if st.PID != pid && processAlive(st.PID) {
		return
	}
	os.Remove(p.State)
}

func writeFile0600(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Ready is what the background child reports to the launching command once
// its panel is listening (or why it failed to get there).
type Ready struct {
	OK           bool   `json:"ok"`
	Error        string `json:"error,omitempty"`
	PID          int    `json:"pid,omitempty"`
	URL          string `json:"url,omitempty"`
	Listen       string `json:"listen,omitempty"`
	SOCKS        string `json:"socks,omitempty"`
	LoginURL     string `json:"login_url,omitempty"`
	Token        string `json:"token,omitempty"` // omitted when it comes from the environment
	TokenEnv     string `json:"token_env,omitempty"`
	TokenFile    string `json:"token_file,omitempty"`
	TokenCreated bool   `json:"token_created,omitempty"`
	Log          string `json:"log,omitempty"`
}
