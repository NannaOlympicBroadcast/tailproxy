package bacarra

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// StateFileName is the standard file name for the Bacarra route state file.
const StateFileName = "bacarra_routes.json"

// RouteState represents the serialized host route hijacking state.
type RouteState struct {
	Kernel       string   `json:"kernel"`
	AdapterName  string   `json:"adapter_name"`
	AdapterIndex int      `json:"adapter_index"`
	UpdatedAt    string   `json:"updated_at"`
	Routes       []string `json:"routes"`
}

// StateFilePath returns the absolute path to the bacarra route state file
// inside the specified state directory.
func StateFilePath(stateDir string) string {
	return filepath.Join(stateDir, StateFileName)
}

// SaveRouteState atomically writes the route state to <stateDir>/bacarra_routes.json.
func SaveRouteState(stateDir string, state *RouteState) error {
	if state == nil {
		return errors.New("bacarra: state cannot be nil")
	}
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return fmt.Errorf("create state dir %q: %w", stateDir, err)
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal route state: %w", err)
	}
	data = append(data, '\n')

	targetPath := StateFilePath(stateDir)
	tmpPath := filepath.Join(stateDir, fmt.Sprintf(".bacarra_routes.%d.tmp", time.Now().UnixNano()))

	if err := os.WriteFile(tmpPath, data, 0600); err != nil {
		return fmt.Errorf("write temp state file: %w", err)
	}

	// Atomic replacement: rename tmpPath to targetPath.
	// On Windows, os.Rename fails if the destination file exists,
	// so remove any existing file first if rename returns an error.
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(targetPath)
		if err2 := os.Rename(tmpPath, targetPath); err2 != nil {
			_ = os.Remove(tmpPath)
			return fmt.Errorf("rename state file to %q: %w", targetPath, err2)
		}
	}

	return nil
}

// ReadRouteState reads and parses the route state from <stateDir>/bacarra_routes.json.
// If the file does not exist, it returns os.ErrNotExist.
// If the file is 0-byte or contains invalid JSON, it returns an error with "corrupt state file".
func ReadRouteState(stateDir string) (*RouteState, error) {
	targetPath := StateFilePath(stateDir)
	data, err := os.ReadFile(targetPath)
	if err != nil {
		return nil, err
	}

	if len(data) == 0 {
		return nil, errors.New("corrupt state file: empty file")
	}

	var state RouteState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("corrupt state file: %w", err)
	}

	if state.Kernel != "bacarra" {
		return nil, fmt.Errorf("corrupt state file: unexpected kernel %q", state.Kernel)
	}

	return &state, nil
}

// RemoveRouteState removes <stateDir>/bacarra_routes.json if it exists.
// If the file does not exist, it returns nil.
func RemoveRouteState(stateDir string) error {
	targetPath := StateFilePath(stateDir)
	if err := os.Remove(targetPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove state file %q: %w", targetPath, err)
	}
	return nil
}
