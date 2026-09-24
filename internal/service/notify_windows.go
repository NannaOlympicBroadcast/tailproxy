//go:build windows

package service

// UnderSystemd is always false on Windows.
func UnderSystemd() bool { return false }

// Notify is a no-op on Windows.
func Notify(state string) error { return nil }
