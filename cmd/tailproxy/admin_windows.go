//go:build windows

package main

import "golang.org/x/sys/windows"

// isAdmin reports whether the process runs elevated (administrator).
func isAdmin() bool { return windows.GetCurrentProcessToken().IsElevated() }
