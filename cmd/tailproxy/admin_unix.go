//go:build !windows

package main

import "os"

// isAdmin reports whether the process may change network devices and routes.
func isAdmin() bool { return os.Geteuid() == 0 }
