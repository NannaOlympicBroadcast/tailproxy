package proxy

import (
	"errors"
	"syscall"

	"golang.org/x/sys/windows"
)

// Winsock reports a refused connection as WSAECONNREFUSED, which
// syscall.ECONNREFUSED (an invented errno on Windows) does not match.
func isConnRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED) || errors.Is(err, syscall.ECONNREFUSED)
}
