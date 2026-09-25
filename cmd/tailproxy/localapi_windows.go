package main

import (
	"context"
	"errors"
	"net"
)

// serveLocalAPI: the LocalAPI socket (for `tpctl ts`) is not implemented on
// Windows yet, where tailscaled uses a named pipe with its own ACL.
func serveLocalAPI(ctx context.Context, path string, dial func(context.Context) (net.Conn, error)) error {
	return errors.New("the LocalAPI socket for tpctl ts is not supported on Windows yet")
}

// localAPIPath: not used on Windows (no LocalAPI socket yet).
func localAPIPath(preferred string) (string, error) { return "", nil }
