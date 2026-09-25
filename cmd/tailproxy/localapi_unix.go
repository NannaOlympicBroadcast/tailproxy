//go:build !windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// maxSockPath keeps below sun_path (108 bytes on Linux, 104 on macOS).
const maxSockPath = 100

// localAPIPath returns where to put the LocalAPI socket: the state
// directory, or, when that path is too long for a Unix socket, a private
// directory tmp/tailproxy-<uid> (0700, owned by us, not a symlink).
func localAPIPath(preferred string) (string, error) {
	if len(preferred) <= maxSockPath {
		return preferred, nil
	}
	dir := filepath.Join(os.TempDir(), fmt.Sprintf("tailproxy-%d", os.Getuid()))
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o700 || !ok || int(st.Uid) != os.Getuid() {
		return "", fmt.Errorf("%s is not a private directory owned by uid %d", dir, os.Getuid())
	}
	sum := sha256.Sum256([]byte(preferred))
	return filepath.Join(dir, "ts-"+hex.EncodeToString(sum[:6])+".sock"), nil
}

// serveLocalAPI exposes the main node's LocalAPI on a Unix socket in the
// state directory (0700), readable only by tailproxy's user (0600), so the
// official tailscale CLI built into tpctl can operate that node.
func serveLocalAPI(ctx context.Context, path string, dial func(context.Context) (net.Conn, error)) error {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return errors.New(path + " exists and is not a socket")
		}
		os.Remove(path) // stale, from a crash
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
		os.Remove(path)
	}()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go proxyLocalAPI(ctx, c, dial)
		}
	}()
	return nil
}

func proxyLocalAPI(ctx context.Context, c net.Conn, dial func(context.Context) (net.Conn, error)) {
	defer c.Close()
	up, err := dial(ctx)
	if err != nil {
		// Answer like an HTTP server so the CLI shows a readable error.
		io.WriteString(c, "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\ntailproxy: "+err.Error()+"\n")
		return
	}
	defer up.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(up, c); closeWrite(up) }()
	go func() { defer wg.Done(); io.Copy(c, up); closeWrite(c) }()
	wg.Wait()
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		c.Close()
	}
}
