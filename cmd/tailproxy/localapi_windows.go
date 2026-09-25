package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

// localAPIPath picks a named pipe with a random name: pipes live in one
// global namespace, and an unpredictable name (recorded in the state file,
// inside the private state directory) cannot be squatted in advance. The
// first instance is created with FILE_CREATE, so an existing pipe of the
// same name makes listening fail instead of sharing it.
func localAPIPath(string) (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return `\\.\pipe\tailproxy-` + hex.EncodeToString(b[:]), nil
}

// serveLocalAPI exposes the main node's LocalAPI on a named pipe that only
// the current user and SYSTEM may open (see pipeSDDL).
func serveLocalAPI(ctx context.Context, path string, dial func(context.Context) (net.Conn, error)) error {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("current user: %w", err)
	}
	ln, err := winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: pipeSDDL(u.User.Sid.String()),
		InputBufferSize:    256 << 10,
		OutputBufferSize:   256 << 10,
	})
	if err != nil {
		return fmt.Errorf("named pipe %s: %w", path, err)
	}
	go func() {
		<-ctx.Done()
		ln.Close()
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
