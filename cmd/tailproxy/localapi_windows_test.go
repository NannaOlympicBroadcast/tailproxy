package main

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/tailscale/go-winio"
	"golang.org/x/sys/windows"
)

func dialPipe(t *testing.T, path string) net.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// The same call the tailscale CLI makes (tailscale.com/safesocket).
	c, err := winio.DialPipeAccessImpLevel(ctx, path, windows.GENERIC_READ|windows.GENERIC_WRITE, winio.PipeImpLevelIdentification)
	if err != nil {
		t.Fatalf("dial %s: %v", path, err)
	}
	return c
}

// TestLocalAPIPipe runs on real Windows: the LocalAPI named pipe carries
// data both ways, and its DACL admits only the current user and SYSTEM.
func TestLocalAPIPipe(t *testing.T) {
	path, err := localAPIPath("")
	if err != nil || !strings.HasPrefix(path, `\\.\pipe\tailproxy-`) {
		t.Fatalf("path %q %v", path, err)
	}
	if other, _ := localAPIPath(""); other == path {
		t.Fatal("pipe name is not random")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	echo := func(context.Context) (net.Conn, error) {
		a, b := net.Pipe()
		go io.Copy(b, b)
		return a, nil
	}
	if err := serveLocalAPI(ctx, path, echo); err != nil {
		t.Fatal(err)
	}
	// A second listener on the same name must fail (no sharing/squatting).
	if err := serveLocalAPI(ctx, path, echo); err == nil {
		t.Fatal("second listener on the same pipe name succeeded")
	}

	c := dialPipe(t, path)
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte("GET /localapi/v0/status HTTP/1.1")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "GET /localapi/v0/status HTTP/1.1" {
		t.Fatalf("round trip: %q %v", buf, err)
	}

	// Read the pipe's security descriptor through the client handle.
	h := windows.Handle(c.(interface{ Fd() uintptr }).Fd())
	sd, err := windows.GetSecurityInfo(h, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("GetSecurityInfo: %v", err)
	}
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	me := u.User.Sid
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("no DACL (a NULL DACL would admit everyone): %v", err)
	}
	var sids []string
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("unexpected ACE type %d", ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(me) && !sid.Equals(system) {
			t.Errorf("DACL admits %s (only %s and SYSTEM expected)", sid, me)
		}
		sids = append(sids, sid.String())
	}
	if len(sids) != 2 {
		t.Errorf("DACL entries: %v", sids)
	}
	t.Logf("pipe %s DACL: %v", path, sids)
}
