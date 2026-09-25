//go:build unix

package service

import (
	"net"
	"os"
	"strings"
)

// UnderSystemd reports whether this process runs as the main process of a
// tailproxy systemd unit. The units are Type=notify, so systemd sets
// NOTIFY_SOCKET. INVOCATION_ID is not enough: every process started from
// any unit (a CI runner, a user's login session) inherits it.
func UnderSystemd() bool {
	return os.Getenv("NOTIFY_SOCKET") != ""
}

// systemdEnv lists variables systemd hands to a unit's main process. They
// describe that process only and must not leak into a detached child.
var systemdEnv = []string{"NOTIFY_SOCKET", "INVOCATION_ID", "JOURNAL_STREAM", "LISTEN_FDS", "LISTEN_PID", "LISTEN_FDNAMES", "WATCHDOG_USEC", "WATCHDOG_PID"}

// childEnv returns the environment for a detached child: os.Environ()
// without systemd's per-process variables.
func childEnv() []string {
	var out []string
next:
	for _, kv := range os.Environ() {
		for _, k := range systemdEnv {
			if strings.HasPrefix(kv, k+"=") {
				continue next
			}
		}
		out = append(out, kv)
	}
	return out
}

// Notify sends a sd_notify(3) message such as "READY=1" to systemd. It is a
// no-op when NOTIFY_SOCKET is not set (not started with Type=notify).
func Notify(state string) error {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return nil
	}
	if addr[0] == '@' { // abstract socket
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}
