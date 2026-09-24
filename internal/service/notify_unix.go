//go:build unix

package service

import (
	"net"
	"os"
)

// UnderSystemd reports whether this process was started by systemd as a
// service (systemd sets INVOCATION_ID for every unit it runs).
func UnderSystemd() bool {
	return os.Getenv("INVOCATION_ID") != "" || os.Getenv("NOTIFY_SOCKET") != ""
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
