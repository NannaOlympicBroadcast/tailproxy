//go:build windows

package service

import (
	"errors"
	"os"
	"time"
)

// Supported reports whether background mode works on this platform. On
// Windows tailproxy should run as a Windows service instead; that is not
// implemented yet, so only `tailproxy run` (foreground) is available.
const Supported = false

var errUnsupported = errors.New("后台模式（tailproxy start）暂不支持 Windows，请使用 tailproxy run 在前台运行")

func Spawn(exe string, args []string, logPath string, timeout time.Duration) (Ready, error) {
	return Ready{}, errUnsupported
}

func ReadyWriter() *os.File { return nil }

func Report(w *os.File, r Ready) error { return errUnsupported }

// Terminate stops the process. Windows has no SIGTERM equivalent for a
// console process started without a console group, so this kills it.
func Terminate(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	p.Release()
	return true
}
