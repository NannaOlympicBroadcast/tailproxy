//go:build !linux

package main

import "errors"

func cmdService(args []string) error {
	return errors.New("tailproxy service（systemd 服务）只支持 Linux")
}
