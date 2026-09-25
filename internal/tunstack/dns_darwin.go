//go:build darwin

package tunstack

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// System DNS on macOS is set per network service with networksetup, the
// way wg-quick does on macOS: every service's DNS servers are saved, set to
// the stack's address, and put back on exit. The saved servers are also
// written to dnsBackupFile, so a crash can be undone (Cleanup, and the
// next start) — manual DNS settings survive a reboot.
var dnsBackupFile = "/var/db/tailproxy/dns-backup.json"

var dnsMu sync.Mutex

// SetSystemDNS points every network service's DNS at addr.
func (r *Router) SetSystemDNS(addr netip.Addr) error {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	if err := restoreLocked(); err != nil { // a crashed run's settings first
		return err
	}
	svcs, err := networkServices()
	if err != nil {
		return err
	}
	saved := map[string]string{}
	for _, s := range svcs {
		out, err := output("/usr/sbin/networksetup", "-getdnsservers", s)
		if err != nil {
			return fmt.Errorf("tun: system DNS: %w", err)
		}
		saved[s] = dnsServersArg(out)
	}
	b, _ := json.Marshal(saved)
	if err := os.MkdirAll(filepath.Dir(dnsBackupFile), 0o755); err != nil {
		return fmt.Errorf("tun: system DNS backup: %w", err)
	}
	if err := os.WriteFile(dnsBackupFile, b, 0o600); err != nil {
		return fmt.Errorf("tun: system DNS backup: %w", err)
	}
	var errs []error
	for _, s := range svcs {
		if err := run("/usr/sbin/networksetup", "-setdnsservers", s, addr.String()); err != nil {
			errs = append(errs, err)
		}
	}
	flushDNSCache()
	if err := errors.Join(errs...); err != nil {
		restoreLocked()
		return fmt.Errorf("tun: system DNS: %w", err)
	}
	return nil
}

func restoreSystemDNS() error {
	dnsMu.Lock()
	defer dnsMu.Unlock()
	return restoreLocked()
}

// restoreLocked puts back the servers in dnsBackupFile, if it exists.
func restoreLocked() error {
	b, err := os.ReadFile(dnsBackupFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("tun: system DNS backup: %w", err)
	}
	saved := map[string]string{}
	if err := json.Unmarshal(b, &saved); err != nil {
		os.Remove(dnsBackupFile)
		return fmt.Errorf("tun: system DNS backup %s: %w", dnsBackupFile, err)
	}
	var errs []error
	for s, servers := range saved {
		args := append([]string{"/usr/sbin/networksetup", "-setdnsservers", s}, strings.Fields(servers)...)
		if err := run(args...); err != nil {
			errs = append(errs, err)
		}
	}
	flushDNSCache()
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("tun: restore system DNS: %w", err)
	}
	return os.Remove(dnsBackupFile)
}

// networkServices lists the network services; the first line of the
// output is a note, and disabled services are marked with a leading "*".
func networkServices() ([]string, error) {
	out, err := output("/usr/sbin/networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, fmt.Errorf("tun: system DNS: %w", err)
	}
	return parseServices(out), nil
}

func flushDNSCache() {
	exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}
