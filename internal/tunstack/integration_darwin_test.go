//go:build darwin

package tunstack_test

import (
	"os/exec"
	"strings"
	"testing"
)

const isDarwin = true

// systemDNSSnapshot is every network service's DNS servers.
func systemDNSSnapshot(t *testing.T) string {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		t.Fatalf("networksetup: %v: %s", err, out)
	}
	var b strings.Builder
	for i, svc := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if i == 0 {
			continue
		}
		svc = strings.TrimPrefix(strings.TrimSpace(svc), "*")
		dns, err := exec.Command("/usr/sbin/networksetup", "-getdnsservers", svc).CombinedOutput()
		if err != nil {
			t.Fatalf("networksetup -getdnsservers %s: %v: %s", svc, err, dns)
		}
		b.WriteString(svc + ": " + strings.TrimSpace(string(dns)) + "\n")
	}
	return b.String()
}
