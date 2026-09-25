//go:build windows

package tunstack_test

import (
	"os/exec"
	"testing"
)

const isDarwin = false

// systemDNSSnapshot is every interface's IPv4 DNS servers.
func systemDNSSnapshot(t *testing.T) string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-DnsClientServerAddress -AddressFamily IPv4 | Sort-Object InterfaceIndex | ForEach-Object { $_.InterfaceAlias + ': ' + ($_.ServerAddresses -join ',') }`).CombinedOutput()
	if err != nil {
		t.Fatalf("Get-DnsClientServerAddress: %v: %s", err, out)
	}
	return string(out)
}
