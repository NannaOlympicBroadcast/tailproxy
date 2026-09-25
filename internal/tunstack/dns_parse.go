package tunstack

import "strings"

// Parsing networksetup(8) output (macOS system DNS); here so it is tested
// on every system.

// parseServices returns the services in `networksetup
// -listallnetworkservices` output.
func parseServices(out string) []string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var svcs []string
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if i == 0 || l == "" {
			continue
		}
		svcs = append(svcs, strings.TrimPrefix(l, "*"))
	}
	return svcs
}

// dnsServersArg turns `networksetup -getdnsservers` output into the
// arguments that restore it: the servers, or "Empty" when the output is
// the "There aren't any DNS Servers set" sentence (servers have no spaces).
func dnsServersArg(out string) string {
	out = strings.TrimSpace(out)
	if out == "" || strings.Contains(out, " ") {
		return "Empty"
	}
	return strings.Join(strings.Fields(out), " ")
}
