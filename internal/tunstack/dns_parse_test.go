package tunstack

import (
	"slices"
	"testing"
)

func TestParseServices(t *testing.T) {
	out := "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\nUSB 10/100/1000 LAN\n"
	got := parseServices(out)
	want := []string{"Wi-Fi", "Thunderbolt Bridge", "USB 10/100/1000 LAN"}
	if !slices.Equal(got, want) {
		t.Fatalf("parseServices = %q, want %q", got, want)
	}
}

func TestDNSServersArg(t *testing.T) {
	for out, want := range map[string]string{
		"There aren't any DNS Servers set on Wi-Fi.\n": "Empty",
		"":                   "Empty",
		"1.1.1.1\n":          "1.1.1.1",
		"1.1.1.1\n8.8.8.8\n": "1.1.1.1 8.8.8.8",
		"2606:4700::1111\n":  "2606:4700::1111",
	} {
		if got := dnsServersArg(out); got != want {
			t.Errorf("dnsServersArg(%q) = %q, want %q", out, got, want)
		}
	}
}
