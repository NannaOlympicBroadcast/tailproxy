package bacarra_test

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel/bacarra"
)

func TestIsTailscaleIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// RFC 6598 CGNAT Range (100.64.0.0/10) - IPv4
		{"CGNAT lower bound", "100.64.0.0", true},
		{"CGNAT start host", "100.64.0.1", true},
		{"Tailscale service IP", "100.100.100.100", true},
		{"CGNAT typical node IP", "100.85.123.45", true},
		{"CGNAT upper bound", "100.127.255.255", true},
		{"Below CGNAT range", "100.63.255.255", false},
		{"Above CGNAT range", "100.128.0.0", false},

		// Standard Non-Tailscale IPv4
		{"Private RFC1918 Class C", "192.168.1.1", false},
		{"Private RFC1918 Class A", "10.0.0.1", false},
		{"Private RFC1918 Class B", "172.16.0.1", false},
		{"Loopback IPv4", "127.0.0.1", false},
		{"Public Cloudflare DNS", "1.1.1.1", false},
		{"Public Google DNS", "8.8.8.8", false},

		// Tailscale IPv6 ULA Range (fd7a:115c:a1e0::/48)
		{"Tailscale ULA lower bound", "fd7a:115c:a1e0::", true},
		{"Tailscale ULA first host", "fd7a:115c:a1e0::1", true},
		{"Tailscale ULA random host", "fd7a:115c:a1e0:ab12:4843:cd96:626b:4314", true},
		{"Tailscale ULA upper bound", "fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff", true},

		// Standard Non-Tailscale IPv6
		{"Generic IPv6 ULA", "fd00::1", false},
		{"Outside Tailscale ULA prefix", "fd7a:115c:a1e1::1", false},
		{"IPv6 Loopback", "::1", false},
		{"IPv6 Link Local", "fe80::1", false},
		{"IPv6 Public Google DNS", "2001:4860:4860::8888", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			addr := netip.MustParseAddr(tc.ip)
			got := bacarra.IsTailscaleIP(addr)
			if got != tc.expected {
				t.Errorf("IsTailscaleIP(%s) = %v, want %v", tc.ip, got, tc.expected)
			}
		})
	}

	// Invalid / zero address
	if bacarra.IsTailscaleIP(netip.Addr{}) {
		t.Errorf("IsTailscaleIP(zero addr) should be false")
	}
}

func TestValidateAdapterIPs(t *testing.T) {
	t.Run("Pure Tailscale IPs", func(t *testing.T) {
		ips := []netip.Addr{
			netip.MustParseAddr("100.64.0.5"),
			netip.MustParseAddr("fd7a:115c:a1e0::5"),
		}
		valid, err := bacarra.ValidateAdapterIPs(ips)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(valid) != 2 {
			t.Fatalf("expected 2 valid IPs, got %d", len(valid))
		}
	})

	t.Run("Mixed IPs Filtered", func(t *testing.T) {
		ips := []netip.Addr{
			netip.MustParseAddr("192.168.1.100"),
			netip.MustParseAddr("100.90.10.20"),
			netip.MustParseAddr("fe80::1"),
			netip.MustParseAddr("fd7a:115c:a1e0:1234::1"),
		}
		valid, err := bacarra.ValidateAdapterIPs(ips)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(valid) != 2 {
			t.Fatalf("expected 2 valid Tailscale IPs, got %d", len(valid))
		}
		for _, ip := range valid {
			if !bacarra.IsTailscaleIP(ip) {
				t.Errorf("filtered IP %s is not a valid Tailscale IP", ip)
			}
		}
	})

	t.Run("No Tailscale IPs Fails Fast", func(t *testing.T) {
		ips := []netip.Addr{
			netip.MustParseAddr("192.168.1.1"),
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("fe80::1"),
		}
		_, err := bacarra.ValidateAdapterIPs(ips)
		if err == nil {
			t.Fatal("expected error for non-Tailscale IPs, got nil")
		}
		if !errors.Is(err, bacarra.ErrTailscaleNotDetected) {
			t.Errorf("expected ErrTailscaleNotDetected, got: %v", err)
		}
	})

	t.Run("Empty Slice Fails Fast", func(t *testing.T) {
		_, err := bacarra.ValidateAdapterIPs(nil)
		if err == nil {
			t.Fatal("expected error for empty IPs, got nil")
		}
		if !errors.Is(err, bacarra.ErrTailscaleNotDetected) {
			t.Errorf("expected ErrTailscaleNotDetected, got: %v", err)
		}
	})
}

func TestDiscoverAdapter_GroundTruth(t *testing.T) {
	ctx := context.Background()
	adapter, err := bacarra.DiscoverAdapter(ctx)
	if err != nil {
		// If Tailscale client is not running on this machine, it must fail fast with ErrTailscaleNotDetected.
		if !errors.Is(err, bacarra.ErrTailscaleNotDetected) {
			t.Fatalf("expected ErrTailscaleNotDetected when Tailscale is absent, got: %v", err)
		}
		return
	}

	// If Tailscale is active and discovered:
	if adapter.Name == "" {
		t.Errorf("expected non-empty adapter name")
	}
	nameLower := strings.ToLower(adapter.Name)
	if strings.Contains(nameLower, "mock") || strings.Contains(nameLower, "dummy") {
		t.Fatalf("anti-mock violation: detected fake or mock adapter %q", adapter.Name)
	}

	if len(adapter.IPs) == 0 {
		t.Fatalf("expected at least one valid Tailscale IP")
	}

	for _, ip := range adapter.IPs {
		if !bacarra.IsTailscaleIP(ip) {
			t.Fatalf("adapter IP %s is not within official Tailscale CGNAT or ULA range", ip)
		}
	}
}
