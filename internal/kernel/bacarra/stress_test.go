package bacarra_test

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/kernel/bacarra"
)

// TestChallenger_IsTailscaleIP_BoundaryMatrix exhaustively validates boundary and edge-case
// IPs against IsTailscaleIP for both RFC 6598 CGNAT (100.64.0.0/10) and Tailscale ULA (fd7a:115c:a1e0::/48).
func TestChallenger_IsTailscaleIP_BoundaryMatrix(t *testing.T) {
	cases := []struct {
		desc string
		ip   string
		want bool
	}{
		// Boundary cases around 100.64.0.0/10
		{"CGNAT lower boundary - 1", "100.63.255.255", false},
		{"CGNAT lower boundary exact", "100.64.0.0", true},
		{"CGNAT lower boundary + 1", "100.64.0.1", true},
		{"CGNAT midpoint service IP", "100.100.100.100", true},
		{"CGNAT upper boundary - 1", "100.127.255.254", true},
		{"CGNAT upper boundary exact", "100.127.255.255", true},
		{"CGNAT upper boundary + 1", "100.128.0.0", false},

		// Out-of-range 100.x.x.x addresses
		{"100.0.0.0", "100.0.0.0", false},
		{"100.63.0.0", "100.63.0.0", false},
		{"100.128.255.255", "100.128.255.255", false},
		{"100.255.255.255", "100.255.255.255", false},

		// Standard IPv4 special ranges
		{"Zero IPv4", "0.0.0.0", false},
		{"Broadcast IPv4", "255.255.255.255", false},
		{"Loopback IPv4 start", "127.0.0.1", false},
		{"Loopback IPv4 end", "127.255.255.255", false},
		{"Link-local IPv4 start", "169.254.0.1", false},
		{"Link-local IPv4 end", "169.254.255.254", false},
		{"RFC1918 10.0.0.0/8", "10.254.254.254", false},
		{"RFC1918 172.16.0.0/12", "172.16.0.1", false},
		{"RFC1918 192.168.0.0/16", "192.168.1.1", false},
		{"Public Cloudflare 1.1.1.1", "1.1.1.1", false},
		{"Public Google 8.8.8.8", "8.8.8.8", false},

		// Boundary cases around Tailscale ULA fd7a:115c:a1e0::/48
		{"Tailscale ULA lower boundary - 1", "fd7a:115c:a1df:ffff:ffff:ffff:ffff:ffff", false},
		{"Tailscale ULA lower boundary exact", "fd7a:115c:a1e0::", true},
		{"Tailscale ULA first host", "fd7a:115c:a1e0::1", true},
		{"Tailscale ULA 8-hextet host", "fd7a:115c:a1e0:1234:5678:9abc:def0:0001", true},
		{"Tailscale ULA compressed host", "fd7a:115c:a1e0::beef", true},
		{"Tailscale ULA upper boundary exact", "fd7a:115c:a1e0:ffff:ffff:ffff:ffff:ffff", true},
		{"Tailscale ULA upper boundary + 1", "fd7a:115c:a1e1::", false},

		// Standard IPv6 special ranges
		{"Generic ULA outside Tailscale prefix", "fd00::1", false},
		{"Alternative ULA", "fc00::1", false},
		{"IPv6 Loopback", "::1", false},
		{"IPv6 Unspecified", "::", false},
		{"IPv6 Link-Local start", "fe80::1", false},
		{"IPv6 Global Unicast Google DNS", "2001:4860:4860::8888", false},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			addr, err := netip.ParseAddr(tc.ip)
			if err != nil {
				t.Fatalf("failed to parse IP %q: %v", tc.ip, err)
			}
			got := bacarra.IsTailscaleIP(addr)
			if got != tc.want {
				t.Errorf("IsTailscaleIP(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}

	// Invalid zero addr
	if bacarra.IsTailscaleIP(netip.Addr{}) {
		t.Errorf("IsTailscaleIP(zero addr) should be false")
	}

	// IPv4-mapped IPv6 check:
	// Unmapped CGNAT address must be true
	mappedCGNAT := netip.MustParseAddr("::ffff:100.64.0.1")
	if bacarra.IsTailscaleIP(mappedCGNAT.Unmap()) != true {
		t.Errorf("IsTailscaleIP(mappedCGNAT.Unmap()) should be true")
	}
}

// TestChallenger_ValidateAdapterIPs_Adversarial tests filtering and fail-fast behavior
// of ValidateAdapterIPs against adversarial inputs.
func TestChallenger_ValidateAdapterIPs_Adversarial(t *testing.T) {
	t.Run("Empty and Nil slices fail fast", func(t *testing.T) {
		if _, err := bacarra.ValidateAdapterIPs(nil); !errors.Is(err, bacarra.ErrTailscaleNotDetected) {
			t.Fatalf("expected ErrTailscaleNotDetected for nil slice, got %v", err)
		}
		if _, err := bacarra.ValidateAdapterIPs([]netip.Addr{}); !errors.Is(err, bacarra.ErrTailscaleNotDetected) {
			t.Fatalf("expected ErrTailscaleNotDetected for empty slice, got %v", err)
		}
	})

	t.Run("All Non-Tailscale IPs fail fast", func(t *testing.T) {
		ips := []netip.Addr{
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("172.16.0.1"),
			netip.MustParseAddr("192.168.1.1"),
			netip.MustParseAddr("127.0.0.1"),
			netip.MustParseAddr("169.254.10.20"),
			netip.MustParseAddr("fe80::1"),
			netip.MustParseAddr("::1"),
		}
		_, err := bacarra.ValidateAdapterIPs(ips)
		if !errors.Is(err, bacarra.ErrTailscaleNotDetected) {
			t.Fatalf("expected ErrTailscaleNotDetected, got %v", err)
		}
	})

	t.Run("Only genuine Tailscale IPs are preserved", func(t *testing.T) {
		ips := []netip.Addr{
			netip.MustParseAddr("192.168.1.1"),
			netip.MustParseAddr("100.64.0.1"), // Tailscale IPv4
			netip.MustParseAddr("fe80::dead:beef"),
			netip.MustParseAddr("fd7a:115c:a1e0::55"), // Tailscale IPv6
			netip.MustParseAddr("8.8.8.8"),
		}
		valid, err := bacarra.ValidateAdapterIPs(ips)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(valid) != 2 {
			t.Fatalf("expected 2 valid Tailscale IPs, got %d", len(valid))
		}
		if valid[0].String() != "100.64.0.1" || valid[1].String() != "fd7a:115c:a1e0::55" {
			t.Fatalf("unexpected valid IPs: %v", valid)
		}
	})
}

// TestChallenger_NextHopForPrefix_EdgeCases checks that NextHopForPrefix never produces
// unspecified addresses (0.0.0.0 or ::) for any prefix types, preventing WSA error 10049.
func TestChallenger_NextHopForPrefix_EdgeCases(t *testing.T) {
	v4Cases := []string{
		"0.0.0.0/0",
		"198.18.0.0/15",
		"198.19.255.255/32", // broadcast IP as host route
		"100.64.0.0/10",
		"255.255.255.255/32",
		"1.1.1.1/32",
	}

	for _, c := range v4Cases {
		p := netip.MustParsePrefix(c)
		nh := bacarra.NextHopForPrefix(p)
		if !nh.IsValid() || nh.IsUnspecified() {
			t.Fatalf("NextHopForPrefix(%s) returned invalid or unspecified IP: %v", c, nh)
		}
		if nh.String() != "100.100.100.100" {
			t.Errorf("NextHopForPrefix(%s) = %s, want 100.100.100.100", c, nh.String())
		}
	}

	v6Cases := []string{
		"::/0",
		"fc00::/18",
		"fd7a:115c:a1e0::/48",
		"2001:db8::1/128",
	}

	for _, c := range v6Cases {
		p := netip.MustParsePrefix(c)
		nh := bacarra.NextHopForPrefix(p)
		if !nh.IsValid() || nh.IsUnspecified() {
			t.Fatalf("NextHopForPrefix(%s) returned invalid or unspecified IP: %v", c, nh)
		}
		if !nh.Is6() {
			t.Errorf("NextHopForPrefix(%s) should be IPv6, got %v", c, nh)
		}
	}
}

// TestChallenger_RouteManager_LargeScaleDiffing tests RouteManager.Apply with large prefix sets,
// overlapping subnets, redundant duplicates, unmasked host bits, and disjoint transitions.
func TestChallenger_RouteManager_LargeScaleDiffing(t *testing.T) {
	tmpDir := t.TempDir()
	driver := newMockRouteDriver()

	adapter := &bacarra.AdapterInfo{
		Name:  "tailscale0",
		Index: 10,
		IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}

	rm, err := bacarra.NewRouteManagerWithDriver(adapter, tmpDir, nil, driver)
	if err != nil {
		t.Fatalf("NewRouteManagerWithDriver: %v", err)
	}

	// 1. Generate 1,000 distinct prefixes for Set A
	setA := make([]netip.Prefix, 1000)
	for i := 0; i < 1000; i++ {
		oct2 := i / 250
		oct3 := i % 250
		setA[i] = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", oct2, oct3))
	}

	// Apply Set A
	if err := rm.Apply(setA); err != nil {
		t.Fatalf("Apply Set A failed: %v", err)
	}

	if len(driver.added) != 1000 {
		t.Fatalf("driver.added count = %d, want 1000", len(driver.added))
	}
	if len(driver.deleted) != 0 {
		t.Fatalf("driver.deleted count = %d, want 0", len(driver.deleted))
	}
	if len(rm.AppliedRoutes()) != 1000 {
		t.Fatalf("AppliedRoutes count = %d, want 1000", len(rm.AppliedRoutes()))
	}

	// Verify state file
	stateA, err := bacarra.ReadRouteState(tmpDir)
	if err != nil {
		t.Fatalf("ReadRouteState: %v", err)
	}
	if len(stateA.Routes) != 1000 {
		t.Fatalf("stateA.Routes count = %d, want 1000", len(stateA.Routes))
	}

	// 2. Redundancy & Unmasked Host Bits:
	// Pass 1,000 prefixes containing unmasked host bits (e.g. 10.0.0.55/24) and duplicates
	setARedundant := make([]netip.Prefix, 2000)
	for i := 0; i < 1000; i++ {
		oct2 := i / 250
		oct3 := i % 250
		// Host bits set
		setARedundant[i] = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.55/24", oct2, oct3))
		// Exact duplicate with different host bit
		setARedundant[1000+i] = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.99/24", oct2, oct3))
	}

	driverBefore := len(driver.added)
	if err := rm.Apply(setARedundant); err != nil {
		t.Fatalf("Apply setARedundant failed: %v", err)
	}
	// Because all 1,000 masked prefixes already exist, driver should receive 0 new AddRoute calls
	if len(driver.added) != driverBefore {
		t.Fatalf("redundant Apply caused new driver additions: got %d, want %d", len(driver.added), driverBefore)
	}
	if len(driver.deleted) != 0 {
		t.Fatalf("redundant Apply caused driver deletions: got %d, want 0", len(driver.deleted))
	}

	// 3. Partial Overlap: Set B keeps 500 prefixes of Set A, drops 500, adds 500 new prefixes (1000 total)
	setB := make([]netip.Prefix, 1000)
	copy(setB[:500], setA[:500])
	for i := 0; i < 500; i++ {
		oct2 := 16 + (i / 250)
		oct3 := i % 250
		setB[500+i] = netip.MustParsePrefix(fmt.Sprintf("172.%d.%d.0/24", oct2, oct3))
	}

	if err := rm.Apply(setB); err != nil {
		t.Fatalf("Apply Set B failed: %v", err)
	}

	// Driver should have added 500 new prefixes (total 1500 additions)
	if len(driver.added) != 1500 {
		t.Fatalf("total driver additions = %d, want 1500", len(driver.added))
	}
	// Driver should have deleted the dropped 500 prefixes
	if len(driver.deleted) != 500 {
		t.Fatalf("total driver deletions = %d, want 500", len(driver.deleted))
	}
	if len(rm.AppliedRoutes()) != 1000 {
		t.Fatalf("AppliedRoutes count after Set B = %d, want 1000", len(rm.AppliedRoutes()))
	}

	// 4. Overlapping Subnet Lengths: Add supernets and subnets
	hierarchical := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),   // supernet
		netip.MustParsePrefix("10.0.1.0/24"),   // subnet
		netip.MustParsePrefix("10.0.1.128/25"), // sub-subnet
	}
	if err := rm.Apply(hierarchical); err != nil {
		t.Fatalf("Apply hierarchical failed: %v", err)
	}
	if len(rm.AppliedRoutes()) != 3 {
		t.Fatalf("AppliedRoutes count = %d, want 3", len(rm.AppliedRoutes()))
	}

	// 5. Disjoint Transition: Set C has 300 completely disjoint IPv6 prefixes
	setC := make([]netip.Prefix, 300)
	for i := 0; i < 300; i++ {
		setC[i] = netip.MustParsePrefix(fmt.Sprintf("2001:db8:%x::/48", i))
	}

	if err := rm.Apply(setC); err != nil {
		t.Fatalf("Apply Set C failed: %v", err)
	}
	if len(rm.AppliedRoutes()) != 300 {
		t.Fatalf("AppliedRoutes count after Set C = %d, want 300", len(rm.AppliedRoutes()))
	}

	// 6. Clean Teardown via Empty Slice
	if err := rm.Apply([]netip.Prefix{}); err != nil {
		t.Fatalf("Apply empty slice failed: %v", err)
	}
	if len(rm.AppliedRoutes()) != 0 {
		t.Fatalf("AppliedRoutes count after empty apply = %d, want 0", len(rm.AppliedRoutes()))
	}

	// 7. Close idempotency
	if err := rm.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	// Calling Close a second time should be safe
	if err := rm.Close(); err != nil {
		t.Fatalf("Second Close failed: %v", err)
	}
}

// TestChallenger_RouteManager_ConcurrentLoad stress tests RouteManager under heavy concurrent
// load across multiple goroutines performing Apply, AppliedRoutes, ReadRouteState, and Close.
func TestChallenger_RouteManager_ConcurrentLoad(t *testing.T) {
	tmpDir := t.TempDir()
	driver := newMockRouteDriver()

	adapter := &bacarra.AdapterInfo{
		Name:  "tailscale0",
		Index: 5,
		IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}

	rm, err := bacarra.NewRouteManagerWithDriver(adapter, tmpDir, nil, driver)
	if err != nil {
		t.Fatalf("NewRouteManagerWithDriver: %v", err)
	}

	prefixPoolA := []netip.Prefix{
		netip.MustParsePrefix("10.0.1.0/24"),
		netip.MustParsePrefix("10.0.2.0/24"),
		netip.MustParsePrefix("10.0.3.0/24"),
	}
	prefixPoolB := []netip.Prefix{
		netip.MustParsePrefix("10.0.2.0/24"),
		netip.MustParsePrefix("10.0.4.0/24"),
		netip.MustParsePrefix("10.0.5.0/24"),
	}
	prefixPoolC := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("192.168.2.0/24"),
	}

	const numWorkers = 20
	const iterations = 50
	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				switch (workerID + i) % 4 {
				case 0:
					_ = rm.Apply(prefixPoolA)
				case 1:
					_ = rm.Apply(prefixPoolB)
				case 2:
					_ = rm.Apply(prefixPoolC)
				case 3:
					applied := rm.AppliedRoutes()
					if len(applied) > 0 {
						isSorted := sort.SliceIsSorted(applied, func(i, j int) bool {
							return applied[i].String() < applied[j].String()
						})
						if !isSorted {
							t.Errorf("AppliedRoutes was not sorted")
						}
					}
				}
				time.Sleep(50 * time.Microsecond)
			}
		}()
	}

	wg.Wait()

	// Final verification: Close must succeed cleanly after high concurrent traffic
	if err := rm.Close(); err != nil {
		t.Fatalf("final Close failed: %v", err)
	}

	if len(rm.AppliedRoutes()) != 0 {
		t.Fatalf("AppliedRoutes after Close = %d, want 0", len(rm.AppliedRoutes()))
	}
}

// TestChallenger_State_AtomicIntegrity tests SaveRouteState and ReadRouteState under concurrent
// execution to verify that readers never encounter partially written or corrupted states.
func TestChallenger_State_AtomicIntegrity(t *testing.T) {
	tmpDir := t.TempDir()

	const writers = 4
	const readers = 8
	const cycles = 30

	var stopCh = make(chan struct{})
	var wg sync.WaitGroup

	// Writer goroutines
	for w := 0; w < writers; w++ {
		wg.Add(1)
		wID := w
		go func() {
			defer wg.Done()
			for i := 0; i < cycles; i++ {
				state := &bacarra.RouteState{
					Kernel:       "bacarra",
					AdapterName:  fmt.Sprintf("tailscale%d", wID),
					AdapterIndex: wID + 1,
					UpdatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
					Routes: []string{
						fmt.Sprintf("10.%d.%d.0/24", wID, i),
						"198.18.0.0/15",
					},
				}
				_ = bacarra.SaveRouteState(tmpDir, state)
				time.Sleep(500 * time.Microsecond)
			}
		}()
	}

	// Reader goroutines
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stopCh:
					return
				default:
					state, err := bacarra.ReadRouteState(tmpDir)
					if err == nil {
						if state.Kernel != "bacarra" {
							t.Errorf("ReadRouteState got invalid kernel: %s", state.Kernel)
						}
						if len(state.Routes) == 0 {
							t.Errorf("ReadRouteState got empty routes")
						}
					}
					time.Sleep(200 * time.Microsecond)
				}
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(stopCh)
	wg.Wait()

	_ = os.RemoveAll(tmpDir)
}

// TestChallenger_DeleteRouteFailure_TrackingBehavior tests how RouteManager behaves
// when driver.DeleteRoute fails: does it report the error and what is internal tracking?
func TestChallenger_DeleteRouteFailure_TrackingBehavior(t *testing.T) {
	tmpDir := t.TempDir()
	driver := newMockRouteDriver()

	failDelPrefix := netip.MustParsePrefix("192.168.50.0/24")
	driver.failDel[failDelPrefix] = fmt.Errorf("simulated delete failure on %s", failDelPrefix)

	adapter := &bacarra.AdapterInfo{
		Name:  "tailscale0",
		Index: 1,
		IPs:   []netip.Addr{netip.MustParseAddr("100.64.0.1")},
	}

	rm, err := bacarra.NewRouteManagerWithDriver(adapter, tmpDir, nil, driver)
	if err != nil {
		t.Fatalf("NewRouteManagerWithDriver: %v", err)
	}

	// Apply 2 routes
	if err := rm.Apply([]netip.Prefix{failDelPrefix, netip.MustParsePrefix("10.0.0.0/24")}); err != nil {
		t.Fatalf("initial Apply failed: %v", err)
	}

	// Now remove failDelPrefix
	err = rm.Apply([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
	if err == nil {
		t.Fatalf("expected error when DeleteRoute fails, got nil")
	}

	if err.Error() == "" {
		t.Fatalf("error was empty")
	}
}

// TestChallenger_TeardownStale_MalformedRoutesInState tests that TeardownStale tolerates
// malformed prefix entries in an otherwise valid JSON state file.
func TestChallenger_TeardownStale_MalformedRoutesInState(t *testing.T) {
	tmpDir := t.TempDir()

	state := &bacarra.RouteState{
		Kernel:       "bacarra",
		AdapterName:  "tailscale0",
		AdapterIndex: 1,
		UpdatedAt:    "2026-10-12T00:00:00Z",
		Routes: []string{
			"malformed_prefix_string",
			"198.18.0.0/15",
			"999.999.999.999/99",
		},
	}

	if err := bacarra.SaveRouteState(tmpDir, state); err != nil {
		t.Fatalf("SaveRouteState failed: %v", err)
	}

	// TeardownStale should parse the valid ones, skip malformed ones, and delete the state file
	_ = bacarra.TeardownStale(tmpDir)

	if _, err := os.Stat(bacarra.StateFilePath(tmpDir)); !os.IsNotExist(err) {
		t.Errorf("expected state file to be purged, got: %v", err)
	}
}
