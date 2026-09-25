//go:build darwin || windows

package tunstack_test

import (
	"os"
	"testing"
)

// TestTUNIntegration creates a real TUN device (utun on macOS, Wintun on
// Windows) on the host and routes test prefixes into it, so it only runs
// when TP_TUN_INTEGRATION=1 and with root / administrator rights (CI).
// Windows needs wintun.dll next to the test binary.
func TestTUNIntegration(t *testing.T) {
	if os.Getenv("TP_TUN_INTEGRATION") != "1" {
		t.Skip("set TP_TUN_INTEGRATION=1 (needs root / administrator)")
	}
	name := "tptest0"
	if isDarwin {
		name = "utun" // the kernel picks utunN
	}
	tunScenario(t, name)
}
