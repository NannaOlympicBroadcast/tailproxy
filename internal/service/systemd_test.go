package service

import (
	"strings"
	"testing"
)

func TestUnitSystem(t *testing.T) {
	u, err := Unit(UnitOptions{Exe: "/usr/local/bin/tailproxy", Config: "/etc/tailproxy/config.yaml", StateDir: "/home/alice/.lighthousepro", User: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Type=notify",
		"ExecStart=/usr/local/bin/tailproxy run -c /etc/tailproxy/config.yaml --state-dir /home/alice/.lighthousepro\n",
		"User=alice\n",
		"ReadWritePaths=/etc/tailproxy /home/alice/.lighthousepro\n",
		"ProtectSystem=strict",
		"After=network-online.target",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("system unit lacks %q:\n%s", want, u)
		}
	}
	if strings.Contains(u, "TAILPROXY_USER_UNIT") {
		t.Error("system unit must not mark itself as a user unit")
	}
}

func TestUnitUserAndRoot(t *testing.T) {
	u, err := Unit(UnitOptions{Exe: "/opt/tp/tailproxy", Config: "/home/bob/tp/config.yaml", StateDir: "/home/bob/.lighthousepro", UserUnit: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"WantedBy=default.target", "Environment=TAILPROXY_USER_UNIT=1"} {
		if !strings.Contains(u, want) {
			t.Errorf("user unit lacks %q", want)
		}
	}
	for _, bad := range []string{"User=", "ProtectSystem", "network-online"} {
		if strings.Contains(u, bad) {
			t.Errorf("user unit must not contain %q", bad)
		}
	}
	root, _ := Unit(UnitOptions{Exe: "/a/tp", Config: "/a/c.yaml", StateDir: "/root/.lighthousepro", User: "root"})
	if strings.Contains(root, "User=") {
		t.Error("root service should not set User=")
	}
}

func TestUnitRejectsBadPaths(t *testing.T) {
	cases := []UnitOptions{
		{Exe: "tailproxy", Config: "/c.yaml", StateDir: "/s"},
		{Exe: "/tp", Config: "c.yaml", StateDir: "/s"},
		{Exe: "/tp", Config: "/c$HOME.yaml", StateDir: "/s"},
		{Exe: "/tp", Config: "/c.yaml", StateDir: "/s", UserUnit: true, User: "x"},
	}
	for _, c := range cases {
		if _, err := Unit(c); err == nil {
			t.Errorf("Unit(%+v) succeeded, want error", c)
		}
	}
	u, err := Unit(UnitOptions{Exe: "/opt/my apps/tailproxy", Config: "/c.yaml", StateDir: "/s"})
	if err != nil || !strings.Contains(u, `ExecStart="/opt/my apps/tailproxy" run`) {
		t.Fatalf("path with space: %v\n%s", err, u)
	}
}
