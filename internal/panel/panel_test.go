package panel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfig = `
egress:
  - {name: us, exit_node: 100.101.102.103}
  - {name: jp, exit_node: tokyo-vps}
rules:
  - {domain_keyword: [openai], egress: us}
  - {ip_cidr: [203.0.113.0/24], egress: jp}
`

func newTestServer(t *testing.T, cfg string) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(path, "test")
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func do(t *testing.T, h http.Handler, method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Host = "127.0.0.1:7708"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestStaticAndStatus(t *testing.T) {
	s, _ := newTestServer(t, testConfig)
	h := s.Handler()
	if rec := do(t, h, "GET", "/", "", nil); rec.Code != 200 || !strings.Contains(rec.Body.String(), "tailproxy") {
		t.Fatalf("index: %d %q", rec.Code, rec.Body.String())
	}
	for _, f := range []string{"/app.js", "/style.css"} {
		if rec := do(t, h, "GET", f, "", nil); rec.Code != 200 {
			t.Fatalf("%s: %d", f, rec.Code)
		}
	}
	rec := do(t, h, "GET", "/api/v1/status", "", nil)
	var st map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil || rec.Code != 200 {
		t.Fatalf("status: %d %v", rec.Code, err)
	}
	if st["rules"].(float64) != 2 || st["egress_slots"].(float64) != 2 || st["auth_enabled"] != false {
		t.Fatalf("status = %v", st)
	}
}

func TestRuleTestEndpoint(t *testing.T) {
	s, _ := newTestServer(t, testConfig)
	h := s.Handler()
	tests := []struct {
		body, target string
		code         int
	}{
		{`{"domain":"chat.openai.com"}`, "us", 200},
		{`{"ip":"203.0.113.7"}`, "jp", 200},
		{`{"domain":"example.org"}`, "direct", 200},
		{`{}`, "", 400},
		{`{"ip":"nope"}`, "", 400},
		{`{"domain":"a","extra":1}`, "", 400},
	}
	for _, tt := range tests {
		rec := do(t, h, "POST", "/api/v1/rules/test", tt.body, nil)
		if rec.Code != tt.code {
			t.Fatalf("%s: code %d, body %s", tt.body, rec.Code, rec.Body.String())
		}
		if tt.code == 200 {
			var r struct{ Target string }
			json.Unmarshal(rec.Body.Bytes(), &r)
			if r.Target != tt.target {
				t.Fatalf("%s: target %q, want %q", tt.body, r.Target, tt.target)
			}
		}
	}
}

func TestHostGuardBlocksRebinding(t *testing.T) {
	s, _ := newTestServer(t, testConfig)
	req := httptest.NewRequest("GET", "/api/v1/status", nil)
	req.Host = "evil.example:7708"
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", rec.Code)
	}
	for _, host := range []string{"localhost:7708", "[::1]:7708", "127.0.0.1"} {
		if !isLoopbackHost(host) {
			t.Fatalf("isLoopbackHost(%q) = false", host)
		}
	}
}

func TestTokenAuth(t *testing.T) {
	t.Setenv("TP_TEST_TOKEN", "s3cret")
	s, _ := newTestServer(t, testConfig+"panel: {listen: '0.0.0.0:7708', auth_token_env: TP_TEST_TOKEN}\n")
	h := s.Handler()
	if rec := do(t, h, "GET", "/api/v1/status", "", nil); rec.Code != 401 {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/metrics", "", map[string]string{"Authorization": "Bearer wrong"}); rec.Code != 401 {
		t.Fatalf("wrong token: %d", rec.Code)
	}
	rec := do(t, h, "GET", "/metrics", "", map[string]string{"Authorization": "Bearer s3cret"})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "tailproxy_rules 2") {
		t.Fatalf("metrics: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, h, "GET", "/", "", nil); rec.Code != 200 {
		t.Fatalf("static page should not need a token: %d", rec.Code)
	}
}

func TestNonLoopbackRequiresToken(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("panel: {listen: '0.0.0.0:7708'}\n"), 0o600)
	if _, err := New(path, "test"); err == nil || !strings.Contains(err.Error(), "not a loopback") {
		t.Fatalf("got %v", err)
	}
}

func TestReload(t *testing.T) {
	s, path := newTestServer(t, testConfig)
	h := s.Handler()
	os.WriteFile(path, []byte(testConfig+"  - {final: jp}\n"), 0o600)
	if rec := do(t, h, "POST", "/api/v1/config/reload", "", nil); rec.Code != 200 {
		t.Fatalf("reload: %d %s", rec.Code, rec.Body.String())
	}
	rec := do(t, h, "POST", "/api/v1/rules/test", `{"domain":"example.org"}`, nil)
	if !strings.Contains(rec.Body.String(), `"target": "jp"`) {
		t.Fatalf("after reload: %s", rec.Body.String())
	}
	os.WriteFile(path, []byte("rules: [{egress: nope, domain: [a]}]\n"), 0o600)
	if rec := do(t, h, "POST", "/api/v1/config/reload", "", nil); rec.Code != 400 {
		t.Fatalf("bad reload: %d", rec.Code)
	}
	rec = do(t, h, "POST", "/api/v1/rules/test", `{"domain":"example.org"}`, nil)
	if !strings.Contains(rec.Body.String(), `"target": "jp"`) {
		t.Fatalf("failed reload must keep old rules: %s", rec.Body.String())
	}
}
