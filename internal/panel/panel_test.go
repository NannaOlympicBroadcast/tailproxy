package panel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
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
	s, err := New(path, "test", Options{})
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

// authed wraps the panel handler so requests carry the panel token unless
// they set their own Authorization header.
func authed(s *Server) http.Handler {
	h := s.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+s.Token())
		}
		h.ServeHTTP(w, r)
	})
}

func TestStaticAndStatus(t *testing.T) {
	s, _ := newTestServer(t, testConfig)
	h := authed(s)
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
	if st["rules"].(float64) != 2 || st["egress_slots"].(float64) != 2 || st["token_source"] != "generated" {
		t.Fatalf("status = %v", st)
	}
}

func TestRuleTestEndpoint(t *testing.T) {
	s, _ := newTestServer(t, testConfig)
	h := authed(s)
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
		{`{"outer_sni":"cloudflare-ech.com"}`, "direct", 200},
		// A draft with an outer_sni rule; the outer name never matches domain rules.
		{`{"outer_sni":"x.cloudflare-ech.com","rules":[{"domain_suffix":["cloudflare-ech.com"],"egress":"jp"},{"outer_sni":["cloudflare-ech.com"],"egress":"us"}]}`, "us", 200},
		{`{"domain":"cloudflare-ech.com","rules":[{"outer_sni":["cloudflare-ech.com"],"egress":"us"}]}`, "direct", 200},
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
	req.Header.Set("Authorization", "Bearer "+s.Token())
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403 even with a valid token", rec.Code)
	}
	for _, host := range []string{"localhost:7708", "[::1]:7708", "127.0.0.1"} {
		if !isLoopbackHost(host) {
			t.Fatalf("isLoopbackHost(%q) = false", host)
		}
	}
}

func TestGeneratedTokenRequired(t *testing.T) {
	s, _ := newTestServer(t, testConfig)
	if len(s.Token()) != 43 || s.TokenEnv() != "" {
		t.Fatalf("token %q (env %q), want a generated 43-char token", s.Token(), s.TokenEnv())
	}
	s2, _ := newTestServer(t, testConfig)
	if s2.Token() == s.Token() {
		t.Fatal("generated tokens must differ per start")
	}
	h := s.Handler()
	for _, path := range []string{"/api/v1/status", "/api/v1/rules", "/api/v1/config", "/api/v1/egress", "/metrics"} {
		if rec := do(t, h, "GET", path, "", nil); rec.Code != 401 {
			t.Fatalf("%s without token: %d", path, rec.Code)
		}
		if rec := do(t, h, "GET", path, "", map[string]string{"Authorization": "Bearer " + s2.Token()}); rec.Code != 401 {
			t.Fatalf("%s with another run's token: %d", path, rec.Code)
		}
	}
	if rec := do(t, h, "PUT", "/api/v1/rules", `{"revision":"x","rules":[]}`, jsonHdr); rec.Code != 401 {
		t.Fatalf("save without token: %d", rec.Code)
	}
	if rec := do(t, h, "POST", "/api/v1/rules/test", `{"domain":"a.com"}`, nil); rec.Code != 401 {
		t.Fatalf("rule test without token: %d", rec.Code)
	}
	if rec := do(t, authed(s), "GET", "/api/v1/status", "", nil); rec.Code != 200 {
		t.Fatalf("with token: %d", rec.Code)
	}
	if rec := do(t, h, "GET", "/", "", nil); rec.Code != 200 {
		t.Fatalf("static login page should not need a token: %d", rec.Code)
	}
	if got := s.LoginURL(); got != "http://127.0.0.1:7708/#token="+s.Token() {
		t.Fatalf("LoginURL = %q", got)
	}
}

func TestEnvToken(t *testing.T) {
	t.Setenv("TP_TEST_TOKEN", "0123456789abcdef-fixed")
	s, _ := newTestServer(t, testConfig+"panel: {listen: '0.0.0.0:7708', auth_token_env: TP_TEST_TOKEN}\n")
	if s.Token() != "0123456789abcdef-fixed" || s.TokenEnv() != "TP_TEST_TOKEN" {
		t.Fatalf("token %q env %q", s.Token(), s.TokenEnv())
	}
	if s.URL() != "http://127.0.0.1:7708/" {
		t.Fatalf("URL for unspecified listen = %q", s.URL())
	}
	h := s.Handler()
	// Non-loopback listen: any Host is fine, the token is the access control.
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Host = "192.168.1.10:7708"
	req.Header.Set("Authorization", "Bearer 0123456789abcdef-fixed")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "tailproxy_rules 2") {
		t.Fatalf("metrics: %d %s", rec.Code, rec.Body.String())
	}
}

func TestEnvTokenUnsetFallsBackToGenerated(t *testing.T) {
	t.Setenv("TP_TEST_TOKEN", "")
	s, _ := newTestServer(t, testConfig+"panel: {auth_token_env: TP_TEST_TOKEN}\n")
	if s.TokenEnv() != "" || len(s.Token()) != 43 {
		t.Fatalf("token %q env %q", s.Token(), s.TokenEnv())
	}
}

func TestShortEnvTokenRejected(t *testing.T) {
	t.Setenv("TP_TEST_TOKEN", "short")
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("panel: {auth_token_env: TP_TEST_TOKEN}\n"), 0o600)
	if _, err := New(path, "test", Options{}); err == nil || !strings.Contains(err.Error(), "shorter than") {
		t.Fatalf("got %v", err)
	}
}

func TestReload(t *testing.T) {
	s, path := newTestServer(t, testConfig)
	h := authed(s)
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

func getRevision(t *testing.T, h http.Handler) string {
	t.Helper()
	var r struct{ Revision string }
	rec := do(t, h, "GET", "/api/v1/rules", "", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || r.Revision == "" {
		t.Fatalf("rules: %d %s", rec.Code, rec.Body.String())
	}
	return r.Revision
}

var jsonHdr = map[string]string{"Content-Type": "application/json"}

func TestSaveRules(t *testing.T) {
	cfg := "# keep this comment\n" + testConfig + "panel:\n  listen: 127.0.0.1:7708   # aligned comment\n"
	s, path := newTestServer(t, cfg)
	h := authed(s)
	rev := getRevision(t, h)
	body := `{"revision":"` + rev + `","rules":[{"domain_suffix":["example.org"],"egress":"jp"},{"final":"us"}]}`
	rec := do(t, h, "PUT", "/api/v1/rules", body, jsonHdr)
	if rec.Code != 200 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	written, _ := os.ReadFile(path)
	for _, want := range []string{"# keep this comment", "listen: 127.0.0.1:7708   # aligned comment", "- {domain_suffix: [example.org], egress: jp}", "- {final: us}"} {
		if !strings.Contains(string(written), want) {
			t.Fatalf("written file missing %q:\n%s", want, written)
		}
	}
	if bak, _ := os.ReadFile(path + ".bak"); string(bak) != cfg {
		t.Fatalf("backup mismatch:\n%s", bak)
	}
	rec = do(t, h, "POST", "/api/v1/rules/test", `{"domain":"www.example.org"}`, nil)
	if !strings.Contains(rec.Body.String(), `"target": "jp"`) {
		t.Fatalf("engine not updated: %s", rec.Body.String())
	}
	if newRev := getRevision(t, h); newRev == rev {
		t.Fatal("revision did not change after save")
	}
	// Saving again with the stale revision is a conflict.
	if rec := do(t, h, "PUT", "/api/v1/rules", body, jsonHdr); rec.Code != 409 {
		t.Fatalf("stale revision: %d", rec.Code)
	}
}

func TestSaveRulesConflictWhenFileEditedOnDisk(t *testing.T) {
	s, path := newTestServer(t, testConfig)
	h := authed(s)
	rev := getRevision(t, h)
	os.WriteFile(path, []byte(testConfig+"  - {final: jp}\n"), 0o600)
	rec := do(t, h, "PUT", "/api/v1/rules", `{"revision":"`+rev+`","rules":[]}`, jsonHdr)
	if rec.Code != 409 {
		t.Fatalf("got %d %s", rec.Code, rec.Body.String())
	}
	if data, _ := os.ReadFile(path); !strings.Contains(string(data), "final: jp") {
		t.Fatal("conflicting save must not touch the file")
	}
}

func TestSaveRulesValidation(t *testing.T) {
	s, path := newTestServer(t, testConfig)
	h := authed(s)
	rev := getRevision(t, h)
	cases := []struct {
		body string
		code int
	}{
		{`{"revision":"` + rev + `","rules":[{"domain":["a.com"],"egress":"nope"}]}`, 400},
		{`{"revision":"` + rev + `","rules":[{"final":"direct"},{"domain":["a.com"],"egress":"us"}]}`, 400},
		{`{"revision":"` + rev + `","rules":[{"domain_keyword":[" "],"egress":"us"}]}`, 400},
		{`{"revision":"` + rev + `","rules":[],"x":1}`, 400},
	}
	for _, c := range cases {
		rec := do(t, h, "PUT", "/api/v1/rules", c.body, jsonHdr)
		if rec.Code != c.code {
			t.Fatalf("%s: got %d %s", c.body, rec.Code, rec.Body.String())
		}
	}
	if rec := do(t, h, "PUT", "/api/v1/rules", `{"revision":"`+rev+`","rules":[]}`, map[string]string{"Content-Type": "text/plain"}); rec.Code != 415 {
		t.Fatalf("wrong content type: %d", rec.Code)
	}
	if data, _ := os.ReadFile(path); string(data) != testConfig {
		t.Fatal("rejected saves must not touch the file")
	}
	if _, err := os.Stat(path + ".bak"); !os.IsNotExist(err) {
		t.Fatal("rejected saves must not write a backup")
	}
}

func TestCrossSiteWritesRefused(t *testing.T) {
	s, _ := newTestServer(t, testConfig)
	h := authed(s)
	rev := getRevision(t, h)
	body := `{"revision":"` + rev + `","rules":[]}`
	for _, hdr := range []map[string]string{
		{"Content-Type": "application/json", "Origin": "https://evil.example"},
		{"Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"},
	} {
		if rec := do(t, h, "PUT", "/api/v1/rules", body, hdr); rec.Code != 403 {
			t.Fatalf("%v: got %d", hdr, rec.Code)
		}
	}
	if rec := do(t, h, "POST", "/api/v1/config/reload", "", map[string]string{"Origin": "http://evil.example"}); rec.Code != 403 {
		t.Fatalf("cross-site reload: %d", rec.Code)
	}
	same := map[string]string{"Content-Type": "application/json", "Origin": "http://127.0.0.1:7708", "Sec-Fetch-Site": "same-origin"}
	if rec := do(t, h, "PUT", "/api/v1/rules", body, same); rec.Code != 200 {
		t.Fatalf("same-origin save: %d %s", rec.Code, rec.Body.String())
	}
}

func TestRuleTestWithDraft(t *testing.T) {
	s, _ := newTestServer(t, testConfig)
	h := authed(s)
	rec := do(t, h, "POST", "/api/v1/rules/test", `{"domain":"chat.openai.com","rules":[{"domain_keyword":["openai"],"egress":"jp"}]}`, nil)
	if !strings.Contains(rec.Body.String(), `"target": "jp"`) {
		t.Fatalf("draft: %s", rec.Body.String())
	}
	rec = do(t, h, "POST", "/api/v1/rules/test", `{"domain":"chat.openai.com"}`, nil)
	if !strings.Contains(rec.Body.String(), `"target": "us"`) {
		t.Fatalf("running rules must be unchanged: %s", rec.Body.String())
	}
	if rec := do(t, h, "POST", "/api/v1/rules/test", `{"domain":"a","rules":[{"domain":["a"],"egress":"nope"}]}`, nil); rec.Code != 400 {
		t.Fatalf("invalid draft: %d", rec.Code)
	}
}

// testRuntime is a test double for the running proxy: it records what the
// panel asks it to do.
type testRuntime struct {
	applied []*config.Config
	key     string
	peers   any
	relay   map[string]string
}

func (r *testRuntime) Components() []Component { return nil }
func (r *testRuntime) Egress() any             { return []any{} }
func (r *testRuntime) Connections() any        { return map[string]any{} }
func (r *testRuntime) Tailnet(context.Context) (any, any, error) {
	return map[string]any{"main": map[string]string{"state": "ready"}, "auto_login": r.key != ""}, r.peers, nil
}
func (r *testRuntime) ApplyEgress(c *config.Config) error {
	r.applied = append(r.applied, c)
	return nil
}
func (r *testRuntime) SetAuthKey(k string) error {
	if !strings.HasPrefix(k, "tskey-") {
		return errors.New("bad key")
	}
	r.key = k
	return nil
}
func (r *testRuntime) ClearAuthKey() error { r.key = ""; return nil }
func (r *testRuntime) SetRelayToken(name, tok string) error {
	if name != "us" || len(tok) < 16 {
		return errors.New("bad relay token")
	}
	if r.relay == nil {
		r.relay = map[string]string{}
	}
	r.relay[name] = tok
	return nil
}

func egressRevision(t *testing.T, h http.Handler) string {
	t.Helper()
	var r struct{ Revision string }
	rec := do(t, h, "GET", "/api/v1/egress", "", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || r.Revision == "" {
		t.Fatalf("egress: %d %s", rec.Code, rec.Body.String())
	}
	return r.Revision
}

func TestSaveEgressAppliesAndWrites(t *testing.T) {
	s, path := newTestServer(t, "# top\n"+testConfig)
	rt := &testRuntime{}
	s.SetRuntime(rt)
	h := authed(s)
	rev := egressRevision(t, h)
	body := `{"revision":"` + rev + `","egress":[{"name":"us","exit_node":"ser647557941975"},{"name":"jp","exit_node":"tokyo-vps"},{"name":"cn","exit_node":"VM-0-5-opencloudos"}]}`
	rec := do(t, h, "PUT", "/api/v1/egress", body, jsonHdr)
	if rec.Code != 200 {
		t.Fatalf("save: %d %s", rec.Code, rec.Body.String())
	}
	data, _ := os.ReadFile(path)
	for _, want := range []string{"# top", "- {name: cn, exit_node: VM-0-5-opencloudos}", "- {domain_keyword: [openai], egress: us}"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("file lacks %q:\n%s", want, data)
		}
	}
	if len(rt.applied) != 1 || len(rt.applied[0].Egress) != 3 {
		t.Fatalf("runtime not updated: %+v", rt.applied)
	}

	// Removing an egress that rules still use fails validation; nothing changes.
	rev = egressRevision(t, h)
	rec = do(t, h, "PUT", "/api/v1/egress", `{"revision":"`+rev+`","egress":[{"name":"us","exit_node":"x"}]}`, jsonHdr)
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), `unknown target \"jp\"`) {
		t.Fatalf("remove referenced egress: %d %s", rec.Code, rec.Body.String())
	}
	if len(rt.applied) != 1 {
		t.Fatal("failed save must not touch the runtime")
	}
	if rec := do(t, h, "PUT", "/api/v1/egress", `{"revision":"stale","egress":[]}`, jsonHdr); rec.Code != 409 {
		t.Fatalf("stale revision: %d", rec.Code)
	}
}

func TestTailnetAndAuthKeyEndpoints(t *testing.T) {
	s, _ := newTestServer(t, testConfig)
	rt := &testRuntime{peers: []map[string]any{{"name": "ser647557941975", "online": true, "exit_node_option": true}}}
	s.SetRuntime(rt)
	h := authed(s)
	rec := do(t, h, "GET", "/api/v1/tailnet", "", nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "ser647557941975") {
		t.Fatalf("tailnet: %d %s", rec.Code, rec.Body.String())
	}
	if rec := do(t, h, "PUT", "/api/v1/tailnet/authkey", `{"auth_key":"nope"}`, jsonHdr); rec.Code != 400 {
		t.Fatalf("bad key: %d", rec.Code)
	}
	if rec := do(t, h, "PUT", "/api/v1/tailnet/authkey", `{"auth_key":"tskey-auth-k1-abc"}`, jsonHdr); rec.Code != 200 || rt.key != "tskey-auth-k1-abc" {
		t.Fatalf("set key: %d %q", rec.Code, rt.key)
	}
	if rec := do(t, h, "DELETE", "/api/v1/tailnet/authkey", "", nil); rec.Code != 200 || rt.key != "" {
		t.Fatalf("clear key: %d %q", rec.Code, rt.key)
	}
	if rec := do(t, s.Handler(), "GET", "/api/v1/tailnet", "", nil); rec.Code != 401 {
		t.Fatalf("tailnet without token: %d", rec.Code)
	}
	if rec := do(t, h, "PUT", "/api/v1/egress/us/relay-token", `{"token":"short"}`, jsonHdr); rec.Code != 400 {
		t.Fatalf("short relay token: %d", rec.Code)
	}
	if rec := do(t, h, "PUT", "/api/v1/egress/us/relay-token", `{"token":"relay-token-0123456789"}`, jsonHdr); rec.Code != 200 || rt.relay["us"] != "relay-token-0123456789" {
		t.Fatalf("relay token: %d %v", rec.Code, rt.relay)
	}
	if rec := do(t, s.Handler(), "PUT", "/api/v1/egress/us/relay-token", `{"token":"relay-token-0123456789"}`, jsonHdr); rec.Code != 401 {
		t.Fatalf("relay token without auth: %d", rec.Code)
	}
}

func TestReloadAppliesEgress(t *testing.T) {
	s, path := newTestServer(t, testConfig)
	rt := &testRuntime{}
	s.SetRuntime(rt)
	h := authed(s)
	os.WriteFile(path, []byte(strings.Replace(testConfig, "tokyo-vps", "osaka-vps", 1)), 0o600)
	rec := do(t, h, "POST", "/api/v1/config/reload", "", nil)
	if rec.Code != 200 || len(rt.applied) != 1 || rt.applied[0].Egress[1].ExitNode != "osaka-vps" {
		t.Fatalf("reload: %d %s applied=%d", rec.Code, rec.Body.String(), len(rt.applied))
	}
	if strings.Contains(rec.Body.String(), "重启") {
		t.Fatalf("egress changes must not ask for a restart: %s", rec.Body.String())
	}
}
