package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
	"github.com/NannaOlympicBroadcast/tailproxy/internal/rule"
)

// maxRulesBody bounds request bodies that carry a rule set.
const maxRulesBody = 1 << 20

type rulesUpdate struct {
	// Revision is the value from GET /api/v1/rules the edit was based on.
	Revision string        `json:"revision"`
	Rules    []config.Rule `json:"rules"`
}

// handleRulesPut validates a new rule set, writes it into the `rules:` section
// of the config file (keeping the rest of the file byte-for-byte, with a .bak
// copy of the previous file) and swaps it into the running engine.
func (s *Server) handleRulesPut(w http.ResponseWriter, r *http.Request) {
	var req rulesUpdate
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Rules == nil {
		req.Rules = []config.Rule{}
	}
	res, ok := s.saveSection(w, req.Revision,
		func(c *config.Config) { c.Rules = req.Rules },
		func(data []byte) ([]byte, error) { return config.ReplaceRules(data, req.Rules) })
	if !ok {
		return
	}
	s.ruleSaves.Add(1)
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"rules":    res.engine.Len(),
		"revision": res.revision,
		"backup":   res.backup,
	})
}

type egressUpdate struct {
	Revision string          `json:"revision"`
	Egress   []config.Egress `json:"egress"`
}

// handleEgressPut saves the `egress:` section like handleRulesPut and applies
// it to the running egress manager: new slots start, removed ones are logged
// out, changed exit nodes are switched. Rules that still point at a removed
// egress make the whole save fail validation.
func (s *Server) handleEgressPut(w http.ResponseWriter, r *http.Request) {
	var req egressUpdate
	if !decodeJSONBody(w, r, &req) {
		return
	}
	if req.Egress == nil {
		req.Egress = []config.Egress{}
	}
	res, ok := s.saveSection(w, req.Revision,
		func(c *config.Config) { c.Egress = req.Egress },
		func(data []byte) ([]byte, error) { return config.ReplaceEgress(data, req.Egress) })
	if !ok {
		return
	}
	resp := map[string]any{"ok": true, "revision": res.revision, "backup": res.backup}
	if s.runtime != nil {
		if err := s.runtime.ApplyEgress(res.cfg); err != nil {
			resp["warning"] = "配置已保存，但应用到运行中的出口时出错：" + err.Error()
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type saveResult struct {
	cfg      *config.Config
	engine   *rule.Engine
	revision string
	backup   string
}

// saveSection is the shared write path for panel edits: optimistic
// concurrency on the file revision, full validation of the edited config,
// rewrite of one top-level section only, round-trip check, .bak copy and
// atomic replace, then swap into the running state. On failure it has
// written the HTTP error and returns ok=false.
func (s *Server) saveSection(w http.ResponseWriter, revision string, mutate func(*config.Config), rewrite func([]byte) ([]byte, error)) (saveResult, bool) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	path, err := filepath.EvalSymlinks(s.cfgPath)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return saveResult{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return saveResult{}, false
	}
	s.mu.RLock()
	cfg, loadedRev := s.cfg, s.rev
	s.mu.RUnlock()
	if diskRev := config.Revision(data); revision != loadedRev || diskRev != loadedRev {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "配置文件在你开始编辑后发生了变化（手动修改、重新加载或其他会话保存）。请重新加载配置后再编辑。",
		})
		return saveResult{}, false
	}

	want := *cfg
	mutate(&want)
	if err := want.Validate(); err != nil {
		writeValidationError(w, err)
		return saveResult{}, false
	}
	engine, err := rule.Compile(want.Rules)
	if err != nil {
		writeValidationError(w, err)
		return saveResult{}, false
	}

	out, err := rewrite(data)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rewrite config: " + err.Error()})
		return saveResult{}, false
	}
	// The written file must parse back to exactly the requested config and
	// leave everything else unchanged; otherwise refuse to touch the file.
	newCfg, err := config.Parse(out)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rewritten config does not parse: " + err.Error()})
		return saveResult{}, false
	}
	if !sameJSON(newCfg, &want) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "rewritten config does not round-trip; file left unchanged"})
		return saveResult{}, false
	}

	backup := path + ".bak"
	if err := writeFileAtomic(path, backup, data, out); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return saveResult{}, false
	}

	s.mu.Lock()
	s.cfg, s.engine, s.rev = newCfg, engine, config.Revision(out)
	rev := s.rev
	s.mu.Unlock()
	return saveResult{cfg: newCfg, engine: engine, revision: rev, backup: backup}, true
}

// decodeJSONBody requires Content-Type: application/json and decodes the body
// strictly into v. On failure it has written the HTTP error.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any) bool {
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "Content-Type must be application/json"})
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRulesBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return false
	}
	return true
}

// compileDraft validates rules against the current config (egress names etc.)
// and compiles them without touching the running state.
func compileDraft(cfg *config.Config, rules []config.Rule) (*rule.Engine, error) {
	draft := *cfg
	draft.Rules = rules
	if err := draft.Validate(); err != nil {
		return nil, err
	}
	return rule.Compile(rules)
}

func writeValidationError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error":  "规则校验失败",
		"errors": strings.Split(err.Error(), "\n"),
	})
}

func sameJSON(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// writeFileAtomic saves old to backup, then replaces path with data via a
// temp file and rename so readers never see a partially written config.
func writeFileAtomic(path, backup string, old, data []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := info.Mode().Perm()
	if err := os.WriteFile(backup, old, mode); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
