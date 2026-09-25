package schema

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/config"
)

func TestEveryConfigFieldDocumented(t *testing.T) {
	var missing []string
	undocumented(reflect.TypeOf(config.Config{}), "", &missing)
	if len(missing) > 0 {
		t.Fatalf("config fields without schema description: %v", missing)
	}
}

// Every key in config.example.yaml must exist in the schema (the parser
// rejects unknown keys, so the schema must know them all).
func TestExampleConfigKeysInSchema(t *testing.T) {
	data, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var walk func(v any, s map[string]any, path string)
	walk = func(v any, s map[string]any, path string) {
		switch x := v.(type) {
		case map[string]any:
			props, _ := s["properties"].(map[string]any)
			for k, vv := range x {
				ps, ok := props[k].(map[string]any)
				if !ok {
					t.Errorf("%s.%s is not in the schema", path, k)
					continue
				}
				walk(vv, ps, path+"."+k)
			}
		case []any:
			items, _ := s["items"].(map[string]any)
			for _, it := range x {
				walk(it, items, path+"[]")
			}
		}
	}
	walk(doc, Config(), "")
}

func TestEgressNamePatternMatchesValidator(t *testing.T) {
	re := regexp.MustCompile(fields["egress[].name"].pattern)
	for _, n := range []string{"us", "a", "cn-2", "x-", strings.Repeat("a", 40), strings.Repeat("a", 41), "-x", "Us", "u_s", ""} {
		if re.MatchString(n) != config.ValidEgressName(n) {
			t.Errorf("%q: pattern %v, validator %v", n, re.MatchString(n), config.ValidEgressName(n))
		}
	}
}

// The OpenAPI document must list exactly the routes the panel serves.
func TestAPICoversPanelRoutes(t *testing.T) {
	src, err := os.ReadFile("../panel/panel.go")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, m := range regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+) ([^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		want = append(want, strings.ToLower(m[1])+" "+m[2])
	}
	var got []string
	for p, ops := range API()["paths"].(map[string]any) {
		for method := range ops.(map[string]any) {
			got = append(got, method+" "+p)
		}
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, "\n") != strings.Join(got, "\n") {
		t.Fatalf("panel routes:\n%s\n\nOpenAPI paths:\n%s", strings.Join(want, "\n"), strings.Join(got, "\n"))
	}
	if _, err := json.Marshal(API()); err != nil {
		t.Fatal(err)
	}
}
