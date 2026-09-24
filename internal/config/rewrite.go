package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Revision returns a content hash of a config file, used for optimistic
// concurrency when the panel writes rules back.
func Revision(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ReplaceRules returns data with the top-level `rules:` section replaced by
// rules. Every byte outside that section is kept as is, so comments and
// formatting elsewhere survive; comments inside the old rules section do not.
// If there is no rules section, one is appended.
func ReplaceRules(data []byte, rules []Rule) ([]byte, error) {
	block, err := encodeRules(rules)
	if err != nil {
		return nil, err
	}

	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if len(doc.Content) == 0 { // empty file
		return append(withTrailingNewline(data), block...), nil
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("config root is not a mapping")
	}

	keyIdx := -1
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "rules" {
			keyIdx = i
			break
		}
	}
	if keyIdx < 0 {
		return append(withTrailingNewline(data), block...), nil
	}
	if root.Content[keyIdx].Column != 1 {
		return nil, fmt.Errorf("unsupported layout: top-level rules key is not at column 1")
	}

	lines := strings.SplitAfter(string(data), "\n")
	start := root.Content[keyIdx].Line - 1 // 0-based, inclusive
	end := len(lines) - 1                  // 0-based, inclusive
	if keyIdx+2 < len(root.Content) {
		end = root.Content[keyIdx+2].Line - 2
	}
	// Leave blank lines and comments before the next key (or at EOF) alone:
	// they belong to what follows, not to the rules.
	for end > start {
		t := strings.TrimSpace(lines[end])
		if t != "" && !strings.HasPrefix(t, "#") {
			break
		}
		end--
	}

	var out bytes.Buffer
	for _, l := range lines[:start] {
		out.WriteString(l)
	}
	out.Write(block)
	for _, l := range lines[end+1:] {
		out.WriteString(l)
	}
	return out.Bytes(), nil
}

// encodeRules renders `rules:` with one flow-style mapping per rule, matching
// the style of config.example.yaml.
func encodeRules(rules []Rule) ([]byte, error) {
	var seq yaml.Node
	if err := seq.Encode(rules); err != nil {
		return nil, err
	}
	seq.Style = 0
	for _, item := range seq.Content {
		item.Style = yaml.FlowStyle
	}
	if len(rules) == 0 {
		seq.Style = yaml.FlowStyle
	}
	top := yaml.Node{Kind: yaml.MappingNode, Content: []*yaml.Node{
		{Kind: yaml.ScalarNode, Value: "rules"},
		&seq,
	}}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&top); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func withTrailingNewline(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return append(append([]byte{}, data...), '\n')
	}
	return data
}
