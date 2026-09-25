package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/token"
)

// client talks to the running tailproxy's REST API (the panel), found
// through the state file; the token comes from the same place the panel
// reads it (environment variable or persisted file).
type client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(g globals) (*client, error) {
	st, err := g.paths.Running()
	if err != nil {
		return nil, err
	}
	if st == nil {
		return nil, fmt.Errorf("tailproxy 没有在运行（状态目录 %s）；启动：tailproxy start -c config.yaml", g.paths.Dir)
	}
	var tok string
	switch {
	case os.Getenv("TAILPROXY_PANEL_TOKEN") != "":
		tok = os.Getenv("TAILPROXY_PANEL_TOKEN")
	case st.TokenEnv != "":
		if tok = os.Getenv(st.TokenEnv); tok == "" {
			return nil, fmt.Errorf("tailproxy 的令牌来自环境变量 $%s，请在当前 shell 里设置它", st.TokenEnv)
		}
	case st.TokenFile != "":
		if tok, err = token.ReadFile(st.TokenFile); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("tailproxy 使用一次性令牌（--ephemeral-token）；请用 TAILPROXY_PANEL_TOKEN 环境变量传入")
	}
	return &client{base: strings.TrimSuffix(st.URL, "/"), token: tok, http: &http.Client{Timeout: 30 * time.Second}}, nil
}

// APIError is a non-2xx answer.
type APIError struct {
	Status int
	Msg    string
	Errors []string
}

func (e *APIError) Error() string {
	if len(e.Errors) > 0 {
		return e.Msg + "：\n  " + strings.Join(e.Errors, "\n  ")
	}
	return e.Msg
}

// do sends body (JSON-encoded if not nil) and decodes the answer into out.
func (c *client) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error  string   `json:"error"`
			Errors []string `json:"errors"`
		}
		json.Unmarshal(data, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(data))
		}
		return &APIError{Status: resp.StatusCode, Msg: fmt.Sprintf("%s (HTTP %d)", e.Error, resp.StatusCode), Errors: e.Errors}
	}
	if out == nil {
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = data
		return nil
	}
	return json.Unmarshal(data, out)
}
