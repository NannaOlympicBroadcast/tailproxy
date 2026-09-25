// Command tpctl operates a running tailproxy and, through `tpctl ts`, the
// Tailscale node tailproxy is logged in with: the official tailscale CLI is
// built in, so the machine needs no separate tailscale install (and gets
// no second tailnet device). `tpctl schema` describes the config file, the
// REST API and these commands as JSON Schema / OpenAPI / JSON for scripts
// and agents.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/service"
)

type globals struct {
	paths service.Paths
	json  bool
	yes   bool
}

func main() {
	if err := run(os.Args[0], os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "tpctl: %v\n", err)
		os.Exit(1)
	}
}

func run(argv0 string, args []string) error {
	// Installed as `tailscale` (symlink): behave like the tailscale CLI.
	if name := strings.TrimSuffix(filepath.Base(argv0), ".exe"); name == "tailscale" {
		g, err := defaultGlobals(os.Getenv("TAILPROXY_STATE_DIR"))
		if err != nil {
			return err
		}
		g.yes = true // the tailscale CLI has no such guard either
		return runTS(g, args)
	}

	fs := flag.NewFlagSet("tpctl", flag.ContinueOnError)
	dir := fs.String("state-dir", "", "")
	jsonOut := fs.Bool("json", false, "")
	yes := fs.Bool("yes", false, "")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usageText()) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 || rest[0] == "help" {
		fmt.Print(usageText())
		return nil
	}
	g, err := defaultGlobals(*dir)
	if err != nil {
		return err
	}
	g.json, g.yes = *jsonOut, *yes
	if rest[0] == "tailscale" {
		rest[0] = "ts"
	}
	c, cargs := lookup(rest)
	if c == nil {
		return fmt.Errorf("未知命令 %q（tpctl help 查看全部命令）", strings.Join(rest, " "))
	}
	return c.run(g, cargs)
}

func defaultGlobals(dir string) (globals, error) {
	if dir == "" {
		d, err := service.DefaultDir()
		if err != nil {
			return globals{}, err
		}
		dir = d
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return globals{}, err
	}
	return globals{paths: service.NewPaths(abs)}, nil
}
