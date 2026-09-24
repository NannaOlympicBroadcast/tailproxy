// Command tailproxy runs the tailproxy daemon. The current build serves the
// web panel (default 127.0.0.1:7708) backed by the config loader and rule
// engine; the egress manager and capture layers are not implemented yet.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/NannaOlympicBroadcast/tailproxy/internal/panel"
)

var version = "dev"

func main() {
	cfgPath := flag.String("c", "config.yaml", "path to the configuration file")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return
	}

	p, err := panel.New(*cfgPath, version)
	if err != nil {
		log.Fatalf("tailproxy: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if p.TailnetRequested() {
		log.Printf("tailproxy: warning: panel.tailnet is not implemented yet (needs the ts egress slot); the panel only listens on %s", p.Addr())
	}
	log.Printf("tailproxy %s: web panel on http://%s", version, p.Addr())
	if err := p.ListenAndServe(ctx); err != nil {
		log.Fatalf("tailproxy: panel: %v", err)
	}
}
