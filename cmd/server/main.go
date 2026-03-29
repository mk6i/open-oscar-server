package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/sync/errgroup"

	"github.com/mk6i/open-oscar-server/server/webapi"
)

var (
	// default build fields populated by GoReleaser
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func init() {
	cfgFile := flag.String("config", "settings.env", "Path to config file")
	showHelp := flag.Bool("help", false, "Display help")
	showVersion := flag.Bool("version", false, "Display build information")

	flag.Parse()

	switch {
	case *showVersion:
		fmt.Printf("%-10s %s\n", "version:", version)
		fmt.Printf("%-10s %s\n", "commit:", commit)
		fmt.Printf("%-10s %s\n", "date:", date)
		os.Exit(0)
	case *showHelp:
		flag.PrintDefaults()
		os.Exit(0)
	}

	// optionally populate environment variables with config file
	if err := godotenv.Load(*cfgFile); err != nil {
		fmt.Printf("Config file (%s) not found, defaulting to env vars for app config...\n", *cfgFile)
	} else {
		fmt.Printf("Successfully loaded config file (%s)\n", *cfgFile)
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	deps, err := MakeCommonDeps()
	if err != nil {
		fmt.Printf("startup failed: %s\n", err)
		os.Exit(1)
	}

	g, ctx := errgroup.WithContext(ctx)

	oscar := OSCAR(deps)
	g.Go(oscar.ListenAndServe)

	kerb := KerberosAPI(deps)
	g.Go(kerb.ListenAndServe)

	api := MgmtAPI(deps)
	g.Go(api.ListenAndServe)

	toc := TOC(deps)
	g.Go(toc.ListenAndServe)

	var webAPI *webapi.Server
	if os.Getenv("ENABLE_WEBAPI") == "1" {
		webAPI = WebAPI(deps)
		g.Go(webAPI.ListenAndServe)
	}

	// Start ICQ Legacy server if enabled
	icqLegacy := ICQLegacy(deps)
	if deps.cfg.ICQLegacy.Enabled {
		g.Go(icqLegacy.ListenAndServe)
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = oscar.Shutdown(shutdownCtx)
		_ = kerb.Shutdown(shutdownCtx)
		_ = api.Shutdown(shutdownCtx)
		_ = toc.Shutdown(shutdownCtx)
		if os.Getenv("ENABLE_WEBAPI") == "1" {
			_ = webAPI.Shutdown(shutdownCtx)
		}
		if deps.cfg.ICQLegacy.Enabled {
			_ = icqLegacy.Shutdown(shutdownCtx)
		}
	}

	if err = g.Wait(); err != nil {
		deps.logger.Error("server initialization failed", "err", err.Error())
		os.Exit(1)
	}
}
