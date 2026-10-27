// Command tui_client is an interactive terminal OSCAR client for testing Open
// OSCAR Server. It supports the buddy list, instant messages, chat rooms,
// profiles, away messages, blocking and warning.
//
// Usage:
//
//	go run ./cmd/tui_client [-server host:port] [-screenname name] [-password pass]
//
// When the server, screen name and password are all given, the client signs
// on right away. Otherwise it shows a sign-on screen, which also lists the
// screen names saved in the config file.
package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	var (
		server     = flag.String("server", "", "OSCAR server address (host:port)")
		screenName = flag.String("screenname", "", "screen name to sign on with")
		password   = flag.String("password", "", "password to sign on with")
		configPath = flag.String("config", defaultConfigPath(), "path of the config file that remembers screen names")
		plain      = flag.Bool("plain", false, "strip HTML formatting instead of rendering it with terminal colors")
		logPath    = flag.String("log", "", "write debug logs to this file")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unable to open log file: %v\n", err)
			os.Exit(1)
		}
		defer func() { _ = f.Close() }()
		logger = slog.New(slog.NewTextHandler(f, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to load config: %v\n", err)
		os.Exit(1)
	}

	m := newModel(cfg, logger, *plain, loginArgs{
		server:     *server,
		screenName: *screenName,
		password:   *password,
	})
	if _, err := tea.NewProgram(m, tea.WithAltScreen()).Run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}
