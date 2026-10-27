package main

import (
	"log/slog"

	tea "github.com/charmbracelet/bubbletea"
)

// loginArgs are the sign-on settings given on the command line.
type loginArgs struct {
	server, screenName, password string
}

// model is the root of the TUI. It shows the sign-on screen until the user
// signs on, then the session screen.
type model struct {
	cfg    *config
	logger *slog.Logger
	plain  bool

	width, height int

	login   *loginModel
	session *sessionModel
}

func newModel(cfg *config, logger *slog.Logger, plain bool, args loginArgs) model {
	return model{
		cfg:    cfg,
		logger: logger,
		plain:  plain,
		login:  newLoginModel(cfg, logger, args),
	}
}

func (m model) Init() tea.Cmd {
	return m.login.init()
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		if msg.Type == tea.KeyCtrlC {
			if m.session != nil {
				m.session.close()
			}
			return m, tea.Quit
		}
	case signedOnMsg:
		m.login.signedOn(msg)
		m.session = newSessionModel(m.cfg, msg, m.plain)
		return m, m.session.init()
	case signedOffMsg:
		if m.session != nil {
			m.session.close()
			m.session = nil
		}
		m.login.signedOff(msg.reason)
		return m, m.login.init()
	}

	var cmd tea.Cmd
	if m.session != nil {
		cmd = m.session.update(msg, m.width, m.height)
	} else {
		cmd = m.login.update(msg)
	}
	return m, cmd
}

func (m model) View() string {
	if m.width == 0 {
		return ""
	}
	if m.session != nil {
		return m.session.view(m.width, m.height)
	}
	return m.login.view(m.width, m.height)
}
