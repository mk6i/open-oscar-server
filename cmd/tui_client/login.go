package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/mk6i/open-oscar-server/client"
)

// clientIdentity is the client name reported to the server.
const clientIdentity = "Open OSCAR TUI"

// signOnTimeout bounds how long signing on may take.
const signOnTimeout = 30 * time.Second

// signedOnMsg reports a successful signon.
type signedOnMsg struct {
	client       *client.Client
	server       string
	screenName   string
	password     string
	savePassword bool
}

// loginFailedMsg reports a failed signon.
type loginFailedMsg struct {
	err error
}

// signedOffMsg returns to the sign-on screen.
type signedOffMsg struct {
	reason string
}

// Fields of the sign-on form, in focus order.
const (
	focusAccounts = iota
	focusServer
	focusScreenName
	focusPassword
	focusSavePassword
	focusCount
)

// loginModel is the sign-on screen.
type loginModel struct {
	cfg    *config
	logger *slog.Logger

	cursor       int
	inputs       [focusCount]textinput.Model
	savePassword bool
	focus        int

	busy       bool
	status     string
	autoSignon bool
}

func newLoginModel(cfg *config, logger *slog.Logger, args loginArgs) *loginModel {
	l := &loginModel{cfg: cfg, logger: logger}
	for i := focusServer; i <= focusPassword; i++ {
		in := textinput.New()
		in.Prompt = ""
		in.Width = 32
		in.CharLimit = 64
		l.inputs[i] = in
	}
	l.inputs[focusServer].Placeholder = client.DefaultServer
	l.inputs[focusScreenName].Placeholder = "screen name"
	l.inputs[focusPassword].Placeholder = "password"
	l.inputs[focusPassword].EchoMode = textinput.EchoPassword
	l.inputs[focusPassword].EchoCharacter = '•'

	l.cursor = cfg.last()
	if l.cursor < 0 && len(cfg.Accounts) > 0 {
		l.cursor = 0
	}
	if l.cursor >= 0 {
		l.selectAccount(l.cursor)
	} else {
		l.inputs[focusServer].SetValue(client.DefaultServer)
	}

	// command line flags override the saved account
	if args.server != "" {
		l.inputs[focusServer].SetValue(args.server)
	}
	if args.screenName != "" {
		l.inputs[focusScreenName].SetValue(args.screenName)
		if args.password == "" {
			l.inputs[focusPassword].SetValue("")
			if a := cfg.find(l.value(focusServer), args.screenName); a != nil {
				l.inputs[focusPassword].SetValue(a.Password)
			}
		}
	}
	if args.password != "" {
		l.inputs[focusPassword].SetValue(args.password)
	}
	l.autoSignon = args.screenName != "" && l.value(focusPassword) != ""

	switch {
	case l.value(focusScreenName) == "":
		l.setFocus(focusScreenName)
	default:
		l.setFocus(focusPassword)
	}
	return l
}

func (l *loginModel) init() tea.Cmd {
	if l.autoSignon {
		l.autoSignon = false
		return l.signOn()
	}
	return textinput.Blink
}

func (l *loginModel) value(field int) string {
	return strings.TrimSpace(l.inputs[field].Value())
}

// selectAccount fills the form from saved account i.
func (l *loginModel) selectAccount(i int) {
	a := l.cfg.Accounts[i]
	l.inputs[focusServer].SetValue(a.Server)
	l.inputs[focusScreenName].SetValue(a.ScreenName)
	l.inputs[focusPassword].SetValue(a.Password)
	l.savePassword = a.Password != ""
}

func (l *loginModel) setFocus(f int) {
	if f == focusAccounts && len(l.cfg.Accounts) == 0 {
		f = focusServer
	}
	l.focus = f
	for i := focusServer; i <= focusPassword; i++ {
		if i == f {
			l.inputs[i].Focus()
		} else {
			l.inputs[i].Blur()
		}
	}
}

func (l *loginModel) moveFocus(delta int) {
	f := (l.focus + delta + focusCount) % focusCount
	if f == focusAccounts && len(l.cfg.Accounts) == 0 {
		f = (f + delta + focusCount) % focusCount
	}
	l.setFocus(f)
}

// signOn validates the form and starts signing on.
func (l *loginModel) signOn() tea.Cmd {
	server := l.value(focusServer)
	if server == "" {
		server = client.DefaultServer
		l.inputs[focusServer].SetValue(server)
	}
	screenName := l.value(focusScreenName)
	password := l.inputs[focusPassword].Value()
	if screenName == "" || password == "" {
		l.status = "Enter a screen name and password."
		return nil
	}

	var profile string
	if a := l.cfg.find(server, screenName); a != nil {
		profile = a.Profile
	}

	l.busy = true
	l.status = fmt.Sprintf("Signing on to %s as %s...", server, screenName)
	savePassword := l.savePassword
	logger := l.logger
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), signOnTimeout)
		defer cancel()
		c, err := client.Dial(ctx, client.Config{
			Server:         server,
			ScreenName:     screenName,
			Password:       password,
			ClientIdentity: clientIdentity,
			Profile:        profile,
			Logger:         logger,
		})
		if err != nil {
			return loginFailedMsg{err: err}
		}
		return signedOnMsg{
			client:       c,
			server:       server,
			screenName:   screenName,
			password:     password,
			savePassword: savePassword,
		}
	}
}

// signedOn saves the account that signed on.
func (l *loginModel) signedOn(msg signedOnMsg) {
	l.busy = false
	l.status = ""
	l.cfg.remember(msg.server, msg.screenName, msg.password, msg.savePassword)
	l.cursor = l.cfg.last()
	_ = l.cfg.save()
}

// signedOff shows the sign-on screen again.
func (l *loginModel) signedOff(reason string) {
	l.busy = false
	l.status = reason
	if l.cursor >= 0 && l.cursor < len(l.cfg.Accounts) {
		l.selectAccount(l.cursor)
	}
	l.setFocus(focusPassword)
}

func (l *loginModel) update(msg tea.Msg) tea.Cmd {
	switch msg := msg.(type) {
	case loginFailedMsg:
		l.busy = false
		l.status = "Sign on failed: " + msg.err.Error()
		return nil
	case tea.KeyMsg:
		if l.busy {
			return nil
		}
		switch msg.String() {
		case "esc":
			return tea.Quit
		case "tab":
			l.moveFocus(1)
			return nil
		case "shift+tab":
			l.moveFocus(-1)
			return nil
		case "enter":
			if l.focus == focusAccounts && l.cursor >= 0 {
				l.selectAccount(l.cursor)
				if l.value(focusPassword) == "" {
					l.setFocus(focusPassword)
					return nil
				}
			}
			return l.signOn()
		}

		switch l.focus {
		case focusAccounts:
			switch msg.String() {
			case "up", "k":
				if l.cursor > 0 {
					l.cursor--
					l.selectAccount(l.cursor)
				}
			case "down", "j":
				if l.cursor < len(l.cfg.Accounts)-1 {
					l.cursor++
					l.selectAccount(l.cursor)
				}
			case "ctrl+d", "delete":
				l.cfg.remove(l.cursor)
				if err := l.cfg.save(); err != nil {
					l.status = "Unable to save config: " + err.Error()
				}
				if l.cursor >= len(l.cfg.Accounts) {
					l.cursor = len(l.cfg.Accounts) - 1
				}
				if l.cursor >= 0 {
					l.selectAccount(l.cursor)
				} else {
					l.setFocus(focusServer)
				}
			}
			return nil
		case focusSavePassword:
			switch msg.String() {
			case " ", "x":
				l.savePassword = !l.savePassword
			case "up":
				l.moveFocus(-1)
			}
			return nil
		default:
			switch msg.String() {
			case "up":
				l.moveFocus(-1)
				return nil
			case "down":
				l.moveFocus(1)
				return nil
			}
			var cmd tea.Cmd
			l.inputs[l.focus], cmd = l.inputs[l.focus].Update(msg)
			return cmd
		}
	}

	if l.focus >= focusServer && l.focus <= focusPassword {
		var cmd tea.Cmd
		l.inputs[l.focus], cmd = l.inputs[l.focus].Update(msg)
		return cmd
	}
	return nil
}

func (l *loginModel) view(width, height int) string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Open OSCAR — Sign On"))
	b.WriteString("\n\n")

	if len(l.cfg.Accounts) > 0 {
		label := "Saved screen names"
		if l.focus == focusAccounts {
			label = focusedLabelStyle.Render(label)
		} else {
			label = labelStyle.Render(label)
		}
		b.WriteString(label + "\n")
		for i, a := range l.cfg.Accounts {
			line := fmt.Sprintf("%s @ %s", a.ScreenName, a.Server)
			if a.Password != "" {
				line += dimStyle.Render("  (password saved)")
			}
			if i == l.cursor {
				marker := "  "
				if l.focus == focusAccounts {
					marker = "> "
					line = selectedStyle.Render(line)
				}
				b.WriteString(marker + line + "\n")
			} else {
				b.WriteString("  " + line + "\n")
			}
		}
		b.WriteString("\n")
	}

	labels := map[int]string{
		focusServer:     "Server",
		focusScreenName: "Screen name",
		focusPassword:   "Password",
	}
	for f := focusServer; f <= focusPassword; f++ {
		label := fmt.Sprintf("%-12s", labels[f])
		if l.focus == f {
			label = focusedLabelStyle.Render(label)
		} else {
			label = labelStyle.Render(label)
		}
		b.WriteString(label + " " + inputBoxStyle.Render(l.inputs[f].View()) + "\n")
	}

	check := "[ ]"
	if l.savePassword {
		check = "[x]"
	}
	saveLine := check + " Save password"
	if l.focus == focusSavePassword {
		saveLine = focusedLabelStyle.Render(saveLine)
	}
	b.WriteString("\n" + saveLine + "\n\n")

	if l.status != "" {
		style := statusStyle
		if strings.HasPrefix(l.status, "Sign on failed") || strings.HasPrefix(l.status, "Disconnected") {
			style = errorStyle
		}
		b.WriteString(style.Render(l.status) + "\n\n")
	}

	help := "Enter: sign on • Tab: next field • Space: toggle • Esc: quit"
	if len(l.cfg.Accounts) > 0 {
		help += " • Del: forget saved screen name"
	}
	b.WriteString(dimStyle.Render(help))

	box := boxStyle.Width(min(72, width-4)).Render(b.String())
	return lipgloss.Place(width, height, lipgloss.Center, lipgloss.Center, box)
}
