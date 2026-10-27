package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// helpText lists the slash commands.
var helpText = []string{
	"Commands (screen names are typed without spaces):",
	"  /im <name> [message]     open a conversation, optionally sending a message",
	"  /info [name]             view a user's info and profile",
	"  /add <name> [group]      add a buddy (default group: Buddies)",
	"  /remove <name>           remove a buddy",
	"  /block <name>            block a user",
	"  /unblock <name>          unblock a user",
	"  /blocks                  list blocked users",
	"  /warn [name]             warn a user who recently messaged you",
	"  /warnanon [name]         warn anonymously",
	"  /profile                 edit your profile",
	"  /font                    show your message style; see /font help to change it",
	"  /away [message]          set an away message",
	"  /back                    clear your away message",
	"  /join <room>             join or create a chat room",
	"  /invite <name> [message] invite a user to the current chat room",
	"  /accept                  join the room of the last chat invitation",
	"  /users                   list the users in the current chat room",
	"  /leave                   leave the current chat room",
	"  /close                   close the current window",
	"  /signoff                 sign off and return to the sign-on screen",
	"  /quit                    sign off and exit",
	"Keys: Tab toggles the buddy list, Ctrl+N/Ctrl+P switch windows, Ctrl+W closes",
	"a window, PgUp/PgDn scroll. In the buddy list: Enter IMs, i shows info, w warns,",
	"b blocks or unblocks, d removes.",
	"Messages may contain formatting HTML such as <b>bold</b>, <i>, <u>, <s>,",
	"<font color=\"red\">, <a href=\"...\"> and <br>. Other text is sent as typed.",
}

// fontHelp describes the /font command.
var fontHelp = []string{
	"Your message style is applied to every IM and chat message you send:",
	"  /font                    show your style with a sample",
	"  /font color <color>      text color: a name such as red, or #RRGGBB",
	"  /font back <color>       background color",
	"  /font face <font name>   font face, such as Arial or Comic Sans MS",
	"  /font size <1-7>         font size (AIM's default is 2)",
	"  /font bold|italic|underline [on|off]   toggle a style",
	"  /font <setting> none     clear a color, face or size",
	"  /font reset              clear your whole style",
}

// runCommand runs a slash command typed into the input.
func (s *sessionModel) runCommand(line string) tea.Cmd {
	fields := strings.Fields(line)
	cmd, args := strings.ToLower(fields[0]), fields[1:]
	rest := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))

	// target returns the screen name argument, defaulting to the active
	// window's correspondent.
	target := func() (string, bool) {
		if len(args) > 0 {
			return args[0], true
		}
		if w := s.current(); (w.kind == winIM || w.kind == winInfo) && w.peer != "" {
			return w.peer, true
		}
		s.notify(fmt.Sprintf("Usage: %s <screen name>", cmd), true)
		return "", false
	}

	switch cmd {
	case "/help", "/?":
		w := s.windows[0]
		for _, h := range helpText {
			w.add(h)
		}
		s.activate(w)
	case "/im", "/msg":
		if len(args) == 0 {
			s.notify("Usage: /im <screen name> [message]", true)
			return nil
		}
		s.activate(s.imWindow(args[0]))
		if msg := strings.TrimSpace(strings.TrimPrefix(rest, args[0])); msg != "" {
			return s.sendIM(args[0], s.compose(msg), false)
		}
	case "/info", "/whois":
		if sn, ok := target(); ok {
			return s.getInfo(sn)
		}
	case "/add":
		if len(args) == 0 {
			s.notify("Usage: /add <screen name> [group]", true)
			return nil
		}
		return s.addBuddy(strings.Join(args[1:], " "), args[0])
	case "/remove", "/del":
		if sn, ok := target(); ok {
			return s.removeBuddy(sn)
		}
	case "/block":
		if sn, ok := target(); ok {
			return s.block(sn)
		}
	case "/unblock":
		if sn, ok := target(); ok {
			return s.unblock(sn)
		}
	case "/blocks":
		blocked := s.client.BlockList()
		if len(blocked) == 0 {
			s.notify("You aren't blocking anyone.", false)
		} else {
			s.notify("Blocked: "+strings.Join(blocked, ", "), false)
		}
	case "/warn", "/evil":
		if sn, ok := target(); ok {
			return s.warn(sn, false)
		}
	case "/warnanon":
		if sn, ok := target(); ok {
			return s.warn(sn, true)
		}
	case "/profile":
		s.editor.SetValue(s.client.Profile())
		s.editor.Focus()
		s.input.Blur()
		s.editing = true
		return nil
	case "/font":
		return s.fontCommand(args)
	case "/away":
		msg := rest
		if msg == "" {
			if a := s.account(); a != nil && a.AwayMessage != "" {
				msg = a.AwayMessage
			} else {
				msg = defaultAwayMessage
			}
		}
		if err := s.client.SetAway(msg); err != nil {
			s.notify("Unable to set away message: "+err.Error(), true)
			return nil
		}
		s.awayReplied = make(map[string]bool)
		if a := s.account(); a != nil {
			a.AwayMessage = msg
			_ = s.cfg.save()
		}
		s.notify("You are away: "+s.render(msg), false)
	case "/back":
		if err := s.client.SetAway(""); err != nil {
			s.notify("Unable to clear away message: "+err.Error(), true)
			return nil
		}
		s.notify("You are back.", false)
	case "/join":
		if rest == "" {
			s.notify("Usage: /join <room name>", true)
			return nil
		}
		return s.joinChat(rest)
	case "/invite":
		w := s.current()
		if w.kind != winChat || w.room == nil {
			s.notify("Switch to a chat room window to invite someone.", true)
			return nil
		}
		if len(args) == 0 {
			s.notify("Usage: /invite <screen name> [message]", true)
			return nil
		}
		msg := strings.TrimSpace(strings.TrimPrefix(rest, args[0]))
		if msg == "" {
			msg = "Join me in this chat."
		}
		room, sn := w.room, args[0]
		return s.do(w.key, func(ctx context.Context) (string, error) {
			if err := room.Invite(ctx, sn, msg); err != nil {
				return "Unable to invite " + sn, err
			}
			return "Invited " + sn + ".", nil
		})
	case "/accept":
		if s.lastInvite == nil {
			s.notify("You have no pending chat invitations.", true)
			return nil
		}
		inv := *s.lastInvite
		s.lastInvite = nil
		return s.acceptInvite(inv)
	case "/users", "/names":
		w := s.current()
		if w.kind != winChat || w.room == nil {
			s.notify("Switch to a chat room window to list its users.", true)
			return nil
		}
		users := w.room.Users()
		w.add(dimStyle.Render(fmt.Sprintf("%d in room: %s", len(users), strings.Join(users, ", "))))
	case "/leave", "/part":
		w := s.current()
		if w.kind != winChat {
			s.notify("Switch to a chat room window to leave it.", true)
			return nil
		}
		s.closeWindow(s.active)
	case "/close":
		s.closeWindow(s.active)
	case "/signoff":
		return func() tea.Msg { return signedOffMsg{reason: "Signed off."} }
	case "/quit", "/exit":
		s.close()
		return tea.Quit
	default:
		s.notify(fmt.Sprintf("Unknown command %s. Type /help for a list of commands.", cmd), true)
	}
	return nil
}

// fontCommand runs /font, which shows or changes the user's message style.
func (s *sessionModel) fontCommand(args []string) tea.Cmd {
	a := s.account()
	if a == nil {
		s.notify("Your account isn't saved, so your style can't be changed.", true)
		return nil
	}
	if len(args) == 0 {
		s.notify("Your style: "+a.Font.describe()+". Sample: "+s.render(a.Font.wrap("The quick brown fox")), false)
		return nil
	}

	f := a.Font
	setting, value := strings.ToLower(args[0]), strings.Join(args[1:], " ")
	clear := strings.EqualFold(value, "none")
	toggle := func(cur bool) (bool, bool) {
		switch strings.ToLower(value) {
		case "":
			return !cur, true
		case "on", "yes", "true":
			return true, true
		case "off", "no", "false":
			return false, true
		}
		return cur, false
	}

	var ok bool
	switch setting {
	case "help":
		w := s.windows[0]
		for _, h := range fontHelp {
			w.add(h)
		}
		s.activate(w)
		return nil
	case "reset":
		f, ok = fontStyle{}, true
	case "color", "colour", "back", "background":
		var c string
		if clear {
			ok = true
		} else {
			c, ok = normalizeColor(value)
		}
		if setting == "color" || setting == "colour" {
			f.Color = c
		} else {
			f.Back = c
		}
	case "face":
		f.Face, ok = value, value != ""
		if clear {
			f.Face = ""
		}
	case "size":
		if clear {
			f.Size, ok = 0, true
		} else if n, err := strconv.Atoi(value); err == nil && n >= 1 && n <= 7 {
			f.Size, ok = n, true
		}
	case "bold":
		f.Bold, ok = toggle(f.Bold)
	case "italic":
		f.Italic, ok = toggle(f.Italic)
	case "underline":
		f.Underline, ok = toggle(f.Underline)
	default:
		s.notify("Unknown /font setting "+setting+". Type /font help for usage.", true)
		return nil
	}
	if !ok {
		s.notify(fmt.Sprintf("Invalid value %q for /font %s. Type /font help for usage.", value, setting), true)
		return nil
	}

	a.Font = f
	if err := s.cfg.save(); err != nil {
		s.notify("Unable to save config: "+err.Error(), true)
	}
	s.notify("Your style: "+f.describe()+". Sample: "+s.render(f.wrap("The quick brown fox")), false)
	return nil
}
