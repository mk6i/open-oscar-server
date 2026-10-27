package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/mk6i/open-oscar-server/client"
)

// account is a saved screen name.
type account struct {
	Server     string `json:"server"`
	ScreenName string `json:"screen_name"`
	// Password is only stored if the user asked to save it.
	Password string `json:"password,omitempty"`
	// Profile is set at each signon, since OSCAR clients store their
	// profiles locally.
	Profile string `json:"profile,omitempty"`
	// AwayMessage is the last away message used.
	AwayMessage string `json:"away_message,omitempty"`
}

// matches reports whether a is the account for server and screenName.
func (a account) matches(server, screenName string) bool {
	return a.Server == server && client.NormalizeScreenName(a.ScreenName) == client.NormalizeScreenName(screenName)
}

// config is the TUI client's saved settings.
type config struct {
	// LastServer and LastScreenName identify the last account used, which
	// is preselected at the next start.
	LastServer     string    `json:"last_server,omitempty"`
	LastScreenName string    `json:"last_screen_name,omitempty"`
	Accounts       []account `json:"accounts"`

	path string
}

// defaultConfigPath returns the config file location in the user's config
// directory.
func defaultConfigPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir = "."
	}
	return filepath.Join(dir, "open-oscar-tui", "config.json")
}

// loadConfig reads the config file at path. A missing file yields an empty
// config.
func loadConfig(path string) (*config, error) {
	cfg := &config{path: path}
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

// save writes the config file. The file may hold passwords, so it's only
// readable by the user.
func (c *config) save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

// find returns the saved account for server and screenName.
func (c *config) find(server, screenName string) *account {
	for i := range c.Accounts {
		if c.Accounts[i].matches(server, screenName) {
			return &c.Accounts[i]
		}
	}
	return nil
}

// last returns the index of the last account used, or -1.
func (c *config) last() int {
	for i, a := range c.Accounts {
		if a.matches(c.LastServer, c.LastScreenName) {
			return i
		}
	}
	return -1
}

// remember records a successful signon. The password is saved only if
// savePassword is set; otherwise any saved password is forgotten.
func (c *config) remember(server, screenName, password string, savePassword bool) *account {
	a := c.find(server, screenName)
	if a == nil {
		c.Accounts = append(c.Accounts, account{Server: server})
		a = &c.Accounts[len(c.Accounts)-1]
	}
	a.ScreenName = screenName
	a.Password = ""
	if savePassword {
		a.Password = password
	}
	c.LastServer = server
	c.LastScreenName = screenName
	return a
}

// remove forgets the account at index i.
func (c *config) remove(i int) {
	if i < 0 || i >= len(c.Accounts) {
		return
	}
	c.Accounts = append(c.Accounts[:i], c.Accounts[i+1:]...)
}
