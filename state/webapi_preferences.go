package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// WebPreferenceManager handles Web API user preferences.
type WebPreferenceManager struct {
	store *SQLiteUserStore
}

// NewWebPreferenceManager creates a new WebPreferenceManager.
func (s *SQLiteUserStore) NewWebPreferenceManager() *WebPreferenceManager {
	return &WebPreferenceManager{store: s}
}

// SetPreferences stores user preferences in the database.
func (m *WebPreferenceManager) SetPreferences(ctx context.Context, screenName IdentScreenName, prefs map[string]interface{}) error {
	prefsJSON, err := json.Marshal(prefs)
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	q := `
		INSERT INTO web_preferences (screen_name, preferences, created_at, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT (screen_name)
		DO UPDATE SET preferences = excluded.preferences, updated_at = excluded.updated_at
	`
	_, err = m.store.db.ExecContext(ctx, q, screenName.String(), string(prefsJSON), now, now)
	return err
}

// GetPreferences retrieves user preferences from the database.
func (m *WebPreferenceManager) GetPreferences(ctx context.Context, screenName IdentScreenName) (map[string]interface{}, error) {
	q := `
		SELECT preferences
		FROM web_preferences
		WHERE screen_name = ?
	`
	var prefsJSON string
	err := m.store.db.QueryRowContext(ctx, q, screenName.String()).Scan(&prefsJSON)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Return empty preferences if none exist
			return make(map[string]interface{}), nil
		}
		return nil, err
	}

	var prefs map[string]interface{}
	if err := json.Unmarshal([]byte(prefsJSON), &prefs); err != nil {
		return nil, err
	}

	return prefs, nil
}

// WebPermitDenyManager handles Web API permit/deny list management.
type WebPermitDenyManager struct {
	store *SQLiteUserStore
}

// NewWebPermitDenyManager creates a new WebPermitDenyManager.
func (s *SQLiteUserStore) NewWebPermitDenyManager() *WebPermitDenyManager {
	return &WebPermitDenyManager{store: s}
}

// SetPDMode sets the permit/deny mode for a user.
func (m *WebPermitDenyManager) SetPDMode(ctx context.Context, screenName IdentScreenName, mode wire.FeedbagPDMode) error {
	q := `
		INSERT INTO buddyListMode (screenName, clientSidePDMode)
		VALUES (?, ?)
		ON CONFLICT (screenName)
		DO UPDATE SET clientSidePDMode = excluded.clientSidePDMode
	`
	_, err := m.store.db.ExecContext(ctx, q, screenName.String(), int(mode))
	return err
}

// GetPDMode retrieves the permit/deny mode for a user.
func (m *WebPermitDenyManager) GetPDMode(ctx context.Context, screenName IdentScreenName) (wire.FeedbagPDMode, error) {
	q := `
		SELECT clientSidePDMode
		FROM buddyListMode
		WHERE screenName = ?
	`
	var mode int
	err := m.store.db.QueryRowContext(ctx, q, screenName.String()).Scan(&mode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Default to PermitAll if not set
			return wire.FeedbagPDModePermitAll, nil
		}
		return 0, err
	}
	return wire.FeedbagPDMode(mode), nil
}

// GetPermitList retrieves the permit list for a user.
func (m *WebPermitDenyManager) GetPermitList(ctx context.Context, screenName IdentScreenName) ([]IdentScreenName, error) {
	q := `
		SELECT them
		FROM clientSideBuddyList
		WHERE me = ? AND isPermit = 1
	`
	rows, err := m.store.db.QueryContext(ctx, q, screenName.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []IdentScreenName
	for rows.Next() {
		var user string
		if err := rows.Scan(&user); err != nil {
			return nil, err
		}
		users = append(users, NewIdentScreenName(user))
	}
	return users, rows.Err()
}

// GetDenyList retrieves the deny list for a user.
func (m *WebPermitDenyManager) GetDenyList(ctx context.Context, screenName IdentScreenName) ([]IdentScreenName, error) {
	q := `
		SELECT them
		FROM clientSideBuddyList
		WHERE me = ? AND isDeny = 1
	`
	rows, err := m.store.db.QueryContext(ctx, q, screenName.String())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []IdentScreenName
	for rows.Next() {
		var user string
		if err := rows.Scan(&user); err != nil {
			return nil, err
		}
		users = append(users, NewIdentScreenName(user))
	}
	return users, rows.Err()
}

// AddPermitBuddy adds a user to the permit list.
func (m *WebPermitDenyManager) AddPermitBuddy(ctx context.Context, me IdentScreenName, them IdentScreenName) error {
	q := `
		INSERT INTO clientSideBuddyList (me, them, isPermit)
		VALUES (?, ?, 1)
		ON CONFLICT (me, them) DO UPDATE SET isPermit = 1
	`
	_, err := m.store.db.ExecContext(ctx, q, me.String(), them.String())
	return err
}

// RemovePermitBuddy removes a user from the permit list.
func (m *WebPermitDenyManager) RemovePermitBuddy(ctx context.Context, me IdentScreenName, them IdentScreenName) error {
	q := `
		UPDATE clientSideBuddyList
		SET isPermit = 0
		WHERE me = ? AND them = ?
	`
	_, err := m.store.db.ExecContext(ctx, q, me.String(), them.String())
	return err
}

// AddDenyBuddy adds a user to the deny list.
func (m *WebPermitDenyManager) AddDenyBuddy(ctx context.Context, me IdentScreenName, them IdentScreenName) error {
	q := `
		INSERT INTO clientSideBuddyList (me, them, isDeny)
		VALUES (?, ?, 1)
		ON CONFLICT (me, them) DO UPDATE SET isDeny = 1
	`
	_, err := m.store.db.ExecContext(ctx, q, me.String(), them.String())
	return err
}

// RemoveDenyBuddy removes a user from the deny list.
func (m *WebPermitDenyManager) RemoveDenyBuddy(ctx context.Context, me IdentScreenName, them IdentScreenName) error {
	q := `
		UPDATE clientSideBuddyList
		SET isDeny = 0
		WHERE me = ? AND them = ?
	`
	_, err := m.store.db.ExecContext(ctx, q, me.String(), them.String())
	return err
}
