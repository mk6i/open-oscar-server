package state

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// OSCARBridgeStore manages the persistence of OSCAR bridge sessions in the database.
// It provides methods to store, retrieve, and manage the mapping between WebAPI
// sessions and OSCAR authentication cookies.
type OSCARBridgeStore struct {
	store *SQLiteUserStore
}

// NewOSCARBridgeStore creates a new OSCAR bridge store instance.
func (s *SQLiteUserStore) NewOSCARBridgeStore() *OSCARBridgeStore {
	return &OSCARBridgeStore{store: s}
}

// OSCARBridgeSession represents a bridge between WebAPI and OSCAR sessions.
type OSCARBridgeSession struct {
	WebSessionID  string    // WebAPI session identifier
	OSCARCookie   []byte    // OSCAR authentication cookie
	BOSHost       string    // BOS server hostname
	BOSPort       int       // BOS server port
	UseSSL        bool      // Whether to use SSL connection
	ScreenName    string    // Screen name associated with the session
	ClientName    string    // Client application name
	ClientVersion string    // Client application version
	CreatedAt     time.Time // Bridge creation timestamp
	LastAccessed  time.Time // Last access timestamp
}

// SaveBridgeSession stores the mapping between WebAPI and OSCAR sessions.
func (s *OSCARBridgeStore) SaveBridgeSession(ctx context.Context, webSessionID string,
	oscarCookie []byte, bosHost string, bosPort int) error {

	query := `
		INSERT INTO oscar_bridge_sessions 
		(web_session_id, oscar_cookie, bos_host, bos_port, screen_name, created_at, last_accessed)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(web_session_id) DO UPDATE SET
			oscar_cookie = excluded.oscar_cookie,
			bos_host = excluded.bos_host,
			bos_port = excluded.bos_port,
			last_accessed = excluded.last_accessed
	`

	now := time.Now()
	// Note: We'll need to get the screen name from the session manager
	// For now, using a placeholder
	screenName := "" // This should be passed from the handler

	_, err := s.store.db.ExecContext(ctx, query,
		webSessionID, oscarCookie, bosHost, bosPort, screenName, now, now)
	if err != nil {
		return fmt.Errorf("failed to save bridge session: %w", err)
	}

	return nil
}

// SaveBridgeSessionWithDetails stores a complete bridge session with all details.
func (s *OSCARBridgeStore) SaveBridgeSessionWithDetails(ctx context.Context, session *OSCARBridgeSession) error {
	query := `
		INSERT INTO oscar_bridge_sessions 
		(web_session_id, oscar_cookie, bos_host, bos_port, use_ssl, screen_name, 
		 client_name, client_version, created_at, last_accessed)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(web_session_id) DO UPDATE SET
			oscar_cookie = excluded.oscar_cookie,
			bos_host = excluded.bos_host,
			bos_port = excluded.bos_port,
			use_ssl = excluded.use_ssl,
			last_accessed = excluded.last_accessed
	`

	_, err := s.store.db.ExecContext(ctx, query,
		session.WebSessionID, session.OSCARCookie, session.BOSHost, session.BOSPort,
		session.UseSSL, session.ScreenName, session.ClientName, session.ClientVersion,
		session.CreatedAt, session.LastAccessed)
	if err != nil {
		return fmt.Errorf("failed to save bridge session: %w", err)
	}

	return nil
}

// GetBridgeSession retrieves bridge session details by WebAPI session ID.
func (s *OSCARBridgeStore) GetBridgeSession(ctx context.Context, webSessionID string) (*OSCARBridgeSession, error) {
	query := `
		SELECT web_session_id, oscar_cookie, bos_host, bos_port, use_ssl, screen_name,
		       client_name, client_version, created_at, last_accessed
		FROM oscar_bridge_sessions
		WHERE web_session_id = ?
	`

	var session OSCARBridgeSession
	var clientName, clientVersion sql.NullString

	err := s.store.db.QueryRowContext(ctx, query, webSessionID).Scan(
		&session.WebSessionID,
		&session.OSCARCookie,
		&session.BOSHost,
		&session.BOSPort,
		&session.UseSSL,
		&session.ScreenName,
		&clientName,
		&clientVersion,
		&session.CreatedAt,
		&session.LastAccessed,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("bridge session not found")
		}
		return nil, fmt.Errorf("failed to get bridge session: %w", err)
	}

	// Handle nullable fields
	if clientName.Valid {
		session.ClientName = clientName.String
	}
	if clientVersion.Valid {
		session.ClientVersion = clientVersion.String
	}

	// Update last accessed time
	go s.touchSession(context.Background(), webSessionID)

	return &session, nil
}

// GetBridgeSessionByScreenName retrieves bridge sessions by screen name.
func (s *OSCARBridgeStore) GetBridgeSessionByScreenName(ctx context.Context, screenName string) ([]*OSCARBridgeSession, error) {
	query := `
		SELECT web_session_id, oscar_cookie, bos_host, bos_port, use_ssl, screen_name,
		       client_name, client_version, created_at, last_accessed
		FROM oscar_bridge_sessions
		WHERE screen_name = ?
		ORDER BY last_accessed DESC
	`

	rows, err := s.store.db.QueryContext(ctx, query, screenName)
	if err != nil {
		return nil, fmt.Errorf("failed to query bridge sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*OSCARBridgeSession

	for rows.Next() {
		var session OSCARBridgeSession
		var clientName, clientVersion sql.NullString

		err := rows.Scan(
			&session.WebSessionID,
			&session.OSCARCookie,
			&session.BOSHost,
			&session.BOSPort,
			&session.UseSSL,
			&session.ScreenName,
			&clientName,
			&clientVersion,
			&session.CreatedAt,
			&session.LastAccessed,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan bridge session: %w", err)
		}

		// Handle nullable fields
		if clientName.Valid {
			session.ClientName = clientName.String
		}
		if clientVersion.Valid {
			session.ClientVersion = clientVersion.String
		}

		sessions = append(sessions, &session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating bridge sessions: %w", err)
	}

	return sessions, nil
}

// DeleteBridgeSession removes a bridge session.
func (s *OSCARBridgeStore) DeleteBridgeSession(ctx context.Context, webSessionID string) error {
	query := `DELETE FROM oscar_bridge_sessions WHERE web_session_id = ?`

	result, err := s.store.db.ExecContext(ctx, query, webSessionID)
	if err != nil {
		return fmt.Errorf("failed to delete bridge session: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return fmt.Errorf("bridge session not found")
	}

	return nil
}

// CleanupExpiredSessions removes bridge sessions that haven't been accessed recently.
func (s *OSCARBridgeStore) CleanupExpiredSessions(ctx context.Context, maxAge time.Duration) (int, error) {
	cutoff := time.Now().Add(-maxAge)

	query := `DELETE FROM oscar_bridge_sessions WHERE last_accessed < ?`

	result, err := s.store.db.ExecContext(ctx, query, cutoff)
	if err != nil {
		return 0, fmt.Errorf("failed to cleanup expired sessions: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected: %w", err)
	}

	return int(rowsAffected), nil
}

// touchSession updates the last accessed time for a session (internal helper).
func (s *OSCARBridgeStore) touchSession(ctx context.Context, webSessionID string) {
	query := `UPDATE oscar_bridge_sessions SET last_accessed = ? WHERE web_session_id = ?`
	_, _ = s.store.db.ExecContext(ctx, query, time.Now(), webSessionID)
}

// GetAllBridgeSessions returns all active bridge sessions (for monitoring/admin).
func (s *OSCARBridgeStore) GetAllBridgeSessions(ctx context.Context) ([]*OSCARBridgeSession, error) {
	query := `
		SELECT web_session_id, oscar_cookie, bos_host, bos_port, use_ssl, screen_name,
		       client_name, client_version, created_at, last_accessed
		FROM oscar_bridge_sessions
		ORDER BY last_accessed DESC
	`

	rows, err := s.store.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query all bridge sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*OSCARBridgeSession

	for rows.Next() {
		var session OSCARBridgeSession
		var clientName, clientVersion sql.NullString

		err := rows.Scan(
			&session.WebSessionID,
			&session.OSCARCookie,
			&session.BOSHost,
			&session.BOSPort,
			&session.UseSSL,
			&session.ScreenName,
			&clientName,
			&clientVersion,
			&session.CreatedAt,
			&session.LastAccessed,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan bridge session: %w", err)
		}

		// Handle nullable fields
		if clientName.Valid {
			session.ClientName = clientName.String
		}
		if clientVersion.Valid {
			session.ClientVersion = clientVersion.String
		}

		sessions = append(sessions, &session)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating bridge sessions: %w", err)
	}

	return sessions, nil
}

// GetStatistics returns statistics about bridge sessions.
func (s *OSCARBridgeStore) GetStatistics(ctx context.Context) (map[string]interface{}, error) {
	stats := make(map[string]interface{})

	// Total sessions
	var totalCount int
	err := s.store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oscar_bridge_sessions`).Scan(&totalCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get total count: %w", err)
	}
	stats["total_sessions"] = totalCount

	// Active sessions (accessed in last hour)
	var activeCount int
	oneHourAgo := time.Now().Add(-time.Hour)
	err = s.store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oscar_bridge_sessions WHERE last_accessed > ?`,
		oneHourAgo).Scan(&activeCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get active count: %w", err)
	}
	stats["active_sessions"] = activeCount

	// SSL vs non-SSL
	var sslCount int
	err = s.store.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM oscar_bridge_sessions WHERE use_ssl = true`).Scan(&sslCount)
	if err != nil {
		return nil, fmt.Errorf("failed to get SSL count: %w", err)
	}
	stats["ssl_sessions"] = sslCount
	stats["non_ssl_sessions"] = totalCount - sslCount

	return stats, nil
}

// ValidateOSCARCookie checks if an OSCAR cookie exists in the bridge store.
// This can be used to validate incoming OSCAR connections.
func (s *OSCARBridgeStore) ValidateOSCARCookie(ctx context.Context, cookie []byte) (*OSCARBridgeSession, error) {
	// Convert cookie to hex for comparison
	cookieHex := hex.EncodeToString(cookie)

	query := `
		SELECT web_session_id, oscar_cookie, bos_host, bos_port, use_ssl, screen_name,
		       client_name, client_version, created_at, last_accessed
		FROM oscar_bridge_sessions
		WHERE hex(oscar_cookie) = ?
	`

	var session OSCARBridgeSession
	var clientName, clientVersion sql.NullString

	err := s.store.db.QueryRowContext(ctx, query, cookieHex).Scan(
		&session.WebSessionID,
		&session.OSCARCookie,
		&session.BOSHost,
		&session.BOSPort,
		&session.UseSSL,
		&session.ScreenName,
		&clientName,
		&clientVersion,
		&session.CreatedAt,
		&session.LastAccessed,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("cookie not found")
		}
		return nil, fmt.Errorf("failed to validate cookie: %w", err)
	}

	// Handle nullable fields
	if clientName.Valid {
		session.ClientName = clientName.String
	}
	if clientVersion.Valid {
		session.ClientVersion = clientVersion.String
	}

	// Update last accessed time
	go s.touchSession(context.Background(), session.WebSessionID)

	return &session, nil
}
