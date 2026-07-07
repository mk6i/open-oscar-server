-- Rollback: recreate the WebAPI-to-OSCAR bridge sessions table (see 0018).

CREATE TABLE IF NOT EXISTS oscar_bridge_sessions (
    web_session_id VARCHAR(64) PRIMARY KEY,
    oscar_cookie BLOB NOT NULL,
    bos_host VARCHAR(255) NOT NULL,
    bos_port INTEGER NOT NULL,
    use_ssl BOOLEAN DEFAULT FALSE,
    screen_name VARCHAR(97) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    client_name VARCHAR(255),
    client_version VARCHAR(50)
);

CREATE INDEX IF NOT EXISTS idx_oscar_bridge_screen_name ON oscar_bridge_sessions(screen_name);
CREATE INDEX IF NOT EXISTS idx_oscar_bridge_last_accessed ON oscar_bridge_sessions(last_accessed);
