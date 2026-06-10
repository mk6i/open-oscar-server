-- Restore webapi_tokens (see 0016_webapi_tokens.up.sql)
CREATE TABLE IF NOT EXISTS webapi_tokens (
    token TEXT PRIMARY KEY,
    screen_name TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_webapi_tokens_expires_at ON webapi_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_webapi_tokens_screen_name ON webapi_tokens(screen_name);
