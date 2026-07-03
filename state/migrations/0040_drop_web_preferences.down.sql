-- Rollback: recreate the Web API preferences table.
CREATE TABLE IF NOT EXISTS web_preferences
(
    screen_name         VARCHAR(16) PRIMARY KEY,
    preferences         TEXT,        -- JSON object of preference key-value pairs
    created_at          INTEGER NOT NULL,
    updated_at          INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_web_preferences_screen_name ON web_preferences(screen_name);
