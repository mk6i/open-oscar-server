-- Rollback: recreate Web API chat room tables

CREATE TABLE IF NOT EXISTS web_chat_rooms (
    room_id VARCHAR(255) PRIMARY KEY,
    room_name VARCHAR(255) NOT NULL,
    description TEXT,
    room_type VARCHAR(50) DEFAULT 'userCreated',
    category_id VARCHAR(50),
    creator_screen_name VARCHAR(16) NOT NULL,
    created_at INTEGER NOT NULL,
    closed_at INTEGER,
    max_participants INTEGER DEFAULT 100
);

CREATE INDEX IF NOT EXISTS idx_web_chat_rooms_name ON web_chat_rooms(room_name);
CREATE INDEX IF NOT EXISTS idx_web_chat_rooms_creator ON web_chat_rooms(creator_screen_name);
CREATE INDEX IF NOT EXISTS idx_web_chat_rooms_created ON web_chat_rooms(created_at);
CREATE INDEX IF NOT EXISTS idx_web_chat_rooms_closed ON web_chat_rooms(closed_at);

CREATE TABLE IF NOT EXISTS web_chat_sessions (
    chat_sid VARCHAR(255) PRIMARY KEY,
    aimsid VARCHAR(255) NOT NULL,
    room_id VARCHAR(255) NOT NULL,
    screen_name VARCHAR(16) NOT NULL,
    instance_id INTEGER NOT NULL,
    joined_at INTEGER NOT NULL,
    left_at INTEGER,
    FOREIGN KEY (room_id) REFERENCES web_chat_rooms(room_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_web_chat_sessions_aimsid ON web_chat_sessions(aimsid);
CREATE INDEX IF NOT EXISTS idx_web_chat_sessions_room ON web_chat_sessions(room_id);
CREATE INDEX IF NOT EXISTS idx_web_chat_sessions_user ON web_chat_sessions(screen_name);
CREATE INDEX IF NOT EXISTS idx_web_chat_sessions_joined ON web_chat_sessions(joined_at);

CREATE TABLE IF NOT EXISTS web_chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id VARCHAR(255) NOT NULL,
    screen_name VARCHAR(16) NOT NULL,
    message TEXT NOT NULL,
    whisper_target VARCHAR(16),
    timestamp INTEGER NOT NULL,
    FOREIGN KEY (room_id) REFERENCES web_chat_rooms(room_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_web_chat_messages_room ON web_chat_messages(room_id);
CREATE INDEX IF NOT EXISTS idx_web_chat_messages_timestamp ON web_chat_messages(timestamp);
CREATE INDEX IF NOT EXISTS idx_web_chat_messages_user ON web_chat_messages(screen_name);

CREATE TABLE IF NOT EXISTS web_chat_participants (
    room_id VARCHAR(255) NOT NULL,
    screen_name VARCHAR(16) NOT NULL,
    chat_sid VARCHAR(255) NOT NULL,
    joined_at INTEGER NOT NULL,
    typing_status VARCHAR(20) DEFAULT 'none',
    typing_updated_at INTEGER,
    PRIMARY KEY (room_id, screen_name),
    FOREIGN KEY (room_id) REFERENCES web_chat_rooms(room_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_web_chat_participants_room ON web_chat_participants(room_id);
CREATE INDEX IF NOT EXISTS idx_web_chat_participants_user ON web_chat_participants(screen_name);
