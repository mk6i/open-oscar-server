-- Rollback: recreate the analytics (0019), buddy feed (0020), and
-- vanity URL (0021) tables that 0039 dropped.

-- API usage analytics (from 0019_api_analytics).
CREATE TABLE IF NOT EXISTS api_usage_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dev_id VARCHAR(255) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    timestamp INTEGER NOT NULL,
    response_time_ms INTEGER,
    status_code INTEGER,
    ip_address VARCHAR(45),
    user_agent TEXT,
    screen_name VARCHAR(16),
    error_message TEXT,
    request_size INTEGER,
    response_size INTEGER
);

CREATE INDEX idx_usage_dev_id ON api_usage_logs(dev_id);
CREATE INDEX idx_usage_timestamp ON api_usage_logs(timestamp);
CREATE INDEX idx_usage_endpoint ON api_usage_logs(endpoint);
CREATE INDEX idx_usage_status ON api_usage_logs(status_code);
CREATE INDEX idx_usage_screen_name ON api_usage_logs(screen_name);

CREATE TABLE IF NOT EXISTS api_usage_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dev_id VARCHAR(255) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    period_type VARCHAR(10) NOT NULL,
    period_start INTEGER NOT NULL,
    request_count INTEGER DEFAULT 0,
    error_count INTEGER DEFAULT 0,
    total_response_time_ms INTEGER DEFAULT 0,
    avg_response_time_ms INTEGER DEFAULT 0,
    total_request_bytes INTEGER DEFAULT 0,
    total_response_bytes INTEGER DEFAULT 0,
    unique_users INTEGER DEFAULT 0,
    UNIQUE(dev_id, endpoint, period_type, period_start)
);

CREATE INDEX idx_stats_dev_id ON api_usage_stats(dev_id);
CREATE INDEX idx_stats_period ON api_usage_stats(period_type, period_start);
CREATE INDEX idx_stats_endpoint ON api_usage_stats(endpoint);

CREATE TABLE IF NOT EXISTS api_quotas (
    dev_id VARCHAR(255) PRIMARY KEY,
    daily_limit INTEGER DEFAULT 10000,
    monthly_limit INTEGER DEFAULT 300000,
    daily_used INTEGER DEFAULT 0,
    monthly_used INTEGER DEFAULT 0,
    last_reset_daily INTEGER NOT NULL,
    last_reset_monthly INTEGER NOT NULL,
    overage_allowed BOOLEAN DEFAULT FALSE
);

-- Buddy feeds (from 0020_buddy_feeds).
CREATE TABLE IF NOT EXISTS buddy_feeds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    screen_name VARCHAR(16) NOT NULL,
    feed_type VARCHAR(50) NOT NULL,
    title TEXT,
    description TEXT,
    link TEXT,
    published_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_buddy_feeds_screen_name ON buddy_feeds(screen_name);
CREATE INDEX idx_buddy_feeds_published ON buddy_feeds(published_at);
CREATE INDEX idx_buddy_feeds_type ON buddy_feeds(feed_type);
CREATE INDEX idx_buddy_feeds_active ON buddy_feeds(is_active);

CREATE TABLE IF NOT EXISTS buddy_feed_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    feed_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    link TEXT,
    guid TEXT,
    author VARCHAR(16),
    categories TEXT,
    published_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (feed_id) REFERENCES buddy_feeds(id) ON DELETE CASCADE
);

CREATE INDEX idx_feed_items_feed_id ON buddy_feed_items(feed_id);
CREATE INDEX idx_feed_items_published ON buddy_feed_items(published_at);
CREATE INDEX idx_feed_items_guid ON buddy_feed_items(guid);

CREATE TABLE IF NOT EXISTS buddy_feed_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subscriber_screen_name VARCHAR(16) NOT NULL,
    feed_id INTEGER NOT NULL,
    subscribed_at INTEGER NOT NULL,
    last_checked_at INTEGER,
    FOREIGN KEY (feed_id) REFERENCES buddy_feeds(id) ON DELETE CASCADE,
    UNIQUE(subscriber_screen_name, feed_id)
);

CREATE INDEX idx_feed_subs_subscriber ON buddy_feed_subscriptions(subscriber_screen_name);
CREATE INDEX idx_feed_subs_feed_id ON buddy_feed_subscriptions(feed_id);

-- Vanity URLs (from 0021_vanity_urls).
CREATE TABLE IF NOT EXISTS vanity_urls (
    screen_name VARCHAR(16) PRIMARY KEY,
    vanity_url VARCHAR(255) UNIQUE NOT NULL,
    display_name VARCHAR(100),
    bio TEXT,
    location VARCHAR(100),
    website VARCHAR(255),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    click_count INTEGER DEFAULT 0,
    last_accessed INTEGER
);

CREATE INDEX idx_vanity_urls_url ON vanity_urls(vanity_url);
CREATE INDEX idx_vanity_urls_active ON vanity_urls(is_active);
CREATE INDEX idx_vanity_urls_created ON vanity_urls(created_at);

CREATE TABLE IF NOT EXISTS vanity_url_redirects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vanity_url VARCHAR(255) NOT NULL,
    accessed_at INTEGER NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    referer TEXT,
    FOREIGN KEY (vanity_url) REFERENCES vanity_urls(vanity_url) ON DELETE CASCADE
);

CREATE INDEX idx_vanity_redirects_url ON vanity_url_redirects(vanity_url);
CREATE INDEX idx_vanity_redirects_time ON vanity_url_redirects(accessed_at);
