-- Drop tables for removed Web API features: usage analytics (0019),
-- buddy feeds (0020), and vanity URLs (0021). The Go code backing these
-- features has been deleted; the tables were never wired into the server.

-- Child tables (foreign keys) first.
DROP TABLE IF EXISTS buddy_feed_subscriptions;
DROP TABLE IF EXISTS buddy_feed_items;
DROP TABLE IF EXISTS buddy_feeds;

DROP TABLE IF EXISTS vanity_url_redirects;
DROP TABLE IF EXISTS vanity_urls;

DROP TABLE IF EXISTS api_usage_logs;
DROP TABLE IF EXISTS api_usage_stats;
DROP TABLE IF EXISTS api_quotas;
