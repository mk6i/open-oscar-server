package state

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// BuddyFeed represents a user's feed configuration.
type BuddyFeed struct {
	ID          int64     `json:"id"`
	ScreenName  string    `json:"screenName"`
	FeedType    string    `json:"feedType"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Link        string    `json:"link"`
	PublishedAt time.Time `json:"publishedAt"`
	CreatedAt   time.Time `json:"createdAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	IsActive    bool      `json:"isActive"`
}

// BuddyFeedItem represents an individual feed entry.
type BuddyFeedItem struct {
	ID          int64     `json:"id"`
	FeedID      int64     `json:"feedId"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Link        string    `json:"link"`
	GUID        string    `json:"guid"`
	Author      string    `json:"author"`
	Categories  []string  `json:"categories"`
	PublishedAt time.Time `json:"publishedAt"`
	CreatedAt   time.Time `json:"createdAt"`
}

// BuddyFeedSubscription represents a feed subscription.
type BuddyFeedSubscription struct {
	ID                   int64      `json:"id"`
	SubscriberScreenName string     `json:"subscriberScreenName"`
	FeedID               int64      `json:"feedId"`
	SubscribedAt         time.Time  `json:"subscribedAt"`
	LastCheckedAt        *time.Time `json:"lastCheckedAt"`
}

// BuddyFeedManager manages buddy feed operations.
type BuddyFeedManager struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewBuddyFeedManager creates a new buddy feed manager.
func NewBuddyFeedManager(db *sql.DB, logger *slog.Logger) *BuddyFeedManager {
	return &BuddyFeedManager{
		db:     db,
		logger: logger,
	}
}

// CreateFeed creates a new buddy feed.
func (m *BuddyFeedManager) CreateFeed(ctx context.Context, feed BuddyFeed) (*BuddyFeed, error) {
	now := time.Now()
	query := `
		INSERT INTO buddy_feeds (
			screen_name, feed_type, title, description, link,
			published_at, created_at, updated_at, is_active
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING id
	`

	var id int64
	err := m.db.QueryRowContext(ctx, query,
		feed.ScreenName, feed.FeedType, feed.Title, feed.Description, feed.Link,
		feed.PublishedAt.Unix(), now.Unix(), now.Unix(), feed.IsActive,
	).Scan(&id)

	if err != nil {
		return nil, fmt.Errorf("failed to create feed: %w", err)
	}

	feed.ID = id
	feed.CreatedAt = now
	feed.UpdatedAt = now

	return &feed, nil
}

// GetUserFeed retrieves the feed configuration for a specific user.
func (m *BuddyFeedManager) GetUserFeed(ctx context.Context, screenName string) (*BuddyFeed, error) {
	var feed BuddyFeed
	query := `
		SELECT id, screen_name, feed_type, title, description, link,
		       published_at, created_at, updated_at, is_active
		FROM buddy_feeds
		WHERE screen_name = ? AND is_active = 1
		ORDER BY published_at DESC
		LIMIT 1
	`

	err := m.db.QueryRowContext(ctx, query, screenName).Scan(
		&feed.ID, &feed.ScreenName, &feed.FeedType, &feed.Title,
		&feed.Description, &feed.Link, &feed.PublishedAt,
		&feed.CreatedAt, &feed.UpdatedAt, &feed.IsActive,
	)

	if err == sql.ErrNoRows {
		return nil, nil // No feed found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user feed: %w", err)
	}

	return &feed, nil
}

// GetBuddyListFeedItems retrieves aggregated feed items for a user's buddy list.
func (m *BuddyFeedManager) GetBuddyListFeedItems(ctx context.Context, buddies []IdentScreenName, limit int) ([]BuddyFeedItem, error) {
	if limit <= 0 {
		limit = 100 // Default limit
	}

	if len(buddies) == 0 {
		return []BuddyFeedItem{}, nil
	}

	// Build placeholders for IN clause
	placeholders := make([]string, len(buddies))
	args := make([]interface{}, len(buddies)+1)
	for i, buddy := range buddies {
		placeholders[i] = "?"
		args[i] = buddy.String()
	}
	args[len(buddies)] = limit

	// Query to get feed items from all buddies, sorted by published date
	query := fmt.Sprintf(`
		SELECT i.id, i.feed_id, i.title, i.description, i.link, i.guid,
		       i.author, i.categories, i.published_at, i.created_at
		FROM buddy_feed_items i
		JOIN buddy_feeds f ON i.feed_id = f.id
		WHERE f.screen_name IN (%s) AND f.is_active = 1
		ORDER BY i.published_at DESC
		LIMIT ?
	`, strings.Join(placeholders, ","))

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query buddy list feed items: %w", err)
	}
	defer rows.Close()

	return m.scanFeedItems(rows)
}

// GetUserFeedItems retrieves feed items for a specific user.
func (m *BuddyFeedManager) GetUserFeedItems(ctx context.Context, screenName string, limit int) ([]BuddyFeedItem, error) {
	query := `
		SELECT i.id, i.feed_id, i.title, i.description, i.link, i.guid,
		       i.author, i.categories, i.published_at, i.created_at
		FROM buddy_feed_items i
		JOIN buddy_feeds f ON i.feed_id = f.id
		WHERE f.screen_name = ? AND f.is_active = 1
		ORDER BY i.published_at DESC
		LIMIT ?
	`

	rows, err := m.db.QueryContext(ctx, query, screenName, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query feed items: %w", err)
	}
	defer rows.Close()

	var items []BuddyFeedItem
	for rows.Next() {
		var item BuddyFeedItem
		var categoriesJSON sql.NullString
		var publishedAt, createdAt int64

		err := rows.Scan(
			&item.ID, &item.FeedID, &item.Title, &item.Description,
			&item.Link, &item.GUID, &item.Author, &categoriesJSON,
			&publishedAt, &createdAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan feed item: %w", err)
		}

		item.PublishedAt = time.Unix(publishedAt, 0)
		item.CreatedAt = time.Unix(createdAt, 0)

		if categoriesJSON.Valid {
			if err := json.Unmarshal([]byte(categoriesJSON.String), &item.Categories); err != nil {
				return nil, fmt.Errorf("failed to unmarshal feed item categories: %w", err)
			}
		}

		items = append(items, item)
	}

	return items, nil
}

// GetFeedItems retrieves items for a specific feed.
func (m *BuddyFeedManager) GetFeedItems(ctx context.Context, feedID int64, limit int) ([]BuddyFeedItem, error) {
	query := `
		SELECT id, feed_id, title, description, link, guid,
		       author, categories, published_at, created_at
		FROM buddy_feed_items
		WHERE feed_id = ?
		ORDER BY published_at DESC
		LIMIT ?
	`

	rows, err := m.db.QueryContext(ctx, query, feedID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query feed items: %w", err)
	}
	defer rows.Close()

	return m.scanFeedItems(rows)
}

// scanFeedItems is a helper to scan feed items from database rows.
func (m *BuddyFeedManager) scanFeedItems(rows *sql.Rows) ([]BuddyFeedItem, error) {
	var items []BuddyFeedItem
	for rows.Next() {
		var item BuddyFeedItem
		var categoriesJSON sql.NullString
		var publishedAt, createdAt int64

		err := rows.Scan(
			&item.ID, &item.FeedID, &item.Title, &item.Description,
			&item.Link, &item.GUID, &item.Author, &categoriesJSON,
			&publishedAt, &createdAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan feed item: %w", err)
		}

		item.PublishedAt = time.Unix(publishedAt, 0)
		item.CreatedAt = time.Unix(createdAt, 0)

		if categoriesJSON.Valid {
			if err := json.Unmarshal([]byte(categoriesJSON.String), &item.Categories); err != nil {
				return nil, fmt.Errorf("failed to unmarshal feed item categories: %w", err)
			}
		}

		items = append(items, item)
	}

	return items, nil
}

// AddFeedItem adds a new item to a feed.
func (m *BuddyFeedManager) AddFeedItem(ctx context.Context, feedID int64, item BuddyFeedItem) (*BuddyFeedItem, error) {
	categoriesJSON, _ := json.Marshal(item.Categories)
	now := time.Now()

	query := `
		INSERT INTO buddy_feed_items (
			feed_id, title, description, link, guid,
			author, categories, published_at, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		RETURNING id
	`

	var id int64
	err := m.db.QueryRowContext(ctx, query,
		feedID, item.Title, item.Description, item.Link, item.GUID,
		item.Author, string(categoriesJSON), item.PublishedAt.Unix(), now.Unix(),
	).Scan(&id)

	if err != nil {
		return nil, fmt.Errorf("failed to add feed item: %w", err)
	}

	item.ID = id
	item.FeedID = feedID
	item.CreatedAt = now

	// Update feed's updated_at timestamp
	updateQuery := `UPDATE buddy_feeds SET updated_at = ? WHERE id = ?`
	if _, err := m.db.ExecContext(ctx, updateQuery, now.Unix(), feedID); err != nil {
		return nil, fmt.Errorf("failed to update feed timestamp: %w", err)
	}

	return &item, nil
}

// GetOrCreateFeedForUser gets an existing feed or creates a new one for a user.
func (m *BuddyFeedManager) GetOrCreateFeedForUser(ctx context.Context, screenName string, feedType string) (int64, error) {
	var feedID int64
	query := `SELECT id FROM buddy_feeds WHERE screen_name = ? AND is_active = 1 LIMIT 1`
	err := m.db.QueryRowContext(ctx, query, screenName).Scan(&feedID)

	if err == nil {
		return feedID, nil
	}

	if err != sql.ErrNoRows {
		return 0, fmt.Errorf("failed to query feed: %w", err)
	}

	// Create new feed
	if feedType == "" {
		feedType = "status"
	}

	feed := BuddyFeed{
		ScreenName:  screenName,
		FeedType:    feedType,
		Title:       fmt.Sprintf("%s's Feed", screenName),
		Description: fmt.Sprintf("Updates from %s", screenName),
		Link:        fmt.Sprintf("/buddyfeed/getUser?u=%s", screenName),
		PublishedAt: time.Now(),
		IsActive:    true,
	}

	createdFeed, err := m.CreateFeed(ctx, feed)
	if err != nil {
		return 0, fmt.Errorf("failed to create feed: %w", err)
	}

	return createdFeed.ID, nil
}
