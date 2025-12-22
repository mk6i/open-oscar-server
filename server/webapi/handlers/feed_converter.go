package handlers

import (
	"encoding/xml"
	"time"

	"github.com/mk6i/open-oscar-server/state"
)

// FeedConverter handles conversion of feed data to various output formats.
type FeedConverter struct{}

// NewFeedConverter creates a new feed converter.
func NewFeedConverter() *FeedConverter {
	return &FeedConverter{}
}

// FeedResponse wraps feed data with conversion methods.
type FeedResponse struct {
	Feed  state.BuddyFeed       `json:"feed"`
	Items []state.BuddyFeedItem `json:"items"`
}

// ToRSS converts the feed response to RSS format.
func (fr *FeedResponse) ToRSS() *RSSFeed {
	rss := &RSSFeed{
		Version: "2.0",
		Channel: RSSChannel{
			Title:       fr.Feed.Title,
			Link:        fr.Feed.Link,
			Description: fr.Feed.Description,
			Language:    "en-US",
			PubDate:     fr.Feed.PublishedAt.Format(time.RFC1123Z),
			Items:       make([]RSSItem, 0, len(fr.Items)),
		},
	}

	for _, item := range fr.Items {
		rssItem := RSSItem{
			Title:       item.Title,
			Link:        item.Link,
			Description: item.Description,
			Author:      item.Author,
			Categories:  item.Categories,
			GUID:        item.GUID,
			PubDate:     item.PublishedAt.Format(time.RFC1123Z),
		}
		rss.Channel.Items = append(rss.Channel.Items, rssItem)
	}

	return rss
}

// ToAtom converts the feed response to Atom format.
func (fr *FeedResponse) ToAtom() *AtomFeed {
	atom := &AtomFeed{
		Title:   fr.Feed.Title,
		Link:    AtomLink{Href: fr.Feed.Link, Rel: "alternate"},
		Updated: fr.Feed.UpdatedAt.Format(time.RFC3339),
		ID:      fr.Feed.Link,
		Author:  AtomAuthor{Name: fr.Feed.ScreenName},
		Entries: make([]AtomEntry, 0, len(fr.Items)),
	}

	for _, item := range fr.Items {
		entry := AtomEntry{
			Title:     item.Title,
			Link:      AtomLink{Href: item.Link},
			ID:        item.GUID,
			Updated:   item.PublishedAt.Format(time.RFC3339),
			Published: item.PublishedAt.Format(time.RFC3339),
			Author:    AtomAuthor{Name: item.Author},
			Summary:   item.Description,
			Content:   AtomContent{Type: "html", Text: item.Description},
		}
		atom.Entries = append(atom.Entries, entry)
	}

	return atom
}

// ToJSON converts the feed response to JSON format.
func (fr *FeedResponse) ToJSON() map[string]interface{} {
	jsonItems := make([]map[string]interface{}, 0, len(fr.Items))

	for _, item := range fr.Items {
		jsonItem := map[string]interface{}{
			"id":          item.GUID,
			"title":       item.Title,
			"description": item.Description,
			"link":        item.Link,
			"author":      item.Author,
			"categories":  item.Categories,
			"published":   item.PublishedAt.Unix(),
		}
		jsonItems = append(jsonItems, jsonItem)
	}

	return map[string]interface{}{
		"title":       fr.Feed.Title,
		"description": fr.Feed.Description,
		"link":        fr.Feed.Link,
		"updated":     fr.Feed.UpdatedAt.Unix(),
		"items":       jsonItems,
	}
}

// RSS/Atom feed structures for XML output
type RSSFeed struct {
	XMLName xml.Name   `xml:"rss"`
	Version string     `xml:"version,attr"`
	Channel RSSChannel `xml:"channel"`
}

type RSSChannel struct {
	Title       string    `xml:"title"`
	Link        string    `xml:"link"`
	Description string    `xml:"description"`
	Language    string    `xml:"language,omitempty"`
	PubDate     string    `xml:"pubDate,omitempty"`
	Items       []RSSItem `xml:"item"`
}

type RSSItem struct {
	Title       string   `xml:"title"`
	Link        string   `xml:"link"`
	Description string   `xml:"description"`
	Author      string   `xml:"author,omitempty"`
	Categories  []string `xml:"category,omitempty"`
	GUID        string   `xml:"guid,omitempty"`
	PubDate     string   `xml:"pubDate"`
}

type AtomFeed struct {
	XMLName xml.Name    `xml:"http://www.w3.org/2005/Atom feed"`
	Title   string      `xml:"title"`
	Link    AtomLink    `xml:"link"`
	Updated string      `xml:"updated"`
	Author  AtomAuthor  `xml:"author,omitempty"`
	ID      string      `xml:"id"`
	Entries []AtomEntry `xml:"entry"`
}

type AtomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr,omitempty"`
}

type AtomAuthor struct {
	Name string `xml:"name"`
}

type AtomEntry struct {
	Title     string      `xml:"title"`
	Link      AtomLink    `xml:"link"`
	ID        string      `xml:"id"`
	Updated   string      `xml:"updated"`
	Published string      `xml:"published,omitempty"`
	Author    AtomAuthor  `xml:"author,omitempty"`
	Summary   string      `xml:"summary,omitempty"`
	Content   AtomContent `xml:"content,omitempty"`
}

type AtomContent struct {
	Type string `xml:"type,attr"`
	Text string `xml:",chardata"`
}

// GenerateEmptyFeed creates an empty feed for users without configured feeds.
func GenerateEmptyFeed(screenName string) *FeedResponse {
	feed := state.BuddyFeed{
		ScreenName:  screenName,
		Title:       screenName + "'s Feed",
		Description: "No updates from " + screenName,
		Link:        "/buddyfeed/getUser?u=" + screenName,
		PublishedAt: time.Now(),
		UpdatedAt:   time.Now(),
	}

	return &FeedResponse{
		Feed:  feed,
		Items: []state.BuddyFeedItem{},
	}
}

// BuildFeedData creates feed data map from request parameters.
func BuildFeedData(params map[string]string) map[string]interface{} {
	feedData := make(map[string]interface{})

	// Required fields
	if title, ok := params["itemTitle"]; ok {
		feedData["title"] = title
	}
	if desc, ok := params["itemDesc"]; ok {
		feedData["description"] = desc
	}
	if link, ok := params["itemLink"]; ok {
		feedData["link"] = link
	}
	if guid, ok := params["itemGuid"]; ok {
		feedData["guid"] = guid
	}

	// Feed metadata
	if feedTitle, ok := params["feedTitle"]; ok {
		feedData["feedTitle"] = feedTitle
	}
	if feedLink, ok := params["feedLink"]; ok {
		feedData["feedLink"] = feedLink
	}
	if feedDesc, ok := params["feedDesc"]; ok {
		feedData["feedDesc"] = feedDesc
	}

	// Optional fields
	if publisher, ok := params["feedPublisher"]; ok && publisher != "" {
		feedData["publisher"] = publisher
	}
	if pubDate, ok := params["itemPubDate"]; ok && pubDate != "" {
		feedData["pubDate"] = pubDate
	}
	if category, ok := params["itemCategory"]; ok && category != "" {
		feedData["categories"] = []string{category}
	}

	// Default type if not specified
	if _, ok := feedData["type"]; !ok {
		feedData["type"] = "status"
	}

	return feedData
}
