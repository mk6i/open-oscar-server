package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// ErrNoBuddyIcon indicates that a user has not set a buddy icon.
var ErrNoBuddyIcon = errors.New("no buddy icon")

// BARTService retrieves BART (Buddy Art) assets by hash.
type BARTService interface {
	RetrieveItem(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x04_BARTDownloadQuery) (wire.SNACMessage, error)
}

// BuddyIconRetriever resolves a user's buddy icon reference. References live in
// the feedbag rather than on the session, so they resolve for offline users too.
type BuddyIconRetriever interface {
	BuddyIconMetadata(ctx context.Context, screenName state.IdentScreenName) (*wire.BARTID, error)
}

// BuddyIconSource resolves buddy icons, both as URLs to publish to the web
// client and as the image bytes those URLs serve.
//
// The client never derives an icon URL: it renders whatever string the server
// puts in a user's buddyIcon field, falling back to a blank-person placeholder
// when the field is absent.
type BuddyIconSource struct {
	IconRetriever BuddyIconRetriever
	BARTService   BARTService
	Logger        *slog.Logger
}

// URL returns the absolute, content-addressed URL that screenName's buddy icon
// is served from, or an empty string if the user has no icon.
//
// The icon hash is part of the URL so that the URL changes whenever the user
// changes their icon. Browsers cache icons by URL, and the client refetches a
// user's large icon only when it observes buddyIconUrl change.
func (s BuddyIconSource) URL(ctx context.Context, baseURL string, screenName state.IdentScreenName) string {
	// The client loads icons from a different origin than the page it runs on,
	// so a URL is only publishable if it can be made absolute. Callers that have
	// no origin to build against pass an empty baseURL to opt out.
	if baseURL == "" {
		return ""
	}

	id, err := s.iconID(ctx, screenName)
	if err != nil {
		if !errors.Is(err, ErrNoBuddyIcon) {
			s.Logger.WarnContext(ctx, "failed to resolve buddy icon",
				"screenName", screenName.String(), "err", err.Error())
		}
		return ""
	}

	return iconURL(baseURL, screenName, id.Hash)
}

// PublishedURL returns a buddyIcon URL that is always non-empty when baseURL is
// set: the content-addressed URL when the user has an icon, otherwise a hash-less
// URL that resolves to the blank placeholder.
//
// Callers that publish icons into buddy-list, presence, or myInfo payloads use
// this so the client always receives a URL. The web client's shallow user-object
// merge never drops a stale buddyIconUrl on its own, so a user who clears their
// icon only stops rendering it once a *different* URL arrives; the hash-less
// placeholder URL is that different URL.
func (s BuddyIconSource) PublishedURL(ctx context.Context, baseURL string, screenName state.IdentScreenName) string {
	if baseURL == "" {
		return ""
	}

	id, err := s.iconID(ctx, screenName)
	switch {
	case errors.Is(err, ErrNoBuddyIcon):
		// No icon set: publish the hash-less placeholder rather than nothing, so
		// a cleared icon propagates to the client.
		return iconURL(baseURL, screenName, nil)
	case err != nil:
		s.Logger.WarnContext(ctx, "failed to resolve buddy icon",
			"screenName", screenName.String(), "err", err.Error())
		return ""
	}

	return iconURL(baseURL, screenName, id.Hash)
}

// URLForHash formats a buddyIcon URL for a hash already known to the caller,
// skipping the metadata lookup that URL/PublishedURL do. The event pump uses this
// on presence broadcasts, whose SNAC already carries the buddy's icon hash (TLV
// wire.OServiceUserInfoBARTInfo).
//
// A non-empty hash yields the content-addressed URL; a nil/empty hash yields the
// hash-less placeholder URL (which serves the blank icon), so a buddy who cleared
// or never set an icon still gets a non-empty URL the client's shallow merge can
// act on. An empty baseURL (no origin to build against) yields "".
func (s BuddyIconSource) URLForHash(baseURL string, screenName state.IdentScreenName, hash []byte) string {
	if baseURL == "" {
		return ""
	}
	return iconURL(baseURL, screenName, hash)
}

// iconURL formats the expressions endpoint URL for screenName's icon. A non-empty
// hash is content-addressed and cacheable; an empty hash yields the placeholder
// form that serves the blank icon.
func iconURL(baseURL string, screenName state.IdentScreenName, hash []byte) string {
	if len(hash) == 0 {
		return fmt.Sprintf("%s/expressions/get?t=%s&type=buddyIcon",
			baseURL, url.QueryEscape(screenName.String()))
	}
	return fmt.Sprintf("%s/expressions/get?t=%s&type=buddyIcon&bartId=%x",
		baseURL, url.QueryEscape(screenName.String()), hash)
}

// Image returns the image bytes of screenName's current buddy icon. It returns
// ErrNoBuddyIcon if the user has no icon set.
func (s BuddyIconSource) Image(ctx context.Context, screenName state.IdentScreenName) ([]byte, error) {
	id, err := s.iconID(ctx, screenName)
	if err != nil {
		return nil, err
	}
	return s.ImageForHash(ctx, screenName, id.Hash)
}

// ImageForHash returns the bytes of the BART asset identified by hash for
// screenName, independent of the user's current icon reference. This lets a
// content-addressed URL resolve to the exact image its hash names, so a URL that
// was cached as immutable never resolves to a different image later. It returns
// ErrNoBuddyIcon if no asset with that hash exists. Passing the clear-icon hash
// yields the blank placeholder image.
func (s BuddyIconSource) ImageForHash(ctx context.Context, screenName state.IdentScreenName, hash []byte) ([]byte, error) {
	msg, err := s.BARTService.RetrieveItem(ctx, wire.SNACFrame{}, wire.SNAC_0x10_0x04_BARTDownloadQuery{
		ScreenName: screenName.String(),
		BARTID: wire.BARTID{
			Type:     wire.BARTTypesBuddyIcon,
			BARTInfo: wire.BARTInfo{Hash: hash},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("RetrieveItem: %w", err)
	}

	reply, ok := msg.Body.(wire.SNAC_0x10_0x05_BARTDownloadReply)
	if !ok {
		return nil, fmt.Errorf("unexpected BART reply body type %T", msg.Body)
	}
	if len(reply.Data) == 0 {
		return nil, ErrNoBuddyIcon
	}

	return reply.Data, nil
}

// iconID looks up a user's buddy icon reference, translating "no icon" and
// "icon cleared" into ErrNoBuddyIcon.
func (s BuddyIconSource) iconID(ctx context.Context, screenName state.IdentScreenName) (*wire.BARTID, error) {
	id, err := s.IconRetriever.BuddyIconMetadata(ctx, screenName)
	if err != nil {
		return nil, fmt.Errorf("BuddyIconMetadata: %w", err)
	}
	if id == nil || id.HasClearIconHash() || len(id.Hash) == 0 {
		return nil, ErrNoBuddyIcon
	}
	return id, nil
}
