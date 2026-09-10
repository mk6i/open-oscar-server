package webapi

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net/http"
	"net/url"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// ExpressionsData lists the expressions (buddy icons, etc.) a user publishes.
type ExpressionsData struct {
	Expressions []Expression `json:"expressions" xml:"expressions>expression"`
}

// Expression is one published asset.
type Expression struct {
	Type string `json:"type" xml:"type"`
	URL  string `json:"url" xml:"url"`
}

const bartUploadMaxBytes = 64 << 10

// ExpressionsHandler handles Web AIM API expressions/buddy icon endpoints.
type ExpressionsHandler struct {
	IconSource     BuddyIconSource
	BARTService    BARTService
	FeedbagService FeedbagService
	Logger         *slog.Logger
}

// NewExpressionsHandler creates a new ExpressionsHandler.
func NewExpressionsHandler(
	iconSource BuddyIconSource,
	bartService BARTService,
	feedbagService FeedbagService,
	logger *slog.Logger,
) *ExpressionsHandler {
	return &ExpressionsHandler{
		IconSource:     iconSource,
		BARTService:    bartService,
		FeedbagService: feedbagService,
		Logger:         logger,
	}
}

// Get handles GET /expressions/get requests for buddy icons and expressions.
//
// The AIM client calls this endpoint two different ways:
//
//   - With type=buddyIcon it fetches the image itself. The buddyIcon URL
//     published in presence, buddylist and myInfo payloads points here, and the
//     client renders it directly as an <img> source.
//   - With no type it asks for the user's expressions as JSON, then scans the
//     returned array for the entry typed bigBuddyIcon and uses its url to render
//     hovercards and other large views. We have only one icon per user, so it is
//     offered as both.
func (h *ExpressionsHandler) Get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	target := r.URL.Query().Get("t")
	if target == "" {
		SendError(w, r, http.StatusBadRequest, "missing target")
		return
	}
	screenName := state.NewIdentScreenName(target)

	switch r.URL.Query().Get("type") {
	case "buddyIcon", "bigBuddyIcon":
		h.serveIcon(w, r, screenName)
		return
	}

	iconURL := h.IconSource.URL(ctx, baseURLFromRequest(r), screenName)

	// f=redirect asks for the icon itself rather than a description of it.
	if r.URL.Query().Get("f") == "redirect" {
		if iconURL == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		http.Redirect(w, r, iconURL, http.StatusFound)
		return
	}

	expressions := []Expression{}
	if iconURL != "" {
		expressions = append(expressions, Expression{Type: "bigBuddyIcon", URL: iconURL})
	}

	SendOK(w, r, &ExpressionsData{Expressions: expressions}, h.Logger)
}

// serveIcon writes a user's buddy icon image.
//
// A bartId names an exact image by content hash, so the endpoint serves that
// image regardless of the user's current icon and lets browsers cache it
// forever. Without a bartId it serves whatever the user's icon is now — which
// keeps changing — so that response is not cacheable, and a user with no icon
// gets the blank placeholder so the client's <img> still renders.
func (h *ExpressionsHandler) serveIcon(w http.ResponseWriter, r *http.Request, screenName state.IdentScreenName) {
	ctx := r.Context()

	var (
		icon      []byte
		err       error
		immutable bool
	)
	if raw := r.URL.Query().Get("bartId"); raw != "" {
		hash, decodeErr := hex.DecodeString(raw)
		if decodeErr != nil || len(hash) == 0 {
			http.Error(w, "invalid bartId", http.StatusBadRequest)
			return
		}
		icon, err = h.IconSource.ImageForHash(ctx, screenName, hash)
		immutable = true
	} else {
		icon, err = h.IconSource.Image(ctx, screenName)
		if errors.Is(err, ErrNoBuddyIcon) {
			// Serve the blank placeholder rather than 404 so a cleared icon still
			// renders something and the client stops showing the previous one.
			icon, err = h.IconSource.ImageForHash(ctx, screenName, wire.GetClearIconHash())
		}
	}

	switch {
	case errors.Is(err, ErrNoBuddyIcon):
		// The client swaps in its own placeholder when the icon fails to load.
		http.Error(w, "icon not found", http.StatusNotFound)
		return
	case err != nil:
		h.Logger.ErrorContext(ctx, "failed to retrieve buddy icon",
			"screenName", screenName.String(), "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if immutable {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}

	w.Header().Set("Content-Type", http.DetectContentType(icon))
	_, _ = w.Write(icon)
}

// UploadData is the payload of an expressions/upload response. The id is the
// BART type followed by the asset's content hash; setExpression takes the same
// string with the leading four hex digits (the type) stripped off.
type UploadData struct {
	ID string `json:"id" xml:"id"`
}

// Upload handles POST /expressions/upload, which stores a buddy icon.
func (h *ExpressionsHandler) Upload(w http.ResponseWriter, r *http.Request, session *Session) {
	ctx := r.Context()

	var bartType uint16
	switch t := r.URL.Query().Get("type"); t {
	case "buddyIcon", "bigBuddyIcon", "largeBuddyIcon":
		bartType = wire.BARTTypesBuddyIcon
	case "":
		SendErrorDetail(w, r, http.StatusBadRequest, statusMissingParameter, 0,
			"required parameter 'type' is missing")
		return
	default:
		SendErrorDetail(w, r, http.StatusBadRequest, statusParameterError, 0,
			"unsupported expression type")
		return
	}

	// One byte past the cap distinguishes "exactly at the limit" from "over it".
	image, err := io.ReadAll(io.LimitReader(r.Body, bartUploadMaxBytes+1))
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to read upload body", "err", err.Error())
		SendError(w, r, http.StatusBadRequest, "failed to read request body")
		return
	}
	switch {
	case len(image) == 0:
		SendErrorDetail(w, r, http.StatusBadRequest, statusParameterError, 0, "empty image")
		return
	case len(image) > bartUploadMaxBytes:
		SendErrorDetail(w, r, http.StatusBadRequest, statusParameterError, 0, "image too large")
		return
	}

	uploadReply, err := h.BARTService.UpsertItem(ctx, session.OSCARSession,
		wire.SNACFrame{FoodGroup: wire.BART, SubGroup: wire.BARTUploadQuery},
		wire.SNAC_0x10_0x02_BARTUploadQuery{Type: bartType, Data: image})
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to store BART item", "err", err.Error())
		SendError(w, r, http.StatusInternalServerError, "failed to store expression")
		return
	}

	body, ok := uploadReply.Body.(wire.SNAC_0x10_0x03_BARTUploadReply)
	if !ok {
		h.Logger.ErrorContext(ctx, "unexpected BART upload reply",
			"type", fmt.Sprintf("%T", uploadReply.Body))
		SendError(w, r, http.StatusInternalServerError, "failed to store expression")
		return
	}
	if body.Code != wire.BARTReplyCodesSuccess {
		h.Logger.ErrorContext(ctx, "BART store rejected upload", "code", body.Code)
		SendError(w, r, http.StatusInternalServerError, "failed to store expression")
		return
	}

	if err := h.publishIcon(ctx, session.OSCARSession, bartType, body.ID.Hash); err != nil {
		h.Logger.ErrorContext(ctx, "failed to publish buddy icon",
			"screenName", session.OSCARSession.IdentScreenName().String(), "err", err.Error())
		SendError(w, r, http.StatusInternalServerError, "failed to publish expression")
		return
	}

	h.Logger.InfoContext(ctx, "stored buddy icon",
		"screenName", session.OSCARSession.IdentScreenName().String(),
		"bytes", len(image),
		"hash", fmt.Sprintf("%x", body.ID.Hash))

	SendOK(w, r, &UploadData{ID: fmt.Sprintf("%04x%x", bartType, body.ID.Hash)}, h.Logger)
}

// publishIcon points the user's feedbag BART reference at hash, which is what
// makes the icon visible to buddies and to expressions/get.
//
// Upserting the item runs the same path an OSCAR client takes when it sets an
// icon: the feedbag service sees the asset already in the BART store, stamps it
// on the session and broadcasts the change to buddies.
func (h *ExpressionsHandler) publishIcon(
	ctx context.Context,
	instance *state.SessionInstance,
	bartType uint16,
	hash []byte,
) error {
	msg, err := h.FeedbagService.Query(ctx, instance,
		wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery})
	if err != nil {
		return err
	}
	reply, ok := msg.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return fmt.Errorf("unexpected feedbag reply %T", msg.Body)
	}

	fl := state.NewFeedbagList(reply.Items, rand.Intn)
	item, inserted := fl.SetIcon(bartType, hash)

	subGroup := wire.FeedbagUpdateItem
	if inserted {
		subGroup = wire.FeedbagInsertItem
	}

	_, err = h.FeedbagService.UpsertItem(ctx, instance,
		wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: subGroup},
		[]wire.FeedbagItem{item})
	return err
}

// ErrNoBuddyIcon indicates that a user has not set a buddy icon.
var ErrNoBuddyIcon = errors.New("no buddy icon")

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
