package handlers

import (
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// ExpressionsHandler handles Web AIM API expressions/buddy icon endpoints.
type ExpressionsHandler struct {
	IconSource BuddyIconSource
	Logger     *slog.Logger
}

// NewExpressionsHandler creates a new ExpressionsHandler.
func NewExpressionsHandler(iconSource BuddyIconSource, logger *slog.Logger) *ExpressionsHandler {
	return &ExpressionsHandler{
		IconSource: iconSource,
		Logger:     logger,
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
		SendError(w, http.StatusBadRequest, "missing target")
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

	expressions := []any{}
	if iconURL != "" {
		expressions = append(expressions, map[string]any{
			"type": "bigBuddyIcon",
			"url":  iconURL,
		})
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]any{"expressions": expressions}
	SendResponse(w, r, resp, h.Logger)
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
