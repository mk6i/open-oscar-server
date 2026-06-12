package handlers

import (
	"log/slog"
	"net/http"
)

// AimStubHandler serves unimplemented Web AIM /aim/* endpoints the client
// calls during normal startup (client-side storage, forward-domain config).
type AimStubHandler struct {
	Logger *slog.Logger
}

// SetForwardDomain acknowledges the client's forward-domain registration.
// The Web AIM client fires this once when the session goes online; name may be
// the literal string "null" for local/dev servers.
func (h *AimStubHandler) SetForwardDomain(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	SendResponse(w, r, resp, h.Logger)
}

// GetData returns empty client-side data blobs (buddy list favorites, etc.).
func (h *AimStubHandler) GetData(w http.ResponseWriter, r *http.Request) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]interface{}{
		"items": []interface{}{},
	}
	SendResponse(w, r, resp, h.Logger)
}
