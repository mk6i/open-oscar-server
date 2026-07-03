package webapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mk6i/open-oscar-server/state"
)

type Handler struct {
	AuthService       AuthService
	BuddyListRegistry BuddyListRegistry
	CookieBaker       CookieBaker
	ICBMService       ICBMService
	LocateService     LocateService
	Logger            *slog.Logger
	OServiceService   OServiceService
	// New fields for WebAPI handlers
	SessionRetriever SessionRetriever
	// Phase 2 additions
	BuddyBroadcaster BuddyBroadcaster
	// Phase 3 additions
	PreferenceManager PreferenceManager
	// Phase 4 additions for OSCAR Bridge
	OSCARBridgeStore OSCARBridgeStore
	OSCARConfig      OSCARConfig
	// Phase 5 additions for buddy list and messaging
	BuddyListManager   interface{}
	RecalcWarning      func(ctx context.Context, instance *state.SessionInstance) error
	LowerWarnLevel     func(ctx context.Context, instance *state.SessionInstance)
	ChatSessionManager ChatSessionManager
	FeedbagService     FeedbagService
}

func (h Handler) GetHelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("got a request to the root endpoint", "method", r.Method, "path", r.URL.Path)
	_, _ = fmt.Fprintf(w, "WebAPI Server Running\n")
	// Must return the same JSON envelope as other Web AIM APIs.
	h.Logger.Info("webapi root GET", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	resp := map[string]interface{}{
		"response": map[string]interface{}{
			"statusCode": 200,
			"statusText": "OK",
			"data":       map[string]interface{}{},
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}
