package webapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

type Handler struct {
	AdminService      AdminService
	AuthService       AuthService
	BuddyListRegistry BuddyListRegistry
	BuddyService      BuddyService
	ChatNavService    ChatNavService
	ChatService       ChatService
	CookieBaker       CookieBaker
	DirSearchService  DirSearchService
	ICBMService       ICBMService
	LocateService     LocateService
	Logger            *slog.Logger
	OServiceService   OServiceService
	PermitDenyService PermitDenyService
	TOCConfigStore    TOCConfigStore
	SNACRateLimits    wire.SNACRateLimits
	// New fields for WebAPI handlers
	SessionRetriever SessionRetriever
	FeedbagRetriever FeedbagRetriever
	FeedbagManager   FeedbagManager
	// Phase 2 additions
	MessageRelayer        MessageRelayer
	OfflineMessageManager OfflineMessageManager
	BuddyBroadcaster      BuddyBroadcaster
	ProfileManager        ProfileManager
	RelationshipFetcher   interface {
		Relationship(ctx context.Context, me state.IdentScreenName, them state.IdentScreenName) (state.Relationship, error)
	}
	// Phase 3 additions
	PreferenceManager PreferenceManager
	PermitDenyManager PermitDenyManager
	// Phase 4 additions for OSCAR Bridge
	OSCARBridgeStore OSCARBridgeStore
	OSCARConfig      OSCARConfig
	// Phase 5 additions for buddy list and messaging
	BuddyListManager interface{}
	// Phase 5 additions for chat rooms
	ChatManager        *state.WebAPIChatManager
	RecalcWarning      func(ctx context.Context, instance *state.SessionInstance) error
	LowerWarnLevel     func(ctx context.Context, instance *state.SessionInstance)
	ChatSessionManager ChatSessionManager
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
