package webapi

import (
	"context"
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
	// Authentication support
	UserManager UserManager
	TokenStore  TokenStore
	// Phase 3 additions
	PreferenceManager PreferenceManager
	PermitDenyManager PermitDenyManager
	// Phase 4 additions for OSCAR Bridge
	OSCARBridgeStore OSCARBridgeStore
	OSCARConfig      OSCARConfig
	// Phase 5 additions for buddy list and messaging
	BuddyListManager interface{}
	// Phase 5 additions for chat rooms
	ChatManager *state.WebAPIChatManager
}

func (h Handler) GetHelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("got a request to the root endpoint", "method", r.Method, "path", r.URL.Path)
	_, _ = fmt.Fprintf(w, "WebAPI Server Running\n")
}
