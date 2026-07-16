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
	AuthService        AuthService
	BuddyListRegistry  BuddyListRegistry
	CookieBaker        CookieBaker
	ICBMService        ICBMService
	LocateService      LocateService
	Logger             *slog.Logger
	OServiceService    OServiceService
	SessionRetriever   SessionRetriever
	BuddyBroadcaster   BuddyBroadcaster
	OSCARConfig        OSCARConfig
	BuddyListManager   interface{}
	RecalcWarning      func(ctx context.Context, instance *state.SessionInstance) error
	LowerWarnLevel     func(ctx context.Context, instance *state.SessionInstance)
	ChatSessionManager ChatSessionManager
	FeedbagService     FeedbagService
	DirSearchService   DirSearchService
}

func (h Handler) GetHelloWorldHandler(w http.ResponseWriter, r *http.Request) {
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
