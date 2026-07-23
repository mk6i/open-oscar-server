package webapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/mk6i/open-oscar-server/server/webapi/handlers"
	"github.com/mk6i/open-oscar-server/server/webapi/middleware"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func NewServer(listeners []string, logger *slog.Logger, handler Handler, apiKeyValidator middleware.APIKeyValidator, sessionManager *state.WebAPISessionManager) *Server {
	servers := make([]*http.Server, 0, len(listeners))

	authMiddleware := middleware.NewAuthMiddleware(apiKeyValidator, logger)
	rateLimiter := handlers.NewRateLimitMiddleware(handler.SNACRateLimits, logger)

	authHandler := &handlers.AuthHandler{
		AuthService: handler.AuthService,
		CookieBaker: handler.CookieBaker,
		Logger:      logger,
	}

	sessionHandler := &handlers.SessionHandler{
		SessionManager:   sessionManager,
		OSCARAuthService: handler.AuthService,
		FeedbagService:   handler.FeedbagService,
		BuddyListManager: handler.BuddyListManager.(*handlers.BuddyListManager),
		IconSource:       handler.IconSource,
		Logger:           logger,
		OServiceService:  handler.OServiceService,
	}

	eventsHandler := &handlers.EventsHandler{
		SessionManager: sessionManager,
		Logger:         logger,
	}

	presenceHandler := &handlers.PresenceHandler{
		SessionManager:   sessionManager,
		FeedbagService:   handler.FeedbagService,
		BuddyBroadcaster: handler.BuddyBroadcaster,
		LocateService:    handler.LocateService,
		IconSource:       handler.IconSource,
		Logger:           logger,
	}

	buddyListHandler := &handlers.BuddyListHandler{
		BuddyListManager: handler.BuddyListManager.(*handlers.BuddyListManager),
		Logger:           logger,
		FeedbagService:   handler.FeedbagService,
	}

	messagingHandler := &handlers.MessagingHandler{
		SessionManager: sessionManager,
		ICBMService:    handler.ICBMService,
		LocateService:  handler.LocateService,
		FeedbagService: handler.FeedbagService,
		Logger:         logger,
	}

	preferenceHandler := &handlers.PreferenceHandler{
		SessionManager: sessionManager,
		FeedbagService: handler.FeedbagService,
		Logger:         logger,
	}

	memberDirHandler := &handlers.MemberDirHandler{
		DirSearchService: handler.DirSearchService,
		LocateService:    handler.LocateService,
		Logger:           logger,
	}

	oscarBridgeHandler := &handlers.OSCARBridgeHandler{
		SessionManager:   sessionManager,
		OSCARAuthService: handler.AuthService,
		CookieBaker:      handler.CookieBaker,
		Config:           handler.OSCARConfig,
		Logger:           logger,
	}

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	for _, l := range listeners {
		mux := http.NewServeMux()

		// Route builders. Each applies the auth chain, plus the OSCAR rate limiter
		// for handlers that reach a food group.
		//
		// oscarRoute is for handlers that reach an OSCAR food group: the request
		// is charged against the session's rate class for (foodGroup, subGroup),
		// the same budget a native OSCAR or TOC client spends. sessionRoute and
		// stubRoute cover handlers that reach no food group and so have no OSCAR
		// budget to charge; they are not rate limited here (edge rate limiting by
		// a reverse proxy is expected to cover them).
		oscarRoute := func(foodGroup uint16, subGroup uint16, h handlers.SessionHandlerFunc) http.Handler {
			return authMiddleware.AuthenticateFlexible(
				authMiddleware.CORSMiddleware(
					authMiddleware.RequireSession(sessionManager,
						rateLimiter.OSCAR(foodGroup, subGroup)(h))))
		}
		sessionRoute := func(h handlers.SessionHandlerFunc) http.Handler {
			return authMiddleware.AuthenticateFlexible(
				authMiddleware.CORSMiddleware(
					authMiddleware.RequireSession(sessionManager, h)))
		}
		// stubRoute is sessionRoute's counterpart for the stub handlers, which
		// never resolve a session object.
		stubRoute := func(h http.HandlerFunc) http.Handler {
			return authMiddleware.AuthenticateFlexible(
				authMiddleware.CORSMiddleware(h))
		}

		// Exact root only. Pattern "GET /" matches every GET path in Go 1.22+ (prefix /), which
		// would steal /getAggregated and other lifestream URLs before stubs/404.
		mux.Handle("GET /{$}", http.HandlerFunc(handler.GetHelloWorldHandler))

		// Authentication endpoint (public - no API key required for user login)
		// Using pattern with explicit method for Go 1.22+ routing.
		mux.Handle("POST /auth/clientLogin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers for public endpoint
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

			authHandler.ClientLogin(w, r)
		}))

		// Handle OPTIONS for CORS preflight. Preflights only set headers and are
		// cached by the browser for an hour, so they are left unlimited rather
		// than risking a rejected preflight blocking the login that follows it.
		mux.HandleFunc("OPTIONS /auth/clientLogin", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
		})

		mux.Handle("GET /auth/getToken", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			authHandler.GetToken(w, r)
		}))

		mux.HandleFunc("OPTIONS /auth/getToken", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
		})

		// Web AIM navigates the browser here on File > Logout; clear SSO state
		// and redirect to the login screen.
		mux.Handle("GET /auth/logout", http.HandlerFunc(authHandler.Logout))

		// GET renders the login form (a browser navigation), POST submits
		// credentials.
		mux.Handle("GET /_cqr/login/login.psp", http.HandlerFunc(authHandler.LoginPSP))
		mux.Handle("POST /_cqr/login/login.psp", http.HandlerFunc(authHandler.LoginPSP))

		// Authenticated Web AIM API endpoints
		// SessionInstance management - supports multiple auth methods (k, a, ts+sig_sha256).
		mux.Handle("GET /aim/startSession",
			authMiddleware.AuthenticateFlexible(
				authMiddleware.CORSMiddleware(
					http.HandlerFunc(sessionHandler.StartSession))))

		// End session - uses aimsid for auth, no k required
		mux.Handle("GET /aim/endSession", sessionRoute(sessionHandler.EndSession))

		// Event fetching - uses aimsid for auth, no k required. This is the
		// long-poll loop the client runs continuously; RecoverOnPoll uses it to
		// surface a rate limit "clear" to an idle session that already recovered.
		mux.Handle("GET /aim/fetchEvents", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager,
					rateLimiter.RecoverOnPoll(eventsHandler.FetchEvents)))))

		// Temp buddies are session-local rather than feedbag-backed, but they
		// are the Web API's equivalent of the BUDDY temp buddy SNACs and are
		// charged as such.
		mux.Handle("GET /aim/addTempBuddy", oscarRoute(wire.Buddy, wire.BuddyAddTempBuddies, buddyListHandler.AddTempBuddy))
		mux.Handle("GET /aim/removeTempBuddy", oscarRoute(wire.Buddy, wire.BuddyDelTempBuddies, buddyListHandler.RemoveTempBuddy))

		aimStub := &handlers.AimStubHandler{Logger: logger}
		mux.Handle("GET /aim/setForwardDomain", stubRoute(aimStub.SetForwardDomain))
		mux.Handle("GET /aim/getData", stubRoute(aimStub.GetData))

		conversationStub := &handlers.ConversationStubHandler{
			SessionManager: sessionManager,
			Logger:         logger,
		}
		mux.Handle("GET /conversation/update", stubRoute(conversationStub.Update))
		mux.Handle("GET /conversation/close", stubRoute(conversationStub.Close))
		mux.Handle("GET /imlog/markRead", stubRoute(conversationStub.MarkRead))
		mux.Handle("GET /imlog/fetchStoredIMs", sessionRoute(conversationStub.FetchStoredIMs))

		// Presence and buddy list
		// GetPresence supports aimsid-based auth, so we use flexible auth
		mux.Handle("GET /presence/get", oscarRoute(wire.Feedbag, wire.FeedbagQuery, presenceHandler.GetPresence))

		// Each buddy list route is charged against the feedbag SNAC its handler
		// ultimately issues, so a client editing the buddy list over HTTP spends
		// the same budget as one editing it over OSCAR.
		mux.Handle("GET /buddylist/addBuddy", oscarRoute(wire.Feedbag, wire.FeedbagInsertItem, buddyListHandler.AddBuddy))
		mux.Handle("GET /buddylist/addGroup", oscarRoute(wire.Feedbag, wire.FeedbagInsertItem, buddyListHandler.AddGroup))
		mux.Handle("GET /buddylist/removeBuddy", oscarRoute(wire.Feedbag, wire.FeedbagDeleteItem, buddyListHandler.RemoveBuddy))
		mux.Handle("GET /buddylist/removeGroup", oscarRoute(wire.Feedbag, wire.FeedbagDeleteItem, buddyListHandler.RemoveGroup))
		mux.Handle("GET /buddylist/renameGroup", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.RenameGroup))
		mux.Handle("GET /buddylist/moveBuddy", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.MoveBuddy))
		mux.Handle("GET /buddylist/setBuddyAttribute", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.SetBuddyAttribute))
		mux.Handle("GET /buddylist/setGroupAttribute", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.SetGroupAttribute))

		// sendIM supports aimsid-based auth, so we use flexible auth.
		// The Web AIM client POSTs the message body (non-IE browsers); IE uses GET.
		sendIMHandler := oscarRoute(wire.ICBM, wire.ICBMChannelMsgToHost, messagingHandler.SendIM)
		mux.Handle("GET /im/sendIM", sendIMHandler)
		mux.Handle("POST /im/sendIM", sendIMHandler)

		mux.Handle("GET /im/setTyping", oscarRoute(wire.ICBM, wire.ICBMClientEvent, messagingHandler.SetTyping))

		// SetState only requires aimsid, no k parameter needed. State and status
		// changes broadcast new user info, the OSERVICE equivalent.
		mux.Handle("GET /presence/setState", oscarRoute(wire.OService, wire.OServiceSetUserInfoFields, presenceHandler.SetState))

		// These presence endpoints support aimsid-based auth where k is not required
		mux.Handle("GET /presence/setStatus", oscarRoute(wire.OService, wire.OServiceSetUserInfoFields, presenceHandler.SetStatus))
		mux.Handle("GET /presence/setProfile", oscarRoute(wire.Locate, wire.LocateSetInfo, presenceHandler.SetProfile))
		mux.Handle("GET /presence/getProfile", oscarRoute(wire.Locate, wire.LocateUserInfoQuery, presenceHandler.GetProfile))

		// Unauthenticated, like /expressions/get below. Buddy icons are loaded
		// as plain <img> sources, many per buddy list render.
		mux.Handle("GET /presence/icon", http.HandlerFunc(presenceHandler.Icon))

		// Member directory search and self directory-info retrieval. Both use
		// aimsid-based auth, so we use flexible auth.
		mux.Handle("GET /memberDir/search", oscarRoute(wire.ODir, wire.ODirInfoQuery, memberDirHandler.Search))
		mux.Handle("GET /memberDir/get", oscarRoute(wire.Locate, wire.LocateGetDirInfo, memberDirHandler.Get))
		mux.Handle("GET /memberDir/update", oscarRoute(wire.Locate, wire.LocateSetDirInfo, memberDirHandler.Update))

		// These endpoints support aimsid-based auth, so we use a flexible auth approach
		mux.Handle("GET /preference/set", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, preferenceHandler.SetPreferences))
		mux.Handle("GET /preference/get", oscarRoute(wire.Feedbag, wire.FeedbagQuery, preferenceHandler.GetPreferences))
		mux.Handle("GET /preference/setPermitDeny", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, preferenceHandler.SetPermitDeny))
		mux.Handle("GET /preference/getPermitDeny", oscarRoute(wire.Feedbag, wire.FeedbagQuery, preferenceHandler.GetPermitDeny))

		// OSCAR Bridge endpoint. Hands off to a BOS session rather than reaching
		// a food group, so there is no OSCAR budget to charge.
		mux.Handle("GET /aim/startOSCARSession",
			authMiddleware.Authenticate(
				authMiddleware.CORSMiddleware(
					http.HandlerFunc(oscarBridgeHandler.StartOSCARSession))))

		// Expressions endpoint (for buddy icons, etc.).
		//
		// Unauthenticated, like /presence/icon: the buddyIcon URLs this serves are
		// published to the client and loaded as plain <img> sources, which carry
		// neither an aimsid nor an API key. Threading a session token through them
		// instead would leak it into the DOM and defeat caching, since these URLs
		// outlive the session that produced them. Buddy icons are public assets.
		expressionsHandler := handlers.NewExpressionsHandler(handler.IconSource, logger)
		mux.Handle("GET /expressions/get",
			authMiddleware.CORSMiddleware(
				http.HandlerFunc(expressionsHandler.Get)))

		// Web AIM calls lifestream/* on the API host (e.g. /lifestream/getUserDetails).
		lifestreamStub := &handlers.UserInfoStubHandler{Logger: logger}
		// getUserDetails returns a minimal AIM identity. Every other lifestream/*
		// method is an unimplemented social-feed feature; the subtree catch-all
		// acknowledges them with an empty 200 so the client doesn't error.
		mux.Handle("GET /lifestream/getUserDetails", stubRoute(lifestreamStub.GetUserDetails))
		mux.Handle("GET /lifestream/", stubRoute(lifestreamStub.EmptyOK))

		// Unmatched paths (pattern "/" matches anything not covered by routes above).
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logger.Debug("webapi 404", "method", r.Method, "path", r.URL.Path)
			handlers.SendError(w, http.StatusNotFound, "not found")
		}))

		servers = append(servers, &http.Server{
			Addr:    l,
			Handler: middleware.RequestLogger(logger, mux),
		})
	}

	sessionHandler.FnSessCfg = func(sess *state.Session) {
		sess.OnSessionClose(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			if !shuttingDown(shutdownCtx) {
				if err := handler.BuddyBroadcaster.BroadcastBuddyDeparted(ctx, sess.IdentScreenName()); err != nil {
					logger.ErrorContext(ctx, "error sending buddy departure notifications", "err", err.Error())
				}
			}

			// buddy list must be cleared before session is closed, otherwise
			// there will be a race condition that could cause the buddy list
			// be prematurely deleted.
			if err := handler.BuddyListRegistry.UnregisterBuddyList(ctx, sess.IdentScreenName()); err != nil {
				logger.ErrorContext(ctx, "error removing buddy list entry", "err", err.Error())
			}
			handler.ChatSessionManager.RemoveUserFromAllChats(sess.IdentScreenName())
			handler.AuthService.Signout(ctx, sess)
		})
	}

	sessionHandler.FnSessInit = func(instance *state.SessionInstance) func() error {
		return func() error {
			// make buddy list visible to other users
			if err := handler.BuddyListRegistry.RegisterBuddyList(shutdownCtx, instance.IdentScreenName()); err != nil {
				return fmt.Errorf("unable to init buddy list: %w", err)
			}
			// restore warning level from last session
			if err := handler.RecalcWarning(shutdownCtx, instance); err != nil {
				return fmt.Errorf("failed to recalculate warning level: %w", err)
			}
			// periodically decay warning level
			go handler.LowerWarnLevel(shutdownCtx, instance)
			return nil
		}
	}

	sessionHandler.FnInstanceClose = func(instance *state.SessionInstance) func() {
		return func() {
			if shuttingDown(shutdownCtx) {
				return
			}
			if instance.Session().Invisible() {
				if err := handler.BuddyBroadcaster.BroadcastBuddyDeparted(shutdownCtx, instance.IdentScreenName()); err != nil {
					logger.ErrorContext(shutdownCtx, "error sending buddy departure notifications", "err", err.Error())
				}
			} else {
				if err := handler.BuddyBroadcaster.BroadcastBuddyArrived(shutdownCtx, instance.IdentScreenName(), instance.Session().TLVUserInfo()); err != nil {
					logger.ErrorContext(shutdownCtx, "error sending buddy arrival notifications", "err", err.Error())
				}
			}
		}
	}
	return &Server{
		servers:        servers,
		logger:         logger,
		sessionManager: sessionManager,
		shutdownCtx:    shutdownCtx,
		shutdownCancel: shutdownCancel,
	}
}

// Server hosts an HTTP endpoint capable of handling AIM-style Kerberos
// authentication. The messages are structured as SNACs transmitted over HTTP.
//
// shutdownCtx bounds the lifetime of the background session reaper: ListenAndServe
// drives it, and Shutdown (or a failed listener) calls shutdownCancel to unwind.
type Server struct {
	servers        []*http.Server
	logger         *slog.Logger
	sessionManager *state.WebAPISessionManager
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
}

func (s *Server) ListenAndServe() error {
	if len(s.servers) == 0 {
		s.logger.Debug("no webapi listeners defined")
		return nil
	}

	g, ctx := errgroup.WithContext(s.shutdownCtx)

	g.Go(func() error {
		s.sessionManager.Run(ctx)
		return nil
	})

	for _, server := range s.servers {
		g.Go(func() error {
			s.logger.Info("starting server", "addr", server.Addr)
			if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				s.shutdownCancel()
				return fmt.Errorf("unable to start webapi server: %w", err)
			}
			return nil
		})
	}

	return g.Wait()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Debug("Initiating graceful shutdown...")
	s.shutdownCancel() // stop the session reaper so ListenAndServe's errgroup can drain

	var errs []error
	if err := s.sessionManager.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("draining webapi sessions: %w", err))
	}

	for _, srv := range s.servers {
		if err := srv.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("stopping webapi listener %s: %w", srv.Addr, err))
		}
	}

	if err := errors.Join(errs...); err != nil {
		s.logger.Error("shutdown incomplete", "err", err.Error())
		return err
	}
	s.logger.Info("shutdown complete")
	return nil
}

func shuttingDown(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		// server is shutting down, don't send buddy notifications
		return true
	default:
	}
	return false
}
