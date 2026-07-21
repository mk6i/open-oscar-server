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
)

func NewServer(listeners []string, logger *slog.Logger, handler Handler, apiKeyValidator middleware.APIKeyValidator, sessionManager *state.WebAPISessionManager) *Server {
	servers := make([]*http.Server, 0, len(listeners))

	authMiddleware := middleware.NewAuthMiddleware(apiKeyValidator, logger)

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

		// Exact root only. Pattern "GET /" matches every GET path in Go 1.22+ (prefix /), which
		// would steal /getAggregated and other lifestream URLs before stubs/404.
		mux.HandleFunc("GET /{$}", handler.GetHelloWorldHandler)

		// Authentication endpoint (public - no API key required for user login)
		// Using pattern with explicit method for Go 1.22+ routing
		mux.HandleFunc("POST /auth/clientLogin", func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers for public endpoint
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

			authHandler.ClientLogin(w, r)
		})

		// Handle OPTIONS for CORS preflight
		mux.HandleFunc("OPTIONS /auth/clientLogin", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
		})

		mux.HandleFunc("GET /auth/getToken", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			authHandler.GetToken(w, r)
		})

		mux.HandleFunc("OPTIONS /auth/getToken", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusNoContent)
		})

		// Web AIM navigates the browser here on File > Logout; clear SSO state
		// and redirect to the login screen.
		mux.HandleFunc("GET /auth/logout", authHandler.Logout)

		mux.HandleFunc("GET /_cqr/login/login.psp", authHandler.LoginPSP)
		mux.HandleFunc("POST /_cqr/login/login.psp", authHandler.LoginPSP)

		// Authenticated Web AIM API endpoints
		// SessionInstance management - supports multiple auth methods (k, a, ts+sig_sha256)
		mux.Handle("GET /aim/startSession", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				http.HandlerFunc(sessionHandler.StartSession))))

		// End session - uses aimsid for auth, no k required
		mux.Handle("GET /aim/endSession", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, sessionHandler.EndSession))))

		// Event fetching - uses aimsid for auth, no k required
		mux.Handle("GET /aim/fetchEvents", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, eventsHandler.FetchEvents))))

		// Add temp buddy - uses aimsid for auth
		mux.Handle("GET /aim/addTempBuddy", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, buddyListHandler.AddTempBuddy))))

		mux.Handle("GET /aim/removeTempBuddy", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, buddyListHandler.RemoveTempBuddy))))

		aimStub := &handlers.AimStubHandler{Logger: logger}
		aimRoute := func(h http.HandlerFunc) http.Handler {
			return authMiddleware.AuthenticateFlexible(
				authMiddleware.CORSMiddleware(http.HandlerFunc(h)))
		}
		mux.Handle("GET /aim/setForwardDomain", aimRoute(aimStub.SetForwardDomain))
		mux.Handle("GET /aim/getData", aimRoute(aimStub.GetData))

		conversationStub := &handlers.ConversationStubHandler{
			SessionManager: sessionManager,
			Logger:         logger,
		}
		mux.Handle("GET /conversation/update", aimRoute(conversationStub.Update))
		mux.Handle("GET /conversation/close", aimRoute(conversationStub.Close))
		mux.Handle("GET /imlog/markRead", aimRoute(conversationStub.MarkRead))
		mux.Handle("GET /imlog/fetchStoredIMs", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, conversationStub.FetchStoredIMs))))

		// Presence and buddy list
		// GetPresence supports aimsid-based auth, so we use flexible auth
		mux.Handle("GET /presence/get", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, presenceHandler.GetPresence))))

		buddyListRoute := func(h func(http.ResponseWriter, *http.Request, *state.WebAPISession)) http.Handler {
			return authMiddleware.AuthenticateFlexible(
				authMiddleware.CORSMiddleware(
					authMiddleware.RequireSession(sessionManager, h)))
		}
		mux.Handle("GET /buddylist/addBuddy", buddyListRoute(buddyListHandler.AddBuddy))
		mux.Handle("GET /buddylist/addGroup", buddyListRoute(buddyListHandler.AddGroup))
		mux.Handle("GET /buddylist/removeBuddy", buddyListRoute(buddyListHandler.RemoveBuddy))
		mux.Handle("GET /buddylist/removeGroup", buddyListRoute(buddyListHandler.RemoveGroup))
		mux.Handle("GET /buddylist/renameGroup", buddyListRoute(buddyListHandler.RenameGroup))
		mux.Handle("GET /buddylist/moveBuddy", buddyListRoute(buddyListHandler.MoveBuddy))
		mux.Handle("GET /buddylist/setBuddyAttribute", buddyListRoute(buddyListHandler.SetBuddyAttribute))
		mux.Handle("GET /buddylist/setGroupAttribute", buddyListRoute(buddyListHandler.SetGroupAttribute))

		// sendIM supports aimsid-based auth, so we use flexible auth.
		// The Web AIM client POSTs the message body (non-IE browsers); IE uses GET.
		sendIMHandler := authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, messagingHandler.SendIM)))
		mux.Handle("GET /im/sendIM", sendIMHandler)
		mux.Handle("POST /im/sendIM", sendIMHandler)

		mux.Handle("GET /im/setTyping", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, messagingHandler.SetTyping))))

		// SetState only requires aimsid, no k parameter needed
		mux.Handle("GET /presence/setState", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, presenceHandler.SetState))))

		// These presence endpoints support aimsid-based auth where k is not required
		mux.Handle("GET /presence/setStatus", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, presenceHandler.SetStatus))))

		mux.Handle("GET /presence/setProfile", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, presenceHandler.SetProfile))))

		mux.Handle("GET /presence/getProfile", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, presenceHandler.GetProfile))))

		mux.HandleFunc("GET /presence/icon", presenceHandler.Icon)

		// Member directory search and self directory-info retrieval. Both use
		// aimsid-based auth, so we use flexible auth.
		mux.Handle("GET /memberDir/search", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, memberDirHandler.Search))))
		mux.Handle("GET /memberDir/get", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, memberDirHandler.Get))))
		mux.Handle("GET /memberDir/update", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, memberDirHandler.Update))))

		// These endpoints support aimsid-based auth, so we use a flexible auth approach
		mux.Handle("GET /preference/set", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, preferenceHandler.SetPreferences))))

		mux.Handle("GET /preference/get", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, preferenceHandler.GetPreferences))))

		mux.Handle("GET /preference/setPermitDeny", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, preferenceHandler.SetPermitDeny))))

		mux.Handle("GET /preference/getPermitDeny", authMiddleware.AuthenticateFlexible(
			authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, preferenceHandler.GetPermitDeny))))

		// OSCAR Bridge endpoint
		mux.Handle("GET /aim/startOSCARSession", authMiddleware.Authenticate(
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
		mux.Handle("GET /expressions/get", authMiddleware.CORSMiddleware(
			http.HandlerFunc(expressionsHandler.Get)))

		// Web AIM calls lifestream/* on the API host (e.g. /lifestream/getUserDetails).
		lifestreamStub := &handlers.UserInfoStubHandler{Logger: logger}
		lifestreamRoute := func(h http.HandlerFunc) http.Handler {
			return authMiddleware.AuthenticateFlexible(
				authMiddleware.CORSMiddleware(http.HandlerFunc(h)))
		}
		// getUserDetails returns a minimal AIM identity. Every other lifestream/*
		// method is an unimplemented social-feed feature; the subtree catch-all
		// acknowledges them with an empty 200 so the client doesn't error.
		mux.Handle("GET /lifestream/getUserDetails", lifestreamRoute(lifestreamStub.GetUserDetails))
		mux.Handle("GET /lifestream/", lifestreamRoute(lifestreamStub.EmptyOK))

		// Unmatched paths (pattern "/" matches anything not covered by routes above).
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			logger.Debug("webapi 404", "method", r.Method, "path", r.URL.Path)
			handlers.SendError(w, http.StatusNotFound, "not found")
		})

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
