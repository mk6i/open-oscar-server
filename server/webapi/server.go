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
		Logger:      logger,
	}

	sessionHandler := &handlers.SessionHandler{
		SessionManager:   sessionManager,
		OSCARAuthService: handler.AuthService,
		FeedbagService:   handler.FeedbagService,
		ICBMService:      handler.ICBMService,
		BuddyListManager: handler.BuddyListManager.(*handlers.BuddyListManager),
		IconSource:       handler.IconSource,
		Logger:           logger,
		OServiceService:  handler.OServiceService,
		SNACRateLimits:   handler.SNACRateLimits,
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
		OSCARAuthService: handler.AuthService,
		Listener:         handler.BOSListener,
		Logger:           logger,
	}

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	for _, l := range listeners {
		mux := http.NewServeMux()

		// CORSMiddleware wraps the auth layer rather than the other way around, so
		// that responses the auth layer rejects (400 missing key, 403 bad key, 429
		// rate limited) still carry Access-Control-Allow-Origin. A browser blocks a
		// cross-origin response without that header, and the Web AIM client reads
		// the resulting status-0 empty response as a CORS failure and permanently
		// switches its whole request pipeline to JSONP.
		//
		// oscarRoute charges the request against the rate class for (foodGroup,
		// subGroup) before the handler runs; sessionRoute and stubRoute reach no
		// food group and so are not rate limited here.
		oscarRoute := func(foodGroup uint16, subGroup uint16, h handlers.SessionHandlerFunc) http.Handler {
			return authMiddleware.CORSMiddleware(
				authMiddleware.AuthenticateFlexible(
					authMiddleware.RequireSession(sessionManager,
						rateLimiter.OSCAR(foodGroup, subGroup)(h))))
		}
		sessionRoute := func(h handlers.SessionHandlerFunc) http.Handler {
			return authMiddleware.CORSMiddleware(
				authMiddleware.AuthenticateFlexible(
					authMiddleware.RequireSession(sessionManager, h)))
		}
		stubRoute := func(h http.HandlerFunc) http.Handler {
			return authMiddleware.CORSMiddleware(
				authMiddleware.AuthenticateFlexible(h))
		}

		// Exact root only. Pattern "GET /" matches every GET path in Go 1.22+ (prefix /), which
		// would steal /getAggregated and other lifestream URLs before stubs/404.
		mux.Handle("GET /{$}", http.HandlerFunc(handler.GetHelloWorldHandler))

		// Unauthenticated and outside every middleware: Flash Player fetches the
		// policy before it has a session, and refuses to look at a redirect or an
		// error envelope.
		mux.Handle("GET /crossdomain.xml", &handlers.CrossDomainPolicyHandler{Logger: logger})

		// Authentication endpoint (public - no API key required for user login)
		// Using pattern with explicit method for Go 1.22+ routing.
		mux.Handle("POST /auth/clientLogin", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers for public endpoint
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

			authHandler.ClientLogin(w, r)
		}))

		// Handle OPTIONS for CORS preflight
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

		// Wrapped in CORS: besides the browser navigation that renders the form,
		// the client fetches this cross-origin for its client2Web SSO handoff, and
		// a response without Access-Control-Allow-Origin reaches it as an ioError.
		loginPSP := authMiddleware.CORSMiddleware(http.HandlerFunc(authHandler.LoginPSP))
		mux.Handle("GET /_cqr/login/login.psp", loginPSP)
		mux.Handle("POST /_cqr/login/login.psp", loginPSP)

		// Authenticated Web AIM API endpoints
		// SessionInstance management - supports multiple auth methods (k, a, ts+sig_sha256).
		mux.Handle("GET /aim/startSession",
			authMiddleware.CORSMiddleware(
				authMiddleware.AuthenticateFlexible(
					http.HandlerFunc(sessionHandler.StartSession))))

		// End session - uses aimsid for auth, no k required
		mux.Handle("GET /aim/endSession", sessionRoute(sessionHandler.EndSession))

		// Event fetching - uses aimsid for auth, no k required. This is the
		// long-poll loop the client runs continuously.
		mux.Handle("GET /aim/fetchEvents", sessionRoute(eventsHandler.FetchEvents))

		// Temp buddies are session-local rather than feedbag-backed, but they
		// are the Web API's equivalent of the BUDDY temp buddy SNACs and are
		// charged as such.
		mux.Handle("GET /aim/addTempBuddy", oscarRoute(wire.Buddy, wire.BuddyAddTempBuddies, buddyListHandler.AddTempBuddy))
		mux.Handle("GET /aim/removeTempBuddy", oscarRoute(wire.Buddy, wire.BuddyDelTempBuddies, buddyListHandler.RemoveTempBuddy))

		aimStub := &handlers.AimStubHandler{Logger: logger}
		mux.Handle("GET /aim/setForwardDomain", stubRoute(aimStub.SetForwardDomain))
		mux.Handle("GET /aim/getData", stubRoute(aimStub.GetData))
		mux.Handle("GET /aim/reportAction", stubRoute(aimStub.ReportAction))

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

		// SetState only requires aimsid, no k parameter needed
		mux.Handle("GET /presence/setState", oscarRoute(wire.OService, wire.OServiceSetUserInfoFields, presenceHandler.SetState))

		// These presence endpoints support aimsid-based auth where k is not required
		mux.Handle("GET /presence/setStatus", oscarRoute(wire.OService, wire.OServiceSetUserInfoFields, presenceHandler.SetStatus))
		mux.Handle("GET /presence/setProfile", oscarRoute(wire.Locate, wire.LocateSetInfo, presenceHandler.SetProfile))
		mux.Handle("GET /presence/getProfile", oscarRoute(wire.Locate, wire.LocateUserInfoQuery, presenceHandler.GetProfile))

		// Unauthenticated, like /expressions/get below: buddy icons load as plain
		// <img> sources that carry no aimsid.
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
			authMiddleware.CORSMiddleware(
				authMiddleware.Authenticate(
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
		// getUserDetails returns a minimal AIM identity and getServices the service
		// list behind it. Every other lifestream/* method is an unimplemented
		// social-feed feature; the subtree catch-all acknowledges them with an
		// empty 200 so the client doesn't error.
		mux.Handle("GET /lifestream/getUserDetails", stubRoute(lifestreamStub.GetUserDetails))
		mux.Handle("GET /lifestream/getServices", stubRoute(lifestreamStub.GetServices))
		mux.Handle("GET /lifestream/heyGetNotifications", stubRoute(lifestreamStub.HeyGetNotifications))
		mux.Handle("GET /lifestream/", stubRoute(lifestreamStub.EmptyOK))

		// The client probes for a linked Google Talk account as soon as the
		// session comes up, and its callback dereferences response.data unless
		// the status says the service is absent.
		serviceStub := &handlers.ServiceStubHandler{Logger: logger}
		mux.Handle("GET /service/getAttributes", stubRoute(serviceStub.GetAttributes))

		// Go 1.22 patterns are method-exact, so an OPTIONS preflight matches none of
		// the "GET /x" routes above and would otherwise fall through to the 404
		// handler, failing the preflight. CORSMiddleware answers OPTIONS with a 204
		// and the appropriate headers before ever reaching the handler below.
		mux.Handle("OPTIONS /", authMiddleware.CORSMiddleware(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))

		// Unmatched paths (pattern "/" matches anything not covered by routes above).
		//
		// Wrapped in CORS: the client probes endpoints this server does not
		// implement (/service/getAttributes, /metrics/sendIM), and a 404 without
		// Access-Control-Allow-Origin is blocked by the browser rather than read as
		// a 404, which latches the client into JSONP for the rest of the session.
		mux.Handle("/", authMiddleware.CORSMiddleware(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logger.Debug("webapi 404", "method", r.Method, "path", r.URL.Path)
				handlers.SendError(w, r, http.StatusNotFound, "not found")
			})))

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
			// broadcast rate limit transitions to every instance on the account
			go handler.OServiceService.MonitorRateLimits(shutdownCtx, instance.Session())
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
