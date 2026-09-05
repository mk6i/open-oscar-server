package webapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func NewServer(listeners []string, logger *slog.Logger, handler Handler, sessionManager *SessionManager) *Server {
	servers := make([]*http.Server, 0, len(listeners))

	authMiddleware := NewAuthMiddleware(logger)
	rateLimiter := NewRateLimitMiddleware(handler.SNACRateLimits, logger)

	authHandler := &AuthHandler{
		AuthService: handler.AuthService,
		Logger:      logger,
	}

	aimHandler := &AimHandler{
		SessionManager:   sessionManager,
		AuthService:      handler.AuthService,
		FeedbagService:   handler.FeedbagService,
		ICBMService:      handler.ICBMService,
		OServiceService:  handler.OServiceService,
		BuddyListManager: handler.BuddyListManager,
		BuddyService:     handler.BuddyService,
		IconSource:       handler.IconSource,
		BOSListener:      handler.BOSListener,
		SNACRateLimits:   handler.SNACRateLimits,
		Logger:           logger,
	}

	presenceHandler := &PresenceHandler{
		SessionManager:   sessionManager,
		FeedbagService:   handler.FeedbagService,
		BuddyBroadcaster: handler.BuddyBroadcaster,
		LocateService:    handler.LocateService,
		IconSource:       handler.IconSource,
		Logger:           logger,
	}

	buddyListHandler := &BuddyListHandler{
		BuddyListManager: handler.BuddyListManager,
		Logger:           logger,
		FeedbagService:   handler.FeedbagService,
	}

	messagingHandler := &MessagingHandler{
		ICBMService:    handler.ICBMService,
		LocateService:  handler.LocateService,
		FeedbagService: handler.FeedbagService,
		Logger:         logger,
	}

	preferenceHandler := &PreferenceHandler{
		SessionManager: sessionManager,
		FeedbagService: handler.FeedbagService,
		Logger:         logger,
	}

	memberDirHandler := &MemberDirHandler{
		DirSearchService: handler.DirSearchService,
		LocateService:    handler.LocateService,
		Logger:           logger,
	}

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	for _, l := range listeners {
		mux := http.NewServeMux()

		// CORSMiddleware wraps the session layer rather than the other way around,
		// so that responses the session layer rejects (400 missing aimsid, 401
		// expired session) still carry Access-Control-Allow-Origin. A browser
		// blocks a cross-origin response without that header, and the Web AIM
		// client reads the resulting status-0 empty response as a CORS failure and
		// permanently switches its whole request pipeline to JSONP.
		//
		// oscarRoute charges the request against the rate class for (foodGroup,
		// subGroup) before the handler runs; sessionRoute and stubRoute reach no
		// food group and so are not rate limited here.
		oscarRoute := func(foodGroup uint16, subGroup uint16, h SessionHandlerFunc) http.Handler {
			return authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager,
					rateLimiter.OSCAR(foodGroup, subGroup)(h)))
		}
		sessionRoute := func(h SessionHandlerFunc) http.Handler {
			return authMiddleware.CORSMiddleware(
				authMiddleware.RequireSession(sessionManager, h))
		}
		stubRoute := func(h http.HandlerFunc) http.Handler {
			return authMiddleware.CORSMiddleware(h)
		}

		mux.Handle("GET /{$}", http.HandlerFunc(handler.GetHelloWorldHandler))

		// Unauthenticated and outside every middleware: Flash Player fetches the
		// policy before it has a session, and refuses to look at a redirect or an
		// error envelope.
		mux.Handle("GET /crossdomain.xml", &CrossDomainPolicyHandler{Logger: logger})

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

		// No SSO cookie is involved, so this sits outside the session middleware.
		// Both methods, since clients differ on which they use.
		getInfo := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			authHandler.GetInfo(w, r)
		})
		mux.Handle("GET /auth/getInfo", getInfo)
		mux.Handle("POST /auth/getInfo", getInfo)

		mux.HandleFunc("OPTIONS /auth/getInfo", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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

		startSession := authMiddleware.CORSMiddleware(http.HandlerFunc(aimHandler.StartSession))
		mux.Handle("GET /aim/startSession", startSession)
		mux.Handle("POST /aim/startSession", startSession)

		mux.Handle("GET /aim/endSession", sessionRoute(aimHandler.EndSession))

		mux.Handle("GET /aim/fetchEvents", sessionRoute(aimHandler.FetchEvents))

		mux.Handle("GET /aim/addTempBuddy", oscarRoute(wire.Buddy, wire.BuddyAddTempBuddies, aimHandler.AddTempBuddy))
		mux.Handle("GET /aim/removeTempBuddy", oscarRoute(wire.Buddy, wire.BuddyDelTempBuddies, aimHandler.RemoveTempBuddy))

		mux.Handle("GET /aim/setForwardDomain", stubRoute(aimHandler.SetForwardDomain))
		mux.Handle("GET /aim/getData", stubRoute(aimHandler.GetData))
		mux.Handle("GET /aim/reportAction", stubRoute(aimHandler.ReportAction))

		// OSCAR Bridge endpoint. Hands off to a BOS session rather than reaching
		// a food group, so there is no OSCAR budget to charge.
		mux.Handle("GET /aim/startOSCARSession",
			authMiddleware.CORSMiddleware(http.HandlerFunc(aimHandler.StartOSCARSession)))

		conversationStub := &ConversationStubHandler{
			Logger: logger,
		}
		mux.Handle("GET /conversation/update", stubRoute(conversationStub.Update))
		mux.Handle("GET /conversation/close", stubRoute(conversationStub.Close))
		mux.Handle("GET /imlog/markRead", stubRoute(conversationStub.MarkRead))
		mux.Handle("GET /imlog/fetchStoredIMs", sessionRoute(conversationStub.FetchStoredIMs))

		// Presence and buddy list
		mux.Handle("GET /presence/get", oscarRoute(wire.Feedbag, wire.FeedbagQuery, presenceHandler.GetPresence))

		mux.Handle("GET /buddylist/addBuddy", oscarRoute(wire.Feedbag, wire.FeedbagInsertItem, buddyListHandler.AddBuddy))
		mux.Handle("GET /buddylist/addGroup", oscarRoute(wire.Feedbag, wire.FeedbagInsertItem, buddyListHandler.AddGroup))
		mux.Handle("GET /buddylist/removeBuddy", oscarRoute(wire.Feedbag, wire.FeedbagDeleteItem, buddyListHandler.RemoveBuddy))
		mux.Handle("GET /buddylist/removeGroup", oscarRoute(wire.Feedbag, wire.FeedbagDeleteItem, buddyListHandler.RemoveGroup))
		mux.Handle("GET /buddylist/renameGroup", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.RenameGroup))
		mux.Handle("GET /buddylist/moveBuddy", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.MoveBuddy))
		mux.Handle("GET /buddylist/setBuddyAttribute", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.SetBuddyAttribute))
		mux.Handle("GET /buddylist/setGroupAttribute", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.SetGroupAttribute))

		// The Web AIM client POSTs the message body (non-IE browsers); IE uses GET.
		sendIMHandler := oscarRoute(wire.ICBM, wire.ICBMChannelMsgToHost, messagingHandler.SendIM)
		mux.Handle("GET /im/sendIM", sendIMHandler)
		mux.Handle("POST /im/sendIM", sendIMHandler)

		mux.Handle("GET /im/setTyping", oscarRoute(wire.ICBM, wire.ICBMClientEvent, messagingHandler.SetTyping))

		mux.Handle("GET /presence/setState", oscarRoute(wire.OService, wire.OServiceSetUserInfoFields, presenceHandler.SetState))

		mux.Handle("GET /presence/setStatus", oscarRoute(wire.OService, wire.OServiceSetUserInfoFields, presenceHandler.SetStatus))
		mux.Handle("GET /presence/setProfile", oscarRoute(wire.Locate, wire.LocateSetInfo, presenceHandler.SetProfile))
		mux.Handle("GET /presence/getProfile", oscarRoute(wire.Locate, wire.LocateUserInfoQuery, presenceHandler.GetProfile))

		// Unauthenticated, like /expressions/get below: buddy icons load as plain
		// <img> sources that carry no aimsid.
		mux.Handle("GET /presence/icon", http.HandlerFunc(presenceHandler.Icon))

		mux.Handle("GET /memberDir/search", oscarRoute(wire.ODir, wire.ODirInfoQuery, memberDirHandler.Search))
		mux.Handle("GET /memberDir/get", oscarRoute(wire.Locate, wire.LocateGetDirInfo, memberDirHandler.Get))
		memberDirUpdate := oscarRoute(wire.Locate, wire.LocateSetDirInfo, memberDirHandler.Update)
		mux.Handle("GET /memberDir/update", memberDirUpdate)
		mux.Handle("POST /memberDir/update", memberDirUpdate)

		mux.Handle("GET /preference/set", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, preferenceHandler.SetPreferences))
		mux.Handle("GET /preference/get", oscarRoute(wire.Feedbag, wire.FeedbagQuery, preferenceHandler.GetPreferences))
		mux.Handle("GET /preference/setPermitDeny", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, preferenceHandler.SetPermitDeny))
		mux.Handle("GET /preference/getPermitDeny", oscarRoute(wire.Feedbag, wire.FeedbagQuery, preferenceHandler.GetPermitDeny))

		// Expressions endpoint (for buddy icons, etc.).
		expressionsHandler := NewExpressionsHandler(
			handler.IconSource, handler.BARTService, handler.FeedbagService, logger)
		mux.Handle("GET /expressions/get",
			authMiddleware.CORSMiddleware(
				http.HandlerFunc(expressionsHandler.Get)))
		// WithBinaryBody: the body is the raw image, and a missed parameter lookup
		// would otherwise feed it to ParseForm and consume it.
		mux.Handle("POST /expressions/upload",
			WithBinaryBody(oscarRoute(wire.BART, wire.BARTUploadQuery, expressionsHandler.Upload)))

		// Web AIM calls lifestream/* on the API host (e.g. /lifestream/getUserDetails).
		lifestreamStub := &UserInfoStubHandler{Logger: logger}
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
		serviceStub := &ServiceStubHandler{Logger: logger}
		mux.Handle("GET /service/getAttributes", stubRoute(serviceStub.GetAttributes))

		mux.Handle("OPTIONS /", authMiddleware.CORSMiddleware(
			http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})))

		mux.Handle("/", authMiddleware.CORSMiddleware(
			http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logger.Debug("webapi 404", "method", r.Method, "path", r.URL.Path)
				SendError(w, r, http.StatusNotFound, "not found")
			})))

		servers = append(servers, &http.Server{
			Addr:    l,
			Handler: RequestLogger(logger, mux),
		})
	}

	aimHandler.FnSessCfg = func(sess *state.Session) {
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

	aimHandler.FnSessInit = func(instance *state.SessionInstance) func() error {
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

	aimHandler.FnInstanceClose = func(instance *state.SessionInstance) func() {
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
	sessionManager *SessionManager
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

type Handler struct {
	AuthService        AuthService
	BuddyListRegistry  BuddyListRegistry
	ICBMService        ICBMService
	LocateService      LocateService
	Logger             *slog.Logger
	OServiceService    OServiceService
	BuddyBroadcaster   BuddyBroadcaster
	BuddyService       BuddyService
	BOSListener        config.ListenerGroup
	BuddyListManager   *BuddyListManager
	RecalcWarning      func(ctx context.Context, instance *state.SessionInstance) error
	LowerWarnLevel     func(ctx context.Context, instance *state.SessionInstance)
	ChatSessionManager ChatSessionManager
	FeedbagService     FeedbagService
	DirSearchService   DirSearchService
	IconSource         BuddyIconSource
	BARTService        BARTService
	SNACRateLimits     wire.SNACRateLimits
}

func (h Handler) GetHelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	_, _ = fmt.Fprintf(w, "WebAPI Server Running\n")
	// Must return the same JSON envelope as other Web AIM APIs.
	h.Logger.Info("webapi root GET", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	resp := map[string]interface{}{
		"response": map[string]interface{}{
			"statusCode": 200,
			"statusText": "Ok",
			"data":       map[string]interface{}{},
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}
