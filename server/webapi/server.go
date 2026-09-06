package webapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/rs/cors"
	"golang.org/x/sync/errgroup"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// allowAnyOrigin allows every origin through AllowOriginFunc, which echoes the
// request origin back. Leaving AllowedOrigins empty would also allow everything,
// but the library answers that with a literal "*".
func allowAnyOrigin(opts cors.Options) cors.Options {
	opts.AllowOriginFunc = func(string) bool { return true }
	return opts
}

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

	expressionsHandler := NewExpressionsHandler(
		handler.IconSource, handler.BARTService, handler.FeedbagService, logger)

	crossDomainHandler := &CrossDomainPolicyHandler{Logger: logger}
	conversationStub := &ConversationStubHandler{Logger: logger}
	lifestreamStub := &UserInfoStubHandler{Logger: logger}
	serviceStub := &ServiceStubHandler{Logger: logger}

	oscarRoute := func(foodGroup uint16, subGroup uint16, h SessionHandlerFunc) http.Handler {
		return authMiddleware.RequireSession(sessionManager,
			rateLimiter.OSCAR(foodGroup, subGroup)(h))
	}
	sessionRoute := func(h SessionHandlerFunc) http.Handler {
		return authMiddleware.RequireSession(sessionManager, h)
	}

	loginPSP := http.HandlerFunc(authHandler.LoginPSP)
	startSession := http.HandlerFunc(aimHandler.StartSession)
	sendIM := oscarRoute(wire.ICBM, wire.ICBMChannelMsgToHost, messagingHandler.SendIM)
	memberDirUpdate := oscarRoute(wire.Locate, wire.LocateSetDirInfo, memberDirHandler.Update)

	corsHandler := cors.New(corsOptions(logger, handler.AllowedOrigins))

	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())

	for _, l := range listeners {
		mux := http.NewServeMux()

		mux.HandleFunc("GET /{$}", handler.GetHelloWorldHandler)
		mux.Handle("GET /crossdomain.xml", crossDomainHandler)

		mux.HandleFunc("POST /auth/clientLogin", authHandler.ClientLogin)
		mux.HandleFunc("GET /auth/getToken", authHandler.GetToken)
		mux.HandleFunc("GET /auth/getInfo", authHandler.GetInfo)
		mux.HandleFunc("POST /auth/getInfo", authHandler.GetInfo)
		mux.HandleFunc("GET /auth/logout", authHandler.Logout)
		mux.Handle("GET /_cqr/login/login.psp", loginPSP)
		mux.Handle("POST /_cqr/login/login.psp", loginPSP)

		mux.Handle("GET /aim/startSession", startSession)
		mux.Handle("POST /aim/startSession", startSession)
		mux.Handle("GET /aim/endSession", sessionRoute(aimHandler.EndSession))
		mux.Handle("GET /aim/fetchEvents", sessionRoute(aimHandler.FetchEvents))
		mux.HandleFunc("GET /aim/startOSCARSession", aimHandler.StartOSCARSession)

		mux.Handle("GET /presence/get", oscarRoute(wire.Feedbag, wire.FeedbagQuery, presenceHandler.GetPresence))
		mux.Handle("GET /presence/setState", oscarRoute(wire.OService, wire.OServiceSetUserInfoFields, presenceHandler.SetState))
		mux.Handle("GET /presence/setStatus", oscarRoute(wire.OService, wire.OServiceSetUserInfoFields, presenceHandler.SetStatus))
		mux.Handle("GET /presence/getProfile", oscarRoute(wire.Locate, wire.LocateUserInfoQuery, presenceHandler.GetProfile))
		mux.Handle("GET /presence/setProfile", oscarRoute(wire.Locate, wire.LocateSetInfo, presenceHandler.SetProfile))
		mux.HandleFunc("GET /presence/icon", presenceHandler.Icon)

		mux.Handle("GET /buddylist/addBuddy", oscarRoute(wire.Feedbag, wire.FeedbagInsertItem, buddyListHandler.AddBuddy))
		mux.Handle("GET /buddylist/addGroup", oscarRoute(wire.Feedbag, wire.FeedbagInsertItem, buddyListHandler.AddGroup))
		mux.Handle("GET /buddylist/removeBuddy", oscarRoute(wire.Feedbag, wire.FeedbagDeleteItem, buddyListHandler.RemoveBuddy))
		mux.Handle("GET /buddylist/removeGroup", oscarRoute(wire.Feedbag, wire.FeedbagDeleteItem, buddyListHandler.RemoveGroup))
		mux.Handle("GET /buddylist/moveBuddy", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.MoveBuddy))
		mux.Handle("GET /buddylist/renameGroup", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.RenameGroup))
		mux.Handle("GET /buddylist/setBuddyAttribute", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.SetBuddyAttribute))
		mux.Handle("GET /buddylist/setGroupAttribute", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, buddyListHandler.SetGroupAttribute))
		mux.Handle("GET /aim/addTempBuddy", oscarRoute(wire.Buddy, wire.BuddyAddTempBuddies, aimHandler.AddTempBuddy))
		mux.Handle("GET /aim/removeTempBuddy", oscarRoute(wire.Buddy, wire.BuddyDelTempBuddies, aimHandler.RemoveTempBuddy))

		// The Web AIM client POSTs the message body (non-IE browsers); IE uses GET.
		mux.Handle("GET /im/sendIM", sendIM)
		mux.Handle("POST /im/sendIM", sendIM)
		mux.Handle("GET /im/setTyping", oscarRoute(wire.ICBM, wire.ICBMClientEvent, messagingHandler.SetTyping))
		mux.Handle("GET /imlog/fetchStoredIMs", sessionRoute(conversationStub.FetchStoredIMs))
		mux.HandleFunc("GET /imlog/markRead", conversationStub.MarkRead)
		mux.HandleFunc("GET /conversation/update", conversationStub.Update)
		mux.HandleFunc("GET /conversation/close", conversationStub.Close)

		mux.Handle("GET /memberDir/search", oscarRoute(wire.ODir, wire.ODirInfoQuery, memberDirHandler.Search))
		mux.Handle("GET /memberDir/get", oscarRoute(wire.Locate, wire.LocateGetDirInfo, memberDirHandler.Get))
		mux.Handle("GET /memberDir/update", memberDirUpdate)
		mux.Handle("POST /memberDir/update", memberDirUpdate)

		mux.Handle("GET /preference/get", oscarRoute(wire.Feedbag, wire.FeedbagQuery, preferenceHandler.GetPreferences))
		mux.Handle("GET /preference/set", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, preferenceHandler.SetPreferences))
		mux.Handle("GET /preference/getPermitDeny", oscarRoute(wire.Feedbag, wire.FeedbagQuery, preferenceHandler.GetPermitDeny))
		mux.Handle("GET /preference/setPermitDeny", oscarRoute(wire.Feedbag, wire.FeedbagUpdateItem, preferenceHandler.SetPermitDeny))

		mux.HandleFunc("GET /expressions/get", expressionsHandler.Get)
		mux.Handle("POST /expressions/upload",
			WithBinaryBody(oscarRoute(wire.BART, wire.BARTUploadQuery, expressionsHandler.Upload)))

		mux.HandleFunc("GET /aim/setForwardDomain", aimHandler.SetForwardDomain)
		mux.HandleFunc("GET /aim/getData", aimHandler.GetData)
		mux.HandleFunc("GET /aim/reportAction", aimHandler.ReportAction)
		mux.HandleFunc("GET /lifestream/getUserDetails", lifestreamStub.GetUserDetails)
		mux.HandleFunc("GET /lifestream/getServices", lifestreamStub.GetServices)
		mux.HandleFunc("GET /lifestream/heyGetNotifications", lifestreamStub.HeyGetNotifications)
		mux.HandleFunc("GET /lifestream/", lifestreamStub.EmptyOK)
		mux.HandleFunc("GET /service/getAttributes", serviceStub.GetAttributes)

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			logger.Debug("webapi 404", "method", r.Method, "path", r.URL.Path)
			SendError(w, r, http.StatusNotFound, "not found")
		})

		servers = append(servers, &http.Server{
			Addr:    l,
			Handler: RequestLogger(logger, corsHandler.Handler(mux)),
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
	AllowedOrigins     []string
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
	resp := map[string]any{
		"response": map[string]any{
			"statusCode": 200,
			"statusText": "Ok",
			"data":       map[string]any{},
		},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

// corsOptions maps the configured origin allowlist onto rs/cors.
func corsOptions(logger *slog.Logger, allowedOrigins []string) cors.Options {
	opts := cors.Options{
		AllowCredentials: false,
		AllowedMethods:   []string{http.MethodGet, http.MethodPost},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		MaxAge:           3600,
	}

	origins := make([]string, 0, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		if origin == "*" {
			logger.Info("WEBAPI_ALLOWED_ORIGINS is *, allowing browser calls from any origin")
			return allowAnyOrigin(opts)
		}
		origins = append(origins, origin)
	}

	if len(origins) == 0 {
		logger.Info("WEBAPI_ALLOWED_ORIGINS is not set, allowing browser calls from any origin")
		return allowAnyOrigin(opts)
	}

	opts.AllowedOrigins = origins
	return opts
}
