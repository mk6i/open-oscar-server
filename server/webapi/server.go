package webapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/rs/cors"
	"golang.org/x/sync/errgroup"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/server/oscarclient"
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

	authHandler := &AuthHandler{
		AuthService: handler.AuthService,
		Logger:      logger,
	}

	aimHandler := &AimHandler{
		SessionManager:   sessionManager,
		AuthService:      handler.AuthService,
		BuddyListManager: handler.BuddyListManager,
		IconSource:       handler.IconSource,
		Dialer:           handler.Dialer,
		BOSListener:      handler.BOSListener,
		SNACRateLimits:   handler.SNACRateLimits,
		Logger:           logger,
	}

	presenceHandler := &PresenceHandler{
		SessionManager: sessionManager,
		IconSource:     handler.IconSource,
		Logger:         logger,
	}

	buddyListHandler := &BuddyListHandler{
		BuddyListManager: handler.BuddyListManager,
		Logger:           logger,
	}

	messagingHandler := &MessagingHandler{
		Logger: logger,
	}

	preferenceHandler := &PreferenceHandler{
		SessionManager: sessionManager,
		Logger:         logger,
	}

	memberDirHandler := &MemberDirHandler{
		Logger: logger,
	}

	expressionsHandler := NewExpressionsHandler(handler.IconSource, logger)

	crossDomainHandler := &CrossDomainPolicyHandler{Logger: logger}
	conversationStub := &ConversationStubHandler{Logger: logger}
	lifestreamStub := &UserInfoStubHandler{Logger: logger}
	serviceStub := &ServiceStubHandler{Logger: logger}

	sessionRoute := func(h SessionHandlerFunc) http.Handler {
		return authMiddleware.RequireSession(sessionManager, h)
	}
	// lookupRoute bounds the routes made of rate-limit-exempt lookups.
	lookupRoute := func(h SessionHandlerFunc) http.Handler {
		return authMiddleware.RequireSession(sessionManager, limitLookups(logger)(h))
	}

	loginPSP := http.HandlerFunc(authHandler.LoginPSP)
	startSession := http.HandlerFunc(aimHandler.StartSession)
	sendIM := sessionRoute(messagingHandler.SendIM)
	memberDirUpdate := sessionRoute(memberDirHandler.Update)

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

		mux.Handle("GET /presence/get", lookupRoute(presenceHandler.GetPresence))
		mux.Handle("GET /presence/setState", sessionRoute(presenceHandler.SetState))
		mux.Handle("GET /presence/setStatus", sessionRoute(presenceHandler.SetStatus))
		mux.Handle("GET /presence/getProfile", lookupRoute(presenceHandler.GetProfile))
		mux.Handle("GET /presence/setProfile", sessionRoute(presenceHandler.SetProfile))
		mux.HandleFunc("GET /presence/icon", presenceHandler.Icon)

		mux.Handle("GET /buddylist/addBuddy", sessionRoute(buddyListHandler.AddBuddy))
		mux.Handle("GET /buddylist/addGroup", sessionRoute(buddyListHandler.AddGroup))
		mux.Handle("GET /buddylist/removeBuddy", sessionRoute(buddyListHandler.RemoveBuddy))
		mux.Handle("GET /buddylist/removeGroup", sessionRoute(buddyListHandler.RemoveGroup))
		mux.Handle("GET /buddylist/moveBuddy", sessionRoute(buddyListHandler.MoveBuddy))
		mux.Handle("GET /buddylist/renameGroup", sessionRoute(buddyListHandler.RenameGroup))
		mux.Handle("GET /buddylist/setBuddyAttribute", sessionRoute(buddyListHandler.SetBuddyAttribute))
		mux.Handle("GET /buddylist/setGroupAttribute", sessionRoute(buddyListHandler.SetGroupAttribute))
		mux.Handle("GET /aim/addTempBuddy", sessionRoute(aimHandler.AddTempBuddy))
		mux.Handle("GET /aim/removeTempBuddy", sessionRoute(aimHandler.RemoveTempBuddy))

		// The Web AIM client POSTs the message body (non-IE browsers); IE uses GET.
		mux.Handle("GET /im/sendIM", sendIM)
		mux.Handle("POST /im/sendIM", sendIM)
		mux.Handle("GET /im/setTyping", sessionRoute(messagingHandler.SetTyping))
		mux.Handle("GET /imlog/fetchStoredIMs", sessionRoute(conversationStub.FetchStoredIMs))
		mux.HandleFunc("GET /imlog/markRead", conversationStub.MarkRead)
		mux.HandleFunc("GET /conversation/update", conversationStub.Update)
		mux.HandleFunc("GET /conversation/close", conversationStub.Close)

		mux.Handle("GET /memberDir/search", lookupRoute(memberDirHandler.Search))
		mux.Handle("GET /memberDir/get", lookupRoute(memberDirHandler.Get))
		mux.Handle("GET /memberDir/update", memberDirUpdate)
		mux.Handle("POST /memberDir/update", memberDirUpdate)

		mux.Handle("GET /preference/get", sessionRoute(preferenceHandler.GetPreferences))
		mux.Handle("GET /preference/set", sessionRoute(preferenceHandler.SetPreferences))
		mux.Handle("GET /preference/getPermitDeny", sessionRoute(preferenceHandler.GetPermitDeny))
		mux.Handle("GET /preference/setPermitDeny", sessionRoute(preferenceHandler.SetPermitDeny))

		mux.HandleFunc("GET /expressions/get", expressionsHandler.Get)
		mux.Handle("POST /expressions/upload", WithBinaryBody(sessionRoute(expressionsHandler.Upload)))

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

type Handler struct {
	AuthService      AuthService
	Logger           *slog.Logger
	BOSListener      config.ListenerGroup
	AllowedOrigins   []string
	BuddyListManager *BuddyListManager
	IconSource       BuddyIconSource
	// Dialer connects sessions to the OSCAR server.
	Dialer         oscarclient.Dialer
	SNACRateLimits wire.SNACRateLimits
}

func (h Handler) GetHelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("webapi root GET", "remote", r.RemoteAddr, "host", r.Host, "path", r.URL.Path)
	SendOK(w, r, nil, h.Logger)
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
