package kerberos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"golang.org/x/sync/errgroup"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/wire"
)

type AuthService interface {
	KerberosLogin(ctx context.Context, inBody wire.SNAC_0x050C_0x0002_KerberosLoginRequest, advertisedHost string) (wire.SNACMessage, error)
}

func NewKerberosServer(listeners []config.Listener, logger *slog.Logger, authService AuthService) *Server {
	servers := make([]*http.Server, 0, len(listeners))

	for _, l := range listeners {
		if l.KerberosListenAddress == "" {
			continue
		}

		mux := http.NewServeMux()

		mux.HandleFunc("POST /", func(writer http.ResponseWriter, request *http.Request) {
			postHandler(writer, request, authService, logger, l.BOSAdvertisedHostSSL)
		})

		servers = append(servers, &http.Server{
			Addr:    l.KerberosListenAddress,
			Handler: mux,
		})
	}

	return &Server{
		servers: servers,
		logger:  logger,
	}
}

// Server hosts an HTTP endpoint capable of handling AIM-style Kerberos
// authentication. The messages are structured as SNACs transmitted over HTTP.
type Server struct {
	servers []*http.Server
	logger  *slog.Logger
}

func (s *Server) ListenAndServe() error {
	if len(s.servers) == 0 {
		s.logger.Debug("no kerberos listeners defined")
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	for _, server := range s.servers {
		g.Go(func() error {
			s.logger.Info("starting server", "addr", server.Addr)
			if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
				cancel()
				return fmt.Errorf("unable to start kerberos server: %w", err)
			}
			return nil
		})
	}

	return g.Wait()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if len(s.servers) > 0 {
		for _, srv := range s.servers {
			_ = srv.Shutdown(ctx)
		}
		s.logger.Info("shutdown complete")
	}
	return nil
}

// postHandler handles AIM-style Kerberos authentication for AIM 6.0+.
func postHandler(w http.ResponseWriter, r *http.Request, authService AuthService, logger *slog.Logger, listenAddress string) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "unable to read HTTP body", http.StatusBadRequest)
		return
	}
	reader := bytes.NewReader(b)

	var header wire.SNACFrame
	if err := wire.UnmarshalBE(&header, reader); err != nil {
		http.Error(w, "unable to read kerberos login SNAC header", http.StatusBadRequest)
		return
	}
	if header.FoodGroup != wire.Kerberos || header.SubGroup != wire.KerberosLoginRequest {
		http.Error(w, "unexpected SNAC type", http.StatusBadRequest)
		return
	}

	var body wire.SNAC_0x050C_0x0002_KerberosLoginRequest
	if err := wire.UnmarshalBE(&body, reader); err != nil {
		http.Error(w, "unable to read kerberos login SNAC body", http.StatusBadRequest)
		return
	}

	response, err := authService.KerberosLogin(r.Context(), body, listenAddress)
	if err != nil {
		logger.Error("authService.KerberosLogin", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	logger = logger.With("ip", r.RemoteAddr)
	switch v := response.Body.(type) {
	case wire.SNAC_0x050C_0x0003_KerberosLoginSuccessResponse:
		logger.InfoContext(r.Context(), "successful kerberos login", "screen_name", v.ClientPrincipal, "redirect_to", listenAddress)
	case wire.SNAC_0x050C_0x0004_KerberosLoginErrResponse:
		logger.InfoContext(r.Context(), "failed kerberos login", "screen_name", v.ScreenName)
	}

	w.Header().Set("Content-Type", "application/x-snac")

	if err := wire.MarshalBE(response, w); err != nil {
		logger.Error("unable to marshal SNAC response", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
}
