package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mk6i/retro-aim-server/config"
	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

func NewManagementAPI(bld config.Build, listener string, userManager UserManager, sessionRetriever SessionRetriever, chatRoomRetriever ChatRoomRetriever, chatRoomCreator ChatRoomCreator, chatSessionRetriever ChatSessionRetriever, directoryManager DirectoryManager, messageRelayer MessageRelayer, bartRetriever BuddyIconRetriever, feedbagRetriever FeedBagRetriever, accountManager AccountManager, profileRetriever ProfileRetriever, logger *slog.Logger) *Server {
	mux := http.NewServeMux()

	// Handlers for '/user' route
	mux.HandleFunc("DELETE /user", func(w http.ResponseWriter, r *http.Request) {
		deleteUserHandler(w, r, userManager, logger)
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		getUserHandler(w, r, userManager, logger)
	})
	mux.HandleFunc("POST /user", func(w http.ResponseWriter, r *http.Request) {
		postUserHandler(w, r, userManager, uuid.New, logger)
	})

	// Handlers for '/user/password' route
	mux.HandleFunc("PUT /user/password", func(w http.ResponseWriter, r *http.Request) {
		putUserPasswordHandler(w, r, userManager, logger)
	})

	// Handlers for '/user/login' route
	mux.HandleFunc("GET /user/login", func(w http.ResponseWriter, r *http.Request) {
		getUserLoginHandler(w, r, userManager, logger)
	})

	// Handlers for '/user/{screenname}/account' route
	mux.HandleFunc("GET /user/{screenname}/account", func(w http.ResponseWriter, r *http.Request) {
		getUserAccountHandler(w, r, userManager, accountManager, profileRetriever, logger)
	})
	mux.HandleFunc("PATCH /user/{screenname}/account", func(w http.ResponseWriter, r *http.Request) {
		patchUserAccountHandler(w, r, userManager, accountManager, logger)
	})

	// Handlers for '/user/{screenname}/icon' route
	mux.HandleFunc("GET /user/{screenname}/icon", func(w http.ResponseWriter, r *http.Request) {
		getUserBuddyIconHandler(w, r, userManager, feedbagRetriever, bartRetriever, logger)
	})

	// Handlers for '/session' route
	mux.HandleFunc("GET /session", func(w http.ResponseWriter, r *http.Request) {
		getSessionHandler(w, r, sessionRetriever, time.Since)
	})

	// Handlers for '/session/{screenname}' route
	mux.HandleFunc("GET /session/{screenname}", func(w http.ResponseWriter, r *http.Request) {
		getSessionHandler(w, r, sessionRetriever, time.Since)
	})
	mux.HandleFunc("DELETE /session/{screenname}", func(w http.ResponseWriter, r *http.Request) {
		deleteSessionHandler(w, r, sessionRetriever)
	})

	// Handlers for '/chat/room/public' route
	mux.HandleFunc("GET /chat/room/public", func(w http.ResponseWriter, r *http.Request) {
		getPublicChatHandler(w, r, chatRoomRetriever, chatSessionRetriever, logger)
	})
	mux.HandleFunc("POST /chat/room/public", func(w http.ResponseWriter, r *http.Request) {
		postPublicChatHandler(w, r, chatRoomCreator, logger)
	})

	// Handlers for '/chat/room/private' route
	mux.HandleFunc("GET /chat/room/private", func(w http.ResponseWriter, r *http.Request) {
		getPrivateChatHandler(w, r, chatRoomRetriever, chatSessionRetriever, logger)
	})

	// Handlers for '/instant-message' route
	mux.HandleFunc("POST /instant-message", func(w http.ResponseWriter, r *http.Request) {
		postInstantMessageHandler(w, r, messageRelayer, logger)
	})

	// Handlers for '/version' route
	mux.HandleFunc("GET /version", func(w http.ResponseWriter, r *http.Request) {
		getVersionHandler(w, bld)
	})

	// Handlers for '/directory/category' route
	mux.HandleFunc("GET /directory/category", func(w http.ResponseWriter, r *http.Request) {
		getDirectoryCategoryHandler(w, r, directoryManager, logger)
	})
	mux.HandleFunc("POST /directory/category", func(w http.ResponseWriter, r *http.Request) {
		postDirectoryCategoryHandler(w, r, directoryManager, logger)
	})

	// Handlers for '/directory/category/{id}' route
	mux.HandleFunc("DELETE /directory/category/{id}", func(w http.ResponseWriter, r *http.Request) {
		deleteDirectoryCategoryHandler(w, r, directoryManager, logger)
	})

	// Handlers for '/directory/category/{id}/keyword' route
	mux.HandleFunc("GET /directory/category/{id}/keyword", func(w http.ResponseWriter, r *http.Request) {
		getDirectoryCategoryKeywordHandler(w, r, directoryManager, logger)
	})

	// Handlers for '/directory/keyword' route
	mux.HandleFunc("POST /directory/keyword", func(w http.ResponseWriter, r *http.Request) {
		postDirectoryKeywordHandler(w, r, directoryManager, logger)
	})

	// Handlers for '/directory/keyword/{id}' route
	mux.HandleFunc("DELETE /directory/keyword/{id}", func(w http.ResponseWriter, r *http.Request) {
		deleteDirectoryKeywordHandler(w, r, directoryManager, logger)
	})

	return &Server{
		server: http.Server{
			Addr:    listener,
			Handler: mux,
		},
		logger: logger,
	}
}

type Server struct {
	server http.Server
	logger *slog.Logger
}

func (s *Server) ListenAndServe() error {
	s.logger.Info("starting server", "addr", s.server.Addr)

	if err := s.server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("unable to start management API server: %w", err)
	}

	return nil
}

func (s *Server) Shutdown(ctx context.Context) error {
	defer s.logger.Info("shutdown complete")
	return s.server.Shutdown(ctx)
}

// deleteUserHandler handles the DELETE /user endpoint.
func deleteUserHandler(w http.ResponseWriter, r *http.Request, manager UserManager, logger *slog.Logger) {
	user, err := userFromBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = manager.DeleteUser(r.Context(), state.NewIdentScreenName(user.ScreenName))
	switch {
	case errors.Is(err, state.ErrNoUser):
		http.Error(w, "user does not exist", http.StatusNotFound)
		return
	case err != nil:
		logger.Error("error deleting user DELETE /user", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	_, _ = fmt.Fprintln(w, "User account successfully deleted.")
}

// putUserPasswordHandler handles the PUT /user/password endpoint.
func putUserPasswordHandler(w http.ResponseWriter, r *http.Request, userManager UserManager, logger *slog.Logger) {
	input, err := userFromBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sn := state.NewIdentScreenName(input.ScreenName)

	if err := userManager.SetUserPassword(r.Context(), sn, input.Password); err != nil {
		switch {
		case errors.Is(err, state.ErrNoUser):
			http.Error(w, "user does not exist", http.StatusNotFound)
			return
		case errors.Is(err, state.ErrPasswordInvalid):
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		default:
			logger.Error("error updating user password PUT /user/password", "err", err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
	_, _ = fmt.Fprintln(w, "Password successfully reset.")
}

// getSessionHandler handles GET /session
func getSessionHandler(w http.ResponseWriter, r *http.Request, sessionRetriever SessionRetriever, funcTimeSince func(t time.Time) time.Duration) {
	w.Header().Set("Content-Type", "application/json")

	var allUsers []*state.Session

	if screenName := r.PathValue("screenname"); screenName != "" {
		session := sessionRetriever.RetrieveSession(state.NewIdentScreenName(screenName))
		if session == nil {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		allUsers = append(allUsers, session)
	} else {
		allUsers = sessionRetriever.AllSessions()
	}

	ou := onlineUsers{
		Count:    len(allUsers),
		Sessions: make([]sessionHandle, len(allUsers)),
	}

	for i, s := range allUsers {
		// report 0 if the user is not idle
		idleSeconds := funcTimeSince(s.IdleTime()).Seconds()
		if !s.Idle() {
			idleSeconds = 0
		}
		onlineSeconds := funcTimeSince(s.SignonTime()).Seconds()

		ou.Sessions[i] = sessionHandle{
			ID:            s.IdentScreenName().String(),
			ScreenName:    s.DisplayScreenName().String(),
			OnlineSeconds: onlineSeconds,
			AwayMessage:   s.AwayMessage(),
			IdleSeconds:   idleSeconds,
			IsICQ:         s.UIN() > 0,
		}
		ra := s.RemoteAddr()
		if ra != nil {
			ou.Sessions[i].RemoteAddr = ra.Addr().String()
			ou.Sessions[i].RemotePort = ra.Port()
		}

	}

	if err := json.NewEncoder(w).Encode(ou); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// deleteSessionHandler handles DELETE /session/{screenname}
func deleteSessionHandler(w http.ResponseWriter, r *http.Request, sessionRetriever SessionRetriever) {
	w.Header().Set("Content-Type", "application/json")

	if screenName := r.PathValue("screenname"); screenName != "" {
		session := sessionRetriever.RetrieveSession(state.NewIdentScreenName(screenName))
		if session == nil {
			errorMsg(w, "session not found", http.StatusNotFound)
			return
		}
		session.Close()
	}
	w.WriteHeader(http.StatusNoContent)
}

// getUserHandler handles the GET /user endpoint.
func getUserHandler(w http.ResponseWriter, r *http.Request, userManager UserManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	users, err := userManager.AllUsers(r.Context())
	if err != nil {
		logger.Error("error in GET /user", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	out := make([]userHandle, len(users))
	for i, u := range users {
		suspendedStatus, err := getSuspendedStatusErrCodeToText(u.SuspendedStatus)
		if err != nil {
			logger.Error("error getting suspended status in GET /user", "err", err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		out[i] = userHandle{
			ID:              u.IdentScreenName.String(),
			ScreenName:      u.DisplayScreenName.String(),
			IsICQ:           u.IsICQ,
			SuspendedStatus: suspendedStatus,
			IsBot:           u.IsBot,
		}
	}

	if err := json.NewEncoder(w).Encode(out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// postUserHandler handles the POST /user endpoint.
func postUserHandler(w http.ResponseWriter, r *http.Request, userManager UserManager, newUUID func() uuid.UUID, logger *slog.Logger) {
	input, err := userFromBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sn := state.DisplayScreenName(input.ScreenName)

	if sn.IsUIN() {
		if err := sn.ValidateUIN(); err != nil {
			http.Error(w, fmt.Sprintf("invalid uin: %s", err), http.StatusBadRequest)
			return
		}
	} else {
		if err := sn.ValidateAIMHandle(); err != nil {
			http.Error(w, fmt.Sprintf("invalid screen name: %s", err), http.StatusBadRequest)
			return
		}
	}

	user := state.User{
		AuthKey:           newUUID().String(),
		DisplayScreenName: sn,
		IdentScreenName:   sn.IdentScreenName(),
		IsICQ:             sn.IsUIN(),
	}

	if err := user.HashPassword(input.Password); err != nil {
		http.Error(w, fmt.Sprintf("invalid password: %s", err), http.StatusBadRequest)
		return
	}

	err = userManager.InsertUser(r.Context(), user)
	switch {
	case errors.Is(err, state.ErrDupUser):
		http.Error(w, "user already exists", http.StatusConflict)
		return
	case err != nil:
		logger.Error("error inserting user POST /user", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintln(w, "User account created successfully.")
}

func userFromBody(r *http.Request) (userWithPassword, error) {
	user := userWithPassword{}
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		return userWithPassword{}, errors.New("malformed input")
	}
	return user, nil
}

// getUserLoginHandler is a temporary endpoint for validating user credentials for
// chivanet. do not rely on this endpoint, as it will be eventually removed.
func getUserLoginHandler(w http.ResponseWriter, r *http.Request, userManager UserManager, logger *slog.Logger) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		// No authentication header found
		w.WriteHeader(http.StatusUnauthorized)
		w.Header().Set("WWW-Authenticate", `Basic realm="User Login"`)
		_, _ = w.Write([]byte("401 Unauthorized\n"))
		return
	}

	auth := strings.SplitN(authHeader, " ", 2)
	if len(auth) != 2 || auth[0] != "Basic" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("401 Unauthorized: Missing Basic prefix\n"))
		return
	}

	payload, err := base64.StdEncoding.DecodeString(auth[1])
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("401 Unauthorized: Invalid Base64 Encoding\n"))
		return
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("401 Unauthorized: Invalid Authentication Token\n"))
		return
	}

	username, password := state.NewIdentScreenName(pair[0]), pair[1]

	user, err := userManager.User(r.Context(), username)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("500 InternalServerError\n"))
		logger.Error("error getting user", "err", err.Error())
		return
	}
	if user == nil || !user.ValidateHash(wire.StrongMD5PasswordHash(password, user.AuthKey)) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("401 Unauthorized: Invalid Credentials\n"))
		return
	}

	// Successfully authenticated
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("200 OK: Successfully Authenticated\n"))
}

// getPublicChatHandler handles the GET /chat/room/public endpoint.
func getPublicChatHandler(w http.ResponseWriter, r *http.Request, chatRoomRetriever ChatRoomRetriever, chatSessionRetriever ChatSessionRetriever, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	rooms, err := chatRoomRetriever.AllChatRooms(r.Context(), state.PublicExchange)
	if err != nil {
		logger.Error("error in GET /chat/rooms/public", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	out := make([]chatRoom, len(rooms))
	for i, room := range rooms {
		sessions := chatSessionRetriever.AllSessions(room.Cookie())
		cr := chatRoom{
			CreateTime:   room.CreateTime(),
			Name:         room.Name(),
			Participants: make([]aimChatUserHandle, len(sessions)),
			URL:          room.URL().String(),
		}
		for j, sess := range sessions {
			cr.Participants[j] = aimChatUserHandle{
				ID:         sess.IdentScreenName().String(),
				ScreenName: sess.DisplayScreenName().String(),
			}
		}

		out[i] = cr
	}

	writeUnescapeChatURL(w, out)
}

// postPublicChatHandler handles the POST /chat/room/public endpoint.
func postPublicChatHandler(w http.ResponseWriter, r *http.Request, chatRoomCreator ChatRoomCreator, logger *slog.Logger) {
	input := chatRoomCreate{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "invalid input", http.StatusBadRequest)
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	if input.Name == "" || len(input.Name) > 50 {
		http.Error(w, "chat room name must be between 1 and 50 characters", http.StatusBadRequest)
		return
	}

	cr := state.NewChatRoom(input.Name, state.NewIdentScreenName("system"), state.PublicExchange)

	err := chatRoomCreator.CreateChatRoom(r.Context(), &cr)
	switch {
	case errors.Is(err, state.ErrDupChatRoom):
		http.Error(w, "Chat room already exists.", http.StatusConflict)
		return
	case err != nil:
		logger.Error("error inserting chat room POST /chat/room/public", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_, _ = fmt.Fprintln(w, "Chat room created successfully.")
}

// getPrivateChatHandler handles the GET /chat/room/private endpoint.
func getPrivateChatHandler(w http.ResponseWriter, r *http.Request, chatRoomRetriever ChatRoomRetriever, chatSessionRetriever ChatSessionRetriever, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	rooms, err := chatRoomRetriever.AllChatRooms(r.Context(), state.PrivateExchange)
	if err != nil {
		logger.Error("error in GET /chat/rooms/private", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	out := make([]chatRoom, len(rooms))
	for i, room := range rooms {
		sessions := chatSessionRetriever.AllSessions(room.Cookie())
		cr := chatRoom{
			CreateTime:   room.CreateTime(),
			CreatorID:    room.Creator().String(),
			Name:         room.Name(),
			Participants: make([]aimChatUserHandle, len(sessions)),
			URL:          room.URL().String(),
		}
		for j, sess := range sessions {
			cr.Participants[j] = aimChatUserHandle{
				ID:         sess.IdentScreenName().String(),
				ScreenName: sess.DisplayScreenName().String(),
			}
		}

		out[i] = cr
	}

	writeUnescapeChatURL(w, out)
}

// writeUnescapeChatURL writes a JSON-encoded list of chat rooms with unescaped
// ampersands preceding the exchange query param.
//
//	before: aim:gochat?roomname=Office+Hijinks\u0026exchange=5
//	after:  aim:gochat?roomname=Office+Hijinks&exchange=5
//
// This makes it easier to copy the gochat URL into AIM, which does not
// recognize the ampersand unicode character \u0026.
func writeUnescapeChatURL(w http.ResponseWriter, out []chatRoom) {
	buf := &bytes.Buffer{}
	if err := json.NewEncoder(buf).Encode(out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	b := bytes.ReplaceAll(buf.Bytes(), []byte(`\u0026exchange`), []byte(`&exchange`))
	if _, err := w.Write(b); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// postIMHandler handles the POST /instant-message endpoint.
func postInstantMessageHandler(w http.ResponseWriter, r *http.Request, messageRelayer MessageRelayer, logger *slog.Logger) {
	input := instantMessage{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "malformed input", http.StatusBadRequest)
		return
	}

	tlv, err := wire.ICBMFragmentList(input.Text)
	if err != nil {
		logger.Error("error sending message POST /instant-message", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	msg := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMChannelMsgToClient,
		},
		Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			ChannelID: 1,
			TLVUserInfo: wire.TLVUserInfo{
				ScreenName: input.From,
			},
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICBMTLVAOLIMData, tlv),
				},
			},
		},
	}
	messageRelayer.RelayToScreenName(context.Background(), state.NewIdentScreenName(input.To), msg)

	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintln(w, "Message sent successfully.")
}

// getUserBuddyIconHandler handles the GET /user/{screenname}/icon endpoint.
func getUserBuddyIconHandler(w http.ResponseWriter, r *http.Request, u UserManager, f FeedBagRetriever, b BuddyIconRetriever, logger *slog.Logger) {
	screenName := state.NewIdentScreenName(r.PathValue("screenname"))
	user, err := u.User(r.Context(), screenName)
	if err != nil {
		logger.Error("error retrieving user", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	iconRef, err := f.BuddyIconMetadata(r.Context(), screenName)
	if err != nil {
		logger.Error("error retrieving buddy icon ref", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if iconRef == nil || iconRef.HasClearIconHash() {
		http.Error(w, "icon not found", http.StatusNotFound)
		return
	}
	icon, err := b.BuddyIcon(r.Context(), iconRef.Hash)
	if err != nil {
		logger.Error("error retrieving buddy icon bart item", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", http.DetectContentType(icon))
	w.Write(icon)
}

// getUserAccountHandler handles the GET /user/{screenname}/account endpoint.
func getUserAccountHandler(w http.ResponseWriter, r *http.Request, userManager UserManager, a AccountManager, p ProfileRetriever, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	screenName := r.PathValue("screenname")
	user, err := userManager.User(r.Context(), state.NewIdentScreenName(screenName))
	if err != nil {
		logger.Error("error in GET /user/{screenname}/account", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	emailAddress := ""
	email, err := a.EmailAddress(r.Context(), user.IdentScreenName)
	if err != nil {
		emailAddress = ""
	} else {
		emailAddress = email.String()
	}
	regStatus, err := a.RegStatus(r.Context(), user.IdentScreenName)
	if err != nil {
		logger.Error("error in GET /user/*/account RegStatus", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	confirmStatus, err := a.ConfirmStatus(r.Context(), user.IdentScreenName)
	if err != nil {
		logger.Error("error in GET /user/*/account ConfirmStatus", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	profile, err := p.Profile(r.Context(), user.IdentScreenName)
	if err != nil {
		logger.Error("error in GET /user/*/account Profile", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	suspendedStatusText, err := getSuspendedStatusErrCodeToText(user.SuspendedStatus)
	if err != nil {
		logger.Error("error in GET /user/{screenname}/account", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
	out := userAccountHandle{
		ID:              user.IdentScreenName.String(),
		ScreenName:      user.DisplayScreenName.String(),
		EmailAddress:    emailAddress,
		RegStatus:       regStatus,
		Confirmed:       confirmStatus,
		Profile:         profile,
		IsICQ:           user.IsICQ,
		SuspendedStatus: suspendedStatusText,
		IsBot:           user.IsBot,
	}

	if err := json.NewEncoder(w).Encode(out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// patchUserAccountHandler handles the PATCH /user/{screenname}/account endpoint.
func patchUserAccountHandler(w http.ResponseWriter, r *http.Request, userManager UserManager, a AccountManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	screenName := r.PathValue("screenname")
	user, err := userManager.User(r.Context(), state.NewIdentScreenName(screenName))
	if err != nil {
		logger.Error("error in PATCH /user/{screenname}/account", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}

	input := userAccountPatch{}
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(&input); err != nil {
		errorMsg(w, err.Error(), http.StatusBadRequest)
		return
	}
	modifiedUser := false

	if input.SuspendedStatusText != nil {
		switch *input.SuspendedStatusText {
		case
			"", "deleted", "expired",
			"suspended", "suspended_age":
			suspendedStatus, err := getSuspendedStatusTextToErrCode(*input.SuspendedStatusText)
			if err != nil {
				logger.Error("error in PATCH /user/{screenname}/account", "err", err.Error())
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			if suspendedStatus != user.SuspendedStatus {
				if err := a.UpdateSuspendedStatus(r.Context(), suspendedStatus, user.IdentScreenName); err != nil {
					logger.Error("error in PATCH /user/{screenname}/account", "err", err.Error())
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
				modifiedUser = true
			}
		default:
			errorMsg(w, "suspended_status must be empty str or one of deleted,expired,suspended,suspended_age", http.StatusBadRequest)
			return
		}
	}

	if input.IsBot != nil && user.IsBot != *input.IsBot {
		if err := a.SetBotStatus(r.Context(), *input.IsBot, user.IdentScreenName); err != nil {
			logger.Error("error in PATCH /user/{screenname}/account", "err", err.Error())
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		modifiedUser = true
	}

	if !modifiedUser {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getSuspendedStatusTextToErrCode maps the given suspendedStatusText to
// the appropriate error code, or 0x0 for none.
func getSuspendedStatusTextToErrCode(suspendedStatusText string) (uint16, error) {
	suspendedStatusTextMap := map[string]uint16{
		"":              0x0,
		"deleted":       wire.LoginErrDeletedAccount,
		"expired":       wire.LoginErrExpiredAccount,
		"suspended":     wire.LoginErrSuspendedAccount,
		"suspended_age": wire.LoginErrSuspendedAccountAge,
	}
	suspendedStatus, ok := suspendedStatusTextMap[suspendedStatusText]
	if !ok {
		return 0x0, errors.New("unable to map suspendedText to error code")
	}
	return suspendedStatus, nil
}

// getSuspendedStatusErrCodeToText maps the given suspendedStatus to
// the appropriate text, or "" for none.
func getSuspendedStatusErrCodeToText(suspendedStatus uint16) (string, error) {
	suspendedStatusTextMap := map[uint16]string{
		0x0:                              "",
		wire.LoginErrDeletedAccount:      "deleted",
		wire.LoginErrExpiredAccount:      "expired",
		wire.LoginErrSuspendedAccount:    "suspended",
		wire.LoginErrSuspendedAccountAge: "suspended_age",
	}
	st, ok := suspendedStatusTextMap[suspendedStatus]
	if !ok {
		return "", errors.New("unable to map error code to suspendedText")
	}
	return st, nil
}

// getVersionHandler handles the GET /version endpoint.
func getVersionHandler(w http.ResponseWriter, bld config.Build) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(bld); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

// getDirectoryCategoryHandler handles the GET /directory/category endpoint.
func getDirectoryCategoryHandler(w http.ResponseWriter, r *http.Request, manager DirectoryManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")
	categories, err := manager.Categories(r.Context())
	if err != nil {
		logger.Error("error in GET /directory/category", "err", err.Error())
		errorMsg(w, "internal server error", http.StatusInternalServerError)
		return
	}

	out := make([]directoryCategory, len(categories))
	for i, category := range categories {
		out[i] = directoryCategory{
			ID:   category.ID,
			Name: category.Name,
		}
	}

	if err := json.NewEncoder(w).Encode(out); err != nil {
		errorMsg(w, err.Error(), http.StatusInternalServerError)
	}
}

// postDirectoryCategoryHandler handles the POST /directory/category endpoint.
func postDirectoryCategoryHandler(w http.ResponseWriter, r *http.Request, manager DirectoryManager, logger *slog.Logger) {
	input := directoryCategoryCreate{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		errorMsg(w, "malformed input", http.StatusBadRequest)
		return
	}

	category, err := manager.CreateCategory(r.Context(), input.Name)
	if err != nil {
		if errors.Is(err, state.ErrKeywordCategoryExists) {
			errorMsg(w, "category already exists", http.StatusConflict)
		} else {
			logger.Error("error in POST /directory/category", "err", err.Error())
			errorMsg(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.WriteHeader(http.StatusCreated)
	dc := directoryCategory{
		ID:   category.ID,
		Name: category.Name,
	}
	if err := json.NewEncoder(w).Encode(dc); err != nil {
		errorMsg(w, err.Error(), http.StatusBadRequest)
	}
}

// deleteDirectoryCategoryHandler handles the DELETE /directory/category/{id} endpoint.
func deleteDirectoryCategoryHandler(w http.ResponseWriter, r *http.Request, manager DirectoryManager, logger *slog.Logger) {
	categoryID, err := strconv.ParseUint(r.PathValue("id"), 10, 8)
	if err != nil {
		http.Error(w, "invalid category ID", http.StatusBadRequest)
		return
	}

	if err := manager.DeleteCategory(r.Context(), uint8(categoryID)); err != nil {
		switch {
		case errors.Is(err, state.ErrKeywordCategoryNotFound):
			errorMsg(w, "category not found", http.StatusNotFound)
			return
		case errors.Is(err, state.ErrKeywordInUse):
			errorMsg(w, "can't delete because category in use by a user", http.StatusConflict)
			return
		default:
			logger.Error("error in DELETE /directory/category/{id}", "err", err.Error())
			errorMsg(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// getDirectoryCategoryKeywordHandler handles the GET /directory/category/{id}/keyword endpoint.
func getDirectoryCategoryKeywordHandler(w http.ResponseWriter, r *http.Request, manager DirectoryManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	categoryID, err := strconv.ParseUint(r.PathValue("id"), 10, 8)
	if err != nil {
		errorMsg(w, "invalid category ID", http.StatusBadRequest)
		return
	}

	categories, err := manager.KeywordsByCategory(r.Context(), uint8(categoryID))
	if err != nil {
		if errors.Is(err, state.ErrKeywordCategoryNotFound) {
			errorMsg(w, "category not found", http.StatusNotFound)
		} else {
			logger.Error("error in GET /directory/category/{id}/keyword", "err", err.Error())
			errorMsg(w, "internal server error", http.StatusInternalServerError)
		}
		return
	}

	out := make([]directoryCategory, len(categories))
	for i, category := range categories {
		out[i] = directoryCategory{
			ID:   category.ID,
			Name: category.Name,
		}
	}

	if err := json.NewEncoder(w).Encode(out); err != nil {
		errorMsg(w, err.Error(), http.StatusInternalServerError)
	}
}

// postDirectoryKeywordHandler handles the POST /directory/keyword endpoint.
func postDirectoryKeywordHandler(w http.ResponseWriter, r *http.Request, manager DirectoryManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	input := directoryKeywordCreate{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		errorMsg(w, "malformed input", http.StatusBadRequest)
		return
	}

	kw, err := manager.CreateKeyword(r.Context(), input.Name, input.CategoryID)
	if err != nil {
		switch {
		case errors.Is(err, state.ErrKeywordCategoryNotFound):
			errorMsg(w, "category not found", http.StatusNotFound)
			return
		case errors.Is(err, state.ErrKeywordExists):
			errorMsg(w, "keyword already exists", http.StatusConflict)
			return
		default:
			logger.Error("error in POST /directory/keyword", "err", err.Error())
			errorMsg(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusCreated)

	dc := directoryKeyword{
		ID:   kw.ID,
		Name: kw.Name,
	}
	if err := json.NewEncoder(w).Encode(dc); err != nil {
		errorMsg(w, err.Error(), http.StatusBadRequest)
	}
}

// deleteDirectoryKeywordHandler handles the DELETE /directory/keyword/{id} endpoint.
func deleteDirectoryKeywordHandler(w http.ResponseWriter, r *http.Request, manager DirectoryManager, logger *slog.Logger) {
	keywordID, err := strconv.ParseUint(r.PathValue("id"), 10, 8)
	if err != nil {
		errorMsg(w, "invalid keyword ID", http.StatusBadRequest)
		return
	}

	if err := manager.DeleteKeyword(r.Context(), uint8(keywordID)); err != nil {
		switch {
		case errors.Is(err, state.ErrKeywordInUse):
			errorMsg(w, "can't delete because category in use by a user", http.StatusConflict)
			return
		case errors.Is(err, state.ErrKeywordNotFound):
			errorMsg(w, "keyword not found", http.StatusNotFound)
			return
		default:
			logger.Error("error in DELETE /directory/keyword/{id}", "err", err.Error())
			errorMsg(w, "internal server error", http.StatusInternalServerError)
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// errorMsg sends an error response message and code.
func errorMsg(w http.ResponseWriter, error string, code int) {
	msg := messageBody{Message: error}
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(msg); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
