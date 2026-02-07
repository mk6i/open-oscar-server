package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func NewManagementAPI(bld config.Build, listener string, userManager UserManager, sessionRetriever SessionRetriever, buddyBroadcaster BuddyBroadcaster, chatRoomRetriever ChatRoomRetriever, chatRoomCreator ChatRoomCreator, chatRoomDeleter ChatRoomDeleter, chatSessionRetriever ChatSessionRetriever, directoryManager DirectoryManager, messageRelayer MessageRelayer, bartAssetManager BARTAssetManager, feedbagRetriever FeedBagRetriever, feedbagManager FeedbagManager, accountManager AccountManager, profileRetriever ProfileRetriever, webAPIKeyManager WebAPIKeyManager, icqProfileManager ICQProfileManager, createAccount state.CreateAccountFunc, logger *slog.Logger) *Server {
	mux := http.NewServeMux()

	// Handlers for '/user' route
	mux.HandleFunc("DELETE /user", func(w http.ResponseWriter, r *http.Request) {
		deleteUserHandler(w, r, userManager, logger)
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		getUserHandler(w, r, userManager, logger)
	})
	mux.HandleFunc("POST /user", func(w http.ResponseWriter, r *http.Request) {
		postUserHandler(w, r, createAccount, logger)
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
		getUserBuddyIconHandler(w, r, userManager, feedbagRetriever, bartAssetManager, logger)
	})

	// Handlers for '/user/{screenname}/icq' route
	mux.HandleFunc("GET /user/{screenname}/icq", func(w http.ResponseWriter, r *http.Request) {
		getICQProfileHandler(w, r, icqProfileManager, logger)
	})
	mux.HandleFunc("PUT /user/{screenname}/icq", func(w http.ResponseWriter, r *http.Request) {
		putICQProfileHandler(w, r, icqProfileManager, logger)
	})

	// Handlers for '/session' route
	mux.HandleFunc("GET /session", func(w http.ResponseWriter, r *http.Request) {
		getSessionHandler(w, r, sessionRetriever, time.Now)
	})

	// Handlers for '/session/{screenname}' route
	mux.HandleFunc("GET /session/{screenname}", func(w http.ResponseWriter, r *http.Request) {
		getSessionHandler(w, r, sessionRetriever, time.Now)
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
	mux.HandleFunc("DELETE /chat/room/public", func(w http.ResponseWriter, r *http.Request) {
		deletePublicChatHandler(w, r, chatRoomDeleter, logger)
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

	// Handler for admin UI
	mux.HandleFunc("GET /admin", adminUIHandler)

	// Handlers for '/admin/webapi/keys' route - Web API key management
	mux.HandleFunc("POST /admin/webapi/keys", func(w http.ResponseWriter, r *http.Request) {
		postWebAPIKeyHandler(w, r, webAPIKeyManager, uuid.New, logger)
	})
	mux.HandleFunc("GET /admin/webapi/keys", func(w http.ResponseWriter, r *http.Request) {
		getWebAPIKeysHandler(w, r, webAPIKeyManager, logger)
	})
	mux.HandleFunc("GET /admin/webapi/keys/{id}", func(w http.ResponseWriter, r *http.Request) {
		getWebAPIKeyHandler(w, r, webAPIKeyManager, logger)
	})
	mux.HandleFunc("PUT /admin/webapi/keys/{id}", func(w http.ResponseWriter, r *http.Request) {
		putWebAPIKeyHandler(w, r, webAPIKeyManager, logger)
	})
	mux.HandleFunc("DELETE /admin/webapi/keys/{id}", func(w http.ResponseWriter, r *http.Request) {
		deleteWebAPIKeyHandler(w, r, webAPIKeyManager, logger)
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

	// Handlers for '/bart' route
	mux.HandleFunc("GET /bart", func(w http.ResponseWriter, r *http.Request) {
		getBARTByTypeHandler(w, r, bartAssetManager, logger)
	})

	// Handlers for '/bart/{hash}' route
	mux.HandleFunc("GET /bart/{hash}", func(w http.ResponseWriter, r *http.Request) {
		getBARTHandler(w, r, bartAssetManager, logger)
	})
	mux.HandleFunc("POST /bart/{hash}", func(w http.ResponseWriter, r *http.Request) {
		postBARTHandler(w, r, bartAssetManager, logger)
	})
	mux.HandleFunc("DELETE /bart/{hash}", func(w http.ResponseWriter, r *http.Request) {
		deleteBARTHandler(w, r, bartAssetManager, logger)
	})

	// Handlers for '/feedbag/{screen_name}/group' route
	mux.HandleFunc("GET /feedbag/{screen_name}/group", func(w http.ResponseWriter, r *http.Request) {
		getFeedbagBuddyHandler(w, r, feedbagManager, logger)
	})

	// Handlers for '/feedbag/{screen_name}/group/{group_id}/buddy/{buddy_screen_name}' route
	mux.HandleFunc("PUT /feedbag/{screen_name}/group/{group_id}/buddy/{buddy_screen_name}", func(w http.ResponseWriter, r *http.Request) {
		putFeedbagBuddyHandler(w, r, buddyBroadcaster, feedbagManager, sessionRetriever, messageRelayer, logger, rand.Intn)
	})
	mux.HandleFunc("DELETE /feedbag/{screen_name}/group/{group_id}/buddy/{buddy_screen_name}", func(w http.ResponseWriter, r *http.Request) {
		deleteFeedbagBuddyHandler(w, r, buddyBroadcaster, feedbagManager, sessionRetriever, messageRelayer, logger)
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
func getSessionHandler(w http.ResponseWriter, r *http.Request, sessionRetriever SessionRetriever, nowFn func() time.Time) {
	w.Header().Set("Content-Type", "application/json")

	var allSessions []*state.Session

	if screenName := r.PathValue("screenname"); screenName != "" {
		session := sessionRetriever.RetrieveSession(state.NewIdentScreenName(screenName))
		if session == nil {
			http.Error(w, "session not found", http.StatusNotFound)
			return
		}
		allSessions = append(allSessions, session)
	} else {
		// AllSessions returns all sessions
		allSessions = sessionRetriever.AllSessions()
	}

	ou := onlineUsers{
		Count:    len(allSessions),
		Sessions: make([]sessionHandle, len(allSessions)),
	}

	for i, s := range allSessions {
		instances := s.Instances()
		instanceHandles := make([]instanceHandle, len(instances))
		for j, inst := range instances {
			instanceIdleSeconds := 0
			if inst.Idle() {
				instanceIdleSeconds = int(nowFn().Sub(inst.IdleTime()).Seconds())
			}

			awayMsg, _ := inst.AwayMessage()
			instanceHandles[j] = instanceHandle{
				Num:         int(inst.Num()),
				IdleSeconds: instanceIdleSeconds,
				IsAway:      inst.Away(),
				AwayMessage: awayMsg,
				IsInvisible: inst.Invisible(),
			}
			ra := inst.RemoteAddr()
			if ra != nil {
				instanceHandles[j].RemoteAddr = ra.Addr().String()
				instanceHandles[j].RemotePort = int(ra.Port())
			}
		}

		sessionIdleSeconds := 0
		if s.Idle() {
			sessionIdleSeconds = int(nowFn().Sub(s.IdleTime()).Seconds())
		}

		allAway := s.Away()
		awayMessage := ""
		if allAway {
			awayMessage = s.AwayMessage()
		}

		ou.Sessions[i] = sessionHandle{
			ID:            s.IdentScreenName().String(),
			ScreenName:    s.DisplayScreenName().String(),
			OnlineSeconds: int(nowFn().Sub(s.SignonTime()).Seconds()),
			IsAway:        allAway,
			AwayMessage:   awayMessage,
			IdleSeconds:   sessionIdleSeconds,
			IsInvisible:   s.Invisible(),
			IsICQ:         s.UIN() > 0,
			InstanceCount: s.InstanceCount(),
			Instances:     instanceHandles,
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
		session.CloseSession()
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
func postUserHandler(w http.ResponseWriter, r *http.Request, createAccount state.CreateAccountFunc, logger *slog.Logger) {
	input, err := userFromBody(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sn := state.DisplayScreenName(input.ScreenName)

	err = createAccount(r.Context(), sn, input.Password)
	switch {
	case errors.Is(err, state.ErrDupUser):
		http.Error(w, "user already exists", http.StatusConflict)
		return
	case errors.Is(err, state.ErrAIMHandleInvalidFormat), errors.Is(err, state.ErrAIMHandleLength):
		http.Error(w, fmt.Sprintf("invalid screen name: %s", err), http.StatusBadRequest)
		return
	case errors.Is(err, state.ErrICQUINInvalidFormat):
		http.Error(w, fmt.Sprintf("invalid uin: %s", err), http.StatusBadRequest)
		return
	case errors.Is(err, state.ErrPasswordInvalid):
		http.Error(w, fmt.Sprintf("invalid password: %s", err), http.StatusBadRequest)
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

// getUserLoginHandler is a temporary endpoint for validating user credentials.
// do not rely on this endpoint, as it will be eventually removed.
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

// deletePublicChatHandler handles the DELETE /chat/room/public endpoint.
func deletePublicChatHandler(w http.ResponseWriter, r *http.Request, chatRoomDeleter ChatRoomDeleter, logger *slog.Logger) {
	input := chatRoomDelete{}
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, "malformed input", http.StatusBadRequest)
		return
	}

	if len(input.Names) == 0 {
		http.Error(w, "no chat room names provided", http.StatusBadRequest)
		return
	}

	err := chatRoomDeleter.DeleteChatRooms(r.Context(), state.PublicExchange, input.Names)
	if err != nil {
		logger.Error("error deleting public chat rooms DELETE /chat/room/public", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
	_, _ = fmt.Fprintln(w, "Chat rooms deleted successfully.")
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
func getUserBuddyIconHandler(w http.ResponseWriter, r *http.Request, u UserManager, f FeedBagRetriever, b BARTAssetManager, logger *slog.Logger) {
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
	icon, err := b.BARTItem(r.Context(), iconRef.Hash)
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
		Profile:         profile.ProfileText,
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

// getICQProfileHandler handles the GET /user/{screenname}/icq endpoint.
func getICQProfileHandler(w http.ResponseWriter, r *http.Request, mgr ICQProfileManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	screenName := r.PathValue("screenname")
	user, err := mgr.User(r.Context(), state.NewIdentScreenName(screenName))
	if err != nil {
		logger.Error("error in GET /user/{screenname}/icq", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if !user.IsICQ {
		http.Error(w, "user is not an ICQ account", http.StatusBadRequest)
		return
	}

	out := icqProfileHandle{
		UIN: user.IdentScreenName.UIN(),
		BasicInfo: icqBasicInfoHandle{
			Nickname:     user.ICQBasicInfo.Nickname,
			FirstName:    user.ICQBasicInfo.FirstName,
			LastName:     user.ICQBasicInfo.LastName,
			EmailAddress: user.ICQBasicInfo.EmailAddress,
			City:         user.ICQBasicInfo.City,
			State:        user.ICQBasicInfo.State,
			Phone:        user.ICQBasicInfo.Phone,
			Fax:          user.ICQBasicInfo.Fax,
			Address:      user.ICQBasicInfo.Address,
			CellPhone:    user.ICQBasicInfo.CellPhone,
			ZIPCode:      user.ICQBasicInfo.ZIPCode,
			CountryCode:  user.ICQBasicInfo.CountryCode,
			GMTOffset:    user.ICQBasicInfo.GMTOffset,
			PublishEmail: user.ICQBasicInfo.PublishEmail,
		},
		MoreInfo: icqMoreInfoHandle{
			Gender:       user.ICQMoreInfo.Gender,
			HomePageAddr: user.ICQMoreInfo.HomePageAddr,
			BirthYear:    user.ICQMoreInfo.BirthYear,
			BirthMonth:   user.ICQMoreInfo.BirthMonth,
			BirthDay:     user.ICQMoreInfo.BirthDay,
			Lang1:        user.ICQMoreInfo.Lang1,
			Lang2:        user.ICQMoreInfo.Lang2,
			Lang3:        user.ICQMoreInfo.Lang3,
		},
		WorkInfo: icqWorkInfoHandle{
			Company:        user.ICQWorkInfo.Company,
			Department:     user.ICQWorkInfo.Department,
			Position:       user.ICQWorkInfo.Position,
			OccupationCode: user.ICQWorkInfo.OccupationCode,
			Address:        user.ICQWorkInfo.Address,
			City:           user.ICQWorkInfo.City,
			State:          user.ICQWorkInfo.State,
			ZIPCode:        user.ICQWorkInfo.ZIPCode,
			CountryCode:    user.ICQWorkInfo.CountryCode,
			Phone:          user.ICQWorkInfo.Phone,
			Fax:            user.ICQWorkInfo.Fax,
			WebPage:        user.ICQWorkInfo.WebPage,
		},
		Notes: user.ICQNotes.Notes,
		Interests: icqInterestsHandle{
			Code1:    user.ICQInterests.Code1,
			Keyword1: user.ICQInterests.Keyword1,
			Code2:    user.ICQInterests.Code2,
			Keyword2: user.ICQInterests.Keyword2,
			Code3:    user.ICQInterests.Code3,
			Keyword3: user.ICQInterests.Keyword3,
			Code4:    user.ICQInterests.Code4,
			Keyword4: user.ICQInterests.Keyword4,
		},
		Affiliations: icqAffiliationsHandle{
			PastCode1:       user.ICQAffiliations.PastCode1,
			PastKeyword1:    user.ICQAffiliations.PastKeyword1,
			PastCode2:       user.ICQAffiliations.PastCode2,
			PastKeyword2:    user.ICQAffiliations.PastKeyword2,
			PastCode3:       user.ICQAffiliations.PastCode3,
			PastKeyword3:    user.ICQAffiliations.PastKeyword3,
			CurrentCode1:    user.ICQAffiliations.CurrentCode1,
			CurrentKeyword1: user.ICQAffiliations.CurrentKeyword1,
			CurrentCode2:    user.ICQAffiliations.CurrentCode2,
			CurrentKeyword2: user.ICQAffiliations.CurrentKeyword2,
			CurrentCode3:    user.ICQAffiliations.CurrentCode3,
			CurrentKeyword3: user.ICQAffiliations.CurrentKeyword3,
		},
		Permissions: icqPermissionsHandle{
			AuthRequired: user.ICQPermissions.AuthRequired,
			WebAware:     user.ICQPermissions.WebAware,
			AllowSpam:    user.ICQPermissions.AllowSpam,
		},
	}

	if err := json.NewEncoder(w).Encode(out); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// putICQProfileHandler handles the PUT /user/{screenname}/icq endpoint.
func putICQProfileHandler(w http.ResponseWriter, r *http.Request, mgr ICQProfileManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	screenName := r.PathValue("screenname")
	user, err := mgr.User(r.Context(), state.NewIdentScreenName(screenName))
	if err != nil {
		logger.Error("error in PUT /user/{screenname}/icq", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		http.Error(w, "user not found", http.StatusNotFound)
		return
	}
	if !user.IsICQ {
		http.Error(w, "user is not an ICQ account", http.StatusBadRequest)
		return
	}

	var input icqProfileHandle
	d := json.NewDecoder(r.Body)
	if err := d.Decode(&input); err != nil {
		errorMsg(w, "malformed input: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Validate field lengths. ICQ clients typically handle:
	// - String fields: max 127 chars (some fields shorter)
	// - Nickname: max 20 chars
	// - Phone/fax: max 30 chars
	// - Email: max 64 chars
	// - Address/city/state: max 64 chars
	// - ZIP: max 12 chars
	// - Homepage: max 127 chars
	// - Notes: max 450 chars (v5 limit)
	// - Interest/affiliation keywords: max 64 chars
	// - Company/department/position: max 64 chars
	// - Web page: max 127 chars
	type fieldCheck struct {
		name string
		val  string
		max  int
	}
	checks := []fieldCheck{
		{"basic_info.nickname", input.BasicInfo.Nickname, 20},
		{"basic_info.first_name", input.BasicInfo.FirstName, 64},
		{"basic_info.last_name", input.BasicInfo.LastName, 64},
		{"basic_info.email", input.BasicInfo.EmailAddress, 64},
		{"basic_info.city", input.BasicInfo.City, 64},
		{"basic_info.state", input.BasicInfo.State, 64},
		{"basic_info.phone", input.BasicInfo.Phone, 30},
		{"basic_info.fax", input.BasicInfo.Fax, 30},
		{"basic_info.address", input.BasicInfo.Address, 64},
		{"basic_info.cell_phone", input.BasicInfo.CellPhone, 30},
		{"basic_info.zip", input.BasicInfo.ZIPCode, 12},
		{"more_info.homepage", input.MoreInfo.HomePageAddr, 127},
		{"work_info.company", input.WorkInfo.Company, 64},
		{"work_info.department", input.WorkInfo.Department, 64},
		{"work_info.position", input.WorkInfo.Position, 64},
		{"work_info.address", input.WorkInfo.Address, 64},
		{"work_info.city", input.WorkInfo.City, 64},
		{"work_info.state", input.WorkInfo.State, 64},
		{"work_info.zip", input.WorkInfo.ZIPCode, 12},
		{"work_info.phone", input.WorkInfo.Phone, 30},
		{"work_info.fax", input.WorkInfo.Fax, 30},
		{"work_info.web_page", input.WorkInfo.WebPage, 127},
		{"notes", input.Notes, 450},
		{"interests.keyword1", input.Interests.Keyword1, 64},
		{"interests.keyword2", input.Interests.Keyword2, 64},
		{"interests.keyword3", input.Interests.Keyword3, 64},
		{"interests.keyword4", input.Interests.Keyword4, 64},
		{"affiliations.past_keyword1", input.Affiliations.PastKeyword1, 64},
		{"affiliations.past_keyword2", input.Affiliations.PastKeyword2, 64},
		{"affiliations.past_keyword3", input.Affiliations.PastKeyword3, 64},
		{"affiliations.current_keyword1", input.Affiliations.CurrentKeyword1, 64},
		{"affiliations.current_keyword2", input.Affiliations.CurrentKeyword2, 64},
		{"affiliations.current_keyword3", input.Affiliations.CurrentKeyword3, 64},
	}
	var validationErrors []string
	for _, c := range checks {
		if len(c.val) > c.max {
			msg := fmt.Sprintf("field %s exceeds max length of %d (got %d)", c.name, c.max, len(c.val))
			validationErrors = append(validationErrors, msg)
			logger.Warn("ICQ profile field exceeds max length",
				"screenname", screenName,
				"field", c.name,
				"max", c.max,
				"got", len(c.val),
			)
		}
	}

	// Validate gender (0=not specified, 1=female, 2=male)
	if input.MoreInfo.Gender > 2 {
		validationErrors = append(validationErrors, "more_info.gender must be 0 (unspecified), 1 (female), or 2 (male)")
		logger.Warn("ICQ profile invalid gender value", "screenname", screenName, "gender", input.MoreInfo.Gender)
	}

	// Validate birth date
	if input.MoreInfo.BirthMonth > 12 {
		validationErrors = append(validationErrors, "more_info.birth_month must be 0-12")
		logger.Warn("ICQ profile invalid birth month", "screenname", screenName, "birth_month", input.MoreInfo.BirthMonth)
	}
	if input.MoreInfo.BirthDay > 31 {
		validationErrors = append(validationErrors, "more_info.birth_day must be 0-31")
		logger.Warn("ICQ profile invalid birth day", "screenname", screenName, "birth_day", input.MoreInfo.BirthDay)
	}

	if len(validationErrors) > 0 {
		errorMsg(w, strings.Join(validationErrors, "; "), http.StatusBadRequest)
		return
	}

	sn := user.IdentScreenName

	if err := mgr.SetBasicInfo(r.Context(), sn, state.ICQBasicInfo{
		Nickname:     input.BasicInfo.Nickname,
		FirstName:    input.BasicInfo.FirstName,
		LastName:     input.BasicInfo.LastName,
		EmailAddress: input.BasicInfo.EmailAddress,
		City:         input.BasicInfo.City,
		State:        input.BasicInfo.State,
		Phone:        input.BasicInfo.Phone,
		Fax:          input.BasicInfo.Fax,
		Address:      input.BasicInfo.Address,
		CellPhone:    input.BasicInfo.CellPhone,
		ZIPCode:      input.BasicInfo.ZIPCode,
		CountryCode:  input.BasicInfo.CountryCode,
		GMTOffset:    input.BasicInfo.GMTOffset,
		PublishEmail: input.BasicInfo.PublishEmail,
	}); err != nil {
		logger.Error("error setting basic info", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := mgr.SetMoreInfo(r.Context(), sn, state.ICQMoreInfo{
		Gender:       input.MoreInfo.Gender,
		HomePageAddr: input.MoreInfo.HomePageAddr,
		BirthYear:    input.MoreInfo.BirthYear,
		BirthMonth:   input.MoreInfo.BirthMonth,
		BirthDay:     input.MoreInfo.BirthDay,
		Lang1:        input.MoreInfo.Lang1,
		Lang2:        input.MoreInfo.Lang2,
		Lang3:        input.MoreInfo.Lang3,
	}); err != nil {
		logger.Error("error setting more info", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := mgr.SetWorkInfo(r.Context(), sn, state.ICQWorkInfo{
		Company:        input.WorkInfo.Company,
		Department:     input.WorkInfo.Department,
		Position:       input.WorkInfo.Position,
		OccupationCode: input.WorkInfo.OccupationCode,
		Address:        input.WorkInfo.Address,
		City:           input.WorkInfo.City,
		State:          input.WorkInfo.State,
		ZIPCode:        input.WorkInfo.ZIPCode,
		CountryCode:    input.WorkInfo.CountryCode,
		Phone:          input.WorkInfo.Phone,
		Fax:            input.WorkInfo.Fax,
		WebPage:        input.WorkInfo.WebPage,
	}); err != nil {
		logger.Error("error setting work info", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := mgr.SetUserNotes(r.Context(), sn, state.ICQUserNotes{
		Notes: input.Notes,
	}); err != nil {
		logger.Error("error setting notes", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := mgr.SetInterests(r.Context(), sn, state.ICQInterests{
		Code1:    input.Interests.Code1,
		Keyword1: input.Interests.Keyword1,
		Code2:    input.Interests.Code2,
		Keyword2: input.Interests.Keyword2,
		Code3:    input.Interests.Code3,
		Keyword3: input.Interests.Keyword3,
		Code4:    input.Interests.Code4,
		Keyword4: input.Interests.Keyword4,
	}); err != nil {
		logger.Error("error setting interests", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := mgr.SetAffiliations(r.Context(), sn, state.ICQAffiliations{
		PastCode1:       input.Affiliations.PastCode1,
		PastKeyword1:    input.Affiliations.PastKeyword1,
		PastCode2:       input.Affiliations.PastCode2,
		PastKeyword2:    input.Affiliations.PastKeyword2,
		PastCode3:       input.Affiliations.PastCode3,
		PastKeyword3:    input.Affiliations.PastKeyword3,
		CurrentCode1:    input.Affiliations.CurrentCode1,
		CurrentKeyword1: input.Affiliations.CurrentKeyword1,
		CurrentCode2:    input.Affiliations.CurrentCode2,
		CurrentKeyword2: input.Affiliations.CurrentKeyword2,
		CurrentCode3:    input.Affiliations.CurrentCode3,
		CurrentKeyword3: input.Affiliations.CurrentKeyword3,
	}); err != nil {
		logger.Error("error setting affiliations", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if err := mgr.SetPermissions(r.Context(), sn, state.ICQPermissions{
		AuthRequired: input.Permissions.AuthRequired,
		WebAware:     input.Permissions.WebAware,
		AllowSpam:    input.Permissions.AllowSpam,
	}); err != nil {
		logger.Error("error setting permissions", "err", err.Error())
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
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

// BARTAsset represents a BART asset entry.
type BARTAsset struct {
	Hash string `json:"hash"`
	Type uint16 `json:"type"`
}

// getBARTByTypeHandler handles the GET /bart endpoint.
func getBARTByTypeHandler(w http.ResponseWriter, r *http.Request, bartAssetManager BARTAssetManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	// Get type from query parameter (required)
	typeStr := r.URL.Query().Get("type")
	if typeStr == "" {
		errorMsg(w, "type query parameter is required", http.StatusBadRequest)
		return
	}
	typeVal, err := strconv.ParseUint(typeStr, 10, 16)
	if err != nil {
		errorMsg(w, "invalid type ID", http.StatusBadRequest)
		return
	}
	itemType := uint16(typeVal)

	// Get BART items, filtered by type
	items, err := bartAssetManager.ListBARTItems(r.Context(), itemType)
	if err != nil {
		logger.Error("error listing BART items", "err", err.Error())
		errorMsg(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Convert to BARTAsset format
	assets := make([]BARTAsset, 0, len(items))
	for _, item := range items {
		assets = append(assets, BARTAsset{
			Hash: item.Hash,
			Type: item.Type,
		})
	}

	if err := json.NewEncoder(w).Encode(assets); err != nil {
		logger.Error("error encoding response", "err", err.Error())
	}
}

// getBARTHandler handles the GET /bart/{hash} endpoint.
func getBARTHandler(w http.ResponseWriter, r *http.Request, bartAssetManager BARTAssetManager, logger *slog.Logger) {
	hashStr := r.PathValue("hash")
	if hashStr == "" {
		errorMsg(w, "hash is required", http.StatusBadRequest)
		return
	}

	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		errorMsg(w, "invalid hash format", http.StatusBadRequest)
		return
	}

	body, err := bartAssetManager.BARTItem(r.Context(), hashBytes)
	if err != nil {
		logger.Error("error retrieving BART asset", "err", err.Error())
		errorMsg(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if len(body) == 0 {
		errorMsg(w, "BART asset not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(body)
}

// postBARTHandler handles the POST /bart endpoint.
func postBARTHandler(w http.ResponseWriter, r *http.Request, bartAssetManager BARTAssetManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	// Extract hash from URL path
	hashStr := r.PathValue("hash")
	if hashStr == "" {
		errorMsg(w, "hash path parameter is required", http.StatusBadRequest)
		return
	}

	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		errorMsg(w, "invalid hash format", http.StatusBadRequest)
		return
	}

	typeStr := r.URL.Query().Get("type")
	if typeStr == "" {
		errorMsg(w, "type query parameter is required", http.StatusBadRequest)
		return
	}
	typeVal, err := strconv.ParseUint(typeStr, 10, 16)
	if err != nil {
		errorMsg(w, "invalid type ID", http.StatusBadRequest)
		return
	}
	bartType := uint16(typeVal)

	data, err := io.ReadAll(r.Body)
	if err != nil {
		errorMsg(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	if err := bartAssetManager.InsertBARTItem(r.Context(), hashBytes, data, bartType); err != nil {
		if errors.Is(err, state.ErrBARTItemExists) {
			errorMsg(w, "BART asset already exists", http.StatusConflict)
			return
		}
		logger.Error("error in POST /bart", "err", err.Error())
		errorMsg(w, "internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	response := BARTAsset{
		Hash: hex.EncodeToString(hashBytes),
		Type: bartType,
	}
	json.NewEncoder(w).Encode(response)
}

// deleteBARTHandler handles the DELETE /bart/{hash} endpoint.
func deleteBARTHandler(w http.ResponseWriter, r *http.Request, bartAssetManager BARTAssetManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	// Extract hash from URL path
	hashStr := r.PathValue("hash")
	if hashStr == "" {
		errorMsg(w, "hash path parameter is required", http.StatusBadRequest)
		return
	}

	hashBytes, err := hex.DecodeString(hashStr)
	if err != nil {
		errorMsg(w, "invalid hash format", http.StatusBadRequest)
		return
	}

	if err := bartAssetManager.DeleteBARTItem(r.Context(), hashBytes); err != nil {
		if errors.Is(err, state.ErrBARTItemNotFound) {
			errorMsg(w, "BART asset not found", http.StatusNotFound)
			return
		}
		logger.Error("error in DELETE /bart", "err", err.Error())
		errorMsg(w, "internal server error", http.StatusInternalServerError)
		return
	}

	msg := messageBody{Message: "BART asset deleted successfully."}
	json.NewEncoder(w).Encode(msg)
}

// getFeedbagBuddyHandler handles the GET /feedbag/{screen_name}/group endpoint.
func getFeedbagBuddyHandler(w http.ResponseWriter, r *http.Request, feedbagManager FeedbagManager, logger *slog.Logger) {
	w.Header().Set("Content-Type", "application/json")

	screenName := r.PathValue("screen_name")
	if screenName == "" {
		errorMsg(w, "screen_name is required", http.StatusBadRequest)
		return
	}

	items, err := feedbagManager.Feedbag(r.Context(), state.NewIdentScreenName(screenName))
	if err != nil {
		logger.Error("error retrieving feedbag", "err", err.Error())
		errorMsg(w, "internal server error", http.StatusInternalServerError)
		return
	}
	if len(items) == 0 {
		errorMsg(w, "feedbag not found", http.StatusNotFound)
		return
	}

	buddyMap := make(map[uint16][]*wire.FeedbagItem)

	for _, item := range items {
		switch item.ClassID {
		case wire.FeedbagClassIdBuddy:
			buddyMap[item.GroupID] = append(buddyMap[item.GroupID], &item)
		}
	}

	type buddyItem struct {
		Name   string `json:"name"`
		ItemID uint16 `json:"item_id"`
	}
	type groupItem struct {
		GroupID   uint16      `json:"group_id"`
		GroupName string      `json:"group_name"`
		Buddies   []buddyItem `json:"buddies"`
	}

	response := make([]groupItem, 0)

	for _, item := range items {
		switch item.ClassID {
		case wire.FeedbagClassIdGroup:
			if item.GroupID == 0 {
				// can't add buddies to the root group
				continue
			}
			group := groupItem{
				GroupID:   item.GroupID,
				GroupName: item.Name,
				Buddies:   make([]buddyItem, 0, len(buddyMap[item.GroupID])),
			}
			for _, buddy := range buddyMap[item.GroupID] {
				group.Buddies = append(group.Buddies, buddyItem{
					Name:   buddy.Name,
					ItemID: buddy.ItemID,
				})
			}
			response = append(response, group)
		}
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Error("error encoding response", "err", err.Error())
	}
}

// putFeedbagBuddyHandler handles the PUT /feedbag/{screen_name}/group/{group_id}/buddy/{buddy_screen_name} endpoint.
func putFeedbagBuddyHandler(w http.ResponseWriter, r *http.Request, buddyBroadcaster BuddyBroadcaster, feedbagManager FeedbagManager, sessionRetriever SessionRetriever, messageRelayer MessageRelayer, logger *slog.Logger, randInt func(n int) int) {
	w.Header().Set("Content-Type", "application/json")

	gid, err := strconv.ParseUint(r.PathValue("group_id"), 10, 16)
	if err != nil {
		errorMsg(w, "invalid group_id", http.StatusBadRequest)
		return
	}
	groupID := uint16(gid)

	if groupID == 0 {
		errorMsg(w, "can't add buddies to root group", http.StatusBadRequest)
		return
	}

	screenName := r.PathValue("screen_name")
	if screenName == "" {
		errorMsg(w, "screen_name is required", http.StatusBadRequest)
		return
	}
	me := state.NewIdentScreenName(screenName)

	buddyScreenName := r.PathValue("buddy_screen_name")
	if buddyScreenName == "" {
		errorMsg(w, "buddy_screen_name is required", http.StatusBadRequest)
		return
	}

	newBuddy := state.DisplayScreenName(buddyScreenName)
	if newBuddy.IsUIN() {
		if err := newBuddy.ValidateUIN(); err != nil {
			errorMsg(w, fmt.Sprintf("invalid uin: %s", err), http.StatusBadRequest)
			return
		}
	} else {
		if err := newBuddy.ValidateAIMHandle(); err != nil {
			errorMsg(w, fmt.Sprintf("invalid screen name: %s", err), http.StatusBadRequest)
			return
		}
	}

	items, err := feedbagManager.Feedbag(r.Context(), me)
	if err != nil {
		logger.Error("error retrieving feedbag", "err", err.Error())
		errorMsg(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var group *wire.FeedbagItem

	count := 0
	for _, item := range items {
		switch {
		case item.ClassID == wire.FeedbagClassIdGroup && item.GroupID == groupID:
			group = &item
		case item.ClassID == wire.FeedbagClassIdBuddy && item.GroupID == groupID:
			count++
			if item.Name == newBuddy.IdentScreenName().String() {
				response := struct {
					Name    string `json:"name"`
					GroupID uint16 `json:"group_id"`
					ItemID  uint16 `json:"item_id"`
				}{
					Name:    buddyScreenName,
					GroupID: groupID,
					ItemID:  item.ItemID,
				}
				w.WriteHeader(http.StatusOK)
				if err := json.NewEncoder(w).Encode(response); err != nil {
					logger.Error("error encoding response", "err", err.Error())
				}
				return
			}
		}
	}

	if count >= 30 {
		errorMsg(w, "too many buddies in group. max: 30", http.StatusBadRequest)
		return
	}

	if group == nil {
		errorMsg(w, "group not found", http.StatusNotFound)
		return
	}

	buddyItem := wire.FeedbagItem{
		Name:    buddyScreenName,
		GroupID: groupID,
		ItemID:  randItemID(randInt, items),
		ClassID: wire.FeedbagClassIdBuddy,
	}

	if buddyItem.ItemID == 0 {
		errorMsg(w, "maximum items reached", http.StatusConflict)
		return
	}

	if order, hasOrder := group.Bytes(wire.FeedbagAttributesOrder); hasOrder {
		var memberIDs []uint16
		if err := wire.UnmarshalBE(&memberIDs, bytes.NewReader(order)); err != nil {
			logger.Error("error decoding order TLV", "err", err.Error())
			errorMsg(w, "internal server error", http.StatusInternalServerError)
			return
		}
		group.Replace(wire.NewTLVBE(wire.FeedbagAttributesOrder, append(memberIDs, buddyItem.ItemID)))
	} else {
		group.Append(wire.NewTLVBE(wire.FeedbagAttributesOrder, []uint16{buddyItem.ItemID}))
	}

	updates := []wire.FeedbagItem{
		buddyItem,
		*group,
	}
	if err := feedbagManager.FeedbagUpsert(r.Context(), me, updates); err != nil {
		logger.Error("error inserting feedbag item", "err", err.Error())
		errorMsg(w, "internal server error", http.StatusInternalServerError)
		return
	}

	session := sessionRetriever.RetrieveSession(me)
	if session != nil {
		messageRelayer.RelayToScreenName(r.Context(), me, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagInsertItem,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{buddyItem},
			},
		})
		messageRelayer.RelayToScreenName(r.Context(), me, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagUpdateItem,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{*group},
			},
		})
		instances := session.Instances()
		if len(instances) > 0 {
			if err := buddyBroadcaster.BroadcastVisibility(r.Context(), instances[0], []state.IdentScreenName{newBuddy.IdentScreenName()}, false); err != nil {
				logger.Error("error broadcasting visibility", "err", err.Error())
			}
		}
	}

	response := struct {
		Name    string `json:"name"`
		GroupID uint16 `json:"group_id"`
		ItemID  uint16 `json:"item_id"`
	}{
		Name:    buddyItem.Name,
		GroupID: buddyItem.GroupID,
		ItemID:  buddyItem.ItemID,
	}

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Error("error encoding response", "err", err.Error())
	}
}

func randItemID(randInt func(n int) int, items []wire.FeedbagItem) uint16 {
	num := uint16(randInt(math.MaxUint16))
	for itemID := num; itemID != num-1; itemID++ {
		if itemID == 0 {
			continue
		}
		exists := false
		for _, item := range items {
			if item.GroupID == itemID || item.ItemID == itemID {
				exists = true
				break
			}
		}
		if !exists {
			return itemID
		}
	}
	return 0
}

// deleteFeedbagBuddyHandler handles the DELETE /feedbag/{screen_name}/group/{group_id}/buddy/{buddy_screen_name} endpoint.
func deleteFeedbagBuddyHandler(w http.ResponseWriter, r *http.Request, buddyBroadcaster BuddyBroadcaster, feedbagManager FeedbagManager, sessionRetriever SessionRetriever, messageRelayer MessageRelayer, logger *slog.Logger) {
	gid, err := strconv.ParseUint(r.PathValue("group_id"), 10, 16)
	if err != nil {
		errorMsg(w, "invalid group_id", http.StatusBadRequest)
		return
	}
	groupID := uint16(gid)

	if groupID == 0 {
		errorMsg(w, "can't add buddies to root group", http.StatusBadRequest)
		return
	}

	screenName := r.PathValue("screen_name")
	if screenName == "" {
		errorMsg(w, "screen_name is required", http.StatusBadRequest)
		return
	}
	me := state.NewIdentScreenName(screenName)

	buddyScreenName := r.PathValue("buddy_screen_name")
	if buddyScreenName == "" {
		errorMsg(w, "buddy_screen_name is required", http.StatusBadRequest)
		return
	}
	deleteBuddy := state.NewIdentScreenName(buddyScreenName)

	items, err := feedbagManager.Feedbag(r.Context(), me)
	if err != nil {
		logger.Error("error retrieving feedbag", "err", err.Error())
		errorMsg(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var itemToDelete *wire.FeedbagItem
	var groupFound bool
	for _, item := range items {
		switch {
		case item.ClassID == wire.FeedbagClassIdGroup && item.GroupID == groupID:
			groupFound = true
		case item.ClassID == wire.FeedbagClassIdBuddy && item.Name == buddyScreenName && item.GroupID == groupID:
			itemToDelete = &item
		}
	}

	switch {
	case !groupFound:
		errorMsg(w, "group not found", http.StatusNotFound)
		return
	case itemToDelete == nil:
		errorMsg(w, "buddy not found", http.StatusNotFound)
		return
	}

	if err := feedbagManager.FeedbagDelete(r.Context(), me, []wire.FeedbagItem{*itemToDelete}); err != nil {
		logger.Error("error deleting feedbag item", "err", err.Error())
		errorMsg(w, "internal server error", http.StatusInternalServerError)
		return
	}

	session := sessionRetriever.RetrieveSession(me)
	if session != nil {
		messageRelayer.RelayToScreenName(r.Context(), me, wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Feedbag,
				SubGroup:  wire.FeedbagDeleteItem,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{*itemToDelete},
			},
		})
		instances := session.Instances()
		if len(instances) > 0 {
			if err := buddyBroadcaster.BroadcastVisibility(r.Context(), instances[0], []state.IdentScreenName{deleteBuddy}, true); err != nil {
				logger.Error("error broadcasting visibility", "err", err.Error())
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}
