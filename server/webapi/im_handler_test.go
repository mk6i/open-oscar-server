package webapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// requireSession wraps next with the session-resolving auth middleware for tests.
func requireSession(sm SessionResolver, next func(http.ResponseWriter, *http.Request, *Session)) http.Handler {
	return NewAuthMiddleware(slog.Default()).RequireSession(sm, next)
}

// createTestSessionManager creates a SessionManager holding one running
// session for screenName over conn. Without events, the session subscribes to
// the events the handlers under test push.
func createTestSessionManager(t *testing.T, screenName string, conn *fakeConn, events ...string) (*SessionManager, *Session) {
	t.Helper()
	if len(events) == 0 {
		events = []string{"im", "presence", "buddylist", "sentIM", "typing"}
	}
	mgr := NewSessionManager()
	sess, err := mgr.CreateSession(state.DisplayScreenName(screenName), events, conn, wire.DefaultSNACRateLimits(), "", slog.Default())
	require.NoError(t, err)
	sess.Start()
	t.Cleanup(sess.Close)
	return mgr, sess
}

// imServer returns a responder that acknowledges each IM and answers each
// locate query with displayName, or with a not-logged-on error when
// displayName is empty.
func imServer(displayName string) func(req wire.SNACMessage) []wire.SNACMessage {
	return func(req wire.SNACMessage) []wire.SNACMessage {
		switch body := req.Body.(type) {
		case wire.SNAC_0x04_0x06_ICBMChannelMsgToHost:
			return []wire.SNACMessage{reply(wire.ICBM, wire.ICBMHostAck, wire.SNAC_0x04_0x0C_ICBMHostAck{
				Cookie:     body.Cookie,
				ChannelID:  body.ChannelID,
				ScreenName: body.ScreenName,
			})}
		case wire.SNAC_0x02_0x05_LocateUserInfoQuery:
			if displayName == "" {
				return []wire.SNACMessage{snacErr(wire.Locate, wire.ErrorCodeNotLoggedOn)}
			}
			return []wire.SNACMessage{reply(wire.Locate, wire.LocateUserInfoReply, wire.SNAC_0x02_0x06_LocateUserInfoReply{
				TLVUserInfo: wire.TLVUserInfo{ScreenName: displayName},
			})}
		}
		return nil
	}
}

// buddyItem is a feedbag holding a single buddy item for buddy, carrying
// alias when one is given.
func buddyItem(buddy, alias string) []wire.FeedbagItem {
	item := wire.FeedbagItem{ItemID: 1, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: buddy}
	if alias != "" {
		item.TLVLBlock = wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, alias)}}
	}
	return []wire.FeedbagItem{item}
}

// sentIMs returns the IMs sent to the OSCAR server.
func sentIMs(conn *fakeConn) []wire.SNAC_0x04_0x06_ICBMChannelMsgToHost {
	var ims []wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
	for _, body := range conn.sentOf(wire.ICBM, wire.ICBMChannelMsgToHost) {
		ims = append(ims, body.(wire.SNAC_0x04_0x06_ICBMChannelMsgToHost))
	}
	return ims
}

// sendIMForDest drives SendIM addressed to t, with the recipient's display name
// resolving to locateName and the sender's alias for them set to alias, and returns
// the events queued for the sender.
func sendIMForDest(t *testing.T, dest, locateName, alias string) []Event {
	t.Helper()

	conn := newFakeConn().answering(imServer(locateName))
	mgr, session := createTestSessionManager(t, "Ann Dupree", conn, "im", "sentIM", "conversation")
	session.feedbag.Reset(buddyItem(dest, alias))

	handler := &MessagingHandler{Logger: slog.Default()}

	req, err := http.NewRequest("GET", "/im/sendIM?aimsid="+session.AimSID+"&t="+url.QueryEscape(dest)+"&message=hi", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(mgr, handler.SendIM).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	return session.EventQueue.GetAllEvents()
}

// The client sends t as the normalized aimId, so the recipient's display name has
// to come from the locate reply. Echoing t back as a displayId would overwrite the
// properly formatted name the client already holds for that aimId.
func TestMessagingHandler_SendIM_DestDisplayIDFromLocateReply(t *testing.T) {
	var sentIM SentIMEvent
	var conv ConversationEntryData
	for _, event := range sendIMForDest(t, "mikelee", "Mike Lee", "") {
		switch event.Type {
		case EventTypeSentIM:
			sentIM, _ = event.Data.(SentIMEvent)
		case EventTypeConversation:
			data, _ := event.Data.(*ConversationData)
			require.NotNil(t, data)
			require.Len(t, data.Conversations, 1)
			conv = data.Conversations[0]
		}
	}

	assert.Equal(t, "anndupree", sentIM.Sender.AimID)
	assert.Equal(t, "Ann Dupree", sentIM.Sender.DisplayID)
	assert.Equal(t, "mikelee", sentIM.Dest.AimID)
	assert.Equal(t, "Mike Lee", sentIM.Dest.DisplayID)
	assert.True(t, sentIM.ISent, "the sender's own echo must be marked iSent")

	assert.Equal(t, "mikelee", conv.AimID)
	assert.Equal(t, "Mike Lee", conv.DisplayID)
}

// An alias is private to the sender and lives only in their feedbag, and the client
// deletes the alias it holds every time it merges a user map. So the sentIM echo has
// to repeat it, or messaging an aliased buddy renames him back to his screen name.
func TestMessagingHandler_SendIM_DestCarriesAlias(t *testing.T) {
	var sentIM SentIMEvent
	for _, event := range sendIMForDest(t, "mikelee", "Mike Lee", "MICHAELLEE") {
		if event.Type == EventTypeSentIM {
			sentIM, _ = event.Data.(SentIMEvent)
		}
	}

	assert.Equal(t, "mikelee", sentIM.Dest.AimID)
	assert.Equal(t, "Mike Lee", sentIM.Dest.DisplayID)
	assert.Equal(t, "MICHAELLEE", sentIM.Dest.Friendly)
}

// When the recipient's display name cannot be resolved, displayId is omitted
// rather than filled in with the aimId, leaving the client's existing name intact.
func TestMessagingHandler_SendIM_OmitsDestDisplayIDWhenUnresolved(t *testing.T) {
	var sentIM SentIMEvent
	var conv ConversationEntryData
	for _, event := range sendIMForDest(t, "mikelee", "", "") {
		switch event.Type {
		case EventTypeSentIM:
			sentIM, _ = event.Data.(SentIMEvent)
		case EventTypeConversation:
			data, _ := event.Data.(*ConversationData)
			require.NotNil(t, data)
			require.Len(t, data.Conversations, 1)
			conv = data.Conversations[0]
		}
	}

	assert.Equal(t, "mikelee", sentIM.Dest.AimID)
	assert.Empty(t, sentIM.Dest.DisplayID)
	encoded, err := json.Marshal(sentIM)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "displayId\":\"mikelee\"")

	assert.Equal(t, "mikelee", conv.AimID)
	assert.Empty(t, conv.DisplayID)
	// omitempty is what keeps it out of the payload.
	encodedConv, err := json.Marshal(conv)
	require.NoError(t, err)
	assert.NotContains(t, string(encodedConv), "displayId")
}

func TestMessagingHandler_SendIM(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        string
		events             []string
		limited            bool
		wantTLVs           []uint16
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success",
			queryParams: "t=recipient&message=hello+world",
			events:      []string{"im"},
			wantTLVs:    []uint16{wire.ICBMTLVAOLIMData, wire.ICBMTLVRequestHostAck},
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"msgId"`)
				assert.Contains(t, body, `"state":"delivered"`)
				assert.Contains(t, body, `"timestamp":`)
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "Success_TypingSubscriberAsksForTypingEvents",
			queryParams:        "t=recipient&message=hello",
			events:             []string{"im", "typing"},
			wantTLVs:           []uint16{wire.ICBMTLVAOLIMData, wire.ICBMTLVWantEvents, wire.ICBMTLVRequestHostAck},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "Success_AutoResponse",
			queryParams:        "t=recipient&message=hello&autoResponse=1",
			events:             []string{"im"},
			wantTLVs:           []uint16{wire.ICBMTLVAOLIMData, wire.ICBMTLVAutoResponse, wire.ICBMTLVRequestHostAck},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "Error_MissingRecipient",
			queryParams:        "message=hello",
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: t")
			},
		},
		{
			name:               "Error_MissingMessage",
			queryParams:        "t=recipient",
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: message")
			},
		},
		{
			name:               "Error_RateLimited",
			queryParams:        "t=recipient&message=hello",
			limited:            true,
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":430`)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn().answering(imServer(""))
			sessionMgr, session := createTestSessionManager(t, "testuser", conn, tt.events...)
			if tt.limited {
				limitRateClass(session, wire.ICBM, wire.ICBMChannelMsgToHost)
			}

			handler := &MessagingHandler{Logger: slog.Default()}

			reqURL := "/im/sendIM?aimsid=" + session.AimSID + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			responseBody := strings.TrimSpace(rr.Body.String())
			if tt.checkResponse != nil {
				tt.checkResponse(t, responseBody)
			}

			ims := sentIMs(conn)
			if tt.wantTLVs == nil {
				assert.Empty(t, ims)
				return
			}
			require.Len(t, ims, 1)
			assert.Equal(t, "recipient", ims[0].ScreenName)
			assert.Equal(t, wire.ICBMChannelIM, ims[0].ChannelID)
			var tags []uint16
			for _, tlv := range ims[0].TLVList {
				tags = append(tags, tlv.Tag)
			}
			assert.Equal(t, tt.wantTLVs, tags)
		})
	}
}

// The ICBM service refuses to store a message for an offline recipient unless the
// store directive is present, so the client's offlineIM flag has to become one.
func TestMessagingHandler_SendIM_OfflineIMSetsStoreTLV(t *testing.T) {
	conn := newFakeConn().answering(imServer(""))
	sessionMgr, session := createTestSessionManager(t, "testuser", conn)
	handler := &MessagingHandler{Logger: slog.Default()}

	req, err := http.NewRequest("GET", "/im/sendIM?aimsid="+session.AimSID+"&t=recipient&message=hi&offlineIM=true", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	ims := sentIMs(conn)
	require.Len(t, ims, 1)
	_, hasStore := ims[0].Bytes(wire.ICBMTLVStore)
	assert.True(t, hasStore)
}

// An undeliverable IM must still produce an envelope: the web client reads
// response.statusCode, and an empty body leaves it with no status at all.
func TestMessagingHandler_SendIM_UndeliverableReportsStatus(t *testing.T) {
	tests := []struct {
		name string
		errs wire.SNACError
	}{
		{
			name: "RecipientOffline",
			errs: wire.SNACError{Code: wire.ErrorCodeNotLoggedOn},
		},
		{
			name: "OfflineInboxFull",
			errs: wire.SNACError{
				Code: wire.ErrorCodeNotLoggedOn,
				TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ErrorTLVErrorSubcode, wire.ICBMSubErrOfflineIMExceedMax),
				}},
			},
		},
		{
			name: "SenderBlockedRecipient",
			errs: wire.SNACError{Code: wire.ErrorCodeInLocalPermitDeny},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn().answering(func(req wire.SNACMessage) []wire.SNACMessage {
				if _, ok := req.Body.(wire.SNAC_0x04_0x06_ICBMChannelMsgToHost); ok {
					return []wire.SNACMessage{reply(wire.ICBM, wire.ICBMErr, tt.errs)}
				}
				return nil
			})
			sessionMgr, session := createTestSessionManager(t, "testuser", conn)
			handler := &MessagingHandler{Logger: slog.Default()}

			req, err := http.NewRequest("GET", "/im/sendIM?aimsid="+session.AimSID+"&f=json&t=recipient&message=hi", nil)
			require.NoError(t, err)
			rr := httptest.NewRecorder()
			requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

			require.Equal(t, http.StatusOK, rr.Code)
			assert.Contains(t, rr.Body.String(), `"statusCode":602`)
			assert.NotContains(t, rr.Body.String(), `"msgId"`)
		})
	}
}

func TestMessagingHandler_SendIM_POST(t *testing.T) {
	conn := newFakeConn().answering(imServer(""))
	sessionMgr, session := createTestSessionManager(t, "testuser", conn)

	handler := &MessagingHandler{Logger: slog.Default()}

	body := strings.NewReader("message=" + url.QueryEscape("hello from post"))
	req, err := http.NewRequest(http.MethodPost, "/im/sendIM?aimsid="+session.AimSID+"&f=json&t=recipient&r=1", body)
	assert.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"msgId"`)
	require.Len(t, sentIMs(conn), 1)
}

func TestMessagingHandler_SendIM_MissingAimsid(t *testing.T) {
	sessionMgr := NewSessionManager()
	handler := &MessagingHandler{
		Logger: slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/sendIM", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}

func TestMessagingHandler_SendIM_InvalidSession(t *testing.T) {
	sessionMgr := NewSessionManager()
	handler := &MessagingHandler{
		Logger: slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/sendIM?aimsid=nonexistent&t=someone&message=hi", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid or expired session")
}

func TestMessagingHandler_SetTyping(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        string
		peerWantsTyping    bool
		wantSent           []any
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:            "Success_TypingStarted",
			queryParams:     "t=recipient&typingStatus=typing",
			peerWantsTyping: true,
			wantSent: []any{wire.SNAC_0x04_0x14_ICBMClientEvent{
				ChannelID:  wire.ICBMChannelIM,
				ScreenName: "recipient",
				Event:      0x0002,
			}},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:            "Success_TypingPaused",
			queryParams:     "t=recipient&typingStatus=typed",
			peerWantsTyping: true,
			wantSent: []any{wire.SNAC_0x04_0x14_ICBMClientEvent{
				ChannelID:  wire.ICBMChannelIM,
				ScreenName: "recipient",
				Event:      0x0001,
			}},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:            "Success_TypingStopped",
			queryParams:     "t=recipient&typingStatus=none",
			peerWantsTyping: true,
			wantSent: []any{wire.SNAC_0x04_0x14_ICBMClientEvent{
				ChannelID:  wire.ICBMChannelIM,
				ScreenName: "recipient",
				Event:      0x0000,
			}},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "PeerDidNotAskForTyping",
			queryParams:        "t=recipient&typingStatus=typing",
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
			},
		},
		{
			name:               "Error_MissingRecipient",
			queryParams:        "typingStatus=typing",
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "missing required parameter: t")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn()
			sessionMgr, sess := createTestSessionManager(t, "testuser", conn)
			sess.setPeerWantsTyping(state.NewIdentScreenName("Recipient"), tt.peerWantsTyping)

			handler := &MessagingHandler{Logger: slog.Default()}

			reqURL := "/im/setTyping?aimsid=" + sess.AimSID + "&" + tt.queryParams
			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()

			requireSession(sessionMgr, handler.SetTyping).ServeHTTP(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			if tt.checkResponse != nil {
				responseBody := strings.TrimSpace(rr.Body.String())
				tt.checkResponse(t, responseBody)
			}
			assert.Equal(t, tt.wantSent, conn.sentOf(wire.ICBM, wire.ICBMClientEvent))
		})
	}
}

func TestMessagingHandler_SetTyping_MissingAimsid(t *testing.T) {
	sessionMgr := NewSessionManager()
	handler := &MessagingHandler{
		Logger: slog.Default(),
	}

	req, err := http.NewRequest("GET", "/im/setTyping", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SetTyping).ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "missing aimsid parameter")
}

// A recipient's client error for a message can reach the session before the
// server's ack of it, and a relayed client error carries the recipient's own
// request ID, which may collide with the send's. The error must still name the
// message, and must not be taken for the send's reply.
func TestMessagingHandler_SendIM_ClientErrorDuringSendNamesTheMessage(t *testing.T) {
	conn := newFakeConn().answering(func(req wire.SNACMessage) []wire.SNACMessage {
		im, ok := req.Body.(wire.SNAC_0x04_0x06_ICBMChannelMsgToHost)
		if !ok {
			return imServer("")(req)
		}
		return append([]wire.SNACMessage{reply(wire.ICBM, wire.ICBMClientErr, wire.SNAC_0x04_0x0B_ICBMClientErr{
			Cookie:     im.Cookie,
			ChannelID:  wire.ICBMChannelIM,
			ScreenName: "Recipient",
		})}, imServer("")(req)...)
	})
	sessionMgr, sess := createTestSessionManager(t, "testuser", conn)

	handler := &MessagingHandler{Logger: slog.Default()}

	req, reqErr := http.NewRequest("GET", "/im/sendIM?aimsid="+sess.AimSID+"&t=recipient&message=hello", nil)
	require.NoError(t, reqErr)
	rr := httptest.NewRecorder()
	requireSession(sessionMgr, handler.SendIM).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), `"state":"delivered"`)

	var sentMsgID string
	var clientErr ClientErrorEvent
	for _, event := range sess.EventQueue.GetAllEvents() {
		switch event.Type {
		case EventTypeSentIM:
			if e, ok := event.Data.(SentIMEvent); ok {
				sentMsgID = e.MsgID
			}
		case EventTypeClientError:
			clientErr, _ = event.Data.(ClientErrorEvent)
		}
	}

	// The cookie the client is told about must be the msgId it was handed for the
	// very message that failed.
	require.NotEmpty(t, sentMsgID)
	assert.Equal(t, sentMsgID, clientErr.Cookie)
	assert.Equal(t, "recipient", clientErr.Source.AimID)
}

// The sentIM echo is merged onto both parties' user objects, and sending a
// message changes nobody's presence.
func TestMessagingHandler_SendIM_EchoesRealStates(t *testing.T) {
	// sendIM drives SendIM from a sender whose own user info is self, with
	// recipientPresence seeded into the session's view.
	sendIM := func(t *testing.T, self wire.TLVUserInfo, recipientPresence *wire.TLVUserInfo) SentIMEvent {
		t.Helper()

		conn := newFakeConn().answering(imServer("Mike Kelly"))
		mgr, session := createTestSessionManager(t, "Ann Dupree", conn, "im", "sentIM")
		session.self.setRelayed(self)

		if recipientPresence != nil {
			buddyArrives(session, *recipientPresence)
		}

		session.feedbag.Reset(buddyItem("mikekelly", ""))

		handler := &MessagingHandler{Logger: slog.Default()}

		req, err := http.NewRequest("GET", "/im/sendIM?aimsid="+session.AimSID+"&t=mikekelly&message=hi", nil)
		require.NoError(t, err)
		rr := httptest.NewRecorder()
		requireSession(mgr, handler.SendIM).ServeHTTP(rr, req)
		require.Equal(t, http.StatusOK, rr.Code)

		for _, event := range session.EventQueue.GetAllEvents() {
			if sent, ok := event.Data.(SentIMEvent); ok {
				return sent
			}
		}
		t.Fatal("no sentIM event was pushed")
		return SentIMEvent{}
	}

	online := wire.TLVUserInfo{ScreenName: "Ann Dupree"}
	away := wire.TLVUserInfo{ScreenName: "Ann Dupree"}
	away.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnavailable))
	awayRecipient := func() *wire.TLVUserInfo {
		info := wire.TLVUserInfo{ScreenName: "Mike Kelly"}
		info.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagUnavailable))
		return &info
	}

	t.Run("the recipient's state comes from the presence view", func(t *testing.T) {
		got := sendIM(t, online, awayRecipient())
		assert.Equal(t, "away", got.Dest.State)
	})

	t.Run("a recipient with no presence carries no state", func(t *testing.T) {
		got := sendIM(t, online, nil)
		assert.Empty(t, got.Dest.State)
	})

	t.Run("the sender's own away state survives sending", func(t *testing.T) {
		got := sendIM(t, away, nil)
		assert.Equal(t, "away", got.Sender.State)
	})

	t.Run("an online sender reports online", func(t *testing.T) {
		got := sendIM(t, online, nil)
		assert.Equal(t, "online", got.Sender.State)
	})
}
