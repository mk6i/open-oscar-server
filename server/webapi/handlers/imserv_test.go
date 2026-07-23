package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/server/webapi/types"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// MockChatService is a mock implementation of ChatService.
type MockChatService struct {
	mock.Mock
}

func (m *MockChatService) ChannelMsgToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x0E_0x05_ChatChannelMsgToHost) (*wire.SNACMessage, error) {
	args := m.Called(ctx, instance, inFrame, inBody)
	msg, _ := args.Get(0).(*wire.SNACMessage)
	return msg, args.Error(1)
}

// MockChatNavService is a mock implementation of ChatNavService.
type MockChatNavService struct {
	mock.Mock
}

func (m *MockChatNavService) CreateRoom(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate) (wire.SNACMessage, error) {
	args := m.Called(ctx, instance, inFrame, inBody)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}

func (m *MockChatNavService) RequestRoomInfo(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo) (wire.SNACMessage, error) {
	args := m.Called(ctx, inFrame, inBody)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}

// MockChatBridgeOServiceService is a mock implementation of ChatBridgeOServiceService.
type MockChatBridgeOServiceService struct {
	mock.Mock
}

func (m *MockChatBridgeOServiceService) ServiceRequest(ctx context.Context, service uint16, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x01_0x04_OServiceServiceRequest, listener config.Listener) (wire.SNACMessage, error) {
	args := m.Called(ctx, service, instance, inFrame, inBody, listener)
	return args.Get(0).(wire.SNACMessage), args.Error(1)
}

func (m *MockChatBridgeOServiceService) ClientOnline(ctx context.Context, service uint16, inBody wire.SNAC_0x01_0x02_OServiceClientOnline, instance *state.SessionInstance) error {
	args := m.Called(ctx, service, inBody, instance)
	return args.Error(0)
}

// MockChatAuthService is a mock implementation of ChatAuthService.
type MockChatAuthService struct {
	mock.Mock
}

func (m *MockChatAuthService) CrackCookie(authCookie []byte) (state.ServerCookie, error) {
	args := m.Called(authCookie)
	return args.Get(0).(state.ServerCookie), args.Error(1)
}

func (m *MockChatAuthService) RegisterChatSession(ctx context.Context, authCookie state.ServerCookie, cfg func(sess *state.Session)) (*state.SessionInstance, error) {
	args := m.Called(ctx, authCookie, cfg)
	inst, _ := args.Get(0).(*state.SessionInstance)
	return inst, args.Error(1)
}

func (m *MockChatAuthService) SignoutChat(ctx context.Context, sess *state.Session) {
	m.Called(ctx, sess)
}

// navInfoReply builds a ChatNav NavInfo reply carrying a room's cookie and name,
// matching what CreateRoom/RequestRoomInfo return.
func navInfoReply(cookie, name string) wire.SNACMessage {
	return wire.SNACMessage{
		Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ChatNavTLVRoomInfo, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
						Cookie: cookie,
						TLVBlock: wire.TLVBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.ChatRoomTLVRoomName, name),
							},
						},
					}),
				},
			},
		},
	}
}

// A room is addressed like a buddy: im/sendIM to a joined room id must relay
// through ChatService (not ICBM) and echo the sender's own line as a room `im`
// event keyed by the room id.
func TestMessagingHandler_SendIM_RoutesRoomToChatService(t *testing.T) {
	const roomID = "room-cookie-123"

	oscarInstance := state.NewSession().AddInstance()
	mgr := state.NewWebAPISessionManager()
	session, err := mgr.CreateSession(state.DisplayScreenName("Ann Dupree"), "test-dev",
		[]string{"im", "sentIM"}, oscarInstance, "", slog.Default())
	require.NoError(t, err)

	// The session has joined the room; its chat instance is what ChatService is
	// invoked against.
	chatInstance := state.NewSession().AddInstance()
	require.True(t, session.AddChatRoom(roomID, chatInstance))

	chatService := &MockChatService{}
	chatService.On("ChannelMsgToHost", mock.Anything, chatInstance, mock.Anything, mock.Anything).
		Return(nil, nil)

	icbmService := &MockICBMService{} // must NOT be called for a room target

	handler := &MessagingHandler{
		SessionManager: mgr,
		ICBMService:    icbmService,
		ChatService:    chatService,
		LocateService:  stubLocateService("Ann Dupree"),
		FeedbagService: &MockFeedbagService{},
		Logger:         slog.Default(),
	}

	req, err := http.NewRequest("GET",
		"/im/sendIM?aimsid="+session.AimSID+"&t="+url.QueryEscape(roomID)+"&message=hi", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(mgr, handler.SendIM).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	chatService.AssertCalled(t, "ChannelMsgToHost", mock.Anything, chatInstance, mock.Anything, mock.Anything)
	icbmService.AssertNotCalled(t, "ChannelMsgToHost", mock.Anything, mock.Anything, mock.Anything, mock.Anything)

	// The sender's own line is echoed as a room `im` event.
	var room types.RoomIMEvent
	var found bool
	for _, e := range session.EventQueue.GetAllEvents() {
		if e.Type == types.EventTypeIM {
			room, found = e.Data.(types.RoomIMEvent)
		}
	}
	require.True(t, found, "expected a room im event")
	assert.Equal(t, roomID, room.Imserv)
	assert.Equal(t, roomID, room.Source.AimID)
	assert.Equal(t, "imservMsg", room.SpecialIM)
	assert.Equal(t, "anndupree", room.SpecialData.ImFromImserv.OrigSender)
	assert.Equal(t, "hi", room.SpecialData.ImFromImserv.Text)
}

// stubChatJoinDeps wires the ServiceRequest/CrackCookie/RegisterChatSession/
// ClientOnline handoff mocks for the room-join path, returning the chat instance
// RegisterChatSession hands back so tests can assert it was registered.
func stubChatJoinDeps(oscarInstance *state.SessionInstance) (*MockChatBridgeOServiceService, *MockChatAuthService, *state.SessionInstance) {
	oservice := &MockChatBridgeOServiceService{}
	oservice.On("ServiceRequest", mock.Anything, wire.BOS, oscarInstance, mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{
			Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("login-cookie")),
					},
				},
			},
		}, nil)

	chatInstance := state.NewSession().AddInstance()
	auth := &MockChatAuthService{}
	auth.On("CrackCookie", []byte("login-cookie")).Return(state.ServerCookie{}, nil)
	auth.On("RegisterChatSession", mock.Anything, mock.Anything, mock.Anything).Return(chatInstance, nil)
	oservice.On("ClientOnline", mock.Anything, wire.Chat, mock.Anything, chatInstance).Return(nil)
	return oservice, auth, chatInstance
}

// imserv/create makes an exchange-4 room, auto-joins the creator (so im/sendIM to
// the room works immediately), and returns the room id as imserv.
func TestImservHandler_Create(t *testing.T) {
	const roomID = "created-cookie"

	oscarInstance := state.NewSession().AddInstance()
	mgr := state.NewWebAPISessionManager()
	session, err := mgr.CreateSession(state.DisplayScreenName("Ann Dupree"), "test-dev",
		[]string{"im"}, oscarInstance, "", slog.Default())
	require.NoError(t, err)

	chatNav := &MockChatNavService{}
	chatNav.On("CreateRoom", mock.Anything, oscarInstance, mock.Anything, mock.Anything).
		Return(navInfoReply(roomID, "My Room"), nil)
	oservice, auth, chatInstance := stubChatJoinDeps(oscarInstance)

	handler := &ImservHandler{
		SessionManager:  mgr,
		ChatNavService:  chatNav,
		OServiceService: oservice,
		AuthService:     auth,
		Logger:          slog.Default(),
	}

	req, err := http.NewRequest("GET",
		"/imserv/create?aimsid="+session.AimSID+"&friendly="+url.QueryEscape("My Room"), nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(mgr, handler.Create).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	chatNav.AssertCalled(t, "CreateRoom", mock.Anything, oscarInstance, mock.Anything, mock.Anything)
	assert.Contains(t, rr.Body.String(), roomID)

	// The creator is auto-joined so subsequent im/sendIM routes to the room.
	got, joined := session.ChatRoom(roomID)
	require.True(t, joined)
	assert.Equal(t, chatInstance, got)
}

// imserv/join runs the OSCAR chat handoff and registers the room's chat session
// on the WebAPISession so subsequent im/sendIM routes to it.
func TestImservHandler_Join(t *testing.T) {
	const roomID = "join-cookie"

	oscarInstance := state.NewSession().AddInstance()
	mgr := state.NewWebAPISessionManager()
	session, err := mgr.CreateSession(state.DisplayScreenName("Ann Dupree"), "test-dev",
		[]string{"im"}, oscarInstance, "", slog.Default())
	require.NoError(t, err)

	chatNav := &MockChatNavService{}
	chatNav.On("RequestRoomInfo", mock.Anything, mock.Anything, mock.Anything).
		Return(navInfoReply(roomID, "My Room"), nil)

	oservice := &MockChatBridgeOServiceService{}
	oservice.On("ServiceRequest", mock.Anything, wire.BOS, oscarInstance, mock.Anything, mock.Anything, mock.Anything).
		Return(wire.SNACMessage{
			Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("login-cookie")),
					},
				},
			},
		}, nil)

	chatInstance := state.NewSession().AddInstance()
	auth := &MockChatAuthService{}
	auth.On("CrackCookie", []byte("login-cookie")).Return(state.ServerCookie{}, nil)
	auth.On("RegisterChatSession", mock.Anything, mock.Anything, mock.Anything).Return(chatInstance, nil)

	oservice.On("ClientOnline", mock.Anything, wire.Chat, mock.Anything, chatInstance).Return(nil)

	handler := &ImservHandler{
		SessionManager:  mgr,
		ChatNavService:  chatNav,
		OServiceService: oservice,
		AuthService:     auth,
		Logger:          slog.Default(),
	}

	req, err := http.NewRequest("GET",
		"/imserv/join?aimsid="+session.AimSID+"&imserv="+url.QueryEscape(roomID), nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(mgr, handler.Join).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	// The room's chat session is registered so im/sendIM can find it.
	got, joined := session.ChatRoom(roomID)
	require.True(t, joined)
	assert.Equal(t, chatInstance, got)
	oservice.AssertCalled(t, "ClientOnline", mock.Anything, wire.Chat, mock.Anything, chatInstance)
}

// imserv/invite sends a chat-room invitation to the buddy named by t as an ICBM
// channel-2 CapChat rendezvous carrying the room info.
func TestImservHandler_Invite(t *testing.T) {
	const roomID = "4-0-Test Room"

	oscarInstance := state.NewSession().AddInstance()
	mgr := state.NewWebAPISessionManager()
	session, err := mgr.CreateSession(state.DisplayScreenName("Ann Dupree"), "test-dev",
		[]string{"im"}, oscarInstance, "", slog.Default())
	require.NoError(t, err)

	var captured wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
	icbm := &MockICBMService{}
	icbm.On("ChannelMsgToHost", mock.Anything, oscarInstance, mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			captured = args.Get(3).(wire.SNAC_0x04_0x06_ICBMChannelMsgToHost)
		}).Return(nil, nil)

	handler := &ImservHandler{SessionManager: mgr, ICBMService: icbm, Logger: slog.Default()}

	req, err := http.NewRequest("GET",
		"/imserv/invite?aimsid="+session.AimSID+"&imserv="+url.QueryEscape(roomID)+"&t=bobsmith", nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(mgr, handler.Invite).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	assert.Equal(t, wire.ICBMChannelRendezvous, captured.ChannelID)
	assert.Equal(t, "bobsmith", captured.ScreenName)
	// The rendezvous carries a CapChat propose fragment with the room info.
	rd, ok := captured.Bytes(wire.ICBMTLVData)
	require.True(t, ok)
	var frag wire.ICBMCh2Fragment
	require.NoError(t, wire.UnmarshalBE(&frag, bytes.NewReader(rd)))
	assert.Equal(t, wire.CapChat, uuid.UUID(frag.Capability))
	svc, ok := frag.Bytes(wire.ICBMRdvTLVTagsSvcData)
	require.True(t, ok)
	var room wire.ICBMRoomInfo
	require.NoError(t, wire.UnmarshalBE(&room, bytes.NewReader(svc)))
	assert.Equal(t, roomID, room.Cookie)
	assert.Equal(t, uint16(4), room.Exchange)
}

// MockChatParticipants is a mock implementation of ChatParticipants.
type MockChatParticipants struct {
	mock.Mock
}

func (m *MockChatParticipants) AllSessions(chatCookie string) []*state.Session {
	args := m.Called(chatCookie)
	s, _ := args.Get(0).([]*state.Session)
	return s
}

// imserv/getSettings must return 200 with the room name (friendly) and member
// count — the client's group-chat entry stays in a permanent loading spinner
// until this succeeds.
func TestImservHandler_GetSettings(t *testing.T) {
	const roomID = "4-0-Ida and Jon chat"

	oscarInstance := state.NewSession().AddInstance()
	mgr := state.NewWebAPISessionManager()
	session, err := mgr.CreateSession(state.DisplayScreenName("Ida Pruitt"), "test-dev",
		[]string{"im", "conversation"}, oscarInstance, "", slog.Default())
	require.NoError(t, err)

	participants := &MockChatParticipants{}
	participants.On("AllSessions", roomID).Return([]*state.Session{state.NewSession()})

	handler := &ImservHandler{SessionManager: mgr, Participants: participants, Logger: slog.Default()}

	req, err := http.NewRequest("GET",
		"/imserv/getSettings?aimsid="+session.AimSID+"&imserv="+url.QueryEscape(roomID), nil)
	require.NoError(t, err)
	rr := httptest.NewRecorder()
	requireSession(mgr, handler.GetSettings).ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Response struct {
			StatusCode int `json:"statusCode"`
			Data       struct {
				Imserv       string `json:"imserv"`
				Friendly     string `json:"friendly"`
				MemberCounts int    `json:"memberCounts"`
			} `json:"data"`
		} `json:"response"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &body))
	assert.Equal(t, 200, body.Response.StatusCode)
	assert.Equal(t, roomID, body.Response.Data.Imserv)
	assert.Equal(t, "Ida and Jon chat", body.Response.Data.Friendly)
	assert.Equal(t, 1, body.Response.Data.MemberCounts)
}
