package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// roomNameMaxLen bounds the room name, matching the client's 45-char truncation
// of the friendly field on imserv/create.
const roomNameMaxLen = 45

// ChatNavService creates chat rooms and serves room metadata for the imserv
// endpoints. Backed by foodgroup.ChatNavService (the same instance BOS and TOC
// use), so web-created rooms are real OSCAR rooms.
type ChatNavService interface {
	CreateRoom(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate) (wire.SNACMessage, error)
	RequestRoomInfo(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo) (wire.SNACMessage, error)
}

// ChatBridgeOServiceService issues the OSCAR service handoff that joining a chat
// room requires: ServiceRequest yields the chat login cookie, and ClientOnline
// brings the chat session online (which triggers the member list and arrival
// announcement).
type ChatBridgeOServiceService interface {
	ServiceRequest(ctx context.Context, service uint16, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x01_0x04_OServiceServiceRequest, listener config.Listener) (wire.SNACMessage, error)
	ClientOnline(ctx context.Context, service uint16, inBody wire.SNAC_0x01_0x02_OServiceClientOnline, instance *state.SessionInstance) error
}

// ChatParticipants lists the current participants of a chat room, keyed by the
// room cookie. Backed by the shared chat session manager (the ChatMessageRelayer).
type ChatParticipants interface {
	AllSessions(chatCookie string) []*state.Session
}

// ChatAuthService registers the dedicated chat SessionInstance a room join needs.
// CrackCookie decodes the chat login cookie from ServiceRequest; RegisterChatSession
// creates the chat session; SignoutChat is its close hook.
type ChatAuthService interface {
	CrackCookie(authCookie []byte) (state.ServerCookie, error)
	RegisterChatSession(ctx context.Context, authCookie state.ServerCookie, cfg func(sess *state.Session)) (*state.SessionInstance, error)
	SignoutChat(ctx context.Context, sess *state.Session)
}

// ImservHandler serves the Web AIM group-chat (imserv) endpoints by bridging them
// onto the OSCAR chat food group. It mirrors the TOC chat bridge
// (server/toc/cmd_client.go ChatJoin/ChatLeave): each joined room gets a
// dedicated chat SessionInstance registered on the WebAPISession, and relayed
// chat SNACs surface through that session's event queue.
type ImservHandler struct {
	SessionManager  *state.WebAPISessionManager
	ChatNavService  ChatNavService
	OServiceService ChatBridgeOServiceService
	AuthService     ChatAuthService
	ICBMService     ICBMService
	Participants    ChatParticipants
	Logger          *slog.Logger
}

// Create handles GET/POST imserv/create. It creates (exchange 4) a user room
// named by the friendly param and returns the room id (the ChatRoom cookie) the
// client will use to join and to address messages. It does not auto-join; the
// client calls imserv/join separately.
func (h *ImservHandler) Create(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	ctx := r.Context()

	name := queryOrFormParam(r, "friendly")
	if name == "" {
		SendError(w, http.StatusBadRequest, "missing required parameter: friendly")
		return
	}
	if len(name) > roomNameMaxLen {
		name = name[:roomNameMaxLen]
	}

	inBody := wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
		Exchange: state.PrivateExchange,
		Cookie:   "create",
		TLVBlock: wire.TLVBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ChatRoomTLVRoomName, name),
			},
		},
	}

	reply, err := h.ChatNavService.CreateRoom(ctx, sess.OSCARSession, wire.SNACFrame{}, inBody)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to create chat room", "err", err.Error())
		SendError(w, http.StatusInternalServerError, "failed to create chat room")
		return
	}

	room, ok := roomInfoFromNavReply(reply)
	if !ok {
		h.Logger.ErrorContext(ctx, "create room reply missing room info")
		SendError(w, http.StatusInternalServerError, "failed to create chat room")
		return
	}

	// Auto-join the creator: the web client's "start group chat" flow creates a
	// room and immediately sends to it without a separate join, so the creator
	// must already be a participant or im/sendIM would fall through to the 1:1
	// path. joinRoom is idempotent, so a client that does call join later is fine.
	if err := h.joinRoom(ctx, sess, room.Cookie); err != nil {
		h.Logger.ErrorContext(ctx, "failed to auto-join created room", "room", room.Cookie, "err", err.Error())
		SendError(w, http.StatusInternalServerError, "failed to join created chat room")
		return
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = roomData(room.Cookie, name)
	SendResponse(w, r, resp, h.Logger)

	h.Logger.InfoContext(ctx, "chat room created and joined",
		"screenName", sess.ScreenName.String(),
		"room", room.Cookie,
		"name", name,
	)
}

// Join handles GET/POST imserv/join. It runs the OSCAR chat-join handoff for the
// room named by the imserv param, registers the resulting chat session on the web
// session, and starts a listener so relayed room messages surface via fetchEvents.
func (h *ImservHandler) Join(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	ctx := r.Context()

	roomID := queryOrFormParam(r, "imserv")
	if roomID == "" {
		SendError(w, http.StatusBadRequest, "missing required parameter: imserv")
		return
	}

	// Already joined: return the room info without a second handoff.
	if _, joined := sess.ChatRoom(roomID); joined {
		h.sendJoinedResponse(w, r, roomID, "")
		return
	}

	// Resolve the room by cookie to confirm it exists and read its name. MVP
	// supports user-created rooms only (exchange 4).
	roomReply, err := h.ChatNavService.RequestRoomInfo(ctx, wire.SNACFrame{},
		wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
			Cookie:   roomID,
			Exchange: state.PrivateExchange,
		})
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to look up chat room", "room", roomID, "err", err.Error())
		SendError(w, http.StatusNotFound, "chat room not found")
		return
	}
	room, ok := roomInfoFromNavReply(roomReply)
	if !ok {
		SendError(w, http.StatusNotFound, "chat room not found")
		return
	}

	if err := h.joinRoom(ctx, sess, room.Cookie); err != nil {
		h.Logger.ErrorContext(ctx, "failed to join chat room", "room", roomID, "err", err.Error())
		SendError(w, http.StatusInternalServerError, "failed to join chat room")
		return
	}

	h.sendJoinedResponse(w, r, room.Cookie, room.Name)

	h.Logger.InfoContext(ctx, "chat room joined",
		"screenName", sess.ScreenName.String(),
		"room", room.Cookie,
	)
}

// joinRoom runs the OSCAR chat handoff for a room cookie, registers the room's
// chat session on the web session, and starts its listener so relayed room
// messages surface via fetchEvents. It is idempotent: joining an
// already-joined room is a no-op. Shared by Create (auto-join the creator) and
// Join. Mirrors the tail of TOC's ChatJoin (server/toc/cmd_client.go).
func (h *ImservHandler) joinRoom(ctx context.Context, sess *state.WebAPISession, cookie string) error {
	if _, joined := sess.ChatRoom(cookie); joined {
		return nil
	}

	chatSess, err := h.registerChatSession(ctx, sess, cookie)
	if err != nil {
		return err
	}

	// Register before ClientOnline so the arrival announcement and member list the
	// server sends in response are captured by the listener.
	if !sess.AddChatRoom(cookie, chatSess) {
		// Session is tearing down; undo the chat session we just created.
		chatSess.CloseInstance()
		return errors.New("session ended")
	}
	sess.StartListeningToChatSession(cookie, chatSess)

	if err := h.OServiceService.ClientOnline(ctx, wire.Chat, wire.SNAC_0x01_0x02_OServiceClientOnline{}, chatSess); err != nil {
		if inst, removed := sess.RemoveChatRoom(cookie); removed {
			inst.CloseInstance()
		}
		return err
	}
	return nil
}

// Leave handles imserv/delete (and any explicit leave): it closes the room's chat
// session, which announces the departure and unwinds its listener.
func (h *ImservHandler) Leave(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	roomID := queryOrFormParam(r, "imserv")
	if roomID == "" {
		SendError(w, http.StatusBadRequest, "missing required parameter: imserv")
		return
	}

	if inst, removed := sess.RemoveChatRoom(roomID); removed {
		inst.CloseInstance()
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	SendResponse(w, r, resp, h.Logger)
}

// Invite handles imserv/invite: it sends a chat-room invitation to the buddy
// named by t. The invite is an ICBM channel-2 CapChat rendezvous carrying the
// room info, exactly like TOC's ChatInvite (server/toc/cmd_client.go). The
// recipient's client surfaces it as an `im` event with specialData.invitation.
func (h *ImservHandler) Invite(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	ctx := r.Context()

	roomID := queryOrFormParam(r, "imserv")
	invitee := queryOrFormParam(r, "t")
	if roomID == "" || invitee == "" {
		SendError(w, http.StatusBadRequest, "missing required parameter: imserv and t")
		return
	}

	exchange, instance, name, ok := parseRoomCookie(roomID)
	if !ok {
		SendError(w, http.StatusBadRequest, "invalid imserv room id")
		return
	}

	roomInfo := wire.ICBMRoomInfo{Exchange: exchange, Cookie: roomID, Instance: instance}
	prompt := fmt.Sprintf("%s would like you to join the chat room %q", sess.ScreenName.String(), name)

	snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		ChannelID:  wire.ICBMChannelRendezvous,
		ScreenName: invitee,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
					Type:       wire.ICBMRdvMessagePropose,
					Capability: wire.CapChat,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMRdvTLVTagsSeqNum, uint16(1)),
							wire.NewTLVBE(wire.ICBMRdvTLVTagsInvitation, prompt),
							wire.NewTLVBE(wire.ICBMRdvTLVTagsInviteMIMECharset, "us-ascii"),
							wire.NewTLVBE(wire.ICBMRdvTLVTagsInviteMIMELang, "en"),
							wire.NewTLVBE(wire.ICBMRdvTLVTagsSvcData, roomInfo),
						},
					},
				}),
			},
		},
	}

	if _, err := h.ICBMService.ChannelMsgToHost(ctx, sess.OSCARSession, wire.SNACFrame{}, snac); err != nil {
		h.Logger.ErrorContext(ctx, "failed to send chat invite", "room", roomID, "invitee", invitee, "err", err.Error())
		SendError(w, http.StatusInternalServerError, "failed to send invite")
		return
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	SendResponse(w, r, resp, h.Logger)

	h.Logger.InfoContext(ctx, "chat invite sent",
		"screenName", sess.ScreenName.String(), "room", roomID, "invitee", invitee)
}

// GetMembers handles imserv/getMembers: it returns the room's current
// participants. The client reads data.members (each {member, memberType}) to
// populate the roster, excluding memberType "invite".
func (h *ImservHandler) GetMembers(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	roomID := queryOrFormParam(r, "imserv")
	if roomID == "" {
		SendError(w, http.StatusBadRequest, "missing required parameter: imserv")
		return
	}

	members := []map[string]interface{}{}
	for _, participant := range h.Participants.AllSessions(roomID) {
		members = append(members, map[string]interface{}{
			"member":     participant.IdentScreenName().String(),
			"memberType": "member",
		})
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]interface{}{"members": members}
	SendResponse(w, r, resp, h.Logger)
}

// GetSettings handles imserv/getSettings: it returns a room's metadata. The
// client blocks a group-chat entry's rendering (a permanent loading spinner)
// until this returns 200 — its loader only flips "loaded" on a successful
// getSettings. The client reads data.friendly (name; falls back to the raw id)
// and data.memberCounts (used when the live roster is empty).
func (h *ImservHandler) GetSettings(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	roomID := queryOrFormParam(r, "imserv")
	if roomID == "" {
		SendError(w, http.StatusBadRequest, "missing required parameter: imserv")
		return
	}

	name := roomID
	if _, _, parsed, ok := parseRoomCookie(roomID); ok {
		name = parsed
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]interface{}{
		"imserv":       roomID,
		"friendly":     name,
		"memberCounts": len(h.Participants.AllSessions(roomID)),
	}
	SendResponse(w, r, resp, h.Logger)
}

// GetRecentActivity handles imserv/getRecentActivity: room message history. Not
// on the render-blocking path (a 404 is tolerated), but implemented to avoid
// noise. Room lines are not persisted yet, so this returns an empty activity list.
func (h *ImservHandler) GetRecentActivity(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	roomID := queryOrFormParam(r, "imserv")
	if roomID == "" {
		SendError(w, http.StatusBadRequest, "missing required parameter: imserv")
		return
	}

	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = map[string]interface{}{
		"imservActivities": []map[string]interface{}{
			{"imserv": roomID, "activities": []map[string]interface{}{}},
		},
	}
	SendResponse(w, r, resp, h.Logger)
}

// Reject handles imserv/reject: the invitee declines an invitation. For MVP this
// is acknowledged without notifying the inviter.
func (h *ImservHandler) Reject(w http.ResponseWriter, r *http.Request, sess *state.WebAPISession) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	SendResponse(w, r, resp, h.Logger)
}

// parseRoomCookie splits a chat room cookie of the form
// "<exchange>-<instance>-<name>" into its parts. The name may contain "-", so
// only the first two segments are parsed off.
func parseRoomCookie(cookie string) (exchange, instance uint16, name string, ok bool) {
	parts := strings.SplitN(cookie, "-", 3)
	if len(parts) < 3 {
		return 0, 0, "", false
	}
	ex, err := strconv.ParseUint(parts[0], 10, 16)
	if err != nil {
		return 0, 0, "", false
	}
	inst, err := strconv.ParseUint(parts[1], 10, 16)
	if err != nil {
		return 0, 0, "", false
	}
	return uint16(ex), uint16(inst), parts[2], true
}

// registerChatSession runs the OSCAR chat handoff for a room cookie and returns
// the newly created chat SessionInstance. Mirrors the tail of TOC's ChatJoin
// (server/toc/cmd_client.go): ServiceRequest -> CrackCookie -> RegisterChatSession.
func (h *ImservHandler) registerChatSession(ctx context.Context, sess *state.WebAPISession, cookie string) (*state.SessionInstance, error) {
	svcReq := wire.SNAC_0x01_0x04_OServiceServiceRequest{
		FoodGroup: wire.Chat,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{Cookie: cookie}),
			},
		},
	}
	svcReply, err := h.OServiceService.ServiceRequest(ctx, wire.BOS, sess.OSCARSession, wire.SNACFrame{}, svcReq, config.Listener{})
	if err != nil {
		return nil, err
	}
	svcBody, ok := svcReply.Body.(wire.SNAC_0x01_0x05_OServiceServiceResponse)
	if !ok {
		return nil, errors.New("unexpected ServiceRequest response type")
	}
	loginCookie, ok := svcBody.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !ok {
		return nil, errors.New("ServiceRequest response missing login cookie")
	}

	serverCookie, err := h.AuthService.CrackCookie(loginCookie)
	if err != nil {
		return nil, err
	}

	sessCfg := func(s *state.Session) {
		s.OnSessionClose(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			h.AuthService.SignoutChat(ctx, s)
		})
	}
	return h.AuthService.RegisterChatSession(ctx, serverCookie, sessCfg)
}

// sendJoinedResponse writes a successful join envelope carrying the room id.
func (h *ImservHandler) sendJoinedResponse(w http.ResponseWriter, r *http.Request, roomID, name string) {
	resp := BaseResponse{}
	resp.Response.StatusCode = 200
	resp.Response.StatusText = "OK"
	resp.Response.Data = roomData(roomID, name)
	SendResponse(w, r, resp, h.Logger)
}

// roomInfo carries the fields the imserv bridge needs from a chat room.
type roomInfo struct {
	Cookie string
	Name   string
}

// roomInfoFromNavReply extracts the room cookie and name from a ChatNav NavInfo
// reply (the room info TLV wraps a ChatRoomInfoUpdate).
func roomInfoFromNavReply(reply wire.SNACMessage) (roomInfo, bool) {
	body, ok := reply.Body.(wire.SNAC_0x0D_0x09_ChatNavNavInfo)
	if !ok {
		return roomInfo{}, false
	}
	buf, ok := body.Bytes(wire.ChatNavTLVRoomInfo)
	if !ok {
		return roomInfo{}, false
	}
	var room wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate
	if err := wire.UnmarshalBE(&room, bytes.NewReader(buf)); err != nil {
		return roomInfo{}, false
	}
	name, _ := room.String(wire.ChatRoomTLVRoomName)
	return roomInfo{Cookie: room.Cookie, Name: name}, true
}

// roomData builds the room object the client reads from create/join responses.
// imserv is the id it uses as the im/sendIM target. The client reads the room's
// display name from `group` (create callback `HG`); friendly is included as a
// harmless alias.
func roomData(roomID, name string) map[string]interface{} {
	data := map[string]interface{}{
		"imserv": roomID,
	}
	if name != "" {
		data["group"] = name
		data["friendly"] = name
	}
	return data
}
