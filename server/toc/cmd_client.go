package toc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// NewChatRegistry creates a new ChatRegistry instance.
func NewChatRegistry() *ChatRegistry {
	chatRegistry := &ChatRegistry{
		lookup:   make(map[int]wire.ICBMRoomInfo),
		sessions: make(map[int]*state.SessionInstance),
		m:        sync.RWMutex{},
	}
	return chatRegistry
}

// ChatRegistry manages the chat rooms that a user is connected to during a TOC
// session. It maintains mappings between chat room identifiers, metadata, and
// active chat sessions.
//
// This struct provides thread-safe operations for adding, retrieving, and managing
// chat room metadata and associated sessions.
type ChatRegistry struct {
	lookup   map[int]wire.ICBMRoomInfo      // Maps chat room IDs to their metadata.
	sessions map[int]*state.SessionInstance // Tracks active chat sessions by chat room ID.
	nextID   int                            // Incremental identifier for newly added chat rooms.
	m        sync.RWMutex                   // Synchronization primitive for concurrent access.
}

// Add registers metadata for a newly joined chat room and returns a unique
// identifier for it. If the room is already registered, it returns the existing ID.
func (c *ChatRegistry) Add(room wire.ICBMRoomInfo) int {
	c.m.Lock()
	defer c.m.Unlock()
	for chatID, r := range c.lookup {
		if r == room {
			return chatID
		}
	}
	id := c.nextID
	c.lookup[id] = room
	c.nextID++
	return id
}

// LookupRoom retrieves metadata for the chat room registered with chatID.
// It returns the room metadata and a boolean indicating whether the chat ID
// was found.
func (c *ChatRegistry) LookupRoom(chatID int) (wire.ICBMRoomInfo, bool) {
	c.m.RLock()
	defer c.m.RUnlock()
	room, found := c.lookup[chatID]
	return room, found
}

// RegisterSess associates a chat session with a chat room. If a session is
// already registered for the given chat ID, it will be overwritten.
func (c *ChatRegistry) RegisterSess(chatID int, instance *state.SessionInstance) {
	c.m.Lock()
	defer c.m.Unlock()
	c.sessions[chatID] = instance
}

// RetrieveSess retrieves the chat session associated with the given chat ID.
// If no session is registered for the chat ID, it returns nil.
func (c *ChatRegistry) RetrieveSess(chatID int) *state.SessionInstance {
	c.m.RLock()
	defer c.m.RUnlock()
	return c.sessions[chatID]
}

// RemoveSess removes a chat session.
func (c *ChatRegistry) RemoveSess(chatID int) {
	c.m.Lock()
	defer c.m.Unlock()
	delete(c.sessions, chatID)
}

// Sessions retrieves all the chat sessions.
func (c *ChatRegistry) Sessions() []*state.SessionInstance {
	c.m.RLock()
	defer c.m.RUnlock()
	sessions := make([]*state.SessionInstance, 0, len(c.sessions))
	for _, s := range c.sessions {
		sessions = append(sessions, s)
	}
	return sessions
}

// OSCARProxy acts as a bridge between TOC clients and the OSCAR server,
// translating protocol messages between the two.
//
// It performs the following functions:
//   - Receives TOC messages from the client, converts them into SNAC messages,
//     and forwards them to the OSCAR server. The SNAC response is then converted
//     back into a TOC response for the client.
//   - Receives incoming messages from the OSCAR server and translates them into
//     TOC responses for the client.
type OSCARProxy struct {
	AdminService       AdminService
	AuthService        AuthService
	BuddyListRegistry  BuddyListRegistry
	BuddyService       BuddyService
	ChatNavService     ChatNavService
	ChatService        ChatService
	ChatSessionManager ChatSessionManager
	CookieBaker        CookieBaker
	DirSearchService   DirSearchService
	ICBMService        ICBMService
	LocateService      LocateService
	Logger             *slog.Logger
	OServiceService    OServiceService
	PermitDenyService  PermitDenyService
	TOCConfigStore     TOCConfigStore
	SessionRetriever   SessionRetriever
	FeedbagService     FeedbagService
	FeedbagManager     FeedbagManager
	SNACRateLimits     wire.SNACRateLimits
	HTTPIPRateLimiter  *IPRateLimiter
	// RandIntn is the source for feedbag item ID generation.
	// Inject a deterministic func in tests to assert exact feedbag item slices.
	RandIntn func(n int) int
}

// RecvClientCmd processes a client TOC command and returns a server reply.
//
// * sessBOS is the current user's session.
// * chatRegistry manages the current user's chat sessions
// * payload is the command + arguments
// * toCh is the channel that transports messages to client
// * doAsync performs async tasks, is auto-cleaned up by caller
//
// It returns true if the server can continue processing commands.
func (s OSCARProxy) RecvClientCmd(
	ctx context.Context,
	sessBOS *state.SessionInstance,
	chatRegistry *ChatRegistry,
	payload []byte,
	toCh chan<- []string,
	doAsync func(f func() error),
) (replies []string) {

	cmd := payload
	var args []byte
	if idx := bytes.IndexByte(payload, ' '); idx > -1 {
		cmd, args = payload[:idx], payload[idx:]
	}

	if s.Logger.Enabled(ctx, slog.LevelDebug) {
		s.Logger.DebugContext(ctx, "client request", "command", payload)
	} else {
		s.Logger.InfoContext(ctx, "client request", "command", cmd)
	}

	switch string(cmd) {
	case "toc_send_im", "toc2_send_im":
		return s.SendIM(ctx, sessBOS, args)
	case "toc_init_done":
		return s.InitDone(ctx, sessBOS)
	case "toc_add_buddy":
		return s.AddBuddy(ctx, sessBOS, args)
	case "toc_get_status":
		return s.GetStatus(ctx, sessBOS, args)
	case "toc_remove_buddy":
		return s.RemoveBuddy(ctx, sessBOS, args)
	case "toc_add_permit":
		return s.AddPermit(ctx, sessBOS, args)
	case "toc_add_deny":
		return s.AddDeny(ctx, sessBOS, args)
	case "toc_set_away":
		return s.SetAway(ctx, sessBOS, args)
	case "toc_set_caps":
		return s.SetCaps(ctx, sessBOS, args)
	case "toc_evil":
		return s.Evil(ctx, sessBOS, args)
	case "toc_get_info":
		return s.GetInfoURL(ctx, sessBOS, args)
	case "toc_change_passwd":
		return s.ChangePassword(ctx, sessBOS, args)
	case "toc_format_nickname":
		return s.FormatNickname(ctx, sessBOS, args)
	case "toc_chat_join", "toc_chat_accept":
		var chatID int
		var msg []string

		if string(cmd) == "toc_chat_join" {
			chatID, msg = s.ChatJoin(ctx, sessBOS, chatRegistry, args)
		} else {
			chatID, msg = s.ChatAccept(ctx, sessBOS, chatRegistry, args)
		}

		if len(msg) > 0 && msg[0] == cmdInternalSvcErr {
			return msg
		}

		doAsync(func() error {
			sess := chatRegistry.RetrieveSess(chatID)
			s.RecvChat(ctx, sess, chatID, toCh)
			return nil
		})

		return msg
	case "toc_chat_send":
		return s.ChatSend(ctx, chatRegistry, args)
	case "toc_chat_whisper":
		return s.ChatWhisper(ctx, chatRegistry, args)
	case "toc_chat_leave":
		return s.ChatLeave(ctx, chatRegistry, args)
	case "toc_set_info":
		return s.SetInfo(ctx, sessBOS, args)
	case "toc_set_dir":
		return s.SetDir(ctx, sessBOS, args)
	case "toc_set_idle":
		return s.SetIdle(ctx, sessBOS, args)
	case "toc_set_config":
		return s.SetConfig(ctx, sessBOS, args)
	case "toc_chat_invite":
		return s.ChatInvite(ctx, sessBOS, chatRegistry, args)
	case "toc_dir_search":
		return s.GetDirSearchURL(ctx, sessBOS, args)
	case "toc_get_dir":
		return s.GetDirURL(ctx, sessBOS, args)
	case "toc_rvous_accept":
		return s.RvousAccept(ctx, sessBOS, args)
	case "toc_rvous_cancel":
		return s.RvousCancel(ctx, sessBOS, args)
	case "toc2_set_pdmode":
		return s.SetPDMode(ctx, sessBOS, args)
	case "toc2_send_im_enc":
		return s.SendIMEnc(ctx, sessBOS, args)
	case "toc2_remove_buddy":
		return s.RemoveBuddy2(ctx, sessBOS, args)
	case "toc2_new_group":
		return s.NewGroup(ctx, sessBOS, args)
	case "toc2_del_group":
		return s.DelGroup(ctx, sessBOS, args)
	case "toc2_new_buddies":
		return s.NewBuddies(ctx, sessBOS, args)
	case "toc2_add_permit":
		return s.AddPermit2(ctx, sessBOS, args)
	case "toc2_remove_permit":
		return s.RemovePermit2(ctx, sessBOS, args)
	case "toc2_add_deny":
		return s.AddDeny2(ctx, sessBOS, args)
	case "toc2_remove_deny":
		return s.RemoveDeny2(ctx, sessBOS, args)
	case "toc2_client_event":
		return s.SendClientEvent(ctx, sessBOS, args)
	}

	s.Logger.ErrorContext(ctx, fmt.Sprintf("unsupported TOC command %s", cmd))
	return []string{cmdInternalSvcErr}
}

// AddBuddy handles the toc_add_buddy TOC command.
//
// From the TiK documentation:
//
//	Add buddies to your buddy list. This does not change your saved config.
//
// Command syntax: toc_add_buddy <Buddy User 1> [<Buddy User2> [<Buddy User 3> [...]]]
func (s OSCARProxy) AddBuddy(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if msg, isLimited := s.checkRateLimit(ctx, me, wire.Buddy, wire.BuddyAddBuddies); isLimited {
		return msg
	}

	users, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	snac := wire.SNAC_0x03_0x04_BuddyAddBuddies{}
	for _, sn := range users {
		snac.Buddies = append(snac.Buddies, struct {
			ScreenName string `oscar:"len_prefix=uint8"`
		}{ScreenName: sn})
	}

	if err := s.BuddyService.AddBuddies(ctx, me, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("BuddyService.AddBuddies: %w", err))
	}

	return []string{}
}

// AddPermit handles the toc_add_permit TOC command.
//
// From the TiK documentation:
//
//	ADD the following people to your permit mode. If you are in deny mode it
//	will switch you to permit mode first. With no arguments and in deny mode
//	this will switch you to permit none. If already in permit mode, no
//	arguments does nothing and your permit list remains the same.
//
// Command syntax: toc_add_permit [ <User 1> [<User 2> [...]]]
func (s OSCARProxy) AddPermit(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if msg, isLimited := s.checkRateLimit(ctx, me, wire.PermitDeny, wire.PermitDenyAddDenyListEntries); isLimited {
		return msg
	}

	users, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	snac := wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{}
	for _, sn := range users {
		snac.Users = append(snac.Users, struct {
			ScreenName string `oscar:"len_prefix=uint8"`
		}{ScreenName: sn})
	}

	if err := s.PermitDenyService.AddPermListEntries(ctx, me, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("PermitDenyService.AddPermListEntries: %w", err))
	}
	return []string{}
}

// AddDeny handles the toc_add_deny TOC command.
//
// From the TiK documentation:
//
//	ADD the following people to your deny mode. If you are in permit mode it
//	will switch you to deny mode first. With no arguments and in permit mode,
//	this will switch you to deny none. If already in deny mode, no arguments
//	does nothing and your deny list remains unchanged.
//
// Command syntax: toc_add_deny [ <User 1> [<User 2> [...]]]
func (s OSCARProxy) AddDeny(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if msg, isLimited := s.checkRateLimit(ctx, me, wire.PermitDeny, wire.PermitDenyAddDenyListEntries); isLimited {
		return msg
	}

	users, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	snac := wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{}
	for _, sn := range users {
		snac.Users = append(snac.Users, struct {
			ScreenName string `oscar:"len_prefix=uint8"`
		}{ScreenName: sn})
	}

	if err := s.PermitDenyService.AddDenyListEntries(ctx, me, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("PermitDenyService.AddDenyListEntries: %w", err))
	}
	return []string{}
}

// ChangePassword handles the toc_change_passwd TOC command.
//
// From the TiK documentation:
//
//	Change a user's password. An ADMIN_PASSWD_STATUS or ERROR message will be
//	sent back to the client.
//
// Command syntax: toc_change_passwd <existing_passwd> <new_passwd>
func (s OSCARProxy) ChangePassword(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if msg, isLimited := s.checkRateLimit(ctx, me, wire.Admin, wire.AdminInfoChangeRequest); isLimited {
		return msg
	}

	var oldPass, newPass string

	if _, err := parseArgs(args, &oldPass, &newPass); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	oldPass = unescape(oldPass)
	newPass = unescape(newPass)

	reqSNAC := wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.AdminTLVOldPassword, oldPass),
				wire.NewTLVBE(wire.AdminTLVNewPassword, newPass),
			},
		},
	}

	reply, err := s.AdminService.InfoChangeRequest(ctx, me, wire.SNACFrame{}, reqSNAC)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("AdminService.InfoChangeRequest: %w", err))
	}

	replyBody, ok := reply.Body.(wire.SNAC_0x07_0x05_AdminChangeReply)
	if !ok {
		return s.runtimeErr(ctx, fmt.Errorf("AdminService.InfoChangeRequest: unexpected response type %v", replyBody))
	}

	code, ok := replyBody.Uint16BE(wire.AdminTLVErrorCode)
	if ok {
		switch code {
		case wire.AdminInfoErrorInvalidPasswordLength:
			return []string{"ERROR:" + wire.TOCErrorAdminInvalidInput}
		case wire.AdminInfoErrorValidatePassword:
			return []string{"ERROR:" + wire.TOCErrorAuthIncorrectNickOrPassword}
		default:
			return []string{"ERROR:" + wire.TOCErrorAdminProcessingRequest}
		}
	}

	return []string{"ADMIN_PASSWD_STATUS:0"}
}

// ChatAccept handles the toc_chat_accept TOC command.
//
// From the TiK documentation:
//
//	Accept a CHAT_INVITE message from TOC. The server will send a CHAT_JOIN in
//	response.
//
// Command syntax: toc_chat_accept <Chat Room ID>
func (s OSCARProxy) ChatAccept(
	ctx context.Context,
	me *state.SessionInstance,
	chatRegistry *ChatRegistry,
	args []byte,
) (int, []string) {

	var chatIDStr string

	if _, err := parseArgs(args, &chatIDStr); err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	chatID, err := strconv.Atoi(chatIDStr)
	if err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}
	chatInfo, found := chatRegistry.LookupRoom(chatID)
	if !found {
		return 0, s.runtimeErr(ctx, fmt.Errorf("chatRegistry.LookupRoom: no chat found for ID %d", chatID))
	}

	if msg, isLimited := s.checkRateLimit(ctx, me, wire.ChatNav, wire.ChatNavRequestRoomInfo); isLimited {
		return 0, msg
	}

	reqRoomSNAC := wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
		Cookie:         chatInfo.Cookie,
		Exchange:       chatInfo.Exchange,
		InstanceNumber: chatInfo.Instance,
	}
	reqRoomReply, err := s.ChatNavService.RequestRoomInfo(ctx, wire.SNACFrame{}, reqRoomSNAC)
	if err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("ChatNavService.RequestRoomInfo: %w", err))
	}

	reqRoomReplyBody, ok := reqRoomReply.Body.(wire.SNAC_0x0D_0x09_ChatNavNavInfo)
	if !ok {
		return 0, s.runtimeErr(
			ctx,
			fmt.Errorf("chatNavService.RequestRoomInfo: unexpected response type %v", reqRoomReplyBody),
		)
	}
	b, hasInfo := reqRoomReplyBody.Bytes(wire.ChatNavTLVRoomInfo)
	if !hasInfo {
		return 0, s.runtimeErr(ctx, errors.New("reqRoomReplyBody.Bytes: missing wire.ChatNavTLVRoomInfo"))
	}

	roomInfo := wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{}
	if err := wire.UnmarshalBE(&roomInfo, bytes.NewReader(b)); err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalBE: %w", err))
	}

	roomName, hasName := roomInfo.Bytes(wire.ChatRoomTLVRoomName)
	if !hasName {
		return 0, s.runtimeErr(ctx, errors.New("roomInfo.Bytes: missing wire.ChatRoomTLVRoomName"))
	}

	if msg, isLimited := s.checkRateLimit(ctx, me, wire.OService, wire.OServiceServiceRequest); isLimited {
		return 0, msg
	}

	svcReqSNAC := wire.SNAC_0x01_0x04_OServiceServiceRequest{
		FoodGroup: wire.Chat,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{
					Cookie: chatInfo.Cookie,
				}),
			},
		},
	}
	svcReqReply, err := s.OServiceService.ServiceRequest(ctx, wire.BOS, me, wire.SNACFrame{}, svcReqSNAC, config.Listener{})
	if err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("OServiceServiceBOS.ServiceRequest: %w", err))
	}

	svcReqReplyBody, ok := svcReqReply.Body.(wire.SNAC_0x01_0x05_OServiceServiceResponse)
	if !ok {
		return 0, s.runtimeErr(
			ctx,
			fmt.Errorf("OServiceServiceBOS.ServiceRequest: unexpected response type %v", svcReqReplyBody),
		)
	}

	loginCookie, hasCookie := svcReqReplyBody.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !hasCookie {
		return 0, s.runtimeErr(ctx, errors.New("missing wire.OServiceTLVTagsLoginCookie"))
	}

	// todo: naming for cookie: login cookie, server cookie, or auth cookie?
	serverCookie, err := s.AuthService.CrackCookie(loginCookie)
	if err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("AuthService.CrackCookie: %w", err))
	}

	sessCfg := func(sess *state.Session) {
		sess.OnSessionClose(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			s.AuthService.SignoutChat(ctx, sess)
		})
	}
	chatSess, err := s.AuthService.RegisterChatSession(ctx, serverCookie, sessCfg)
	if err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("AuthService.RegisterChatSession: %w", err))
	}

	if msg, isLimited := s.checkRateLimit(ctx, me, wire.OService, wire.OServiceClientOnline); isLimited {
		return 0, msg
	}

	if err := s.OServiceService.ClientOnline(ctx, wire.Chat, wire.SNAC_0x01_0x02_OServiceClientOnline{}, chatSess); err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("OServiceServiceChat.ClientOnline: %w", err))
	}

	chatRegistry.RegisterSess(chatID, chatSess)
	if me.IsTOC2() {
		chatSess.SetTOC2(me.SupportsTOC2MsgEnc())
	}

	return chatID, []string{fmt.Sprintf("CHAT_JOIN:%d:%s", chatID, roomName)}
}

// ChatInvite handles the toc_chat_invite TOC command.
//
// From the TiK documentation:
//
//	Once you are inside a chat room you can invite other people into that room.
//	Remember to quote and encode the invite message.
//
// Command syntax: toc_chat_invite <Chat Room ID> <Invite Msg> <buddy1> [<buddy2> [<buddy3> [...]]]
func (s OSCARProxy) ChatInvite(ctx context.Context, me *state.SessionInstance, chatRegistry *ChatRegistry, args []byte) []string {
	var chatRoomIDStr, msg string

	users, err := parseArgs(args, &chatRoomIDStr, &msg)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	msg = unescape(msg)

	chatID, err := strconv.Atoi(chatRoomIDStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	roomInfo, found := chatRegistry.LookupRoom(chatID)
	if !found {
		return s.runtimeErr(ctx, fmt.Errorf("chatRegistry.LookupRoom: chat ID `%d` not found", chatID))
	}

	for _, guest := range users {
		if msg, isLimited := s.checkRateLimit(ctx, me, wire.ICBM, wire.ICBMChannelMsgToHost); isLimited {
			return msg
		}

		snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
			ChannelID:  wire.ICBMChannelRendezvous,
			ScreenName: guest,
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
						Type:       wire.ICBMRdvMessagePropose,
						Capability: wire.CapChat,
						TLVRestBlock: wire.TLVRestBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.ICBMRdvTLVTagsSeqNum, uint16(1)),
								wire.NewTLVBE(wire.ICBMRdvTLVTagsInvitation, msg),
								wire.NewTLVBE(wire.ICBMRdvTLVTagsInviteMIMECharset, "us-ascii"),
								wire.NewTLVBE(wire.ICBMRdvTLVTagsInviteMIMELang, "en"),
								wire.NewTLVBE(wire.ICBMRdvTLVTagsSvcData, roomInfo),
							},
						},
					}),
				},
			},
		}

		if _, err := s.ICBMService.ChannelMsgToHost(ctx, me, wire.SNACFrame{}, snac); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("ICBMService.ChannelMsgToHost: %w", err))
		}
	}

	return []string{}
}

// ChatJoin handles the toc_chat_join TOC command.
//
// From the TiK documentation:
//
//	Join a chat room in the given exchange. Exchange is an integer that
//	represents a group of chat rooms. Different exchanges have different
//	properties. For example some exchanges might have room replication (ie a
//	room never fills up, there are just multiple instances.) and some exchanges
//	might have navigational information. Currently, exchange should always be
//	4, however this may change in the future. You will either receive an ERROR
//	if the room couldn't be joined or a CHAT_JOIN message. The Chat Room Name
//	is case-insensitive and consecutive spaces are removed.
//
// Command syntax: toc_chat_join <Exchange> <Chat Room Name>
func (s OSCARProxy) ChatJoin(
	ctx context.Context,
	me *state.SessionInstance,
	chatRegistry *ChatRegistry,
	args []byte,
) (int, []string) {
	var exchangeStr, roomName string

	if _, err := parseArgs(args, &exchangeStr, &roomName); err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	roomName = unescape(roomName)

	// create room or retrieve the room if it already exists
	exchange, err := strconv.Atoi(exchangeStr)
	if err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	if msg, isLimited := s.checkRateLimit(ctx, me, wire.Chat, wire.ChatRoomInfoUpdate); isLimited {
		return 0, msg
	}

	mkRoomReq := wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
		Exchange: uint16(exchange),
		Cookie:   "create",
		TLVBlock: wire.TLVBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ChatRoomTLVRoomName, roomName),
			},
		},
	}
	mkRoomReply, err := s.ChatNavService.CreateRoom(ctx, me, wire.SNACFrame{}, mkRoomReq)
	if err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("ChatNavService.CreateRoom: %w", err))
	}

	mkRoomReplyBody, ok := mkRoomReply.Body.(wire.SNAC_0x0D_0x09_ChatNavNavInfo)
	if !ok {
		return 0, s.runtimeErr(
			ctx,
			fmt.Errorf("chatNavService.CreateRoom: unexpected response type %v", mkRoomReplyBody),
		)
	}
	buf, ok := mkRoomReplyBody.Bytes(wire.ChatNavTLVRoomInfo)
	if !ok {
		return 0, s.runtimeErr(ctx, errors.New("mkRoomReplyBody.Bytes: missing wire.ChatNavTLVRoomInfo"))
	}

	inBody := wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{}
	if err := wire.UnmarshalBE(&inBody, bytes.NewReader(buf)); err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalBE: %w", err))
	}

	if msg, isLimited := s.checkRateLimit(ctx, me, wire.OService, wire.OServiceServiceRequest); isLimited {
		return 0, msg
	}

	svcReqSNAC := wire.SNAC_0x01_0x04_OServiceServiceRequest{
		FoodGroup: wire.Chat,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{
					Cookie: inBody.Cookie,
				}),
			},
		},
	}
	svcReqReply, err := s.OServiceService.ServiceRequest(ctx, wire.BOS, me, wire.SNACFrame{}, svcReqSNAC, config.Listener{})
	if err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("OServiceServiceBOS.ServiceRequest: %w", err))
	}

	svcReqReplyBody, ok := svcReqReply.Body.(wire.SNAC_0x01_0x05_OServiceServiceResponse)
	if !ok {
		return 0, s.runtimeErr(
			ctx,
			fmt.Errorf("OServiceServiceBOS.ServiceRequest: unexpected response type %v", svcReqReplyBody),
		)
	}

	loginCookie, hasCookie := svcReqReplyBody.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !hasCookie {
		return 0, s.runtimeErr(ctx, errors.New("svcReqReplyBody.Bytes: missing wire.OServiceTLVTagsLoginCookie"))
	}

	// todo: naming for cookie: login cookie, server cookie, or auth cookie?
	serverCookie, err := s.AuthService.CrackCookie(loginCookie)
	if err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("AuthService.CrackCookie: %w", err))
	}

	sessCfg := func(sess *state.Session) {
		sess.OnSessionClose(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			s.AuthService.SignoutChat(ctx, sess)
		})
	}
	chatSess, err := s.AuthService.RegisterChatSession(ctx, serverCookie, sessCfg)
	if err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("AuthService.RegisterChatSession: %w", err))
	}

	if msg, isLimited := s.checkRateLimit(ctx, me, wire.OService, wire.OServiceClientOnline); isLimited {
		return 0, msg
	}

	if err := s.OServiceService.ClientOnline(ctx, wire.Chat, wire.SNAC_0x01_0x02_OServiceClientOnline{}, chatSess); err != nil {
		return 0, s.runtimeErr(ctx, fmt.Errorf("OServiceServiceChat.ClientOnline: %w", err))
	}

	roomInfo := wire.ICBMRoomInfo{
		Exchange: inBody.Exchange,
		Cookie:   inBody.Cookie,
		Instance: inBody.InstanceNumber,
	}
	chatID := chatRegistry.Add(roomInfo)
	chatRegistry.RegisterSess(chatID, chatSess)
	if me.IsTOC2() {
		chatSess.SetTOC2(me.SupportsTOC2MsgEnc())
	}

	return chatID, []string{fmt.Sprintf("CHAT_JOIN:%d:%s", chatID, roomName)}
}

// ChatLeave handles the toc_chat_leave TOC command.
//
// From the TiK documentation:
//
//	Leave the chat room.
//
// Command syntax: toc_chat_leave <Chat Room ID>
func (s OSCARProxy) ChatLeave(ctx context.Context, chatRegistry *ChatRegistry, args []byte) []string {
	var chatIDStr string

	if _, err := parseArgs(args, &chatIDStr); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	chatID, err := strconv.Atoi(chatIDStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	me := chatRegistry.RetrieveSess(chatID)
	if me == nil {
		return s.runtimeErr(ctx, fmt.Errorf("chatRegistry.RetrieveSess: chat session `%d` not found", chatID))
	}

	me.CloseInstance() // stop async server SNAC reply handler for this chat room

	chatRegistry.RemoveSess(chatID)

	return []string{fmt.Sprintf("CHAT_LEFT:%d", chatID)}
}

// ChatSend handles the toc_chat_send TOC command.
//
// From the TiK documentation:
//
//	Send a message in a chat room using the chat room id from CHAT_JOIN. Since
//	reflection is always on in TOC, you do not need to add the message to your
//	chat UI, since you will get a CHAT_IN with the message. Remember to quote
//	and encode the message.
//
// Command syntax: toc_chat_send <Chat Room ID> <Message>
func (s OSCARProxy) ChatSend(ctx context.Context, chatRegistry *ChatRegistry, args []byte) []string {
	var chatIDStr, msg string

	if _, err := parseArgs(args, &chatIDStr, &msg); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	msg = unescape(msg)

	chatID, err := strconv.Atoi(chatIDStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	me := chatRegistry.RetrieveSess(chatID)
	if me == nil {
		return s.runtimeErr(ctx, fmt.Errorf("chatRegistry.RetrieveSess: session for chat ID `%d` not found", chatID))
	}

	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Chat, wire.ChatChannelMsgToHost); isLimited {
		return errMsg
	}

	block := wire.TLVRestBlock{}
	// the order of these TLVs matters for AIM 2.x. if out of order, screen
	// names do not appear with each chat message.
	block.Append(wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, uint8(1)))
	block.Append(wire.NewTLVBE(wire.ChatTLVSenderInformation, me.Session().TLVUserInfo()))
	block.Append(wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}))
	block.Append(wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
		TLVList: wire.TLVList{
			wire.NewTLVBE(wire.ChatTLVMessageInfoText, msg),
		},
	}))

	snac := wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
		Channel:      wire.ICBMChannelMIME,
		TLVRestBlock: block,
	}
	reply, err := s.ChatService.ChannelMsgToHost(ctx, me, wire.SNACFrame{}, snac)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("ChatService.ChannelMsgToHost: %w", err))
	}

	if reply == nil {
		return s.runtimeErr(ctx, errors.New("ChatService.ChannelMsgToHost: missing response "))
	}

	switch v := reply.Body.(type) {
	case wire.SNAC_0x0E_0x06_ChatChannelMsgToClient:
		msgInfo, ok := v.Bytes(wire.ChatTLVMessageInfo)
		if !ok {
			return s.runtimeErr(ctx, errors.New("ChatService.ChannelMsgToHost: missing wire.ChatTLVMessageInfo"))
		}
		reflectMsg, err := wire.UnmarshalChatMessageText(msgInfo)
		if err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalChatMessageText: %w", err))
		}

		senderInfo, ok := v.Bytes(wire.ChatTLVSenderInformation)
		if !ok {
			return s.runtimeErr(ctx, errors.New("ChatService.ChannelMsgToHost: missing wire.ChatTLVSenderInformation"))
		}

		var userInfo wire.TLVUserInfo
		if err := wire.UnmarshalBE(&userInfo, bytes.NewReader(senderInfo)); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalBE: %w", err))
		}

		if me.SupportsTOC2MsgEnc() {
			return []string{fmt.Sprintf("CHAT_IN_ENC:%d:%s:F:A:en:%s", chatID, userInfo.ScreenName, reflectMsg)}
		}

		return []string{fmt.Sprintf("CHAT_IN:%d:%s:F:%s", chatID, userInfo.ScreenName, reflectMsg)}
	default:
		return s.runtimeErr(ctx, errors.New("ChatService.ChannelMsgToHost: unexpected response"))
	}
}

// ChatWhisper handles the toc_chat_whisper TOC command.
//
// From the TiK documentation:
//
//	Send a message in a chat room using the chat room id from CHAT_JOIN.
//	This message is directed at only one person. (Currently you DO need to add
//	this to your UI.) Remember to quote and encode the message. Chat whispering
//	is different from IMs since it is linked to a chat room, and should usually
//	be displayed in the chat room UI.
//
// Command syntax: toc_chat_whisper <Chat Room ID> <dst_user> <Message>
func (s OSCARProxy) ChatWhisper(ctx context.Context, chatRegistry *ChatRegistry, args []byte) []string {
	var chatIDStr, recip, msg string

	if _, err := parseArgs(args, &chatIDStr, &recip, &msg); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	msg = unescape(msg)

	chatID, err := strconv.Atoi(chatIDStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	me := chatRegistry.RetrieveSess(chatID)
	if me == nil {
		return s.runtimeErr(ctx, fmt.Errorf("chatRegistry.RetrieveSess: session for chat ID `%d` not found", chatID))
	}

	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Chat, wire.ChatChannelMsgToHost); isLimited {
		return errMsg
	}

	block := wire.TLVRestBlock{}
	block.Append(wire.NewTLVBE(wire.ChatTLVSenderInformation, me.Session().TLVUserInfo()))
	block.Append(wire.NewTLVBE(wire.ChatTLVWhisperToUser, recip))
	block.Append(wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
		TLVList: wire.TLVList{
			wire.NewTLVBE(wire.ChatTLVMessageInfoText, msg),
		},
	}))

	snac := wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
		Channel:      wire.ICBMChannelMIME,
		TLVRestBlock: block,
	}
	if _, err = s.ChatService.ChannelMsgToHost(ctx, me, wire.SNACFrame{}, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("ChatService.ChannelMsgToHost: %w", err))
	}

	return []string{}
}

// Evil handles the toc_evil TOC command.
//
// From the TiK documentation:
//
//	Evil/Warn someone else. The 2nd argument is either the string "norm" for a
//	normal warning, or "anon" for an anonymous warning. You can only evil
//	people who have recently sent you ims. The higher someones evil level, the
//	slower they can send message.
//
// An ERROR message will be sent back to the client if the warning was unsuccessful.
//
// Command syntax: toc_evil <User> <norm|anon>
func (s OSCARProxy) Evil(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.ICBM, wire.ICBMEvilRequest); isLimited {
		return errMsg
	}

	var user, scope string

	if _, err := parseArgs(args, &user, &scope); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	snac := wire.SNAC_0x04_0x08_ICBMEvilRequest{
		ScreenName: user,
	}

	switch scope {
	case "anon":
		snac.SendAs = 1
	case "norm":
		snac.SendAs = 0
	default:
		return s.runtimeErr(ctx, fmt.Errorf("incorrect warning type `%s`. allowed values: anon, norm", scope))
	}

	response, err := s.ICBMService.EvilRequest(ctx, me, wire.SNACFrame{}, snac)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("ICBMService.EvilRequest: %w", err))
	}

	switch v := response.Body.(type) {
	case wire.SNAC_0x04_0x09_ICBMEvilReply:
		return []string{}
	case wire.SNACError:
		s.Logger.InfoContext(ctx, "unable to warn user", "code", v.Code)
		return []string{"ERROR:" + wire.TOCErrorGeneralWarningUserNotAvailable}
	default:
		return s.runtimeErr(ctx, errors.New("unexpected response"))
	}
}

// FormatNickname handles the toc_format_nickname TOC command.
//
// From the TiK documentation:
//
//	Reformat a user's nickname. An ADMIN_NICK_STATUS or ERROR message will be
//	sent back to the client.
//
// From the BizTOCSock documentation:
//
//	[NICK is also sent with ADMIN_NICK_STATUS. This gets called [...] whenever
//	you do a format change.
//
// Command syntax: toc_format_nickname <new_format>
func (s OSCARProxy) FormatNickname(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Admin, wire.AdminInfoChangeRequest); isLimited {
		return errMsg
	}

	var newFormat string

	if _, err := parseArgs(args, &newFormat); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	// remove curly braces added by TiK
	newFormat = strings.Trim(newFormat, "{}")

	reqSNAC := wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, newFormat),
			},
		},
	}

	reply, err := s.AdminService.InfoChangeRequest(ctx, me, wire.SNACFrame{}, reqSNAC)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("AdminService.InfoChangeRequest: %w", err))
	}

	replyBody, ok := reply.Body.(wire.SNAC_0x07_0x05_AdminChangeReply)
	if !ok {
		return s.runtimeErr(ctx, fmt.Errorf("AdminService.InfoChangeRequest: unexpected response type %v", replyBody))
	}

	code, ok := replyBody.Uint16BE(wire.AdminTLVErrorCode)
	if ok {
		switch code {
		case wire.AdminInfoErrorInvalidNickNameLength, wire.AdminInfoErrorInvalidNickName:
			return []string{"ERROR:" + wire.TOCErrorAdminInvalidInput}
		default:
			return []string{"ERROR:" + wire.TOCErrorAdminProcessingRequest}
		}
	}
	val, hasVal := replyBody.TLVBlock.String(wire.AdminTLVScreenNameFormatted)
	if !hasVal {
		return s.runtimeErr(ctx, fmt.Errorf("AdminService.InfoChangeRequest: missing AdminTLVScreenNameFormatted %v", replyBody))
	}

	return []string{"ADMIN_NICK_STATUS:0", "NICK:" + val}
}

// GetDirSearchURL handles the toc_dir_search TOC command.
//
// From the TiK documentation:
//
//	Perform a search of the Oscar Directory, using colon separated fields as in:
//
//		"first name":"middle name":"last name":"maiden name":"city":"state":"country":"email"
//
// You can search by keyword by setting search terms in the 11th position (this
// feature is not in the TiK docs but is present in the code):
//
//	::::::::::"search kw"
//
//	Returns either a GOTO_URL or ERROR msg.
//
// Command syntax: toc_dir_search <info information>
func (s OSCARProxy) GetDirSearchURL(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if status := me.Session().EvaluateRateLimit(time.Now(), 1); status == wire.RateLimitStatusLimited {
		return []string{rateLimitExceededErr}
	}

	var info string

	if _, err := parseArgs(args, &info); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	info = unescape(info)

	params := strings.Split(info, ":")
	labels := []string{
		"first_name",
		"middle_name",
		"last_name",
		"maiden_name",
		"city",
		"state",
		"country",
		"email",
		"nop", // unused placeholder
		"nop",
		"keyword",
	}

	// map labels to param values at their corresponding positions
	p := url.Values{}
	for i, param := range params {
		if i >= len(labels) {
			break
		}
		if param != "" {
			p.Add(labels[i], strings.Trim(param, "\""))
		}
	}

	if len(p) == 0 {
		return s.runtimeErr(ctx, errors.New("no search fields found"))
	}

	cookie, err := s.newHTTPAuthToken(me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("newHTTPAuthToken: %w", err))
	}
	p.Add("cookie", cookie)

	return []string{fmt.Sprintf("GOTO_URL:search results:dir_search?%s", p.Encode())}
}

// GetDirURL handles the toc_get_dir TOC command.
//
// From the TiK documentation:
//
//	Gets a user's dir info a GOTO_URL or ERROR message will be sent back to the client.
//
// Command syntax: toc_get_dir <username>
func (s OSCARProxy) GetDirURL(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if status := me.Session().EvaluateRateLimit(time.Now(), 1); status == wire.RateLimitStatusLimited {
		return []string{rateLimitExceededErr}
	}

	var user string

	if _, err := parseArgs(args, &user); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	cookie, err := s.newHTTPAuthToken(me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("newHTTPAuthToken: %w", err))
	}

	p := url.Values{}
	p.Add("cookie", cookie)
	p.Add("user", user)

	return []string{fmt.Sprintf("GOTO_URL:directory info:dir_info?%s", p.Encode())}
}

// GetInfoURL handles the toc_get_info TOC command.
//
// From the TiK documentation:
//
//	Gets a user's info a GOTO_URL or ERROR message will be sent back to the client.
//
// Command syntax: toc_get_info <username>
func (s OSCARProxy) GetInfoURL(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if status := me.Session().EvaluateRateLimit(time.Now(), 1); status == wire.RateLimitStatusLimited {
		return []string{rateLimitExceededErr}
	}

	var user string

	if _, err := parseArgs(args, &user); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	cookie, err := s.newHTTPAuthToken(me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("newHTTPAuthToken: %w", err))
	}

	p := url.Values{}
	p.Add("cookie", cookie)
	p.Add("from", me.IdentScreenName().String())
	p.Add("user", user)

	return []string{fmt.Sprintf("GOTO_URL:profile:info?%s", p.Encode())}
}

// GetStatus handles the toc_get_status TOC command.
//
// From the BlueTOC documentation:
//
//	This useful command wasn't ever really documented. It returns either an
//	UPDATE_BUDDY message or an ERROR message depending on whether or not the
//	guy appears to be online. The command is used in both TOC1 and TOC2 with
//	the same syntax.
//
// Command syntax: toc_get_status <screenname>
func (s OSCARProxy) GetStatus(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Locate, wire.LocateUserInfoQuery); isLimited {
		return errMsg
	}

	var them string

	if _, err := parseArgs(args, &them); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	inBody := wire.SNAC_0x02_0x05_LocateUserInfoQuery{
		ScreenName: them,
	}

	info, err := s.LocateService.UserInfoQuery(ctx, me, wire.SNACFrame{}, inBody)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("LocateService.UserInfoQuery: %w", err))
	}

	switch v := info.Body.(type) {
	case wire.SNACError:
		if v.Code == wire.ErrorCodeNotLoggedOn {
			return []string{fmt.Sprintf("ERROR:%s:%s", wire.TOCErrorGeneralUserNotAvailable, them)}
		} else {
			return s.runtimeErr(ctx, fmt.Errorf("LocateService.UserInfoQuery error code: %d", v.Code))
		}
	case wire.SNAC_0x02_0x06_LocateUserInfoReply:
		return []string{userInfoToUpdateBuddy(v.TLVUserInfo, me)}
	default:
		return s.runtimeErr(ctx, fmt.Errorf("AdminService.InfoChangeRequest: unexpected response type %v", v))
	}
}

// InitDone handles the toc_init_done TOC command.
//
// From the TiK documentation:
//
//	Tells TOC that we are ready to go online. TOC clients should first send TOC
//	the buddy list and any permit/deny lists. However, toc_init_done must be
//	called within 30 seconds after toc_signon, or the connection will be
//	dropped. Remember, it can't be called until after the SIGN_ON message is
//	received. Calling this before or multiple times after a SIGN_ON will cause
//	the connection to be dropped.
//
// Note: The business logic described in the last 3 sentences are not yet
// implemented.
//
// Command syntax: toc_init_done
func (s OSCARProxy) InitDone(ctx context.Context, instance *state.SessionInstance) []string {
	err := s.FeedbagManager.UseFeedbag(ctx, instance.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.UseFeedbag: %w", err))
	}
	if errMsg, isLimited := s.checkRateLimit(ctx, instance, wire.OService, wire.OServiceClientOnline); isLimited {
		return errMsg
	}
	if err := s.OServiceService.ClientOnline(ctx, wire.BOS, wire.SNAC_0x01_0x02_OServiceClientOnline{}, instance); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("OServiceServiceBOS.ClientOnliney: %w", err))
	}
	return []string{}
}

// RemoveBuddy handles the toc_remove_buddy TOC command.
//
// From the TiK documentation:
//
//	Remove buddies from your buddy list. This does not change your saved config.
//
// Command syntax: toc_remove_buddy <Buddy User 1> [<Buddy User2> [<Buddy User 3> [...]]]
func (s OSCARProxy) RemoveBuddy(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Buddy, wire.BuddyDelBuddies); isLimited {
		return errMsg
	}

	users, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	snac := wire.SNAC_0x03_0x05_BuddyDelBuddies{}
	for _, sn := range users {
		snac.Buddies = append(snac.Buddies, struct {
			ScreenName string `oscar:"len_prefix=uint8"`
		}{ScreenName: sn})
	}

	if err := s.BuddyService.DelBuddies(ctx, me, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("BuddyService.DelBuddies: %w", err))
	}
	return []string{}
}

// RvousAccept handles the toc_rvous_accept TOC command.
//
// From the TiK documentation:
//
//	Accept a rendezvous proposal from the user <nick>. <cookie> is the cookie
//	from the RVOUS_PROPOSE message. <service> is the UUID the proposal was for.
//	<tlvlist> contains a list of tlv tags followed by base64 encoded values.
//
// Note: This method does not actually process the TLV list param, as it's not
// passed in the TiK client, the reference implementation.
//
// Command syntax: toc_rvous_accept <nick> <cookie> <service>
func (s OSCARProxy) RvousAccept(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.ICBM, wire.ICBMChannelMsgToHost); isLimited {
		return errMsg
	}

	var nick, cookie, service string

	if _, err := parseArgs(args, &nick, &cookie, &service); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	cbytes, err := base64.StdEncoding.DecodeString(cookie)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("base64.Decode: %w", err))
	}

	var arr [8]byte
	copy(arr[:], cbytes) // copy slice into array

	svcUUID, err := uuid.Parse(service)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("uuid.Parse: %w", err))
	}

	snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		ChannelID:  wire.ICBMChannelRendezvous,
		ScreenName: nick,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
					Type:       wire.ICBMRdvMessageAccept,
					Cookie:     arr,
					Capability: svcUUID,
				}),
			},
		},
	}

	if _, err = s.ICBMService.ChannelMsgToHost(ctx, me, wire.SNACFrame{}, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("ICBMService.ChannelMsgToHost: %w", err))
	}

	return []string{}
}

// RvousCancel handles the toc_rvous_cancel TOC command.
//
// From the TiK documentation:
//
//	Cancel a rendezvous proposal from the user <nick>. <cookie> is the cookie
//	from the RVOUS_PROPOSE message. <service> is the UUID the proposal was for.
//	<tlvlist> contains a list of tlv tags followed by base64 encoded values.
//
// Note: This method does not actually process the TLV list param, as it's not
// passed in the TiK client, the reference implementation.
//
// Command syntax: toc_rvous_cancel <nick> <cookie> <service>
func (s OSCARProxy) RvousCancel(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.ICBM, wire.ICBMChannelMsgToHost); isLimited {
		return errMsg
	}

	var nick, cookie, service string

	if _, err := parseArgs(args, &nick, &cookie, &service); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	cbytes, err := base64.StdEncoding.DecodeString(cookie)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("base64.Decode: %w", err))
	}

	var arr [8]byte
	copy(arr[:], cbytes) // copy slice into array

	svcUUID, err := uuid.Parse(service)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("uuid.Parse: %w", err))
	}

	snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		ChannelID:  wire.ICBMChannelRendezvous,
		ScreenName: nick,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
					Type:       wire.ICBMRdvMessageCancel,
					Cookie:     arr,
					Capability: svcUUID,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICBMRdvTLVTagsCancelReason, wire.ICBMRdvCancelReasonsUserCancel),
						},
					},
				}),
			},
		},
	}

	if _, err = s.ICBMService.ChannelMsgToHost(ctx, me, wire.SNACFrame{}, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("ICBMService.ChannelMsgToHost: %w", err))
	}

	return []string{}
}

// SetPDMode handles the toc2_set_pdmode TOC2 command.
//
// From the BlueTOC documentation:
//
//	Set permit/deny mode. Value: 1 = Allow all (default), 2 = Block all,
//	3 = Allow "permit group" only, 4 = Block "deny group" only, 5 = Allow buddy list only.
//
// Command syntax: toc2_set_pdmode <mode>
func (s OSCARProxy) SetPDMode(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.OService, wire.FeedbagInsertItem); isLimited {
		return errMsg
	}

	var pdModeStr string

	if _, err := parseArgs(args, &pdModeStr); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	mode, err := strconv.Atoi(pdModeStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	if mode < 1 || mode > 5 {
		return s.runtimeErr(ctx, errors.New("invalid pd mode specified"))
	}

	fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.Feedbag: %w", err))
	}

	fl := newFeedbagList(fb, s.RandIntn)
	fl.SetMode(uint8(mode))

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := s.FeedbagService.UpsertItem(ctx, me, frame, pending); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.UpsertItem: %w", err))
		}
	}

	return []string{}
}

// NewGroup handles the toc2_new_group TOC2 command.
//
// From the TOC2 docs by Jeffrey Rosen:
//
//	This is an entirely new command that allows you to add groups. These should be
//	quoted and you can't add more than one per command.
//
// Command syntax: toc2_new_group <group>
func (s OSCARProxy) NewGroup(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Feedbag, wire.FeedbagInsertItem); isLimited {
		return errMsg
	}

	var groupName string
	if _, err := parseArgs(args, &groupName); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	groupName = unescape(groupName)

	if groupName == "" {
		return s.runtimeErr(ctx, fmt.Errorf("empty group name"))
	}

	fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.Feedbag: %w", err))
	}

	fl := newFeedbagList(fb, s.RandIntn)
	fl.AddGroup(groupName)

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := s.FeedbagService.UpsertItem(ctx, me, frame, pending); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.UpsertItem: %w", err))
		}
	}

	return []string{}
}

// DelGroup handles the toc2_del_group TOC2 command.
//
// From the TOC2 docs by Jeffrey Rosen:
//
//	Delete a group.
//
// Command syntax: toc2_del_group <group>
func (s OSCARProxy) DelGroup(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Feedbag, wire.FeedbagDeleteItem); isLimited {
		return errMsg
	}

	var groupName string
	if _, err := parseArgs(args, &groupName); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	groupName = unescape(groupName)

	if groupName == "" {
		return s.runtimeErr(ctx, fmt.Errorf("empty group name"))
	}

	fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.Feedbag: %w", err))
	}

	fl := newFeedbagList(fb, s.RandIntn)
	fl.DeleteGroup(groupName)

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		deleteItem := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
			Items: pending,
		}
		if _, err := s.FeedbagService.DeleteItem(ctx, me, wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem}, deleteItem); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.DeleteItem: %w", err))
		}
	} else {
		return s.runtimeErr(ctx, fmt.Errorf("group not found: %s", groupName))
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := s.FeedbagService.UpsertItem(ctx, me, frame, pending); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.UpsertItem: %w", err))
		}
	}

	return []string{}
}

// NewBuddies handles the toc2_new_buddies TOC2 command.
//
// From the TOC2 docs by Jeffrey Rosen:
//
//	In TOC2.0, you must add buddies in "config format". If you sent that with the
//	toc2_new_buddies command, you would add the three buddies (buddytest,
//	buddytest2, and buddytest3) into the group "test". Note that if the group
//	doesn't already exist, it will be created.
//
// Config format: {g:group<lf>b:buddy1<lf>b:buddy2<lf>}
// Where <lf> is a linefeed character (ASCII 10).
//
// Command syntax: toc2_new_buddies <config format>
func (s OSCARProxy) NewBuddies(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Feedbag, wire.FeedbagInsertItem); isLimited {
		return errMsg
	}

	// Parse config string (handle quotes, unescape)
	configStr := string(args)
	configStr = strings.Trim(configStr, "'\" ")
	configStr = unescape(configStr)

	if configStr == "" {
		return s.runtimeErr(ctx, fmt.Errorf("empty config"))
	}

	// Parse config format
	groups, err := parseTOC2Config(configStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseTOC2Config: %w", err))
	}

	fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.Feedbag: %w", err))
	}

	fl := newFeedbagList(fb, s.RandIntn)

	var replies []string

	// Process each group in config (deterministic order so tests and root Order are stable)
	groupNames := make([]string, 0, len(groups))
	for k := range groups {
		groupNames = append(groupNames, k)
	}
	sort.Strings(groupNames)

	for _, groupName := range groupNames {
		buddies := groups[groupName]

		fl.AddGroup(groupName)

		for _, buddy := range buddies {
			// Parse buddy entry (may contain alias/note: b:buddy:alias:::::note)
			parts := strings.Split(buddy, ":")
			buddyName := parts[0]
			if buddyName == "" {
				continue
			}

			var alias, note string
			if len(parts) > 1 {
				alias = parts[1]
			}
			if len(parts) > 6 {
				note = parts[6]
			}
			inserted, err := fl.AddBuddy(groupName, buddyName, alias, note)
			if err != nil {
				return s.runtimeErr(ctx, fmt.Errorf("fl.AddBuddy: %w", err))
			}
			if inserted {
				replies = append(replies, fmt.Sprintf("NEW_BUDDY_REPLY2:%s:added", buddyName))
			}
		}
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {

		buddyItems := make(map[uint16][]wire.FeedbagItem)
		for _, item := range pending {
			if item.ClassID == wire.FeedbagClassIdBuddy {
				if _, ok := buddyItems[item.GroupID]; !ok {
					buddyItems[item.GroupID] = nil
				}
				buddyItems[item.GroupID] = append(buddyItems[item.GroupID], item)
			}
		}

		if len(buddyItems) == 0 {
			return replies
		}

		for _, item := range pending {
			if item.ClassID == wire.FeedbagClassIdGroup {
				frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
				if _, err := s.FeedbagService.UpsertItem(ctx, me, frame, []wire.FeedbagItem{item}); err != nil {
					return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.UpsertItem: %w", err))
				}
			}
		}

		for _, buddies := range buddyItems {
			frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
			if _, err := s.FeedbagService.UpsertItem(ctx, me, frame, buddies); err != nil {
				return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.UpsertItem: %w", err))
			}
		}
	}

	return replies
}

// RemoveBuddy2 handles the toc2_remove_buddy command.
//
// From the TOC2 docs by Jeffrey Rosen:
//
//	You can remove multiple names in the same group using the syntax <screenname> <screenname> <group>.
//
// Command syntax: toc2_remove_buddy <screenname> [screenname] ... [screenname] <group>
func (s OSCARProxy) RemoveBuddy2(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Feedbag, wire.FeedbagDeleteItem); isLimited {
		return errMsg
	}

	params, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	if len(params) < 2 {
		return s.runtimeErr(ctx, fmt.Errorf("missing params: need at least one screenname and group"))
	}

	fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.Feedbag: %w", err))
	}

	fl := newFeedbagList(fb, s.RandIntn)

	groupName := params[len(params)-1]
	screenNames := params[:len(params)-1]
	for _, buddyName := range screenNames {
		if err := fl.DeleteBuddy(groupName, buddyName); err != nil {
			return s.runtimeErr(ctx, err)
		}
	}

	// ensure to delete buddies before groups to ensure they correctly propagate
	// to concurrent sessions
	if pending := fl.PendingDeletes(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem}
		deleteItem := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
			Items: pending,
		}
		if _, err := s.FeedbagService.DeleteItem(ctx, me, frame, deleteItem); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.DeleteItem: %w", err))
		}
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem}
		if _, err := s.FeedbagService.UpsertItem(ctx, me, frame, pending); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.UpsertItem: %w", err))
		}
	}

	return []string{}
}

// AddPermit2 handles the toc2_add_permit TOC2 command.
//
// From the TOC2 docs by Jeffrey Rosen:
//
//	Add user(s) to permit list. <screenname> should be normalized and you can add
//	multiple people at a time by separating the screennames with a space.
//
// Command syntax: toc2_add_permit <screenname> [screenname] ...
func (s OSCARProxy) AddPermit2(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Feedbag, wire.FeedbagInsertItem); isLimited {
		return errMsg
	}

	screenNames, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	if len(screenNames) == 0 {
		return s.runtimeErr(ctx, fmt.Errorf("no screennames provided"))
	}

	fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.Feedbag: %w", err))
	}

	fl := newFeedbagList(fb, s.RandIntn)

	for _, sn := range screenNames {
		fl.PermitUser(sn)
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := s.FeedbagService.UpsertItem(ctx, me, frame, pending); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.UpsertItem: %w", err))
		}
	}

	return []string{}
}

// RemovePermit2 handles the toc2_remove_permit TOC2 command.
//
// From the TOC2 docs by Jeffrey Rosen:
//
//	Remove user(s) from permit list. <screenname> should be normalized and you can
//	remove multiple people at a time by separating the screennames with a space.
//
// Command syntax: toc2_remove_permit <screenname> [screenname] ...
func (s OSCARProxy) RemovePermit2(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Feedbag, wire.FeedbagDeleteItem); isLimited {
		return errMsg
	}

	screenNames, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	if len(screenNames) == 0 {
		return s.runtimeErr(ctx, fmt.Errorf("no screennames provided"))
	}

	fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.Feedbag: %w", err))
	}

	fl := newFeedbagList(fb, s.RandIntn)

	for _, sn := range screenNames {
		fl.DeletePermit(sn)
	}

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		deleteItem := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
			Items: pending,
		}
		if _, err := s.FeedbagService.DeleteItem(ctx, me, wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem}, deleteItem); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.DeleteItem: %w", err))
		}
	}

	return []string{}
}

// AddDeny2 handles the toc2_add_deny TOC2 command.
//
// From the TOC2 docs by Jeffrey Rosen:
//
//	Add user(s) to deny list. <screenname> should be normalized and you can add
//	multiple people at a time by separating the screennames with a space.
//
// Command syntax: toc2_add_deny <screenname> [screenname] ...
func (s OSCARProxy) AddDeny2(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Feedbag, wire.FeedbagInsertItem); isLimited {
		return errMsg
	}

	screenNames, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	if len(screenNames) == 0 {
		return s.runtimeErr(ctx, fmt.Errorf("no screennames provided"))
	}

	fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.Feedbag: %w", err))
	}

	fl := newFeedbagList(fb, s.RandIntn)

	for _, sn := range screenNames {
		fl.DenyUser(sn)
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		frame := wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem}
		if _, err := s.FeedbagService.UpsertItem(ctx, me, frame, pending); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.UpsertItem: %w", err))
		}
	}

	return []string{}
}

// RemoveDeny2 handles the toc2_remove_deny TOC2 command.
//
// From the TOC2 docs by Jeffrey Rosen:
//
//	Remove user(s) from deny list. <screenname> should be normalized and you can
//	remove multiple people at a time by separating the screennames with a space.
//
// Command syntax: toc2_remove_deny <screenname> [screenname] ...
func (s OSCARProxy) RemoveDeny2(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Feedbag, wire.FeedbagDeleteItem); isLimited {
		return errMsg
	}

	screenNames, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	if len(screenNames) == 0 {
		return s.runtimeErr(ctx, fmt.Errorf("no screennames provided"))
	}

	fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.Feedbag: %w", err))
	}

	fl := newFeedbagList(fb, s.RandIntn)

	for _, sn := range screenNames {
		fl.DeleteDeny(sn)
	}

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		deleteItem := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
			Items: pending,
		}
		if _, err := s.FeedbagService.DeleteItem(ctx, me, wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem}, deleteItem); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("FeedbagService.DeleteItem: %w", err))
		}
	}

	return []string{}
}

// SendIMEnc handles the toc2_send_im_enc TOC2 command.
//
// From the BlueTOC source code:
//
//	Sends an encoded instant message to a user
//	Internally, this uses the "TOC3" encoded message format
//	This encoded message version supports a few more variables as well as encoding
//
// Command syntax: toc2_send_im_enc <Destination user> "F" <Encoding> <Language> <Message> [auto]
func (s OSCARProxy) SendIMEnc(ctx context.Context, sender *state.SessionInstance, args []byte) []string {
	if msg, isLimited := s.checkRateLimit(ctx, sender, wire.ICBM, wire.ICBMChannelMsgToHost); isLimited {
		return msg
	}

	var recip, unknown, enc, lang, msg string

	autoReply, err := parseArgs(args, &recip, &unknown, &enc, &lang, &msg)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	return s.sendIm(ctx, sender, msg, recip, autoReply)
}

// SendIM handles the toc_send_im and toc2_send_im TOC commands.
//
// From the TiK documentation (TOC1):
//
//	Send a message to a remote user. Remember to quote and encode the message.
//	If the optional string "auto" is the last argument, then the auto response
//	flag will be turned on for the IM.
//
// TOC2 uses the same syntax as TOC1 (BlueTOC documentation).
//
// Command syntax: toc_send_im <Destination User> <Message> [auto]
// Command syntax: toc2_send_im <user> <message> [auto]
func (s OSCARProxy) SendIM(ctx context.Context, sender *state.SessionInstance, args []byte) []string {
	if msg, isLimited := s.checkRateLimit(ctx, sender, wire.ICBM, wire.ICBMChannelMsgToHost); isLimited {
		return msg
	}

	var recip, msg string

	autoReply, err := parseArgs(args, &recip, &msg)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	return s.sendIm(ctx, sender, msg, recip, autoReply)
}

func (s OSCARProxy) sendIm(ctx context.Context, sender *state.SessionInstance, msg string, recip string, autoReply []string) []string {
	frags, err := wire.ICBMFragmentList(unescape(msg))
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("wire.ICBMFragmentList: %w", err))
	}

	snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: recip,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags),
			},
		},
	}

	if len(autoReply) > 0 && autoReply[0] == "auto" {
		snac.Append(wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}))
	}

	// send message and ignore response since there is no TOC error code to
	// handle errors such as "user is offline", etc.
	_, err = s.ICBMService.ChannelMsgToHost(ctx, sender, wire.SNACFrame{}, snac)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("ICBMService.ChannelMsgToHost: %w", err))
	}

	return []string{}
}

// SendClientEvent handles the toc2_client_event TOC2 command.
//
// From the BlueTOC documentation:
//
//	This is used to send a typing notification. Typing status: 0 for no activity,
//	1 for typing paused, 2 for currently typing.
//
// Command syntax: toc2_client_event <user> <typing status>
func (s OSCARProxy) SendClientEvent(ctx context.Context, sender *state.SessionInstance, args []byte) []string {
	if msg, isLimited := s.checkRateLimit(ctx, sender, wire.ICBM, wire.ICBMClientEvent); isLimited {
		return msg
	}

	var user, statusStr string
	if _, err := parseArgs(args, &user, &statusStr); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("SendClientEvent: invalid args: %w", err))
	}
	status, err := strconv.ParseUint(statusStr, 10, 16)
	if err != nil || status > 2 {
		return s.runtimeErr(ctx, fmt.Errorf("SendClientEvent: typing status must be 0, 1, or 2, got %q", statusStr))
	}
	inBody := wire.SNAC_0x04_0x14_ICBMClientEvent{
		Cookie:     0,
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: user,
		Event:      uint16(status),
	}
	if err := s.ICBMService.ClientEvent(ctx, sender, wire.SNACFrame{}, inBody); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("ICBMService.ClientEvent: %w", err))
	}
	return []string{}
}

// SetAway handles the toc_set_away TOC command.
//
// From the TiK documentation:
//
//	If the away message is present, then the unavailable status flag is set for
//	the user. If the away message is not present, then the unavailable status
//	flag is unset. The away message is basic HTML, remember to encode the
//	information.
//
// Command syntax: toc_set_away [<away message>]
func (s OSCARProxy) SetAway(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Locate, wire.LocateSetInfo); isLimited {
		return errMsg
	}

	maybeMsg, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	var msg string
	if len(maybeMsg) > 0 {
		msg = unescape(maybeMsg[0])
	}

	snac := wire.SNAC_0x02_0x04_LocateSetInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, msg),
			},
		},
	}

	if err := s.LocateService.SetInfo(ctx, me, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("LocateService.SetInfo: %w", err))
	}

	return []string{}
}

// SetCaps handles the toc_set_caps TOC command.
//
// From the TiK documentation:
//
//	Set my capabilities. All capabilities that we support need to be sent at
//	the same time. Capabilities are represented by UUIDs.
//
// This method automatically adds the "chat" capability since it doesn't seem
// to be sent explicitly by the official clients, even though they support
// chat.
//
// Command syntax: toc_set_caps [ <Capability 1> [<Capability 2> [...]]]
func (s OSCARProxy) SetCaps(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Locate, wire.LocateSetInfo); isLimited {
		return errMsg
	}

	params, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	// Clients may send capabilities as space-separated UUIDs or as a single
	// comma-separated string (e.g. TameClone: "UUID,1348,134B,..."). Split each
	// param on comma. Accept full UUIDs and OSCAR short caps (1–4 hex digits
	// expanded to 0946XXYY-4C7F-11D1-8222-444553540000); ignore unknown tokens.
	caps := make([]uuid.UUID, 0, 16)
	for _, param := range params {
		for _, token := range strings.Split(param, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			uid, err := uuid.Parse(token)
			if err != nil {
				uid, ok := wire.ShortCapHexToUUID(token)
				if !ok {
					continue
				}
				caps = append(caps, uid)
				continue
			}
			caps = append(caps, uid)
		}
	}
	// assume client supports chat, although we may want to do this according
	// to client ID
	caps = append(caps, wire.CapChat)

	snac := wire.SNAC_0x02_0x04_LocateSetInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, caps),
			},
		},
	}

	if err := s.LocateService.SetInfo(ctx, me, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("LocateService.SetInfo: %w", err))
	}

	return []string{}
}

// SetConfig handles the toc_set_config TOC command.
//
// From the TiK documentation:
//
//	Set the config information for this user. The config information is line
//	oriented with the first character being the item type, followed by a space,
//	with the rest of the line being the item value. Only letters, numbers, and
//	spaces should be used. Remember you will have to enclose the entire config
//	in quotes.
//
//	Item Types:
//		- g - Buddy Group (All Buddies until the next g or the end of config are in this group.)
//		- b - A Buddy
//		- p - Person on permit list
//		- d - Person on deny list
//		- m - Permit/Deny Mode. Possible values are
//		- 1 - Permit All
//		- 2 - Deny All
//		- 3 - Permit Some
//		- 4 - Deny Some
//
// This method doesn't attempt to validate any of the configuration--it saves
// the config as received from the client.
//
// Command syntax: toc_set_config <Config Info>
func (s OSCARProxy) SetConfig(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if status := me.Session().EvaluateRateLimit(time.Now(), 1); status == wire.RateLimitStatusLimited {
		return []string{rateLimitExceededErr}
	}

	// most TOC clients don't quote the config info argument, despite what the
	// documentation specifies. this makes the argument payload incompatible
	// for CSV parsing. since this command takes a single argument, we can get
	// away with trimming quotes and spaces from the byte slice before passing
	// it to the config store.
	args = bytes.Trim(args, "'\" ")

	cfg := string(args)
	if cfg == "" {
		return s.runtimeErr(ctx, fmt.Errorf("empty config"))
	}

	if err := s.TOCConfigStore.SetTOCConfig(ctx, me.IdentScreenName(), cfg); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("TOCConfigStore.SaveTOCConfig: %w", err))
	}

	return []string{}
}

// SetDir handles the toc_set_dir TOC command.
//
// From the TiK documentation:
//
//	Set the DIR user information. This is a colon separated fields as in:
//
//		"first name":"middle name":"last name":"maiden name":"city":"state":"country":"email":"allow web searches".
//
//	Should return a DIR_STATUS msg. Having anything in the "allow web searches"
//	field allows people to use web-searches to find your directory info.
//	Otherwise, they'd have to use the client.
//
// The fields "email" and "allow web searches" are ignored by this method.
//
// Command syntax: toc_set_dir <info information>
func (s OSCARProxy) SetDir(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Locate, wire.LocateSetDirInfo); isLimited {
		return errMsg
	}

	var info string

	if _, err := parseArgs(args, &info); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	info = unescape(info)

	rawFields := strings.Split(info, ":")

	var finalFields [9]string

	if len(rawFields) > len(finalFields) {
		return s.runtimeErr(ctx, fmt.Errorf("expected at most %d params, got %d", len(finalFields), len(rawFields)))
	}
	for i, a := range rawFields {
		finalFields[i] = strings.Trim(a, "\"")
	}

	snac := wire.SNAC_0x02_0x09_LocateSetDirInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ODirTLVFirstName, finalFields[0]),
				wire.NewTLVBE(wire.ODirTLVMiddleName, finalFields[1]),
				wire.NewTLVBE(wire.ODirTLVLastName, finalFields[2]),
				wire.NewTLVBE(wire.ODirTLVMaidenName, finalFields[3]),
				wire.NewTLVBE(wire.ODirTLVCountry, finalFields[6]),
				wire.NewTLVBE(wire.ODirTLVState, finalFields[5]),
				wire.NewTLVBE(wire.ODirTLVCity, finalFields[4]),
			},
		},
	}
	if _, err := s.LocateService.SetDirInfo(ctx, me, wire.SNACFrame{}, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("LocateService.SetDirInfo: %w", err))
	}

	return []string{}
}

// SetIdle handles the toc_set_idle TOC command.
//
// From the TiK documentation:
//
//	Set idle information. If <idle secs> is 0 then the user isn't idle at all.
//	If <idle secs> is greater than 0 then the user has already been idle for
//	<idle secs> number of seconds. The server will automatically keep
//	incrementing this number, so do not repeatedly call with new idle times.
//
// Command syntax: toc_set_idle <idle secs>
func (s OSCARProxy) SetIdle(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.OService, wire.OServiceIdleNotification); isLimited {
		return errMsg
	}

	var idleTimeStr string

	if _, err := parseArgs(args, &idleTimeStr); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	t, err := strconv.Atoi(idleTimeStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	snac := wire.SNAC_0x01_0x11_OServiceIdleNotification{
		IdleTime: uint32(t),
	}
	if err := s.OServiceService.IdleNotification(ctx, me, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("OServiceServiceBOS.IdleNotification: %w", err))
	}

	return []string{}
}

// SetInfo handles the toc_set_info TOC command.
//
// From the TiK documentation:
//
//	Set the LOCATE user information. This is basic HTML. Remember to encode the info.
//
// Command syntax: toc_set_info <info information>
func (s OSCARProxy) SetInfo(ctx context.Context, me *state.SessionInstance, args []byte) []string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Locate, wire.LocateSetInfo); isLimited {
		return errMsg
	}

	var info string

	if _, err := parseArgs(args, &info); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	info = unescape(info)

	snac := wire.SNAC_0x02_0x04_LocateSetInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, info),
			},
		},
	}
	if err := s.LocateService.SetInfo(ctx, me, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("LocateService.SetInfo: %w", err))
	}

	return []string{}
}

// Signon handles the toc_signon, toc2_signon, and toc2_login TOC commands.
//
// From the TiK documentation (TOC1 toc_signon):
//
//	The password needs to be roasted with the Roasting String if coming over a
//	FLAP connection, CP connections don't use roasted passwords. The language
//	specified will be used when generating web pages, such as the get info
//	pages. Currently, the only supported language is "english". If the language
//	sent isn't found, the default "english" language will be used. The version
//	string will be used for the client identity, and must be less than 50
//	characters.
//
//	Passwords are roasted when sent to the host. This is done so they aren't
//	sent in "clear text" over the wire, although they are still trivial to
//	decode. Roasting is performed by first xoring each byte in the password
//	with the equivalent modulo byte in the roasting string. The result is then
//	converted to ascii hex, and prepended with "0x". So for example the
//	password "password" roasts to "0x2408105c23001130".
//
//	The Roasting String is Tic/Toc.
//
// toc2_signon uses the same parameters as toc_signon. toc2_login (TOC2) may
// include additional trailing parameters (e.g. agent string, code); see
// BlueTOC documentation.
//
// Command syntax: toc_signon <authorizer host> <authorizer port> <User Name> <Password> <language> <version>
// Command syntax: toc2_signon <authorizer host> <authorizer port> <User Name> <Password> <language> <version>
// Command syntax: toc2_login <authorizer host> <authorizer port> <User Name> <Password> <language> <version> [additional params...]
func (s OSCARProxy) Signon(ctx context.Context, args []byte, recalcWarning func(ctx context.Context, instance *state.SessionInstance) error, lowerWarnLevel func(ctx context.Context, instance *state.SessionInstance), chatRegistry *ChatRegistry) (*state.SessionInstance, []string) {
	var cmd, userName, password string

	if _, err := parseArgs(args, &cmd, nil, nil, &userName, &password); err != nil {
		return nil, s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	switch cmd {
	case "toc_signon", "toc2_signon", "toc2_login":
		// valid
	default:
		return nil, s.runtimeErr(ctx, errors.New("expected one of toc_signon, toc2_signon, toc2_login"))
	}

	if len(password) < 3 {
		return nil, s.runtimeErr(ctx, fmt.Errorf("password too short for roasted hex (need 2-char prefix + hex)"))
	}
	passwordHash, err := hex.DecodeString(password[2:])
	if err != nil {
		return nil, s.runtimeErr(ctx, fmt.Errorf("hex.DecodeString: %w", err))
	}

	signonFrame := wire.FLAPSignonFrame{}
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, userName))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, passwordHash))
	if cmd == "toc2_login" || cmd == "toc2_signon" {
		signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient))
	}

	block, err := s.AuthService.FLAPLogin(ctx, signonFrame, "")
	if err != nil {
		return nil, s.runtimeErr(ctx, fmt.Errorf("AuthService.FLAPLogin: %w", err))
	}

	if block.HasTag(wire.LoginTLVTagsErrorSubcode) {
		s.Logger.DebugContext(ctx, "login failed")
		return nil, []string{"ERROR:" + wire.TOCErrorAuthIncorrectNickOrPassword}
	}

	authCookie, ok := block.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !ok {
		return nil, s.runtimeErr(ctx, fmt.Errorf("unable to get session id from payload"))
	}

	// todo: naming for cookie: login cookie, server cookie, or auth cookie?
	serverCookie, err := s.AuthService.CrackCookie(authCookie)
	if err != nil {
		return nil, s.runtimeErr(ctx, fmt.Errorf("AuthService.CrackCookie: %w", err))
	}

	fnCfg := func(sess *state.Session) {
		sess.OnSessionClose(func() {
			if !shuttingDown(ctx) {
				if err := s.BuddyService.BroadcastBuddyDeparted(ctx, sess.IdentScreenName()); err != nil {
					s.Logger.ErrorContext(ctx, "error sending buddy departure notifications", "err", err.Error())
				}
			}

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			// buddy list must be cleared before session is closed, otherwise
			// there will be a race condition that could cause the buddy list
			// be prematurely deleted.
			if err := s.BuddyListRegistry.UnregisterBuddyList(ctx, sess.IdentScreenName()); err != nil {
				s.Logger.ErrorContext(ctx, "error removing buddy list entry", "err", err.Error())
			}
			s.ChatSessionManager.RemoveUserFromAllChats(sess.IdentScreenName())
			s.AuthService.Signout(ctx, sess)
		})

	}

	instance, err := s.AuthService.RegisterBOSSession(ctx, serverCookie, fnCfg)
	if err != nil {
		return nil, s.runtimeErr(ctx, fmt.Errorf("AuthService.RegisterBOSSession: %w", err))
	}

	if err = instance.Session().RunOnce(func() error {
		// make buddy list visible to other users
		if err := s.BuddyListRegistry.RegisterBuddyList(ctx, instance.IdentScreenName()); err != nil {
			return fmt.Errorf("unable to init buddy list: %w", err)
		}
		// restore warning level from last session
		if err := recalcWarning(ctx, instance); err != nil {
			return fmt.Errorf("failed to recalculate warning level: %w", err)
		}
		// periodically decay warning level
		go lowerWarnLevel(ctx, instance)
		return nil
	}); err != nil {
		return nil, s.runtimeErr(ctx, fmt.Errorf("Session.RunOnce: %w", err))
	}

	// Update user visibility when an instance closes, as the user's overall status may change.
	// Example: With 1 away and 1 non-away instance, the user appears available. If the non-away
	// instance closes, the user should appear away.
	instance.OnClose(func() {
		if shuttingDown(ctx) {
			return
		}
		if instance.Session().Invisible() {
			if err := s.BuddyService.BroadcastBuddyDeparted(ctx, instance.IdentScreenName()); err != nil {
				s.Logger.ErrorContext(ctx, "error sending buddy departure notifications", "err", err.Error())
			}
		} else {
			if err := s.BuddyService.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), instance.Session().TLVUserInfo()); err != nil {
				s.Logger.ErrorContext(ctx, "error sending buddy arrival notifications", "err", err.Error())
			}
		}
	})

	// set chat capability so that... tk
	instance.SetCaps([][16]byte{wire.CapChat})

	if cmd == "toc_signon" {
		u, err := s.TOCConfigStore.User(ctx, instance.IdentScreenName())
		if err != nil {
			return nil, s.runtimeErr(ctx, fmt.Errorf("TOCConfigStore.User: %w", err))
		}
		if u == nil {
			return nil, s.runtimeErr(ctx, fmt.Errorf("TOCConfigStore.User: user not found"))
		}

		return instance, []string{"SIGN_ON:TOC1.0", fmt.Sprintf("CONFIG:%s", u.TOCConfig), fmt.Sprintf("NICK:%s", instance.DisplayScreenName().String())}
	}

	supportsTOC2MsgEnc := cmd == "toc2_login"
	instance.SetTOC2(supportsTOC2MsgEnc)

	if err := s.FeedbagService.Use(ctx, instance); err != nil {
		return instance, s.runtimeErr(ctx, fmt.Errorf("FeedbagService.Use: %w", err))
	}

	fb, err := s.FeedbagManager.Feedbag(ctx, instance.IdentScreenName())
	if err != nil {
		return instance, s.runtimeErr(ctx, fmt.Errorf("FeedbagManager.Feedbag: %w", err))
	}

	signon := []string{
		"SIGN_ON:TOC2.0",
		fmt.Sprintf("NICK:%s", instance.DisplayScreenName().String()),
	}

	cfg, err := buildToc2Config(fb)
	if err != nil {
		return instance, s.runtimeErr(ctx, fmt.Errorf("buildToc2Config: %w", err))
	}
	signon = append(signon, cfg...)

	return instance, signon
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

// buildToc2Config constructs configuration for CONFIG2
// - Lines are separated by LF; data between colons.
// - g: = group (before buddies in that group), b: = buddy (optionally :alias and :::::note),
// - d: = blocked, p: = private (permit), m: = privacy level (1-5), done: = end.
func buildToc2Config(fb []wire.FeedbagItem) ([]string, error) {
	type buddy struct {
		name  string
		alias string
		note  string
	}
	type group struct {
		name    string
		buddies map[uint16]buddy
		order   []uint16
	}
	type feedbag struct {
		order  []uint16
		groups map[uint16]group
	}
	buddylist := feedbag{
		groups: make(map[uint16]group),
	}

	for _, item := range fb {
		if item.ClassID == wire.FeedbagClassIdGroup {
			// root group contains the order of all other groups
			if item.GroupID == 0 {
				val, hasVal := item.Uint16SliceBE(wire.FeedbagAttributesOrder)
				if !hasVal {
					return []string{}, fmt.Errorf("root group missing order attribute")
				}
				buddylist.order = val
				continue
			}

			group := group{
				name:    item.Name,
				buddies: make(map[uint16]buddy),
			}
			// order will be empty if the group is empty
			val, _ := item.Uint16SliceBE(wire.FeedbagAttributesOrder)
			group.order = val
			buddylist.groups[item.GroupID] = group
		}
	}

	var cfg []string
	for _, item := range fb {
		if item.ClassID == wire.FeedbagClassIdBuddy {
			// Ensure group exists (handle orphaned buddies)
			if _, exists := buddylist.groups[item.GroupID]; !exists {
				buddylist.groups[item.GroupID] = group{
					name:    "", // Unknown group name
					buddies: make(map[uint16]buddy),
					order:   []uint16{},
				}
			}
			buddy := buddy{
				name: item.Name,
			}
			if val, hasVal := item.String(wire.FeedbagAttributesNote); hasVal {
				buddy.note = val
			}
			if val, hasVal := item.String(wire.FeedbagAttributesAlias); hasVal {
				buddy.alias = val
			}
			buddylist.groups[item.GroupID].buddies[item.ItemID] = buddy
		}
		if item.ClassID == wire.FeedbagClassIDDeny {
			cfg = append(cfg, "d:"+item.Name)
		}
		if item.ClassID == wire.FeedbagClassIDPermit {
			cfg = append(cfg, "p:"+item.Name)
		}
		if item.ClassID == wire.FeedbagClassIdPdinfo {
			val, hasVal := item.Uint8(wire.FeedbagAttributesPdMode)
			if hasVal {
				cfg = append(cfg, fmt.Sprintf("m:%d", val))
			}
		}
	}

	for _, gid := range buddylist.order {
		group := buddylist.groups[gid]
		cfg = append(cfg, "g:"+group.name)

		for _, bid := range group.order {
			buddy := group.buddies[bid]
			tmpLine := "b:" + buddy.name
			if buddy.alias != "" {
				tmpLine += ":" + buddy.alias
			}
			if buddy.note != "" {
				tmpLine += ":::::" + buddy.note
			}
			cfg = append(cfg, tmpLine)
		}
	}
	cfg = append(cfg, "done:")

	return []string{"CONFIG2:" + strings.Join(cfg, "\n") + "\n"}, nil
}

// newHTTPAuthToken creates a HMAC token for authenticating TOC HTTP requests
func (s OSCARProxy) newHTTPAuthToken(me state.IdentScreenName) (string, error) {
	cookie, err := s.CookieBaker.Issue([]byte(me.String()))
	if err != nil {
		return "", err
	}
	// trim padding so that gaim doesn't choke on the long value
	cookie = bytes.TrimRight(cookie, "\x00")
	return hex.EncodeToString(cookie), nil
}

// parseArgs extracts arguments from a TOC command. Each positional argument is
// assigned to its corresponding args pointer. It returns the remaining
// arguments as varargs.
func parseArgs(payload []byte, args ...*string) (varArgs []string, err error) {
	if len(payload) == 0 && len(args) == 0 {
		return []string{}, nil
	}
	reader := csv.NewReader(bytes.NewReader(payload))
	reader.Comma = ' '
	reader.LazyQuotes = true
	reader.TrimLeadingSpace = true

	segs, err := reader.Read()
	if err != nil {
		return []string{}, fmt.Errorf("CSV reader error: %w", err)
	}

	if len(segs) < len(args) {
		return []string{}, fmt.Errorf("command contains fewer arguments than expected")
	}

	// populate placeholder pointers with their corresponding values
	for i, arg := range args {
		if arg != nil {
			*arg = strings.TrimSpace(segs[i])
		}
	}

	// dump remaining arguments as varargs
	return segs[len(args):], err
}

// runtimeErr is a convenience function that logs an error and returns a TOC
// internal server error.
func (s OSCARProxy) runtimeErr(ctx context.Context, err error) []string {
	s.Logger.ErrorContext(ctx, "internal service error", "err", err.Error())
	return []string{cmdInternalSvcErr}
}

func (s OSCARProxy) checkRateLimit(ctx context.Context, sender *state.SessionInstance, foodGroup uint16, subGroup uint16) ([]string, bool) {
	rateClassID, ok := s.SNACRateLimits.RateClassLookup(foodGroup, subGroup)
	if !ok {
		s.Logger.ErrorContext(ctx, "rate limit not found, allowing request through")
		return []string{}, false
	}

	if status := sender.Session().EvaluateRateLimit(time.Now(), rateClassID); status == wire.RateLimitStatusLimited {
		s.Logger.DebugContext(ctx, "(toc) rate limit exceeded, dropping SNAC",
			"foodgroup", wire.FoodGroupName(foodGroup),
			"subgroup", wire.SubGroupName(foodGroup, subGroup))
		return []string{rateLimitExceededErr}, true
	}

	return []string{}, false
}

// unescape removes escaping from the following TOC characters: \ { } ( ) [ ] $ "
func unescape(encoded string) string {
	if !strings.ContainsRune(encoded, '\\') {
		return encoded
	}

	var result strings.Builder
	result.Grow(len(encoded))

	escaped := false

	for i := 0; i < len(encoded); i++ {
		ch := encoded[i]

		if escaped {
			// append escaped character without the backslash
			result.WriteByte(ch)
			escaped = false
		} else if ch == '\\' {
			escaped = true
		} else {
			result.WriteByte(ch)
		}
	}

	return result.String()
}

// parseTOC2Config parses the TOC2 config format string into a map of group names to buddy lists.
//
// Config format: {g:group<lf>b:buddy1<lf>b:buddy2<lf>}
// Where <lf> is a linefeed character (ASCII 10, \n).
//
// Extended format for buddies with alias/note:
// b:buddy:alias:::::note
//
// Returns a map where keys are group names and values are slices of buddy entries.
// Each buddy entry is a string that may contain alias/note information.
func parseTOC2Config(config string) (map[string][]string, error) {
	// Remove surrounding braces
	config = strings.TrimPrefix(config, "{")
	config = strings.TrimSuffix(config, "}")

	// Split by linefeed (ASCII 10)
	lines := strings.Split(config, "\n")

	result := make(map[string][]string)
	var currentGroup string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "g:") {
			// Group line: g:groupname
			currentGroup = strings.TrimPrefix(line, "g:")
			if currentGroup == "" {
				return nil, fmt.Errorf("empty group name")
			}
			if result[currentGroup] == nil {
				result[currentGroup] = []string{}
			}
		} else if strings.HasPrefix(line, "b:") {
			// Buddy line: b:buddy or b:buddy:alias:::::note
			if currentGroup == "" {
				return nil, fmt.Errorf("buddy entry without group")
			}
			buddyEntry := strings.TrimPrefix(line, "b:")
			if buddyEntry == "" {
				return nil, fmt.Errorf("empty buddy name")
			}
			result[currentGroup] = append(result[currentGroup], buddyEntry)
		}
	}

	return result, nil
}
