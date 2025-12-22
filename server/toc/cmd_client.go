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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mk6i/open-oscar-server/config"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// NewChatRegistry creates a new ChatRegistry instances.
func NewChatRegistry() *ChatRegistry {
	chatRegistry := &ChatRegistry{
		lookup:   make(map[int]wire.ICBMRoomInfo),
		sessions: make(map[int]*state.Session),
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
	lookup   map[int]wire.ICBMRoomInfo // Maps chat room IDs to their metadata.
	sessions map[int]*state.Session    // Tracks active chat sessions by chat room ID.
	nextID   int                       // Incremental identifier for newly added chat rooms.
	m        sync.RWMutex              // Synchronization primitive for concurrent access.
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
func (c *ChatRegistry) RegisterSess(chatID int, sess *state.Session) {
	c.m.Lock()
	defer c.m.Unlock()
	c.sessions[chatID] = sess
}

// RetrieveSess retrieves the chat session associated with the given chat ID.
// If no session is registered for the chat ID, it returns nil.
func (c *ChatRegistry) RetrieveSess(chatID int) *state.Session {
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
func (c *ChatRegistry) Sessions() []*state.Session {
	c.m.RLock()
	defer c.m.RUnlock()
	sessions := make([]*state.Session, 0, len(c.sessions))
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
	AdminService      AdminService
	AuthService       AuthService
	BuddyListRegistry BuddyListRegistry
	BuddyService      BuddyService
	ChatNavService    ChatNavService
	ChatService       ChatService
	CookieBaker       CookieBaker
	DirSearchService  DirSearchService
	ICBMService       ICBMService
	LocateService     LocateService
	Logger            *slog.Logger
	OServiceService   OServiceService
	PermitDenyService PermitDenyService
	TOCConfigStore    TOCConfigStore
	SNACRateLimits    wire.SNACRateLimits
	HTTPIPRateLimiter *IPRateLimiter
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
	sessBOS *state.Session,
	chatRegistry *ChatRegistry,
	payload []byte,
	toCh chan<- []byte,
	doAsync func(f func() error),
) (reply string) {

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
	case "toc_send_im":
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
		var msg string

		if string(cmd) == "toc_chat_join" {
			chatID, msg = s.ChatJoin(ctx, sessBOS, chatRegistry, args)
		} else {
			chatID, msg = s.ChatAccept(ctx, sessBOS, chatRegistry, args)
		}

		if msg == cmdInternalSvcErr {
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
	}

	s.Logger.ErrorContext(ctx, fmt.Sprintf("unsupported TOC command %s", cmd))
	return cmdInternalSvcErr
}

// AddBuddy handles the toc_add_buddy TOC command.
//
// From the TiK documentation:
//
//	Add buddies to your buddy list. This does not change your saved config.
//
// Command syntax: toc_add_buddy <Buddy User 1> [<Buddy User2> [<Buddy User 3> [...]]]
func (s OSCARProxy) AddBuddy(ctx context.Context, me *state.Session, args []byte) string {
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

	return ""
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
func (s OSCARProxy) AddPermit(ctx context.Context, me *state.Session, args []byte) string {
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
	return ""
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
func (s OSCARProxy) AddDeny(ctx context.Context, me *state.Session, args []byte) string {
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
	return ""
}

// ChangePassword handles the toc_change_passwd TOC command.
//
// From the TiK documentation:
//
//	Change a user's password. An ADMIN_PASSWD_STATUS or ERROR message will be
//	sent back to the client.
//
// Command syntax: toc_change_passwd <existing_passwd> <new_passwd>
func (s OSCARProxy) ChangePassword(ctx context.Context, me *state.Session, args []byte) string {
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
			return "ERROR:911"
		case wire.AdminInfoErrorValidatePassword:
			return "ERROR:912"
		default:
			return "ERROR:913"
		}
	}

	return "ADMIN_PASSWD_STATUS:0"
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
	me *state.Session,
	chatRegistry *ChatRegistry,
	args []byte,
) (int, string) {

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

	chatSess, err := s.AuthService.RegisterChatSession(ctx, serverCookie)
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

	return chatID, fmt.Sprintf("CHAT_JOIN:%d:%s", chatID, roomName)
}

// ChatInvite handles the toc_chat_invite TOC command.
//
// From the TiK documentation:
//
//	Once you are inside a chat room you can invite other people into that room.
//	Remember to quote and encode the invite message.
//
// Command syntax: toc_chat_invite <Chat Room ID> <Invite Msg> <buddy1> [<buddy2> [<buddy3> [...]]]
func (s OSCARProxy) ChatInvite(ctx context.Context, me *state.Session, chatRegistry *ChatRegistry, args []byte) string {
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

	return ""
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
	me *state.Session,
	chatRegistry *ChatRegistry,
	args []byte,
) (int, string) {
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

	chatSess, err := s.AuthService.RegisterChatSession(ctx, serverCookie)
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

	return chatID, fmt.Sprintf("CHAT_JOIN:%d:%s", chatID, roomName)
}

// ChatLeave handles the toc_chat_leave TOC command.
//
// From the TiK documentation:
//
//	Leave the chat room.
//
// Command syntax: toc_chat_leave <Chat Room ID>
func (s OSCARProxy) ChatLeave(ctx context.Context, chatRegistry *ChatRegistry, args []byte) string {
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

	s.AuthService.SignoutChat(ctx, me)

	me.Close() // stop async server SNAC reply handler for this chat room

	chatRegistry.RemoveSess(chatID)

	return fmt.Sprintf("CHAT_LEFT:%d", chatID)
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
func (s OSCARProxy) ChatSend(ctx context.Context, chatRegistry *ChatRegistry, args []byte) string {
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
	block.Append(wire.NewTLVBE(wire.ChatTLVSenderInformation, me.TLVUserInfo()))
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

		return fmt.Sprintf("CHAT_IN:%d:%s:F:%s", chatID, userInfo.ScreenName, reflectMsg)
	default:
		return s.runtimeErr(ctx, errors.New("ChatService.ChannelMsgToHost: unexpected response"))
	}
}

// ChatWhisper handles the toc_chat_send TOC command.
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
func (s OSCARProxy) ChatWhisper(ctx context.Context, chatRegistry *ChatRegistry, args []byte) string {
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
	block.Append(wire.NewTLVBE(wire.ChatTLVSenderInformation, me.TLVUserInfo()))
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

	return ""
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
// Command syntax: toc_evil <User> <norm|anon>
func (s OSCARProxy) Evil(ctx context.Context, me *state.Session, args []byte) string {
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
		return ""
	case wire.SNACError:
		s.Logger.InfoContext(ctx, "unable to warn user", "code", v.Code)
	default:
		return s.runtimeErr(ctx, errors.New("unexpected response"))
	}

	return ""
}

// FormatNickname handles the toc_format_nickname TOC command.
//
// From the TiK documentation:
//
//	Reformat a user's nickname. An ADMIN_NICK_STATUS or ERROR message will be
//	sent back to the client.
//
// Command syntax: toc_format_nickname <new_format>
func (s OSCARProxy) FormatNickname(ctx context.Context, me *state.Session, args []byte) string {
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
			return "ERROR:911"
		default:
			return "ERROR:913"
		}
	}

	return "ADMIN_NICK_STATUS:0"
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
func (s OSCARProxy) GetDirSearchURL(ctx context.Context, me *state.Session, args []byte) string {
	if status := me.EvaluateRateLimit(time.Now(), 1); status == wire.RateLimitStatusLimited {
		return rateLimitExceededErr
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

	return fmt.Sprintf("GOTO_URL:search results:dir_search?%s", p.Encode())
}

// GetDirURL handles the toc_get_dir TOC command.
//
// From the TiK documentation:
//
//	Gets a user's dir info a GOTO_URL or ERROR message will be sent back to the client.
//
// Command syntax: toc_get_dir <username>
func (s OSCARProxy) GetDirURL(ctx context.Context, me *state.Session, args []byte) string {
	if status := me.EvaluateRateLimit(time.Now(), 1); status == wire.RateLimitStatusLimited {
		return rateLimitExceededErr
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

	return fmt.Sprintf("GOTO_URL:directory info:dir_info?%s", p.Encode())
}

// GetInfoURL handles the toc_get_info TOC command.
//
// From the TiK documentation:
//
//	Gets a user's info a GOTO_URL or ERROR message will be sent back to the client.
//
// Command syntax: toc_get_info <username>
func (s OSCARProxy) GetInfoURL(ctx context.Context, me *state.Session, args []byte) string {
	if status := me.EvaluateRateLimit(time.Now(), 1); status == wire.RateLimitStatusLimited {
		return rateLimitExceededErr
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

	return fmt.Sprintf("GOTO_URL:profile:info?%s", p.Encode())
}

// GetStatus handles the toc_get_status TOC command.
//
// From the TOC2 documentation:
//
//	This useful command wasn't ever really documented. It returns either an
//	UPDATE_BUDDY message or an ERROR message depending on whether or not the
//	guy appears to be online.
//
// Command syntax: toc_get_status <screenname>
func (s OSCARProxy) GetStatus(ctx context.Context, me *state.Session, args []byte) string {
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
			return fmt.Sprintf("ERROR:901:%s", them)
		} else {
			return s.runtimeErr(ctx, fmt.Errorf("LocateService.UserInfoQuery error code: %d", v.Code))
		}
	case wire.SNAC_0x02_0x06_LocateUserInfoReply:
		return userInfoToUpdateBuddy(v.TLVUserInfo)
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
func (s OSCARProxy) InitDone(ctx context.Context, sess *state.Session) string {
	if errMsg, isLimited := s.checkRateLimit(ctx, sess, wire.OService, wire.OServiceClientOnline); isLimited {
		return errMsg
	}
	if err := s.OServiceService.ClientOnline(ctx, wire.BOS, wire.SNAC_0x01_0x02_OServiceClientOnline{}, sess); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("OServiceServiceBOS.ClientOnliney: %w", err))
	}
	return ""
}

// RemoveBuddy handles the toc_remove_buddy TOC command.
//
// From the TiK documentation:
//
//	Remove buddies from your buddy list. This does not change your saved config.
//
// Command syntax: toc_remove_buddy <Buddy User 1> [<Buddy User2> [<Buddy User 3> [...]]]
func (s OSCARProxy) RemoveBuddy(ctx context.Context, me *state.Session, args []byte) string {
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
	return ""
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
func (s OSCARProxy) RvousAccept(ctx context.Context, me *state.Session, args []byte) string {
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

	return ""
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
func (s OSCARProxy) RvousCancel(ctx context.Context, me *state.Session, args []byte) string {
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

	return ""
}

// SendIM handles the toc_send_im TOC command.
//
// From the TiK documentation:
//
//	Send a message to a remote user. Remember to quote and encode the message.
//	If the optional string "auto" is the last argument, then the auto response
//	flag will be turned on for the IM.
//
// Command syntax: toc_send_im <Destination User> <Message> [auto]
func (s OSCARProxy) SendIM(ctx context.Context, sender *state.Session, args []byte) string {
	if msg, isLimited := s.checkRateLimit(ctx, sender, wire.ICBM, wire.ICBMChannelMsgToHost); isLimited {
		return msg
	}

	var recip, msg string

	autoReply, err := parseArgs(args, &recip, &msg)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	msg = unescape(msg)

	frags, err := wire.ICBMFragmentList(msg)
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

	return ""
}

// SetAway handles the toc_chat_join TOC command.
//
// From the TiK documentation:
//
//	If the away message is present, then the unavailable status flag is set for
//	the user. If the away message is not present, then the unavailable status
//	flag is unset. The away message is basic HTML, remember to encode the
//	information.
//
// Command syntax: toc_set_away [<away message>]
func (s OSCARProxy) SetAway(ctx context.Context, me *state.Session, args []byte) string {
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

	return ""
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
func (s OSCARProxy) SetCaps(ctx context.Context, me *state.Session, args []byte) string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.Locate, wire.LocateSetInfo); isLimited {
		return errMsg
	}

	params, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	caps := make([]uuid.UUID, 0, 16*(len(params)+1))
	for _, capStr := range params {
		uid, err := uuid.Parse(capStr)
		if err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("UUID.Parse: %w", err))
		}
		caps = append(caps, uid)
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

	return ""
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
func (s OSCARProxy) SetConfig(ctx context.Context, me *state.Session, args []byte) string {
	if status := me.EvaluateRateLimit(time.Now(), 1); status == wire.RateLimitStatusLimited {
		return rateLimitExceededErr
	}

	// most TOC clients don't quote the config info argument, despite what the
	// documentation specifies. this makes the argument payload incompatible
	// for CSV parsing. since this command takes a single argument, we can get
	// away with trimming quotes and spaces from the byte slice before passing
	// it to the config store.
	args = bytes.Trim(args, "'\" ")

	config := string(args)
	if config == "" {
		return s.runtimeErr(ctx, fmt.Errorf("empty config"))
	}

	if err := s.TOCConfigStore.SetTOCConfig(ctx, me.IdentScreenName(), config); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("TOCConfigStore.SaveTOCConfig: %w", err))
	}

	return ""
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
func (s OSCARProxy) SetDir(ctx context.Context, me *state.Session, args []byte) string {
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

	return ""
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
func (s OSCARProxy) SetIdle(ctx context.Context, me *state.Session, args []byte) string {
	if errMsg, isLimited := s.checkRateLimit(ctx, me, wire.OService, wire.OServiceIdleNotification); isLimited {
		return errMsg
	}

	var idleTimeStr string

	if _, err := parseArgs(args, &idleTimeStr); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	time, err := strconv.Atoi(idleTimeStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	snac := wire.SNAC_0x01_0x11_OServiceIdleNotification{
		IdleTime: uint32(time),
	}
	if err := s.OServiceService.IdleNotification(ctx, me, snac); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("OServiceServiceBOS.IdleNotification: %w", err))
	}

	return ""
}

// SetInfo handles the toc_set_info TOC command.
//
// From the TiK documentation:
//
//	Set the LOCATE user information. This is basic HTML. Remember to encode the info.
//
// Command syntax: toc_set_info <info information>
func (s OSCARProxy) SetInfo(ctx context.Context, me *state.Session, args []byte) string {
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

	return ""
}

// Signon handles the toc_signon TOC command.
//
// From the TiK documentation:
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
// Command syntax: toc_signon <authorizer host> <authorizer port> <User Name> <Password> <language> <version>
func (s OSCARProxy) Signon(ctx context.Context, args []byte) (*state.Session, []string) {
	var userName, password string

	if _, err := parseArgs(args, nil, nil, &userName, &password); err != nil {
		return nil, []string{s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))}
	}

	passwordHash, err := hex.DecodeString(password[2:])
	if err != nil {
		return nil, []string{s.runtimeErr(ctx, fmt.Errorf("hex.DecodeString: %w", err))}
	}

	signonFrame := wire.FLAPSignonFrame{}
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsScreenName, userName))
	signonFrame.Append(wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, passwordHash))

	block, err := s.AuthService.FLAPLogin(ctx, signonFrame, state.NewStubUser, "")
	if err != nil {
		return nil, []string{s.runtimeErr(ctx, fmt.Errorf("AuthService.FLAPLogin: %w", err))}
	}

	if block.HasTag(wire.LoginTLVTagsErrorSubcode) {
		s.Logger.DebugContext(ctx, "login failed")
		return nil, []string{"ERROR:980"} // bad username/password
	}

	authCookie, ok := block.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !ok {
		return nil, []string{s.runtimeErr(ctx, fmt.Errorf("unable to get session id from payload"))}
	}

	// todo: naming for cookie: login cookie, server cookie, or auth cookie?
	serverCookie, err := s.AuthService.CrackCookie(authCookie)

	sess, err := s.AuthService.RegisterBOSSession(ctx, serverCookie)
	if err != nil {
		return nil, []string{s.runtimeErr(ctx, fmt.Errorf("AuthService.RegisterBOSSession: %w", err))}
	}

	// set chat capability so that... tk
	sess.SetCaps([][16]byte{wire.CapChat})

	if err := s.BuddyListRegistry.RegisterBuddyList(ctx, sess.IdentScreenName()); err != nil {
		return nil, []string{s.runtimeErr(ctx, fmt.Errorf("BuddyListRegistry.RegisterBuddyList: %w", err))}
	}

	u, err := s.TOCConfigStore.User(ctx, sess.IdentScreenName())
	if err != nil {
		return nil, []string{s.runtimeErr(ctx, fmt.Errorf("TOCConfigStore.User: %w", err))}
	}
	if u == nil {
		return nil, []string{s.runtimeErr(ctx, fmt.Errorf("TOCConfigStore.User: user not found"))}
	}

	return sess, []string{"SIGN_ON:TOC1.0", fmt.Sprintf("CONFIG:%s", u.TOCConfig)}
}

// Signout terminates a TOC session. It sends departure notifications to
// buddies, de-registers buddy list and session.
func (s OSCARProxy) Signout(ctx context.Context, me *state.Session, chatRegistry *ChatRegistry) {
	if err := s.BuddyService.BroadcastBuddyDeparted(ctx, me); err != nil {
		s.Logger.ErrorContext(ctx, "error sending departure notifications", "err", err.Error())
	}
	if err := s.BuddyListRegistry.UnregisterBuddyList(ctx, me.IdentScreenName()); err != nil {
		s.Logger.ErrorContext(ctx, "error removing buddy list entry", "err", err.Error())
	}
	s.AuthService.Signout(ctx, me)

	for _, sess := range chatRegistry.Sessions() {
		s.AuthService.SignoutChat(ctx, sess)
		sess.Close() // stop async server SNAC reply handler for this chat room
	}
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
func (s OSCARProxy) runtimeErr(ctx context.Context, err error) string {
	s.Logger.ErrorContext(ctx, "internal service error", "err", err.Error())
	return cmdInternalSvcErr
}

func (s OSCARProxy) checkRateLimit(ctx context.Context, sender *state.Session, foodGroup uint16, subGroup uint16) (string, bool) {
	rateClassID, ok := s.SNACRateLimits.RateClassLookup(foodGroup, subGroup)
	if !ok {
		s.Logger.ErrorContext(ctx, "rate limit not found, allowing request through")
		return "", false
	}

	if status := sender.EvaluateRateLimit(time.Now(), rateClassID); status == wire.RateLimitStatusLimited {
		s.Logger.DebugContext(ctx, "(toc) rate limit exceeded, dropping SNAC",
			"foodgroup", wire.FoodGroupName(foodGroup),
			"subgroup", wire.SubGroupName(foodGroup, subGroup))
		return rateLimitExceededErr, true
	}

	return "", false
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
