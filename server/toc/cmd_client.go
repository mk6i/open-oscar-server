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
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// OSCARProxy acts as a bridge between TOC clients and the OSCAR server,
// translating protocol messages between the two.
//
// It performs the following functions:
//   - Receives TOC commands from the client, converts them into SNAC
//     requests, and sends them to the OSCAR server (cmd_client.go).
//   - Receives SNACs from the OSCAR server, both replies to those requests and
//     server-initiated messages, and translates them into TOC responses for
//     the client (cmd_server.go).
type OSCARProxy struct {
	CookieBaker       CookieBaker
	DirSearchService  DirSearchService
	HTTPIPRateLimiter *IPRateLimiter
	LocateService     LocateService
	Logger            *slog.Logger
	// OSCARServer serves the OSCAR connections TOC opens for its users.
	OSCARServer OSCARServer
	// OSCAREndpoint is the OSCAR listener that TOC's connections appear to
	// arrive on.
	OSCAREndpoint    config.Endpoint
	SessionRetriever SessionRetriever
	TOCConfigStore   TOCConfigStore
	// RandIntn is the source for feedbag item ID generation.
	// Inject a deterministic func in tests to assert exact feedbag item slices.
	RandIntn func(n int) int
}

// signonTimeout bounds how long signon waits for each OSCAR server reply.
const signonTimeout = 10 * time.Second

// Request contexts are cached with each SNAC that TOC sends to the OSCAR
// server, under the SNAC's request ID (see snacCache). When the reply or error
// comes back, cmd_server.go uses the context's type to tell which TOC command
// the reply answers, and the context's fields for what the reply doesn't
// carry.
type (
	// getStatusReqCtx is the request context of a toc_get_status user info
	// query.
	getStatusReqCtx struct {
		screenName string
	}

	// evilReqCtx is the request context of a toc_evil warning.
	evilReqCtx struct{}

	// changePasswdReqCtx is the request context of a toc_change_passwd admin
	// request.
	changePasswdReqCtx struct{}

	// formatNickReqCtx is the request context of a toc_format_nickname admin
	// request.
	formatNickReqCtx struct{}

	// chatJoinReqCtx is the request context of the room creation that starts
	// toc_chat_join.
	chatJoinReqCtx struct{}

	// chatAcceptReqCtx is the request context of the room info query that
	// starts toc_chat_accept.
	chatAcceptReqCtx struct {
		chatID int
	}

	// chatServiceReqCtx is the request context of a request for a chat room
	// connection.
	chatServiceReqCtx struct {
		chatID   int
		roomName string
	}

	// feedbagChangeReqCtx is the request context of a feedbag change.
	feedbagChangeReqCtx struct{}

	// feedbagReloadReqCtx is the request context of a feedbag query that
	// reloads the feedbag mirror. marker identifies the changes sent before
	// the query.
	feedbagReloadReqCtx struct {
		marker uint64
	}
)

// RecvClientCmd processes a client TOC command and returns the replies that
// don't depend on a response from the OSCAR server. Replies that do are sent
// by cmd_server.go once the response arrives.
//
// * me is the current user's TOC connection.
// * payload is the command + arguments
func (s OSCARProxy) RecvClientCmd(ctx context.Context, me *tocConn, payload []byte) (replies []string) {

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

	if bytes.HasPrefix(cmd, []byte("toc2_")) && !me.IsTOC2() {
		s.Logger.ErrorContext(ctx, fmt.Sprintf("TOC2 command %s from a TOC1 session", cmd))
		return []string{cmdInternalSvcErr}
	}

	switch string(cmd) {
	case "toc_send_im", "toc2_send_im":
		return s.SendIM(ctx, me, args)
	case "toc_init_done":
		return s.InitDone(ctx, me)
	case "toc_add_buddy":
		return s.AddBuddy(ctx, me, args)
	case "toc_get_status":
		return s.GetStatus(ctx, me, args)
	case "toc_remove_buddy":
		return s.RemoveBuddy(ctx, me, args)
	case "toc_add_permit":
		return s.AddPermit(ctx, me, args)
	case "toc_add_deny":
		return s.AddDeny(ctx, me, args)
	case "toc_set_away":
		return s.SetAway(ctx, me, args)
	case "toc_set_caps":
		return s.SetCaps(ctx, me, args)
	case "toc_evil":
		return s.Evil(ctx, me, args)
	case "toc_get_info":
		return s.GetInfoURL(ctx, me, args)
	case "toc_change_passwd":
		return s.ChangePassword(ctx, me, args)
	case "toc_format_nickname":
		return s.FormatNickname(ctx, me, args)
	case "toc_chat_join":
		return s.ChatJoin(ctx, me, args)
	case "toc_chat_accept":
		return s.ChatAccept(ctx, me, args)
	case "toc_chat_send":
		return s.ChatSend(ctx, me, args)
	case "toc_chat_whisper":
		return s.ChatWhisper(ctx, me, args)
	case "toc_chat_leave":
		return s.ChatLeave(ctx, me, args)
	case "toc_set_info":
		return s.SetInfo(ctx, me, args)
	case "toc_set_dir":
		return s.SetDir(ctx, me, args)
	case "toc_set_idle":
		return s.SetIdle(ctx, me, args)
	case "toc_set_config":
		return s.SetConfig(ctx, me, args)
	case "toc_chat_invite":
		return s.ChatInvite(ctx, me, args)
	case "toc_dir_search":
		return s.GetDirSearchURL(ctx, me, args)
	case "toc_get_dir":
		return s.GetDirURL(ctx, me, args)
	case "toc_rvous_accept":
		return s.RvousAccept(ctx, me, args)
	case "toc_rvous_cancel":
		return s.RvousCancel(ctx, me, args)
	case "toc2_set_pdmode":
		return s.SetPDMode(ctx, me, args)
	case "toc2_send_im_enc":
		return s.SendIMEnc(ctx, me, args)
	case "toc2_remove_buddy":
		return s.RemoveBuddy2(ctx, me, args)
	case "toc2_new_group":
		return s.NewGroup(ctx, me, args)
	case "toc2_del_group":
		return s.DelGroup(ctx, me, args)
	case "toc2_new_buddies":
		return s.NewBuddies(ctx, me, args)
	case "toc2_add_permit":
		return s.AddPermit2(ctx, me, args)
	case "toc2_remove_permit":
		return s.RemovePermit2(ctx, me, args)
	case "toc2_add_deny":
		return s.AddDeny2(ctx, me, args)
	case "toc2_remove_deny":
		return s.RemoveDeny2(ctx, me, args)
	case "toc2_client_event":
		return s.SendClientEvent(ctx, me, args)
	}

	s.Logger.ErrorContext(ctx, fmt.Sprintf("unsupported TOC command %s", cmd))
	return []string{cmdInternalSvcErr}
}

// send sends a SNAC request to the OSCAR server over conn. The request is
// cached by request ID along with data so that cmd_server.go can handle the
// reply. It returns a TOC error if the SNAC could not be sent.
func (s OSCARProxy) send(ctx context.Context, me *tocConn, conn oscarConn, foodGroup uint16, subGroup uint16, body any, data any) []string {
	frame := wire.SNACFrame{
		FoodGroup: foodGroup,
		SubGroup:  subGroup,
	}
	me.cache.add(&frame, data)
	return s.sendFrame(ctx, me, conn, frame, body)
}

// sendFrame sends a SNAC request whose frame is already cached. It returns a
// TOC error if the SNAC could not be sent.
func (s OSCARProxy) sendFrame(ctx context.Context, me *tocConn, conn oscarConn, frame wire.SNACFrame, body any) []string {
	if err := conn.SendSNAC(frame, body); err != nil {
		me.cache.remove(frame.RequestID)
		return s.runtimeErr(ctx, fmt.Errorf("SendSNAC(%s, %s): %w",
			wire.FoodGroupName(frame.FoodGroup), wire.SubGroupName(frame.FoodGroup, frame.SubGroup), err))
	}
	return nil
}

// AddBuddy handles the toc_add_buddy TOC command.
//
// From the TiK documentation:
//
//	Add buddies to your buddy list. This does not change your saved config.
//
// Command syntax: toc_add_buddy <Buddy User 1> [<Buddy User2> [<Buddy User 3> [...]]]
func (s OSCARProxy) AddBuddy(ctx context.Context, me *tocConn, args []byte) []string {
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

	if msg := s.send(ctx, me, me.bos, wire.Buddy, wire.BuddyAddBuddies, snac, nil); msg != nil {
		return msg
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
func (s OSCARProxy) AddPermit(ctx context.Context, me *tocConn, args []byte) []string {
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

	if msg := s.send(ctx, me, me.bos, wire.PermitDeny, wire.PermitDenyAddPermListEntries, snac, nil); msg != nil {
		return msg
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
func (s OSCARProxy) AddDeny(ctx context.Context, me *tocConn, args []byte) []string {
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

	if msg := s.send(ctx, me, me.bos, wire.PermitDeny, wire.PermitDenyAddDenyListEntries, snac, nil); msg != nil {
		return msg
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
// The reply is sent by AdminChangeReply.
//
// Command syntax: toc_change_passwd <existing_passwd> <new_passwd>
func (s OSCARProxy) ChangePassword(ctx context.Context, me *tocConn, args []byte) []string {
	var oldPass, newPass string

	if _, err := parseArgs(args, &oldPass, &newPass); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	oldPass = unescape(oldPass)
	newPass = unescape(newPass)

	snac := wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.AdminTLVOldPassword, oldPass),
				wire.NewTLVBE(wire.AdminTLVNewPassword, newPass),
			},
		},
	}

	if msg := s.send(ctx, me, me.bos, wire.Admin, wire.AdminInfoChangeRequest, snac, changePasswdReqCtx{}); msg != nil {
		return msg
	}
	return []string{}
}

// ChatAccept handles the toc_chat_accept TOC command.
//
// From the TiK documentation:
//
//	Accept a CHAT_INVITE message from TOC. The server will send a CHAT_JOIN in
//	response.
//
// This command looks up the invited room. ChatNavInfo continues the join once
// the room info arrives.
//
// Command syntax: toc_chat_accept <Chat Room ID>
func (s OSCARProxy) ChatAccept(ctx context.Context, me *tocConn, args []byte) []string {
	var chatIDStr string

	if _, err := parseArgs(args, &chatIDStr); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	chatID, err := strconv.Atoi(chatIDStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}
	chatInfo, found := me.chats.LookupRoom(chatID)
	if !found {
		return s.runtimeErr(ctx, fmt.Errorf("chatRegistry.LookupRoom: no chat found for ID %d", chatID))
	}

	snac := wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
		Cookie:         chatInfo.Cookie,
		Exchange:       chatInfo.Exchange,
		InstanceNumber: chatInfo.Instance,
	}
	if msg := s.send(ctx, me, me.bos, wire.ChatNav, wire.ChatNavRequestRoomInfo, snac, chatAcceptReqCtx{chatID: chatID}); msg != nil {
		return msg
	}
	return []string{}
}

// ChatInvite handles the toc_chat_invite TOC command.
//
// From the TiK documentation:
//
//	Once you are inside a chat room you can invite other people into that room.
//	Remember to quote and encode the invite message.
//
// Command syntax: toc_chat_invite <Chat Room ID> <Invite Msg> <buddy1> [<buddy2> [<buddy3> [...]]]
func (s OSCARProxy) ChatInvite(ctx context.Context, me *tocConn, args []byte) []string {
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

	roomInfo, found := me.chats.LookupRoom(chatID)
	if !found {
		return s.runtimeErr(ctx, fmt.Errorf("chatRegistry.LookupRoom: chat ID `%d` not found", chatID))
	}

	for _, guest := range users {
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

		if msg := s.send(ctx, me, me.bos, wire.ICBM, wire.ICBMChannelMsgToHost, snac, nil); msg != nil {
			return msg
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
// This command creates the room, or retrieves it if it already exists.
// ChatNavInfo continues the join once the room info arrives.
//
// Command syntax: toc_chat_join <Exchange> <Chat Room Name>
func (s OSCARProxy) ChatJoin(ctx context.Context, me *tocConn, args []byte) []string {
	var exchangeStr, roomName string

	if _, err := parseArgs(args, &exchangeStr, &roomName); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	roomName = unescape(roomName)

	exchange, err := strconv.Atoi(exchangeStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	snac := wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
		Exchange: uint16(exchange),
		Cookie:   "create",
		TLVBlock: wire.TLVBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ChatRoomTLVRoomName, roomName),
			},
		},
	}
	if msg := s.send(ctx, me, me.bos, wire.ChatNav, wire.ChatNavCreateRoom, snac, chatJoinReqCtx{}); msg != nil {
		return msg
	}
	return []string{}
}

// requestChatService asks the BOS server for a connection to the chat room
// identified by cookie. ChatServiceResponse finishes the join once the
// connection details arrive.
func (s OSCARProxy) requestChatService(ctx context.Context, me *tocConn, chatID int, roomName string, cookie string) []string {
	snac := wire.SNAC_0x01_0x04_OServiceServiceRequest{
		FoodGroup: wire.Chat,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{
					Cookie: cookie,
				}),
			},
		},
	}
	return s.send(ctx, me, me.bos, wire.OService, wire.OServiceServiceRequest, snac, chatServiceReqCtx{
		chatID:   chatID,
		roomName: roomName,
	})
}

// connectChat opens a connection to the chat room identified by loginCookie
// and signs the user into the room.
func (s OSCARProxy) connectChat(ctx context.Context, me *tocConn, loginCookie []byte) (oscarConn, error) {
	conn, err := s.connectService(me.clientAddr, loginCookie)
	if err != nil {
		return nil, fmt.Errorf("connectService: %w", err)
	}

	subscribe := wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{
		ClassIDs: []uint16{1, 2, 3, 4, 5},
	}
	if msg := s.send(ctx, me, conn, wire.OService, wire.OServiceRateParamsSubAdd, subscribe, nil); msg != nil {
		conn.Close()
		return nil, errors.New("unable to subscribe to rate limit changes")
	}
	if msg := s.send(ctx, me, conn, wire.OService, wire.OServiceClientOnline, wire.SNAC_0x01_0x02_OServiceClientOnline{}, nil); msg != nil {
		conn.Close()
		return nil, errors.New("unable to send client online")
	}
	return conn, nil
}

// ChatLeave handles the toc_chat_leave TOC command.
//
// From the TiK documentation:
//
//	Leave the chat room.
//
// Command syntax: toc_chat_leave <Chat Room ID>
func (s OSCARProxy) ChatLeave(ctx context.Context, me *tocConn, args []byte) []string {
	var chatIDStr string

	if _, err := parseArgs(args, &chatIDStr); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	chatID, err := strconv.Atoi(chatIDStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	conn := me.chats.RetrieveConn(chatID)
	if conn == nil {
		return s.runtimeErr(ctx, fmt.Errorf("chatRegistry.RetrieveConn: chat session `%d` not found", chatID))
	}

	conn.Close() // stop async server SNAC reply handler for this chat room

	me.chats.RemoveConn(chatID)

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
// The reflected message is sent by ChatIn.
//
// Command syntax: toc_chat_send <Chat Room ID> <Message>
func (s OSCARProxy) ChatSend(ctx context.Context, me *tocConn, args []byte) []string {
	var chatIDStr, msg string

	if _, err := parseArgs(args, &chatIDStr, &msg); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	msg = unescape(msg)

	chatID, err := strconv.Atoi(chatIDStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	conn := me.chats.RetrieveConn(chatID)
	if conn == nil {
		return s.runtimeErr(ctx, fmt.Errorf("chatRegistry.RetrieveConn: session for chat ID `%d` not found", chatID))
	}

	block := wire.TLVRestBlock{}
	block.Append(wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, uint8(1)))
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
	if msg := s.send(ctx, me, conn, wire.Chat, wire.ChatChannelMsgToHost, snac, nil); msg != nil {
		return msg
	}
	return []string{}
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
func (s OSCARProxy) ChatWhisper(ctx context.Context, me *tocConn, args []byte) []string {
	var chatIDStr, recip, msg string

	if _, err := parseArgs(args, &chatIDStr, &recip, &msg); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	msg = unescape(msg)

	chatID, err := strconv.Atoi(chatIDStr)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("strconv.Atoi: %w", err))
	}

	conn := me.chats.RetrieveConn(chatID)
	if conn == nil {
		return s.runtimeErr(ctx, fmt.Errorf("chatRegistry.RetrieveConn: session for chat ID `%d` not found", chatID))
	}

	block := wire.TLVRestBlock{}
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
	if msg := s.send(ctx, me, conn, wire.Chat, wire.ChatChannelMsgToHost, snac, nil); msg != nil {
		return msg
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
// An ERROR message will be sent back to the client if the warning was
// unsuccessful (see SNACError).
//
// Command syntax: toc_evil <User> <norm|anon>
func (s OSCARProxy) Evil(ctx context.Context, me *tocConn, args []byte) []string {
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

	if msg := s.send(ctx, me, me.bos, wire.ICBM, wire.ICBMEvilRequest, snac, evilReqCtx{}); msg != nil {
		return msg
	}
	return []string{}
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
// The reply is sent by AdminChangeReply.
//
// Command syntax: toc_format_nickname <new_format>
func (s OSCARProxy) FormatNickname(ctx context.Context, me *tocConn, args []byte) []string {
	var newFormat string

	if _, err := parseArgs(args, &newFormat); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	// remove curly braces added by TiK
	newFormat = strings.Trim(newFormat, "{}")

	snac := wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, newFormat),
			},
		},
	}

	if msg := s.send(ctx, me, me.bos, wire.Admin, wire.AdminInfoChangeRequest, snac, formatNickReqCtx{}); msg != nil {
		return msg
	}
	return []string{}
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
func (s OSCARProxy) GetDirSearchURL(ctx context.Context, me *tocConn, args []byte) []string {
	if !me.limiter.Allow() {
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
func (s OSCARProxy) GetDirURL(ctx context.Context, me *tocConn, args []byte) []string {
	if !me.limiter.Allow() {
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
func (s OSCARProxy) GetInfoURL(ctx context.Context, me *tocConn, args []byte) []string {
	if !me.limiter.Allow() {
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
// The reply is sent by UserInfoReply or SNACError.
//
// Command syntax: toc_get_status <screenname>
func (s OSCARProxy) GetStatus(ctx context.Context, me *tocConn, args []byte) []string {
	var them string

	if _, err := parseArgs(args, &them); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	snac := wire.SNAC_0x02_0x05_LocateUserInfoQuery{
		ScreenName: them,
	}
	if msg := s.send(ctx, me, me.bos, wire.Locate, wire.LocateUserInfoQuery, snac, getStatusReqCtx{screenName: them}); msg != nil {
		return msg
	}
	return []string{}
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
func (s OSCARProxy) InitDone(ctx context.Context, me *tocConn) []string {
	if msg := s.send(ctx, me, me.bos, wire.OService, wire.OServiceClientOnline, wire.SNAC_0x01_0x02_OServiceClientOnline{}, nil); msg != nil {
		return msg
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
func (s OSCARProxy) RemoveBuddy(ctx context.Context, me *tocConn, args []byte) []string {
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

	if msg := s.send(ctx, me, me.bos, wire.Buddy, wire.BuddyDelBuddies, snac, nil); msg != nil {
		return msg
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
func (s OSCARProxy) RvousAccept(ctx context.Context, me *tocConn, args []byte) []string {
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

	if msg := s.send(ctx, me, me.bos, wire.ICBM, wire.ICBMChannelMsgToHost, snac, nil); msg != nil {
		return msg
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
func (s OSCARProxy) RvousCancel(ctx context.Context, me *tocConn, args []byte) []string {
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

	if msg := s.send(ctx, me, me.bos, wire.ICBM, wire.ICBMChannelMsgToHost, snac, nil); msg != nil {
		return msg
	}
	return []string{}
}

// upsertFeedbag sends feedbag items to insert or update.
func (s OSCARProxy) upsertFeedbag(ctx context.Context, me *tocConn, subGroup uint16, items []wire.FeedbagItem) []string {
	body := any(wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: items})
	if subGroup == wire.FeedbagUpdateItem {
		body = wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: items}
	}
	return s.sendFeedbagChange(ctx, me, subGroup, body, false, items)
}

// deleteFeedbag sends feedbag items to delete.
func (s OSCARProxy) deleteFeedbag(ctx context.Context, me *tocConn, items []wire.FeedbagItem) []string {
	body := wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: items}
	return s.sendFeedbagChange(ctx, me, wire.FeedbagDeleteItem, body, true, items)
}

// sendFeedbagChange sends a feedbag change and records it in the feedbag
// mirror as pending until the server confirms it.
func (s OSCARProxy) sendFeedbagChange(ctx context.Context, me *tocConn, subGroup uint16, body any, del bool, items []wire.FeedbagItem) []string {
	me.feedbag.sendMu.Lock()
	defer me.feedbag.sendMu.Unlock()

	frame := wire.SNACFrame{
		FoodGroup: wire.Feedbag,
		SubGroup:  subGroup,
	}
	me.cache.add(&frame, feedbagChangeReqCtx{})
	me.feedbag.sent(frame.RequestID, del, items)

	if msg := s.sendFrame(ctx, me, me.bos, frame, body); msg != nil {
		me.feedbag.discard(frame.RequestID)
		return msg
	}
	return nil
}

// reloadFeedbag queries the server's feedbag to replace the feedbag mirror.
// FeedbagReply finishes the reload.
func (s OSCARProxy) reloadFeedbag(ctx context.Context, me *tocConn) []string {
	me.feedbag.sendMu.Lock()
	defer me.feedbag.sendMu.Unlock()

	return s.send(ctx, me, me.bos, wire.Feedbag, wire.FeedbagQuery, struct{}{}, feedbagReloadReqCtx{
		marker: me.feedbag.mark(),
	})
}

// SetPDMode handles the toc2_set_pdmode TOC2 command.
//
// From the BlueTOC documentation:
//
//	Set permit/deny mode. Value: 1 = Allow all (default), 2 = Block all,
//	3 = Allow "permit group" only, 4 = Block "deny group" only, 5 = Allow buddy list only.
//
// Command syntax: toc2_set_pdmode <mode>
func (s OSCARProxy) SetPDMode(ctx context.Context, me *tocConn, args []byte) []string {
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

	fl := state.NewFeedbagList(me.feedbag.snapshot(), s.RandIntn)
	fl.SetMode(uint8(mode))

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if msg := s.upsertFeedbag(ctx, me, wire.FeedbagInsertItem, pending); msg != nil {
			return msg
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
func (s OSCARProxy) NewGroup(ctx context.Context, me *tocConn, args []byte) []string {
	var groupName string
	if _, err := parseArgs(args, &groupName); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	groupName = unescape(groupName)

	if groupName == "" {
		return s.runtimeErr(ctx, fmt.Errorf("empty group name"))
	}

	fl := state.NewFeedbagList(me.feedbag.snapshot(), s.RandIntn)
	fl.AddGroup(groupName)

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if msg := s.upsertFeedbag(ctx, me, wire.FeedbagInsertItem, pending); msg != nil {
			return msg
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
func (s OSCARProxy) DelGroup(ctx context.Context, me *tocConn, args []byte) []string {
	var groupName string
	if _, err := parseArgs(args, &groupName); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	groupName = unescape(groupName)

	if groupName == "" {
		return s.runtimeErr(ctx, fmt.Errorf("empty group name"))
	}

	fl := state.NewFeedbagList(me.feedbag.snapshot(), s.RandIntn)
	fl.DeleteGroup(groupName)

	pending := fl.PendingDeletes()
	if len(pending) == 0 {
		return s.runtimeErr(ctx, fmt.Errorf("group not found: %s", groupName))
	}
	if msg := s.deleteFeedbag(ctx, me, pending); msg != nil {
		return msg
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if msg := s.upsertFeedbag(ctx, me, wire.FeedbagInsertItem, pending); msg != nil {
			return msg
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
func (s OSCARProxy) NewBuddies(ctx context.Context, me *tocConn, args []byte) []string {
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

	fl := state.NewFeedbagList(me.feedbag.snapshot(), s.RandIntn)

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
		var groupOrder []uint16
		for _, item := range pending {
			if item.ClassID == wire.FeedbagClassIdBuddy {
				if _, ok := buddyItems[item.GroupID]; !ok {
					groupOrder = append(groupOrder, item.GroupID)
				}
				buddyItems[item.GroupID] = append(buddyItems[item.GroupID], item)
			}
		}

		if len(buddyItems) == 0 {
			return replies
		}

		// all groups go in one SNAC, ahead of all buddies in another
		var groups []wire.FeedbagItem
		for _, item := range pending {
			if item.ClassID == wire.FeedbagClassIdGroup {
				groups = append(groups, item)
			}
		}
		if msg := s.upsertFeedbag(ctx, me, wire.FeedbagUpdateItem, groups); msg != nil {
			return msg
		}

		var buddies []wire.FeedbagItem
		for _, groupID := range groupOrder {
			buddies = append(buddies, buddyItems[groupID]...)
		}
		if msg := s.upsertFeedbag(ctx, me, wire.FeedbagInsertItem, buddies); msg != nil {
			return msg
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
func (s OSCARProxy) RemoveBuddy2(ctx context.Context, me *tocConn, args []byte) []string {
	params, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}
	if len(params) < 2 {
		return s.runtimeErr(ctx, fmt.Errorf("missing params: need at least one screenname and group"))
	}

	fl := state.NewFeedbagList(me.feedbag.snapshot(), s.RandIntn)

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
		if msg := s.deleteFeedbag(ctx, me, pending); msg != nil {
			return msg
		}
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if msg := s.upsertFeedbag(ctx, me, wire.FeedbagUpdateItem, pending); msg != nil {
			return msg
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
func (s OSCARProxy) AddPermit2(ctx context.Context, me *tocConn, args []byte) []string {
	screenNames, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	if len(screenNames) == 0 {
		return s.runtimeErr(ctx, fmt.Errorf("no screennames provided"))
	}

	fl := state.NewFeedbagList(me.feedbag.snapshot(), s.RandIntn)

	for _, sn := range screenNames {
		fl.PermitUser(sn)
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if msg := s.upsertFeedbag(ctx, me, wire.FeedbagInsertItem, pending); msg != nil {
			return msg
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
func (s OSCARProxy) RemovePermit2(ctx context.Context, me *tocConn, args []byte) []string {
	screenNames, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	if len(screenNames) == 0 {
		return s.runtimeErr(ctx, fmt.Errorf("no screennames provided"))
	}

	fl := state.NewFeedbagList(me.feedbag.snapshot(), s.RandIntn)

	for _, sn := range screenNames {
		fl.DeletePermit(sn)
	}

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		if msg := s.deleteFeedbag(ctx, me, pending); msg != nil {
			return msg
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
func (s OSCARProxy) AddDeny2(ctx context.Context, me *tocConn, args []byte) []string {
	screenNames, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	if len(screenNames) == 0 {
		return s.runtimeErr(ctx, fmt.Errorf("no screennames provided"))
	}

	fl := state.NewFeedbagList(me.feedbag.snapshot(), s.RandIntn)

	for _, sn := range screenNames {
		fl.DenyUser(sn)
	}

	if pending := fl.PendingUpdates(); len(pending) > 0 {
		if msg := s.upsertFeedbag(ctx, me, wire.FeedbagInsertItem, pending); msg != nil {
			return msg
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
func (s OSCARProxy) RemoveDeny2(ctx context.Context, me *tocConn, args []byte) []string {
	screenNames, err := parseArgs(args)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	if len(screenNames) == 0 {
		return s.runtimeErr(ctx, fmt.Errorf("no screennames provided"))
	}

	fl := state.NewFeedbagList(me.feedbag.snapshot(), s.RandIntn)

	for _, sn := range screenNames {
		fl.DeleteDeny(sn)
	}

	if pending := fl.PendingDeletes(); len(pending) > 0 {
		if msg := s.deleteFeedbag(ctx, me, pending); msg != nil {
			return msg
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
// Encoding is A (ASCII) or U (UTF-8). U messages containing non-ASCII text are
// sent as Unicode; everything else is sent as ASCII.
//
// Command syntax: toc2_send_im_enc <Destination user> "F" <Encoding> <Language> <Message> [auto]
func (s OSCARProxy) SendIMEnc(ctx context.Context, me *tocConn, args []byte) []string {
	var recip, unknown, enc, lang, msg string

	autoReply, err := parseArgs(args, &recip, &unknown, &enc, &lang, &msg)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	fragList := wire.ICBMFragmentListASCII
	if enc == "U" {
		fragList = wire.ICBMFragmentList
	}

	return s.sendIm(ctx, me, fragList, msg, recip, autoReply)
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
func (s OSCARProxy) SendIM(ctx context.Context, me *tocConn, args []byte) []string {
	var recip, msg string

	autoReply, err := parseArgs(args, &recip, &msg)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("parseArgs: %w", err))
	}

	return s.sendIm(ctx, me, wire.ICBMFragmentListASCII, msg, recip, autoReply)
}

func (s OSCARProxy) sendIm(ctx context.Context, me *tocConn, fragList func(string) ([]wire.ICBMCh1Fragment, error), msg string, recip string, autoReply []string) []string {
	frags, err := fragList(unescape(msg))
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

	// errors such as "user is offline" are not reported to the client since
	// there is no TOC error code for them
	if msg := s.send(ctx, me, me.bos, wire.ICBM, wire.ICBMChannelMsgToHost, snac, nil); msg != nil {
		return msg
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
func (s OSCARProxy) SendClientEvent(ctx context.Context, me *tocConn, args []byte) []string {
	var user, statusStr string
	if _, err := parseArgs(args, &user, &statusStr); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("SendClientEvent: invalid args: %w", err))
	}
	status, err := strconv.ParseUint(statusStr, 10, 16)
	if err != nil || status > 2 {
		return s.runtimeErr(ctx, fmt.Errorf("SendClientEvent: typing status must be 0, 1, or 2, got %q", statusStr))
	}
	snac := wire.SNAC_0x04_0x14_ICBMClientEvent{
		Cookie:     0,
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: user,
		Event:      uint16(status),
	}
	if msg := s.send(ctx, me, me.bos, wire.ICBM, wire.ICBMClientEvent, snac, nil); msg != nil {
		return msg
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
func (s OSCARProxy) SetAway(ctx context.Context, me *tocConn, args []byte) []string {
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

	if msg := s.send(ctx, me, me.bos, wire.Locate, wire.LocateSetInfo, snac, nil); msg != nil {
		return msg
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
func (s OSCARProxy) SetCaps(ctx context.Context, me *tocConn, args []byte) []string {
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

	if msg := s.send(ctx, me, me.bos, wire.Locate, wire.LocateSetInfo, snac, nil); msg != nil {
		return msg
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
func (s OSCARProxy) SetConfig(ctx context.Context, me *tocConn, args []byte) []string {
	if !me.limiter.Allow() {
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
func (s OSCARProxy) SetDir(ctx context.Context, me *tocConn, args []byte) []string {
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
	if msg := s.send(ctx, me, me.bos, wire.Locate, wire.LocateSetDirInfo, snac, nil); msg != nil {
		return msg
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
func (s OSCARProxy) SetIdle(ctx context.Context, me *tocConn, args []byte) []string {
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
	if msg := s.send(ctx, me, me.bos, wire.OService, wire.OServiceIdleNotification, snac, nil); msg != nil {
		return msg
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
func (s OSCARProxy) SetInfo(ctx context.Context, me *tocConn, args []byte) []string {
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
	if msg := s.send(ctx, me, me.bos, wire.Locate, wire.LocateSetInfo, snac, nil); msg != nil {
		return msg
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
// It returns the user's TOC connection, or nil if signon failed.
//
// Command syntax: toc_signon <authorizer host> <authorizer port> <User Name> <Password> <language> <version>
// Command syntax: toc2_signon <authorizer host> <authorizer port> <User Name> <Password> <language> <version>
// Command syntax: toc2_login <authorizer host> <authorizer port> <User Name> <Password> <language> <version> [additional params...]
func (s OSCARProxy) Signon(ctx context.Context, args []byte, clientAddr net.Addr) (*tocConn, []string) {
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

	signonTLVs := []wire.TLV{
		wire.NewTLVBE(wire.LoginTLVTagsScreenName, userName),
		wire.NewTLVBE(wire.LoginTLVTagsRoastedTOCPassword, passwordHash),
	}
	if cmd == "toc2_login" || cmd == "toc2_signon" {
		signonTLVs = append(signonTLVs, wire.NewTLVBE(wire.LoginTLVTagsMultiConnFlags, wire.MultiConnFlagsRecentClient))
	}

	block, err := s.authenticate(clientAddr, signonTLVs)
	if err != nil {
		return nil, s.runtimeErr(ctx, fmt.Errorf("authenticate: %w", err))
	}

	if code, failed := block.Uint16BE(wire.LoginTLVTagsErrorSubcode); failed {
		s.Logger.DebugContext(ctx, "login failed", "code", code)
		if code == wire.LoginErrRateLimitExceeded {
			return nil, []string{"ERROR:" + wire.TOCErrorAuthRatedFromLogin}
		}
		return nil, []string{"ERROR:" + wire.TOCErrorAuthIncorrectNickOrPassword}
	}

	authCookie, ok := block.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !ok {
		return nil, s.runtimeErr(ctx, fmt.Errorf("unable to get session id from payload"))
	}

	bos, err := s.connectService(clientAddr, authCookie)
	if err != nil {
		return nil, s.runtimeErr(ctx, fmt.Errorf("connectService: %w", err))
	}

	me := newTOCConn(bos, state.NewIdentScreenName(userName), clientAddr)
	me.isTOC2 = cmd != "toc_signon"
	me.supportsMsgEnc = cmd == "toc2_login"

	msgs, err := s.signonConfig(ctx, me, cmd)
	if err != nil {
		bos.Close()
		return nil, s.runtimeErr(ctx, err)
	}
	return me, msgs
}

// signonConfig prepares a newly signed-on TOC connection and returns the
// SIGN_ON, NICK and config messages for the client.
func (s OSCARProxy) signonConfig(ctx context.Context, me *tocConn, cmd string) ([]string, error) {
	// learn when the server starts dropping the user's requests
	subscribe := wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{
		ClassIDs: []uint16{1, 2, 3, 4, 5},
	}
	if msg := s.send(ctx, me, me.bos, wire.OService, wire.OServiceRateParamsSubAdd, subscribe, nil); msg != nil {
		return nil, errors.New("unable to subscribe to rate limit changes")
	}

	// advertise chat support, since TOC clients don't report capabilities
	// until they send toc_set_caps
	caps := wire.SNAC_0x02_0x04_LocateSetInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{wire.CapChat}),
			},
		},
	}
	if msg := s.send(ctx, me, me.bos, wire.Locate, wire.LocateSetInfo, caps, nil); msg != nil {
		return nil, errors.New("unable to set capabilities")
	}

	reply, err := s.await(ctx, me, wire.OService, wire.OServiceUserInfoQuery, struct{}{})
	if err != nil {
		return nil, fmt.Errorf("unable to query user info: %w", err)
	}
	userInfo, ok := reply.Body.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate)
	if !ok || len(userInfo.UserInfo) == 0 {
		return nil, fmt.Errorf("unexpected user info reply %v", reply.Frame)
	}
	nick := "NICK:" + userInfo.UserInfo[0].ScreenName

	if cmd == "toc_signon" {
		u, err := s.TOCConfigStore.User(ctx, me.IdentScreenName())
		if err != nil {
			return nil, fmt.Errorf("TOCConfigStore.User: %w", err)
		}
		if u == nil {
			return nil, fmt.Errorf("TOCConfigStore.User: user not found")
		}
		return []string{"SIGN_ON:TOC1.0", fmt.Sprintf("CONFIG:%s", u.TOCConfig), nick}, nil
	}

	if msg := s.send(ctx, me, me.bos, wire.Feedbag, wire.FeedbagUse, struct{}{}, nil); msg != nil {
		return nil, errors.New("unable to use feedbag")
	}

	reply, err = s.await(ctx, me, wire.Feedbag, wire.FeedbagQuery, struct{}{})
	if err != nil {
		return nil, fmt.Errorf("unable to query feedbag: %w", err)
	}
	feedbag, ok := reply.Body.(wire.SNAC_0x13_0x06_FeedbagReply)
	if !ok {
		return nil, fmt.Errorf("unexpected feedbag reply %v", reply.Frame)
	}

	me.feedbag.reset(feedbag.Items)

	cfg, err := buildToc2Config(feedbag.Items)
	if err != nil {
		return nil, fmt.Errorf("buildToc2Config: %w", err)
	}
	return append([]string{"SIGN_ON:TOC2.0", nick}, cfg...), nil
}

// await sends a SNAC request over the BOS connection and waits for its reply.
// SNACs that arrive in the meantime are kept for RecvBOS. It is only used
// during signon, before RecvBOS starts.
func (s OSCARProxy) await(ctx context.Context, me *tocConn, foodGroup uint16, subGroup uint16, body any) (wire.SNACMessage, error) {
	frame := wire.SNACFrame{
		FoodGroup: foodGroup,
		SubGroup:  subGroup,
	}
	me.cache.add(&frame, nil)
	defer me.cache.remove(frame.RequestID)

	if err := me.bos.SendSNAC(frame, body); err != nil {
		return wire.SNACMessage{}, fmt.Errorf("SendSNAC: %w", err)
	}

	timeout := time.NewTimer(signonTimeout)
	defer timeout.Stop()

	for {
		select {
		case msg := <-me.bos.Messages():
			if msg.Frame.FoodGroup != foodGroup || msg.Frame.RequestID != frame.RequestID {
				me.backlog = append(me.backlog, msg)
				continue
			}
			if snacErr, ok := msg.Body.(wire.SNACError); ok {
				return wire.SNACMessage{}, fmt.Errorf("received SNAC error code %d", snacErr.Code)
			}
			return msg, nil
		case <-me.bos.Closed():
			return wire.SNACMessage{}, errSignedOff
		case <-timeout.C:
			return wire.SNACMessage{}, errors.New("timed out waiting for reply")
		case <-ctx.Done():
			return wire.SNACMessage{}, ctx.Err()
		}
	}
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
		group, ok := buddylist.groups[gid]
		if !ok {
			continue // the root group lists a group that isn't in the feedbag
		}
		cfg = append(cfg, "g:"+group.name)

		for _, bid := range group.order {
			buddy, ok := group.buddies[bid]
			if !ok {
				continue // the group lists a buddy that isn't in the feedbag
			}
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
	cookie, err := s.CookieBaker.Issue([]byte(me.String()), state.DefaultCookieTTL)
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
