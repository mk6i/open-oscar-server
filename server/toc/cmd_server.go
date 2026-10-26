package toc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/wire"
)

var (
	// cmdInternalSvcErr indicates a general failure. Use wire.TOCErrorAdminProcessingRequest
	// error code as this is the closest applicable code as per TiK, Tameclone, phptoclib.
	cmdInternalSvcErr    = "ERROR:" + wire.TOCErrorAdminProcessingRequest + ":internal server error"
	rateLimitExceededErr = "ERROR:" + wire.TOCErrorGeneralRateLimitHit
	errDisconnect        = errors.New("OSCAR server closed the connection")
)

// OServiceRateParamsChange codes the OSCAR server sends when one of the user's
// rate classes becomes limited or clears.
const (
	rateParamsChangeLimited uint16 = 3
	rateParamsChangeClear   uint16 = 4
)

// RecvBOS routes SNACs from the BOS server, replies and server-initiated
// messages alike, to their corresponding TOC handlers. It ignores any SNAC for
// which there is no TOC response.
func (s OSCARProxy) RecvBOS(ctx context.Context, me *tocConn) error {
	for _, snac := range me.backlog {
		s.recvBOSSNAC(ctx, me, snac)
	}
	me.backlog = nil

	for {
		select {
		case <-ctx.Done():
			me.bos.Close()
			return nil
		case <-me.bos.Closed():
			return errDisconnect
		case snac := <-me.bos.Messages():
			s.recvBOSSNAC(ctx, me, snac)
		}
	}
}

func (s OSCARProxy) recvBOSSNAC(ctx context.Context, me *tocConn, snac wire.SNACMessage) {
	var msg []string

	switch v := snac.Body.(type) {
	case wire.SNAC_0x03_0x0B_BuddyArrived:
		msg = s.UpdateBuddyArrival(v, me)
	case wire.SNAC_0x03_0x0C_BuddyDeparted:
		msg = s.UpdateBuddyDeparted(v, me)
	case wire.SNAC_0x04_0x07_ICBMChannelMsgToClient:
		msg = s.IMIn(ctx, me, v)
	case wire.SNAC_0x01_0x10_OServiceEvilNotification:
		msg = s.Eviled(v)
	case wire.SNAC_0x01_0x0A_OServiceRateParamsChange:
		msg = s.RateParamsChange(v)
		if v.Code == rateParamsChangeClear && me.feedbag.hasPending() {
			// the server may have dropped feedbag changes without replying
			// while limited
			msg = s.reloadFeedbag(ctx, me)
		}
	case wire.SNAC_0x04_0x14_ICBMClientEvent:
		if me.IsTOC2() {
			msg = s.ClientEvent(v)
		}
	case wire.SNAC_0x13_0x08_FeedbagInsertItem:
		if me.IsTOC2() {
			me.feedbag.applyRemote(false, v.Items)
			msg = s.Inserted2(me, v.Items)
		}
	case wire.SNAC_0x13_0x09_FeedbagUpdateItem:
		if me.IsTOC2() {
			me.feedbag.applyRemote(false, v.Items)
			msg = s.Inserted2(me, v.Items)
		}
	case wire.SNAC_0x13_0x0A_FeedbagDeleteItem:
		if me.IsTOC2() {
			msg = s.Deleted2(me, v)
			me.feedbag.applyRemote(true, v.Items)
		}
	case wire.SNACError:
		msg = s.SNACError(ctx, me, snac.Frame, v)
	case wire.SNAC_0x02_0x06_LocateUserInfoReply:
		msg = s.UserInfoReply(me, snac.Frame, v)
	case wire.SNAC_0x07_0x05_AdminChangeReply:
		msg = s.AdminChangeReply(ctx, me, snac.Frame, v)
	case wire.SNAC_0x0D_0x09_ChatNavNavInfo:
		msg = s.ChatNavInfo(ctx, me, snac.Frame, v)
	case wire.SNAC_0x01_0x05_OServiceServiceResponse:
		msg = s.ChatServiceResponse(ctx, me, snac.Frame, v)
	case wire.SNAC_0x13_0x0E_FeedbagStatus:
		s.FeedbagStatus(me, snac.Frame, v)
	case wire.SNAC_0x13_0x06_FeedbagReply:
		s.FeedbagReply(me, snac.Frame, v)
	case wire.SNAC_0x04_0x09_ICBMEvilReply:
		// the warning succeeded and there's nothing to tell the client
		me.cache.take(snac.Frame)
	default:
		s.Logger.DebugContext(ctx, fmt.Sprintf("unsupported snac. foodgroup: %s subgroup: %s",
			wire.FoodGroupName(snac.Frame.FoodGroup),
			wire.SubGroupName(snac.Frame.FoodGroup, snac.Frame.SubGroup)))
	}

	if len(msg) > 0 {
		sendOrCancel(ctx, me.toCh, msg)
	}
}

// RecvChat routes SNACs from a chat room connection to their corresponding
// TOC handlers. It ignores any SNAC for which there is no TOC response.
func (s OSCARProxy) RecvChat(ctx context.Context, me *tocConn, conn oscarConn, chatID int) {
	for {
		select {
		case <-ctx.Done():
			conn.Close()
			return
		case <-conn.Closed():
			return
		case snac := <-conn.Messages():
			switch v := snac.Body.(type) {
			case wire.SNAC_0x0E_0x04_ChatUsersLeft:
				sendOrCancel(ctx, me.toCh, s.ChatUpdateBuddyLeft(v, chatID))
			case wire.SNAC_0x0E_0x03_ChatUsersJoined:
				sendOrCancel(ctx, me.toCh, s.ChatUpdateBuddyArrived(v, chatID))
			case wire.SNAC_0x0E_0x06_ChatChannelMsgToClient:
				// a reflected message answers the user's own toc_chat_send
				me.cache.take(snac.Frame)
				sendOrCancel(ctx, me.toCh, s.ChatIn(ctx, me, v, chatID))
			case wire.SNAC_0x01_0x0A_OServiceRateParamsChange:
				if msg := s.RateParamsChange(v); len(msg) > 0 {
					sendOrCancel(ctx, me.toCh, msg)
				}
			case wire.SNACError:
				if msg := s.SNACError(ctx, me, snac.Frame, v); len(msg) > 0 {
					sendOrCancel(ctx, me.toCh, msg)
				}
			default:
				s.Logger.DebugContext(ctx, fmt.Sprintf("unsupported snac. foodgroup: %s subgroup: %s",
					wire.FoodGroupName(snac.Frame.FoodGroup),
					wire.SubGroupName(snac.Frame.FoodGroup, snac.Frame.SubGroup)))
			}
		}
	}
}

// RateParamsChange tells the client that it's being rate limited when one of
// its rate classes becomes limited, since the OSCAR server drops rate-limited
// requests without replying.
func (s OSCARProxy) RateParamsChange(snac wire.SNAC_0x01_0x0A_OServiceRateParamsChange) []string {
	if snac.Code == rateParamsChangeLimited {
		return []string{rateLimitExceededErr}
	}
	return nil
}

// SNACError handles an error reply from the OSCAR server according to the
// request that caused it.
func (s OSCARProxy) SNACError(ctx context.Context, me *tocConn, frame wire.SNACFrame, snac wire.SNACError) []string {
	req, ok := me.cache.take(frame)
	if !ok {
		s.Logger.DebugContext(ctx, "received SNAC error for unknown request",
			"foodgroup", wire.FoodGroupName(frame.FoodGroup), "code", snac.Code)
		return nil
	}

	switch data := req.data.(type) {
	case getStatusReqCtx:
		if snac.Code == wire.ErrorCodeNotLoggedOn {
			return []string{fmt.Sprintf("ERROR:%s:%s", wire.TOCErrorGeneralUserNotAvailable, data.screenName)}
		}
		return s.runtimeErr(ctx, fmt.Errorf("LocateUserInfoQuery error code: %d", snac.Code))
	case evilReqCtx:
		s.Logger.InfoContext(ctx, "unable to warn user", "code", snac.Code)
		return []string{"ERROR:" + wire.TOCErrorGeneralWarningUserNotAvailable}
	case feedbagChangeReqCtx:
		s.Logger.DebugContext(ctx, "feedbag change failed", "code", snac.Code)
		me.feedbag.discard(frame.RequestID)
		return nil
	case chatJoinReqCtx, chatAcceptReqCtx, chatServiceReqCtx:
		return s.runtimeErr(ctx, fmt.Errorf("unable to join chat room, %s error code: %d",
			wire.SubGroupName(req.frame.FoodGroup, req.frame.SubGroup), snac.Code))
	default:
		s.Logger.DebugContext(ctx, "received SNAC error",
			"request", wire.SubGroupName(req.frame.FoodGroup, req.frame.SubGroup), "code", snac.Code)
		return nil
	}
}

// FeedbagStatus confirms the items of a feedbag change that the server
// accepted.
func (s OSCARProxy) FeedbagStatus(me *tocConn, frame wire.SNACFrame, snac wire.SNAC_0x13_0x0E_FeedbagStatus) {
	me.cache.take(frame)
	me.feedbag.confirm(frame.RequestID, snac.Results)
}

// FeedbagReply finishes reloading the feedbag mirror.
func (s OSCARProxy) FeedbagReply(me *tocConn, frame wire.SNACFrame, snac wire.SNAC_0x13_0x06_FeedbagReply) {
	req, ok := me.cache.take(frame)
	if !ok {
		return
	}
	if data, ok := req.data.(feedbagReloadReqCtx); ok {
		me.feedbag.reload(data.marker, snac.Items)
	}
}

// UserInfoReply handles the user info reply to toc_get_status, which is sent
// to the client as UPDATE_BUDDY.
func (s OSCARProxy) UserInfoReply(me *tocConn, frame wire.SNACFrame, snac wire.SNAC_0x02_0x06_LocateUserInfoReply) []string {
	me.cache.take(frame)
	return []string{userInfoToUpdateBuddy(snac.TLVUserInfo, me)}
}

// AdminChangeReply handles the reply to toc_change_passwd, sent as
// ADMIN_PASSWD_STATUS, or to toc_format_nickname, sent as ADMIN_NICK_STATUS
// and NICK.
func (s OSCARProxy) AdminChangeReply(ctx context.Context, me *tocConn, frame wire.SNACFrame, snac wire.SNAC_0x07_0x05_AdminChangeReply) []string {
	req, ok := me.cache.take(frame)
	if !ok {
		s.Logger.DebugContext(ctx, "received admin change reply for unknown request")
		return nil
	}

	code, hasErr := snac.Uint16BE(wire.AdminTLVErrorCode)

	switch req.data.(type) {
	case changePasswdReqCtx:
		if hasErr {
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
	case formatNickReqCtx:
		if hasErr {
			switch code {
			case wire.AdminInfoErrorInvalidNickNameLength, wire.AdminInfoErrorInvalidNickName:
				return []string{"ERROR:" + wire.TOCErrorAdminInvalidInput}
			default:
				return []string{"ERROR:" + wire.TOCErrorAdminProcessingRequest}
			}
		}
		val, hasVal := snac.String(wire.AdminTLVScreenNameFormatted)
		if !hasVal {
			return s.runtimeErr(ctx, fmt.Errorf("AdminChangeReply: missing AdminTLVScreenNameFormatted %v", snac))
		}
		return []string{"ADMIN_NICK_STATUS:0", "NICK:" + val}
	default:
		return s.runtimeErr(ctx, fmt.Errorf("AdminChangeReply: unexpected request %v", req.frame))
	}
}

// ChatNavInfo continues toc_chat_join and toc_chat_accept once the chat room
// info arrives, by requesting a connection to the room.
func (s OSCARProxy) ChatNavInfo(ctx context.Context, me *tocConn, frame wire.SNACFrame, snac wire.SNAC_0x0D_0x09_ChatNavNavInfo) []string {
	req, ok := me.cache.take(frame)
	if !ok {
		s.Logger.DebugContext(ctx, "received chat nav info for unknown request")
		return nil
	}

	b, hasInfo := snac.Bytes(wire.ChatNavTLVRoomInfo)
	if !hasInfo {
		return s.runtimeErr(ctx, errors.New("ChatNavNavInfo: missing wire.ChatNavTLVRoomInfo"))
	}

	roomInfo := wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{}
	if err := wire.UnmarshalBE(&roomInfo, bytes.NewReader(b)); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalBE: %w", err))
	}
	roomName, hasName := roomInfo.String(wire.ChatRoomTLVRoomName)
	if !hasName {
		return s.runtimeErr(ctx, errors.New("roomInfo.String: missing wire.ChatRoomTLVRoomName"))
	}

	switch data := req.data.(type) {
	case chatJoinReqCtx:
		chatID := me.chats.Add(wire.ICBMRoomInfo{
			Exchange: roomInfo.Exchange,
			Cookie:   roomInfo.Cookie,
			Instance: roomInfo.InstanceNumber,
		})
		return s.requestChatService(ctx, me, chatID, roomName, roomInfo.Cookie)
	case chatAcceptReqCtx:
		return s.requestChatService(ctx, me, data.chatID, roomName, roomInfo.Cookie)
	default:
		return s.runtimeErr(ctx, fmt.Errorf("ChatNavNavInfo: unexpected request %v", req.frame))
	}
}

// ChatServiceResponse finishes toc_chat_join and toc_chat_accept by
// connecting to the chat room. It sends CHAT_JOIN before relaying anything
// from the room, so that the client knows the room before its first
// CHAT_UPDATE_BUDDY.
func (s OSCARProxy) ChatServiceResponse(ctx context.Context, me *tocConn, frame wire.SNACFrame, snac wire.SNAC_0x01_0x05_OServiceServiceResponse) []string {
	req, ok := me.cache.take(frame)
	if !ok {
		s.Logger.DebugContext(ctx, "received service response for unknown request")
		return nil
	}
	data, ok := req.data.(chatServiceReqCtx)
	if !ok {
		return s.runtimeErr(ctx, fmt.Errorf("OServiceServiceResponse: unexpected request %v", req.frame))
	}

	loginCookie, hasCookie := snac.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !hasCookie {
		return s.runtimeErr(ctx, errors.New("OServiceServiceResponse: missing wire.OServiceTLVTagsLoginCookie"))
	}

	conn, err := s.connectChat(ctx, me, loginCookie)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("connectChat: %w", err))
	}
	me.chats.RegisterConn(data.chatID, conn)

	sendOrCancel(ctx, me.toCh, []string{fmt.Sprintf("CHAT_JOIN:%d:%s", data.chatID, data.roomName)})

	me.goAsync(func(ctx context.Context) error {
		s.RecvChat(ctx, me, conn, data.chatID)
		return nil
	})
	return nil
}

// ChatIn handles the CHAT_IN and ENC_CHAT_IN TOC commands.
//
// From the TiK documentation:
//
//	A chat message was sent in a chat room.
//
// From the BlueTOC documentation:
//
//	This command received instead of CHAT_IN. It is similar to TOC 1.0 except there are a two new parameters.
//	One of them is language; the other is unknown but is usually "A"
//
// Command syntax: CHAT_IN:<Chat Room Id>:<Source User>:<Whisper? T/F>:<Message>
// Command syntax: CHAT_IN_ENC:<chatroom id>:<user>:<whisper T/F>:<???>:en:<message>
func (s OSCARProxy) ChatIn(ctx context.Context, me *tocConn, snac wire.SNAC_0x0E_0x06_ChatChannelMsgToClient, chatID int) []string {
	b, ok := snac.Bytes(wire.ChatTLVSenderInformation)
	if !ok {
		return s.runtimeErr(ctx, errors.New("snac.Bytes: missing wire.ChatTLVSenderInformation"))
	}

	u := wire.TLVUserInfo{}
	err := wire.UnmarshalBE(&u, bytes.NewReader(b))
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalBE: %w", err))
	}

	b, ok = snac.Bytes(wire.ChatTLVMessageInfo)
	if !ok {
		return s.runtimeErr(ctx, errors.New("snac.Bytes: missing wire.ChatTLVMessageInfo"))
	}

	text, err := wire.UnmarshalChatMessageText(b)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalChatMessageText: %w", err))
	}

	if me.SupportsTOC2MsgEnc() {
		return []string{fmt.Sprintf("CHAT_IN_ENC:%d:%s:F:A:en:%s", chatID, u.ScreenName, text)}
	}

	return []string{fmt.Sprintf("CHAT_IN:%d:%s:F:%s", chatID, u.ScreenName, text)}
}

// ChatUpdateBuddyArrived handles the CHAT_UPDATE_BUDDY TOC command for chat
// room arrival events.
//
// From the TiK documentation:
//
//	This one command handles arrival/departs from a chat room. The very first
//	message of this type for each chat room contains the users already in the
//	room.
//
// Command syntax: CHAT_UPDATE_BUDDY:<Chat Room Id>:<Inside? T/F>:<User 1>:<User 2>...
func (s OSCARProxy) ChatUpdateBuddyArrived(snac wire.SNAC_0x0E_0x03_ChatUsersJoined, chatID int) []string {
	users := make([]string, 0, len(snac.Users))
	for _, u := range snac.Users {
		users = append(users, u.ScreenName)
	}
	return []string{fmt.Sprintf("CHAT_UPDATE_BUDDY:%d:T:%s", chatID, strings.Join(users, ":"))}
}

// ChatUpdateBuddyLeft handles the CHAT_UPDATE_BUDDY TOC command for chat
// room departure events.
//
// From the TiK documentation:
//
//	This one command handles arrival/departs from a chat room. The very first
//	message of this type for each chat room contains the users already in the
//	room.
//
// Command syntax: CHAT_UPDATE_BUDDY:<Chat Room Id>:<Inside? T/F>:<User 1>:<User 2>...
func (s OSCARProxy) ChatUpdateBuddyLeft(snac wire.SNAC_0x0E_0x04_ChatUsersLeft, chatID int) []string {
	users := make([]string, 0, len(snac.Users))
	for _, u := range snac.Users {
		users = append(users, u.ScreenName)
	}
	return []string{fmt.Sprintf("CHAT_UPDATE_BUDDY:%d:F:%s", chatID, strings.Join(users, ":"))}
}

// Eviled handles the EVILED TOC command.
//
// From the TiK documentation:
//
//	The user was just eviled.
//
// Command syntax: EVILED:<new evil>:<name of eviler, blank if anonymous>
func (s OSCARProxy) Eviled(snac wire.SNAC_0x01_0x10_OServiceEvilNotification) []string {
	warning := fmt.Sprintf("%d", snac.NewEvil/10)
	who := ""
	if snac.Snitcher != nil {
		who = snac.Snitcher.ScreenName
	}
	return []string{fmt.Sprintf("EVILED:%s:%s", warning, who)}
}

// IMIn handles incoming ICBM channel messages and returns one of: IM_IN (TOC1), IM_IN2 or
// IM_IN_ENC2 (TOC2), or for rendezvous channel CHAT_INVITE or RVOUS_PROPOSE.
//
// From the TiK documentation (TOC1 IM_IN):
//
//	Receive an IM from someone. Everything after the third colon is the
//	incoming message, including other colons.
//
// TOC2 clients receive IM_IN2 (same structure as IM_IN with an extra field) or
// IM_IN_ENC2 when the client supports encoded messages (BlueTOC/BizTOCSock documentation).
// For ICBM rendezvous (chat invite, file transfer), this returns CHAT_INVITE or RVOUS_PROPOSE
// instead (see convertICBMRendezvous).
//
// Command syntax: IM_IN:<Source User>:<Auto Response T/F?>:<Message>
// Command syntax: IM_IN2:<Source User>:<Auto Response T/F?>:<Whisper?>:<Message>
// Command syntax: IM_IN_ENC2:<User>:<Auto>:<???>:<???>:<User Class>:<???>:<???>:<Language>:<Message>
func (s OSCARProxy) IMIn(ctx context.Context, me *tocConn, snac wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) []string {
	switch snac.ChannelID {
	case wire.ICBMChannelIM:
		return []string{s.convertICBMInstantMsg(ctx, me, snac)}
	case wire.ICBMChannelRendezvous:
		return []string{s.convertICBMRendezvous(ctx, me.chats, snac)}
	default:
		s.Logger.DebugContext(ctx, "received unsupported ICBM channel message", "channel_id", snac.ChannelID)
		return []string{}
	}
}

// convertICBMInstantMsg converts an ICBM instant message SNAC to a TOC IM_IN or TOC2 IM_IN2, or TOC2Enhanced IM_IN_ENC2 response.
func (s OSCARProxy) convertICBMInstantMsg(ctx context.Context, me *tocConn, snac wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) string {
	buf, ok := snac.Bytes(wire.ICBMTLVAOLIMData)
	if !ok {
		return s.runtimeErr(ctx, errors.New("TLVRestBlock.Bytes: missing wire.ICBMTLVAOLIMData"))[0]
	}
	txt, err := wire.UnmarshalICBMMessageText(buf)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalICBMMessageText: %w", err))[0]
	}

	autoResp := "F"
	if _, isAutoReply := snac.Bytes(wire.ICBMTLVAutoResponse); isAutoReply {
		autoResp = "T"
	}

	if me.SupportsTOC2MsgEnc() {
		uFlags, _ := snac.TLVUserInfo.Uint16BE(wire.OServiceUserInfoUserFlags)
		classStr := userClassString(uFlags, snac.IsAway())
		// from a packet dump found in this russian zine: https://xn--lcss68aj21b.xn--w8je.xn--tckwe/books/xakep/spec65.pdf
		// interesting that "L" is a value, not sure what it's for.
		return fmt.Sprintf("IM_IN_ENC2:%s:%s:F:T:%s:F:L:en:%s", snac.ScreenName, autoResp, classStr, txt)
	}

	if me.IsTOC2() {
		return fmt.Sprintf("IM_IN2:%s:%s:%s:%s", snac.ScreenName, autoResp, "F", txt)
	}

	return fmt.Sprintf("IM_IN:%s:%s:%s", snac.ScreenName, autoResp, txt)
}

// convertICBMRendezvous converts an ICBM rendezvous SNAC to a TOC response.
//   - if chat, return CHAT_INVITE
//   - file transfer, return RVOUS_PROPOSE
//   - don't respond for other rendezvous types
func (s OSCARProxy) convertICBMRendezvous(ctx context.Context, chatRegistry *ChatRegistry, snac wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) string {
	rdinfo, has := snac.Bytes(wire.ICBMTLVData)
	if !has {
		return s.runtimeErr(ctx, errors.New("TLVRestBlock.Bytes: missing rendezvous block"))[0]
	}
	frag := wire.ICBMCh2Fragment{}
	if err := wire.UnmarshalBE(&frag, bytes.NewReader(rdinfo)); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalBE: %w", err))[0]
	}

	if frag.Type != wire.ICBMRdvMessagePropose {
		s.Logger.DebugContext(ctx, "can't convert ICBM rendezvous message to TOC response", "rdv_type", frag.Type)
		return ""
	}

	switch uuid.UUID(frag.Capability) {
	case wire.CapChat:
		prompt, ok := frag.Bytes(wire.ICBMRdvTLVTagsInvitation)
		if !ok {
			return s.runtimeErr(ctx, errors.New("frag.Bytes: missing chat invite prompt"))[0]
		}

		svcData, ok := frag.Bytes(wire.ICBMRdvTLVTagsSvcData)
		if !ok || svcData == nil {
			return s.runtimeErr(ctx, errors.New("frag.Bytes: missing room info"))[0]
		}

		roomInfo := wire.ICBMRoomInfo{}
		if err := wire.UnmarshalBE(&roomInfo, bytes.NewReader(svcData)); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalBE: %w", err))[0]
		}

		cookie := strings.Split(roomInfo.Cookie, "-") // make this safe
		if len(cookie) < 3 {
			return s.runtimeErr(ctx, errors.New("roomInfo.Cookie: malformed cookie, could not get room name"))[0]
		}

		roomName := cookie[2]
		chatID := chatRegistry.Add(roomInfo)

		return fmt.Sprintf("CHAT_INVITE:%s:%d:%s:%s", roomName, chatID, snac.ScreenName, prompt)
	case wire.CapFileTransfer:
		user := snac.ScreenName
		capability := strings.ToUpper(wire.CapFileTransfer.String()) // TiK requires upper-case UUID characters
		cookie := base64.StdEncoding.EncodeToString(frag.Cookie[:])
		seq, _ := frag.Uint16BE(wire.ICBMRdvTLVTagsSeqNum)

		rvousIP := "0.0.0.0"
		if ip, ok := frag.Bytes(wire.ICBMRdvTLVTagsRdvIP); ok && len(ip) == 4 {
			rvousIP = net.IPv4(ip[0], ip[1], ip[2], ip[3]).String()
		}

		proposerIP := "0.0.0.0"
		if ip, ok := frag.Bytes(wire.ICBMRdvTLVTagsRequesterIP); ok && len(ip) == 4 {
			proposerIP = net.IPv4(ip[0], ip[1], ip[2], ip[3]).String()
		}

		verifiedIP := "0.0.0.0"
		if ip, ok := frag.Bytes(wire.ICBMRdvTLVTagsVerifiedIP); ok && len(ip) == 4 {
			verifiedIP = net.IPv4(ip[0], ip[1], ip[2], ip[3]).String()
		}

		rvousPort, _ := frag.Uint16BE(wire.ICBMRdvTLVTagsPort)

		var fileMetadata string
		if f, ok := frag.Bytes(wire.ICBMRdvTLVTagsSvcData); ok {
			// remove sequence of null bytes from the end that causes TiK file open
			// dialog to crash
			f = bytes.TrimRight(f, "\x00")
			fileMetadata = base64.StdEncoding.EncodeToString(f)
		}

		return fmt.Sprintf("RVOUS_PROPOSE:%s:%s:%s:%d:%s:%s:%s:%d:%d:%s",
			user, capability, cookie, seq, rvousIP, proposerIP, verifiedIP, rvousPort, wire.ICBMRdvTLVTagsSvcData, fileMetadata)
	default:
		s.Logger.DebugContext(ctx, "received rendezvous ICBM for unsupported capability", "capability", wire.CapChat)
		return ""
	}
}

// UpdateBuddyArrival handles the UPDATE_BUDDY TOC command for buddy arrival events.
//
// From the TiK documentation:
//
//	This one command handles arrival/depart/updates. Evil Amount is a percentage, Signon Time is UNIX epoc, idle time is in minutes, UC (User Class) is a two/three character string.
//		- uc[0]
//			- ' ' - Ignore
//			- 'A' - On AOL
//		- uc[1]
//			- ' ' - Ignore
//			- 'A' - Oscar Admin
//			- 'U' - Oscar Unconfirmed
//			- 'O' - Oscar Normal
//		- uc[2]
//			- '\0' - Ignore
//			- ' ' - Ignore
//			- 'U' - The user has set their unavailable flag.
//
// Command syntax: UPDATE_BUDDY:<Buddy User>:<Online? T/F>:<Evil Amount>:<Signon Time>:<IdleTime>:<UC>
//
// For TOC2 this sends UPDATE_BUDDY2 with the same fields (plus a trailing field). When
// the buddy has capabilities, BUDDY_CAPS2 is also sent (see userInfoToBuddyCaps).
func (s OSCARProxy) UpdateBuddyArrival(snac wire.SNAC_0x03_0x0B_BuddyArrived, me *tocConn) []string {
	msgs := []string{userInfoToUpdateBuddy(snac.TLVUserInfo, me)}
	if caps := userInfoToBuddyCaps(snac.TLVUserInfo, me, s.Logger); caps != "" {
		msgs = append(msgs, caps)
	}
	return msgs
}

// UpdateBuddyDeparted handles the UPDATE_BUDDY TOC command for buddy departure events.
//
// From the TiK documentation:
//
//	This one command handles arrival/depart/updates. Evil Amount is a
//	percentage, Signon Time is UNIX epoc, idle time is in minutes, UC (User
//	Class) is a two/three character string.
//		- uc[0]
//			- ' ' - Ignore
//			- 'A' - On AOL
//		- uc[1]
//			- ' ' - Ignore
//			- 'A' - Oscar Admin
//			- 'U' - Oscar Unconfirmed
//			- 'O' - Oscar Normal
//		- uc[2]
//			- '\0' - Ignore
//			- ' ' - Ignore
//			- 'U' - The user has set their unavailable flag.
//
// Command syntax: UPDATE_BUDDY:<Buddy User>:<Online? T/F>:<Evil Amount>:<Signon Time>:<IdleTime>:<UC>
// TOC2 uses UPDATE_BUDDY2 with the same fields.
func (s OSCARProxy) UpdateBuddyDeparted(snac wire.SNAC_0x03_0x0C_BuddyDeparted, me *tocConn) []string {
	if me.IsTOC2() {
		return []string{fmt.Sprintf("UPDATE_BUDDY2:%s:F:0:0:0:   :", snac.ScreenName)}
	}
	return []string{fmt.Sprintf("UPDATE_BUDDY:%s:F:0:0:0:   ", snac.ScreenName)}
}

// Inserted2 handles the INSERTED2 TOC2 server-to-client notifications.
//
// From the BlueTOC documentation:
//
//	Sent whenever the buddy list is modified from a different location (e.g. logged
//	in twice). Dynamic updates when items are added to the buddy list.
//
//	INSERTED2:g:<group name>
//	  A new group has been added to the buddy list.
//
//	INSERTED2:b:<alias>:<username>:<group>
//	  A new screenname has been added.
//
//	INSERTED2:d:<username>
//	  Somebody has been added to the deny list.
//
//	INSERTED2:p:<username>
//	  Somebody has been added to the permit list.
//
// Inserted2 is invoked when this session receives FeedbagInsertItem or
// FeedbagUpdateItem (e.g. list modified from another client). Group names come
// from the feedbag mirror; buddy alias comes from TLV.
func (s OSCARProxy) Inserted2(me *tocConn, items []wire.FeedbagItem) []string {
	var out []string
	groupNameByID := me.feedbag.groupNames()
	for _, item := range items {
		switch item.ClassID {
		case wire.FeedbagClassIdGroup:
			out = append(out, fmt.Sprintf("INSERTED2:g:%s", item.Name))
		case wire.FeedbagClassIdBuddy:
			group := groupNameByID[item.GroupID]
			if group == "" {
				group = "Buddies"
			}
			alias := ""
			if b, ok := item.Bytes(wire.FeedbagAttributesAlias); ok {
				alias = string(b)
			}
			out = append(out, fmt.Sprintf("INSERTED2:b:%s:%s:%s", alias, item.Name, group))
		case wire.FeedbagClassIDDeny:
			out = append(out, fmt.Sprintf("INSERTED2:d:%s", item.Name))
		case wire.FeedbagClassIDPermit:
			out = append(out, fmt.Sprintf("INSERTED2:p:%s", item.Name))
		}
	}
	return out
}

// Deleted2 handles the DELETED2 TOC2 server-to-client notifications.
//
// From the BlueTOC documentation:
//
//	Sent whenever the buddy list is modified from a different location. Dynamic
//	updates when items are removed from the buddy list.
//
//	DELETED2:g:<group name>
//	  A group has been deleted from the buddy list.
//
//	DELETED2:b:<username>:<group>
//	  A user has been deleted from the buddy list.
//
//	DELETED2:d:<username>
//	  A user has been removed from the deny list.
//
//	DELETED2:p:<username>
//	  A user has been removed from the permit list.
//
// Deleted2 is invoked when this session receives FeedbagDeleteItem (e.g. list
// modified from another client), before the items leave the feedbag mirror, so
// that deleted buddies' group names can still be found there.
func (s OSCARProxy) Deleted2(me *tocConn, snac wire.SNAC_0x13_0x0A_FeedbagDeleteItem) []string {
	var out []string
	groupNameByID := me.feedbag.groupNames()
	for _, item := range snac.Items {
		switch item.ClassID {
		case wire.FeedbagClassIdGroup:
			out = append(out, fmt.Sprintf("DELETED2:g:%s", item.Name))
		case wire.FeedbagClassIdBuddy:
			group := groupNameByID[item.GroupID]
			if group == "" {
				group = "Buddies"
			}
			out = append(out, fmt.Sprintf("DELETED2:b:%s:%s", item.Name, group))
		case wire.FeedbagClassIDDeny:
			out = append(out, fmt.Sprintf("DELETED2:d:%s", item.Name))
		case wire.FeedbagClassIDPermit:
			out = append(out, fmt.Sprintf("DELETED2:p:%s", item.Name))
		}
	}
	return out
}

// ClientEvent handles the CLIENT_EVENT2 TOC2 command.
//
// From BizTOCSock documentation:
//
//	I discovered this a while ago, but this is the typing status of a user in IMs, much
//  like what AIM does. It is only sent while you're currently being IMed by someone.
//  There are only three codes as I know of, but I believe there is one for "User is
//  recording..." If it were one, it would probably be code 3.

//	0 = User is doing nothing
//	1 = User has entered text
//	2 = User is currently typing
//
// Command syntax: CLIENT_EVENT2:<Buddy User>:<Typing Status>
func (s OSCARProxy) ClientEvent(snac wire.SNAC_0x04_0x14_ICBMClientEvent) []string {
	return []string{fmt.Sprintf("CLIENT_EVENT2:%s:%d", snac.ScreenName, snac.Event)}
}

// userClassString generates the 3-character user class (UC) string based on user flags and away status.
func userClassString(uFlags uint16, isAway bool) string {
	uc := [3]string{" ", " ", " "}

	if hasFlag(uFlags, wire.OServiceUserFlagAOL) {
		uc[0] = "A"
	}

	if hasFlag(uFlags, wire.OServiceUserFlagAdministrator) {
		uc[1] = "A"
	} else if hasFlag(uFlags, wire.OServiceUserFlagWireless) {
		uc[1] = "C"
	} else if hasFlag(uFlags, wire.OServiceUserFlagUnconfirmed) {
		uc[1] = "U"
	} else if hasFlag(uFlags, wire.OServiceUserFlagOSCARFree) {
		uc[1] = "O"
	}

	if isAway {
		uc[2] = "U"
	}

	return strings.Join(uc[:], "")
}

func sendOrCancel(ctx context.Context, ch chan<- []string, msg []string) {
	select {
	case <-ctx.Done():
		return
	case ch <- msg:
		return
	}
}

// userInfoToUpdateBuddy creates an UPDATE_BUDDY or UPDATE_BUDDY2 server reply from a User
// Info TLV.
func userInfoToUpdateBuddy(snac wire.TLVUserInfo, me *tocConn) string {
	online, _ := snac.Uint32BE(wire.OServiceUserInfoSignonTOD)
	idle, _ := snac.Uint16BE(wire.OServiceUserInfoIdleTime)

	uFlags, _ := snac.Uint16BE(wire.OServiceUserInfoUserFlags)
	uc := userClassString(uFlags, snac.IsAway())
	warning := fmt.Sprintf("%d", snac.WarningLevel/10)

	if me.IsTOC2() {
		return fmt.Sprintf("UPDATE_BUDDY2:%s:%s:%s:%d:%d:%s:", snac.ScreenName, "T", warning, online, idle, uc)
	}

	return fmt.Sprintf("UPDATE_BUDDY:%s:%s:%s:%d:%d:%s", snac.ScreenName, "T", warning, online, idle, uc)
}

// hasFlag checks if a specific flag is set in the bitmask.
func hasFlag[T ~uint16 | ~uint8](bitmask, flag T) bool {
	return (bitmask & flag) == flag
}

// userInfoToBuddyCaps creates a BUDDY_CAPS2 server-to-client message from a User Info TLV.
//
// From the BizTOCSock documentation:
//
//	These are the buddies capabilities, such as Chat, Live Video, Direct Connect, etc.
//	They are sent with every UPDATE_BUDDY2. If a user updates to where they can use
//	Direct Connect, you will get sent both packets.
//
// Format: BUDDY_CAPS2:<User>:<Cap1>,<Cap2>,...
func userInfoToBuddyCaps(snac wire.TLVUserInfo, me *tocConn, logger *slog.Logger) string {
	if !me.IsTOC2() {
		return ""
	}
	b, hasCaps := snac.Bytes(wire.OServiceUserInfoOscarCaps)
	if !hasCaps {
		logger.DebugContext(context.Background(), "userInfoToBuddyCaps: no buddy caps found")
		return ""
	}
	if len(b)%16 != 0 {
		logger.DebugContext(context.Background(), "userInfoToBuddyCaps: buddy caps length not divisible by 16")
		return ""
	}
	var capStrings []string
	for i := 0; i < len(b); i += 16 {
		var c [16]byte
		copy(c[:], b[i:i+16])
		uid := uuid.UUID(c)
		capStrings = append(capStrings, uid.String())
	}
	clientCaps := strings.Join(capStrings, ",")
	return fmt.Sprintf("BUDDY_CAPS2:%s:%s", snac.ScreenName, clientCaps)
}
