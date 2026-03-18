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

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

var (
	// cmdInternalSvcErr indicates a general failure. Use wire.TOCErrorAdminProcessingRequest
	// error code as this is the closest applicable code as per TiK, Tameclone, phptoclib.
	cmdInternalSvcErr    = "ERROR:" + wire.TOCErrorAdminProcessingRequest + ":internal server error"
	rateLimitExceededErr = "ERROR:" + wire.TOCErrorGeneralRateLimitHit
	errDisconnect        = errors.New("got booted by another session")
)

// RecvBOS routes incoming SNAC messages from the BOS server to their
// corresponding TOC handlers. It ignores any SNAC messages for which there is
// no TOC response.
func (s OSCARProxy) RecvBOS(ctx context.Context, me *state.SessionInstance, chatRegistry *ChatRegistry, ch chan<- []string) error {
	for {
		select {
		case <-ctx.Done():
			me.CloseInstance()
			return nil
		case <-me.Closed():
			return errDisconnect
		case snac := <-me.ReceiveMessage():
			switch v := snac.Body.(type) {
			case wire.SNAC_0x03_0x0B_BuddyArrived:
				sendOrCancel(ctx, ch, s.UpdateBuddyArrival(v, me))
			case wire.SNAC_0x03_0x0C_BuddyDeparted:
				sendOrCancel(ctx, ch, s.UpdateBuddyDeparted(v, me))
			case wire.SNAC_0x04_0x07_ICBMChannelMsgToClient:
				sendOrCancel(ctx, ch, s.IMIn(ctx, chatRegistry, me, v))
			case wire.SNAC_0x01_0x10_OServiceEvilNotification:
				sendOrCancel(ctx, ch, s.Eviled(v))
			case wire.SNAC_0x04_0x14_ICBMClientEvent:
				if me.IsTOC2() {
					sendOrCancel(ctx, ch, s.ClientEvent(v))
				}
			case wire.SNAC_0x13_0x09_FeedbagUpdateItem:
				if me.IsTOC2() {
					sendOrCancel(ctx, ch, s.Inserted2(ctx, me, v))
				}
			case wire.SNAC_0x13_0x0A_FeedbagDeleteItem:
				if me.IsTOC2() {
					sendOrCancel(ctx, ch, s.Deleted2(ctx, me, v))
				}

			default:
				s.Logger.DebugContext(ctx, fmt.Sprintf("unsupported snac. foodgroup: %s subgroup: %s",
					wire.FoodGroupName(snac.Frame.FoodGroup),
					wire.SubGroupName(snac.Frame.FoodGroup, snac.Frame.SubGroup)))
			}
		}
	}
}

// RecvChat routes incoming SNAC messages from the chat server to their
// corresponding TOC handlers. It ignores any SNAC messages for which there is
// no TOC response.
func (s OSCARProxy) RecvChat(ctx context.Context, me *state.SessionInstance, chatID int, ch chan<- []string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-me.Closed():
			return
		case snac := <-me.ReceiveMessage():
			switch v := snac.Body.(type) {
			case wire.SNAC_0x0E_0x04_ChatUsersLeft:
				sendOrCancel(ctx, ch, s.ChatUpdateBuddyLeft(v, chatID))
			case wire.SNAC_0x0E_0x03_ChatUsersJoined:
				sendOrCancel(ctx, ch, s.ChatUpdateBuddyArrived(v, chatID))
			case wire.SNAC_0x0E_0x06_ChatChannelMsgToClient:
				sendOrCancel(ctx, ch, s.ChatIn(ctx, me, v, chatID))
			default:
				s.Logger.DebugContext(ctx, fmt.Sprintf("unsupported snac. foodgroup: %s subgroup: %s",
					wire.FoodGroupName(snac.Frame.FoodGroup),
					wire.SubGroupName(snac.Frame.FoodGroup, snac.Frame.SubGroup)))
			}
		}
	}
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
func (s OSCARProxy) ChatIn(ctx context.Context, me *state.SessionInstance, snac wire.SNAC_0x0E_0x06_ChatChannelMsgToClient, chatID int) []string {
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
func (s OSCARProxy) IMIn(ctx context.Context, chatRegistry *ChatRegistry, me *state.SessionInstance, snac wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) []string {
	switch snac.ChannelID {
	case wire.ICBMChannelIM:
		return []string{s.convertICBMInstantMsg(ctx, me, snac)}
	case wire.ICBMChannelRendezvous:
		return []string{s.convertICBMRendezvous(ctx, chatRegistry, snac)}
	default:
		s.Logger.DebugContext(ctx, "received unsupported ICBM channel message", "channel_id", snac.ChannelID)
		return []string{}
	}
}

// convertICBMInstantMsg converts an ICBM instant message SNAC to a TOC IM_IN or TOC2 IM_IN2, or TOC2Enhanced IM_IN_ENC2 response.
func (s OSCARProxy) convertICBMInstantMsg(ctx context.Context, me *state.SessionInstance, snac wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) string {
	buf, ok := snac.TLVRestBlock.Bytes(wire.ICBMTLVAOLIMData)
	if !ok {
		return s.runtimeErr(ctx, errors.New("TLVRestBlock.Bytes: missing wire.ICBMTLVAOLIMData"))[0]
	}
	txt, err := wire.UnmarshalICBMMessageText(buf)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalICBMMessageText: %w", err))[0]
	}

	autoResp := "F"
	if _, isAutoReply := snac.TLVRestBlock.Bytes(wire.ICBMTLVAutoResponse); isAutoReply {
		autoResp = "T"
	}

	if me.SupportsTOC2MsgEnc() {
		uFlags, hasVal := snac.TLVUserInfo.TLVList.Uint16BE(wire.OServiceUserInfoUserFlags)
		if !hasVal {
			s.Logger.DebugContext(ctx, "missing wire.OServiceUserInfoUserFlags in ICBM message")
			return ""
		}
		ucArray := userClassString(uFlags, snac.IsAway())
		// from a packet dump found in this russian zine: https://xn--lcss68aj21b.xn--w8je.xn--tckwe/books/xakep/spec65.pdf
		// interesting that "L" is a value, not sure what it's for.
		return fmt.Sprintf("IM_IN_ENC2:%s:%s:F:T:%s:F:L:en:%s", snac.ScreenName, autoResp, ucArray, txt)
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
	rdinfo, has := snac.TLVRestBlock.Bytes(wire.ICBMTLVData)
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
		user := snac.TLVUserInfo.ScreenName
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
func (s OSCARProxy) UpdateBuddyArrival(snac wire.SNAC_0x03_0x0B_BuddyArrived, me *state.SessionInstance) []string {
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
func (s OSCARProxy) UpdateBuddyDeparted(snac wire.SNAC_0x03_0x0C_BuddyDeparted, me *state.SessionInstance) []string {
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
// Inserted2 is invoked when this session receives FeedbagUpdateItem (e.g. list
// modified from another client). The feedbag is queried when adding buddies to
// resolve GroupID to group name; buddy alias comes from TLV.
func (s OSCARProxy) Inserted2(ctx context.Context, me *state.SessionInstance, snac wire.SNAC_0x13_0x09_FeedbagUpdateItem) []string {
	var out []string
	groupNameByID := make(map[uint16]string)
	hasBuddy := false
	for _, item := range snac.Items {
		if item.ClassID == wire.FeedbagClassIdBuddy {
			hasBuddy = true
			break
		}
	}
	if hasBuddy {
		fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
		if err != nil {
			s.Logger.DebugContext(ctx, "Inserted2: feedbag lookup failed", "err", err)
			return nil
		}
		for _, item := range fb {
			if item.ClassID == wire.FeedbagClassIdGroup {
				groupNameByID[item.GroupID] = item.Name
			}
		}
	}
	for _, item := range snac.Items {
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
// modified from another client). The feedbag is queried when deleting buddies to
// resolve GroupID to group name.
func (s OSCARProxy) Deleted2(ctx context.Context, me *state.SessionInstance, snac wire.SNAC_0x13_0x0A_FeedbagDeleteItem) []string {
	var out []string
	groupNameByID := make(map[uint16]string)
	hasBuddy := false
	for _, item := range snac.Items {
		if item.ClassID == wire.FeedbagClassIdBuddy {
			hasBuddy = true
			break
		}
	}
	if hasBuddy {
		fb, err := s.FeedbagManager.Feedbag(ctx, me.IdentScreenName())
		if err != nil {
			s.Logger.DebugContext(ctx, "Deleted2: feedbag lookup failed", "err", err)
			return nil
		}
		for _, item := range fb {
			if item.ClassID == wire.FeedbagClassIdGroup {
				groupNameByID[item.GroupID] = item.Name
			}
		}
	}
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
func userInfoToUpdateBuddy(snac wire.TLVUserInfo, me *state.SessionInstance) string {
	online, _ := snac.Uint32BE(wire.OServiceUserInfoSignonTOD)
	idle, _ := snac.Uint16BE(wire.OServiceUserInfoIdleTime)

	uFlags, _ := snac.TLVList.Uint16BE(wire.OServiceUserInfoUserFlags)
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
func userInfoToBuddyCaps(snac wire.TLVUserInfo, me *state.SessionInstance, logger *slog.Logger) string {
	if !me.IsTOC2() {
		return ""
	}
	b, hasCaps := snac.TLVList.Bytes(wire.OServiceUserInfoOscarCaps)
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
