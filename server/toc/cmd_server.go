package toc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

var (
	cmdInternalSvcErr    = fmt.Sprintf("ERROR:%s:internal server error", wire.TOCErrorAuthUnknownError) // jgk: should this be a SubErrorCode?
	rateLimitExceededErr = "ERROR:903"
	errDisconnect        = errors.New("got booted by another session")
)

// RecvBOS routes incoming SNAC messages from the BOS server to their
// corresponding TOC handlers. It ignores any SNAC messages for which there is
// no TOC response.
func (s OSCARProxy) RecvBOS(ctx context.Context, me *state.SessionInstance, chatRegistry *ChatRegistry, ch chan<- []string) error {
	for {
		select {
		case <-ctx.Done():
			func() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				s.Signout(shutdownCtx, me, chatRegistry)
			}()
			return nil
		case <-me.Closed():
			return errDisconnect
		case snac := <-me.ReceiveMessage():
			switch v := snac.Body.(type) {
			case wire.SNAC_0x03_0x0B_BuddyArrived:
				sendOrCancel(ctx, ch, s.UpdateBuddyArrival(v, me))
			case wire.SNAC_0x03_0x0C_BuddyDeparted:
				sendOrCancel(ctx, ch, s.UpdateBuddyDeparted(v))
			case wire.SNAC_0x04_0x07_ICBMChannelMsgToClient:
				sendOrCancel(ctx, ch, s.IMIn(ctx, chatRegistry, me, v))
			case wire.SNAC_0x01_0x10_OServiceEvilNotification:
				sendOrCancel(ctx, ch, s.Eviled(v))
			case wire.SNAC_0x04_0x14_ICBMClientEvent:
				if hasFlag(me.TocVersion(), state.SupportsTOC2Enhanced) {
					sendOrCancel(ctx, ch, s.ClientEvent(v))
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
				sendOrCancel(ctx, ch, s.ChatIn(ctx, v, chatID))
			default:
				s.Logger.DebugContext(ctx, fmt.Sprintf("unsupported snac. foodgroup: %s subgroup: %s",
					wire.FoodGroupName(snac.Frame.FoodGroup),
					wire.SubGroupName(snac.Frame.FoodGroup, snac.Frame.SubGroup)))
			}
		}
	}
}

// ChatIn handles the CHAT_IN TOC command.
//
// From the TiK documentation:
//
//	A chat message was sent in a chat room.
//
// Command syntax: CHAT_IN:<Chat Room Id>:<Source User>:<Whisper? T/F>:<Message>
func (s OSCARProxy) ChatIn(ctx context.Context, snac wire.SNAC_0x0E_0x06_ChatChannelMsgToClient, chatID int) []string {
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

// IMIn handles the IM_IN and IM_IN_ENC2 TOC commands.
//
// From the TiK documentation:
//
//	Receive an IM from someone. Everything after the third colon is the
//	incoming message, including other colons.
//
// Command syntax: IM_IN:<Source User>:<Auto Response T/F?>:<Message>
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
	fmt.Println(("jgk: convertICBMInstantMsg"))
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

	if hasFlag(me.TocVersion(), state.SupportsTOC2Enhanced) {
		// IM_IN_ENC2:<user>:<auto>:<???>:<???>:<buddy status>:<???>:<???>:en:<message>
		uFlags, hasVal := snac.TLVUserInfo.TLVList.Uint16BE(wire.OServiceUserInfoUserFlags)
		if !hasVal {
			// todo: handle if this tlv doesn't exist for some reason
			fmt.Println("no has val")
			return ""
		}
		ucArray := userClassString(uFlags, snac.IsAway())
		uc := strings.Join(ucArray[:], "")
		return fmt.Sprintf("IM_IN_ENC2:%s:%s:::%s:::en:%s", snac.ScreenName, autoResp, uc, txt)
	}

	cmdSuffix := ""
	if (me.TocVersion() & state.SupportsTOC2) == state.SupportsTOC2 {
		cmdSuffix = "2"
	}
	return fmt.Sprintf("IM_IN%s:%s:%s:%s", cmdSuffix, snac.ScreenName, autoResp, txt)
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
func (s OSCARProxy) UpdateBuddyArrival(snac wire.SNAC_0x03_0x0B_BuddyArrived, me *state.SessionInstance) []string {

	return []string{userInfoToUpdateBuddy(snac.TLVUserInfo, me), userInfoToBuddyCaps(snac.TLVUserInfo, me)}
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
func (s OSCARProxy) UpdateBuddyDeparted(snac wire.SNAC_0x03_0x0C_BuddyDeparted) []string {
	return []string{fmt.Sprintf("UPDATE_BUDDY:%s:F:0:0:0:   ", snac.ScreenName)}
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
//	1 = User has enterted Text
//	2 = User is currently typing
//
// Command syntax: CLIENT_EVENT2:<Buddy User>:<Typing Status>
func (s OSCARProxy) ClientEvent(snac wire.SNAC_0x04_0x14_ICBMClientEvent) []string {
	return []string{fmt.Sprintf("CLIENT_EVENT2:%s:%d", snac.ScreenName, snac.Event)}
}

// userClassString generates the 3-character user class (UC) string based on user flags and away status.
func userClassString(uFlags uint16, isAway bool) [3]string {
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
	return uc
}

func sendOrCancel(ctx context.Context, ch chan<- []string, msg []string) {
	select {
	case <-ctx.Done():
		return
	case ch <- msg:
		return
	}
}

// '''''''BUDDY_CAPS2''''''''

// '[BUDDY_CAPS2] [User] [Cap 1, Cap 2, Cap3, etc]

// 'These are the buddies capabilities, such as Chat, Live Video, Direct Connect, etc.
// 'These are sent with every UPDATE_BUDDY2. Meaning, if a user updates to where they
// 'can use Direct Connect, you will get sent both packets.

// 'Example: BUDDY_CAPS2:Bizkit047:0,105,1FF,1,101,102,
// wire.OServiceUserInfoOscarCaps

// userInfoToUpdateBuddy creates an UPDATE_BUDDY or UPDATE_BUDDY2 server reply from a User
// Info TLV.
func userInfoToUpdateBuddy(snac wire.TLVUserInfo, me *state.SessionInstance) string {
	online, _ := snac.Uint32BE(wire.OServiceUserInfoSignonTOD)
	idle, _ := snac.Uint16BE(wire.OServiceUserInfoIdleTime)

	uFlags, hasVal := snac.TLVList.Uint16BE(wire.OServiceUserInfoUserFlags)
	if !hasVal {
		// todo: handle if this tlv doesn't exist for some reason
		return ""
	}
	ucArray := userClassString(uFlags, snac.IsAway())
	uc := strings.Join(ucArray[:], "")

	warning := fmt.Sprintf("%d", snac.WarningLevel/10)
	cmd := "UPDATE_BUDDY"
	if hasFlag(me.TocVersion(), state.SupportsTOC2) {
		cmd = "UPDATE_BUDDY2"
	}
	return fmt.Sprintf("%s:%s:%s:%s:%d:%d:%s", cmd, snac.ScreenName, "T", warning, online, idle, uc)
}

// hasFlag checks if a specific flag is set in the bitmask.
func hasFlag[T ~uint16 | ~uint8](bitmask, flag T) bool {
	return (bitmask & flag) == flag
}

// userInfoToBuddyCaps creates a BUDDY_CAPS2 server reply from a User Info TLV.
func userInfoToBuddyCaps(snac wire.TLVUserInfo, me *state.SessionInstance) string {
	if hasFlag(me.TocVersion(), state.SupportsTOC) {
		return ""
	}
	clientCaps := ""
	if b, hasCaps := snac.TLVList.Bytes(wire.OServiceUserInfoOscarCaps); hasCaps {
		if len(b)%16 != 0 {
			// todo: capability list must be array of 16-byte values
		}
		var capStrings []string
		for i := 0; i < len(b); i += 16 {
			var c [16]byte
			copy(c[:], b[i:i+16])
			uid := uuid.UUID(c)
			capStrings = append(capStrings, uid.String())
		}
		clientCaps = strings.Join(capStrings, ",")
	}
	return fmt.Sprintf("BUDDY_CAPS2:%s:%s", snac.ScreenName, clientCaps)
}
