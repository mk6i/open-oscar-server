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
	cmdInternalSvcErr    = "ERROR:989:internal server error"
	rateLimitExceededErr = "ERROR:903"
	errDisconnect        = errors.New("got booted by another session")
)

// RecvBOS routes incoming SNAC messages from the BOS server to their
// corresponding TOC handlers. It ignores any SNAC messages for which there is
// no TOC response.
func (s OSCARProxy) RecvBOS(ctx context.Context, me *state.Session, chatRegistry *ChatRegistry, ch chan<- []byte) error {
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
				sendOrCancel(ctx, ch, s.UpdateBuddyArrival(v))
			case wire.SNAC_0x03_0x0C_BuddyDeparted:
				sendOrCancel(ctx, ch, s.UpdateBuddyDeparted(v))
			case wire.SNAC_0x04_0x07_ICBMChannelMsgToClient:
				sendOrCancel(ctx, ch, s.IMIn(ctx, chatRegistry, v))
			case wire.SNAC_0x01_0x10_OServiceEvilNotification:
				sendOrCancel(ctx, ch, s.Eviled(v))
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
func (s OSCARProxy) RecvChat(ctx context.Context, me *state.Session, chatID int, ch chan<- []byte) {
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
func (s OSCARProxy) ChatIn(ctx context.Context, snac wire.SNAC_0x0E_0x06_ChatChannelMsgToClient, chatID int) string {
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

	return fmt.Sprintf("CHAT_IN:%d:%s:F:%s", chatID, u.ScreenName, text)
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
func (s OSCARProxy) ChatUpdateBuddyArrived(snac wire.SNAC_0x0E_0x03_ChatUsersJoined, chatID int) string {
	users := make([]string, 0, len(snac.Users))
	for _, u := range snac.Users {
		users = append(users, u.ScreenName)
	}
	return fmt.Sprintf("CHAT_UPDATE_BUDDY:%d:T:%s", chatID, strings.Join(users, ":"))
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
func (s OSCARProxy) ChatUpdateBuddyLeft(snac wire.SNAC_0x0E_0x04_ChatUsersLeft, chatID int) string {
	users := make([]string, 0, len(snac.Users))
	for _, u := range snac.Users {
		users = append(users, u.ScreenName)
	}
	return fmt.Sprintf("CHAT_UPDATE_BUDDY:%d:F:%s", chatID, strings.Join(users, ":"))
}

// Eviled handles the EVILED TOC command.
//
// From the TiK documentation:
//
//	The user was just eviled.
//
// Command syntax: EVILED:<new evil>:<name of eviler, blank if anonymous>
func (s OSCARProxy) Eviled(snac wire.SNAC_0x01_0x10_OServiceEvilNotification) string {
	warning := fmt.Sprintf("%d", snac.NewEvil/10)
	who := ""
	if snac.Snitcher != nil {
		who = snac.Snitcher.ScreenName
	}
	return fmt.Sprintf("EVILED:%s:%s", warning, who)
}

// IMIn handles the IM_IN TOC command.
//
// From the TiK documentation:
//
//	Receive an IM from someone. Everything after the third colon is the
//	incoming message, including other colons.
//
// Command syntax: IM_IN:<Source User>:<Auto Response T/F?>:<Message>
func (s OSCARProxy) IMIn(ctx context.Context, chatRegistry *ChatRegistry, snac wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) string {
	switch snac.ChannelID {
	case wire.ICBMChannelIM:
		return s.convertICBMInstantMsg(ctx, snac)
	case wire.ICBMChannelRendezvous:
		return s.convertICBMRendezvous(ctx, chatRegistry, snac)
	default:
		s.Logger.DebugContext(ctx, "received unsupported ICBM channel message", "channel_id", snac.ChannelID)
		return ""
	}
}

// convertICBMInstantMsg converts an ICBM instant message SNAC to a TOC IM_IN response.
func (s OSCARProxy) convertICBMInstantMsg(ctx context.Context, snac wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) string {
	buf, ok := snac.TLVRestBlock.Bytes(wire.ICBMTLVAOLIMData)
	if !ok {
		return s.runtimeErr(ctx, errors.New("TLVRestBlock.Bytes: missing wire.ICBMTLVAOLIMData"))
	}
	txt, err := wire.UnmarshalICBMMessageText(buf)
	if err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalICBMMessageText: %w", err))
	}

	autoResp := "F"
	if _, isAutoReply := snac.TLVRestBlock.Bytes(wire.ICBMTLVAutoResponse); isAutoReply {
		autoResp = "T"
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
		return s.runtimeErr(ctx, errors.New("TLVRestBlock.Bytes: missing rendezvous block"))
	}
	frag := wire.ICBMCh2Fragment{}
	if err := wire.UnmarshalBE(&frag, bytes.NewReader(rdinfo)); err != nil {
		return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalBE: %w", err))
	}

	if frag.Type != wire.ICBMRdvMessagePropose {
		s.Logger.DebugContext(ctx, "can't convert ICBM rendezvous message to TOC response", "rdv_type", frag.Type)
		return ""
	}

	switch uuid.UUID(frag.Capability) {
	case wire.CapChat:
		prompt, ok := frag.Bytes(wire.ICBMRdvTLVTagsInvitation)
		if !ok {
			return s.runtimeErr(ctx, errors.New("frag.Bytes: missing chat invite prompt"))
		}

		svcData, ok := frag.Bytes(wire.ICBMRdvTLVTagsSvcData)
		if !ok || svcData == nil {
			return s.runtimeErr(ctx, errors.New("frag.Bytes: missing room info"))
		}

		roomInfo := wire.ICBMRoomInfo{}
		if err := wire.UnmarshalBE(&roomInfo, bytes.NewReader(svcData)); err != nil {
			return s.runtimeErr(ctx, fmt.Errorf("wire.UnmarshalBE: %w", err))
		}

		cookie := strings.Split(roomInfo.Cookie, "-") // make this safe
		if len(cookie) < 3 {
			return s.runtimeErr(ctx, errors.New("roomInfo.Cookie: malformed cookie, could not get room name"))
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
func (s OSCARProxy) UpdateBuddyArrival(snac wire.SNAC_0x03_0x0B_BuddyArrived) string {
	return userInfoToUpdateBuddy(snac.TLVUserInfo)
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
func (s OSCARProxy) UpdateBuddyDeparted(snac wire.SNAC_0x03_0x0C_BuddyDeparted) string {
	return fmt.Sprintf("UPDATE_BUDDY:%s:F:0:0:0:   ", snac.ScreenName)
}

func sendOrCancel(ctx context.Context, ch chan<- []byte, msg string) {
	select {
	case <-ctx.Done():
		return
	case ch <- []byte(msg):
		return
	}
}

// userInfoToUpdateBuddy creates an UPDATE_BUDDY server reply from a User
// Info TLV.
func userInfoToUpdateBuddy(snac wire.TLVUserInfo) string {
	online, _ := snac.Uint32BE(wire.OServiceUserInfoSignonTOD)
	idle, _ := snac.Uint16BE(wire.OServiceUserInfoIdleTime)
	uc := [3]string{" ", "O", " "}
	if snac.IsAway() {
		uc[2] = "U"
	}
	warning := fmt.Sprintf("%d", snac.WarningLevel/10)
	class := strings.Join(uc[:], "")
	return fmt.Sprintf("UPDATE_BUDDY:%s:%s:%s:%d:%d:%s", snac.ScreenName, "T", warning, online, idle, class)
}
