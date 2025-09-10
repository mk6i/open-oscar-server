package foodgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/html"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

var (
	// sessOnlineHost represents the OnlineHost user that announcements die
	// roll results.
	sessOnlineHost = func() *state.Session {
		sn := state.DisplayScreenName("OnlineHost")
		sess := state.NewSession()
		sess.SetDisplayScreenName(sn)
		sess.SetIdentScreenName(sn.IdentScreenName())
		return sess
	}()

	// rollDiceRgxp matches a roll dice chat command.
	// ex: //roll //roll-sides3 //roll-dice2 //role-sides3-dice2
	rollDiceRgxp = regexp.MustCompile(`^//roll(?:-(dice|sides)([0-9]{1,3}))?(?:-(dice|sides)([0-9]{1,3}))?\s*$`)
)

// NewChatService creates a new instance of ChatService.
func NewChatService(chatMessageRelayer ChatMessageRelayer) *ChatService {
	return &ChatService{
		chatMessageRelayer: chatMessageRelayer,
		randRollDie: func(sides int) int {
			// generate random number between 1 and sides
			return rand.IntN(sides) + 1
		},
	}
}

// ChatService provides functionality for the Chat food group, which is
// responsible for sending and receiving chat messages.
type ChatService struct {
	chatMessageRelayer ChatMessageRelayer
	randRollDie        func(sides int) int
}

// ChannelMsgToHost relays wire.ChatChannelMsgToClient to chat room
// participants. If TLV wire.ChatTLVWhisperToUser is set, "whisper" the message
// to just that user and omit the remaining participants. If TLV
// wire.ChatTLVEnableReflectionFlag is set, return the message ("reflect") back
// to the caller.
func (s ChatService) ChannelMsgToHost(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x0E_0x05_ChatChannelMsgToHost) (*wire.SNACMessage, error) {
	frameOut := wire.SNACFrame{
		FoodGroup: wire.Chat,
		SubGroup:  wire.ChatChannelMsgToClient,
	}
	bodyOut := wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
		Cookie:  inBody.Cookie,
		Channel: inBody.Channel,
	}
	if bodyOut.Channel == math.MaxUint16 {
		// fix incorrect channel bug in macOS client v4.0.9.
		bodyOut.Channel = wire.ICBMChannelMIME
	}

	var err error
	if bodyOut.TLVRestBlock, err = s.transformChatMessage(inBody, sess); err != nil {
		return nil, err
	}

	if inBody.HasTag(wire.ChatTLVWhisperToUser) && !inBody.HasTag(wire.ChatTLVPublicWhisperFlag) {
		// forward a whisper message to just one recipient
		r, _ := inBody.String(wire.ChatTLVWhisperToUser)
		recip := state.NewIdentScreenName(r)
		s.chatMessageRelayer.RelayToScreenName(ctx, sess.ChatRoomCookie(), recip, wire.SNACMessage{
			Frame: frameOut,
			Body:  bodyOut,
		})
	} else {
		// forward message all participants, except sender
		s.chatMessageRelayer.RelayToAllExcept(ctx, sess.ChatRoomCookie(), sess.IdentScreenName(), wire.SNACMessage{
			Frame: frameOut,
			Body:  bodyOut,
		})
	}

	var ret *wire.SNACMessage
	if _, ackMsg := inBody.Bytes(wire.ChatTLVEnableReflectionFlag); ackMsg {
		// reflect the message back to the sender
		ret = &wire.SNACMessage{
			Frame: frameOut,
			Body:  bodyOut,
		}
		ret.Frame.RequestID = inFrame.RequestID
	}

	return ret, nil
}

// transformChatMessage inspects and modifies the incoming chat message payload.
//   - If message contains a properly formatted //roll command, return a roll
//     die response.
//   - Else return the unmodified incoming message.
//
// In the future, this function will validate the incoming message for correct form.
func (s ChatService) transformChatMessage(inBody wire.SNAC_0x0E_0x05_ChatChannelMsgToHost, sender *state.Session) (wire.TLVRestBlock, error) {
	messageBlob, hasMessage := inBody.Bytes(wire.ChatTLVMessageInfo)
	if !hasMessage {
		return wire.TLVRestBlock{}, errors.New("SNAC(0x0E,0x05) does not contain a message TLV")
	}
	msgBlock := wire.TLVRestBlock{}
	if err := wire.UnmarshalBE(&msgBlock, bytes.NewBuffer(messageBlob)); err != nil {
		return wire.TLVRestBlock{}, err
	}

	msgBlock = removeUnsupportedTLVs(msgBlock)

	messageText, err := textFromChatMsgBlob(msgBlock)
	if err != nil {
		return wire.TLVRestBlock{}, err
	}

	newMessageBlock := func(sess *state.Session, msg any) wire.TLVRestBlock {
		block := wire.TLVRestBlock{}
		// the order of these TLVs matters for AIM 2.x. if out of order, screen
		// names do not appear with each chat message.
		block.Append(wire.NewTLVBE(wire.ChatTLVSenderInformation, sess.TLVUserInfo()))
		if inBody.HasTag(wire.ChatTLVPublicWhisperFlag) {
			// send message to all chat room participants
			block.Append(wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}))
		}
		block.Append(wire.NewTLVBE(wire.ChatTLVMessageInfo, msg))
		return block
	}

	if doRoll, dice, sides := parseDiceCommand(messageText); doRoll {
		payload := s.rollDice(sender, dice, sides)
		// send die roll results from OnlineHost user
		return newMessageBlock(sessOnlineHost, payload), nil
	}

	// return the incoming payload without modification
	return newMessageBlock(sender, msgBlock), nil
}

// remove TLVs that break the macos 2.x chat
func removeUnsupportedTLVs(block wire.TLVRestBlock) wire.TLVRestBlock {
	newBlock := wire.TLVRestBlock{}
	for _, tlv := range block.TLVList {
		if tlv.Tag < 4 {
			newBlock.TLVList = append(newBlock.TLVList, tlv)
		}
	}
	return newBlock
}

// rollDice generates a chat response for the results of a die roll.
func (s ChatService) rollDice(sess *state.Session, dice int, sides int) wire.TLVRestBlock {
	sb := strings.Builder{}
	sb.WriteString("<HTML><BODY BGCOLOR=\"#ffffff\"><FONT LANG=\"0\">")
	sb.WriteString(fmt.Sprintf("%s rolled %d %d-sided dice:", sess.DisplayScreenName().String(), dice, sides))
	for i := 0; i < dice; i++ {
		sb.WriteString(fmt.Sprintf(" %d", s.randRollDie(sides)))
	}
	sb.WriteString("</FONT></BODY></HTML>")

	block := wire.TLVRestBlock{}
	block.Append(wire.NewTLVBE(wire.ChatTLVMessageInfoEncoding, "us-ascii"))
	block.Append(wire.NewTLVBE(wire.ChatTLVMessageInfoLang, "en"))
	block.Append(wire.NewTLVBE(wire.ChatTLVMessageInfoText, sb.String()))
	return block
}

// textFromChatMsgBlob extracts plaintext message text from HTML located in
// chat message info TLV(0x05).
func textFromChatMsgBlob(msg wire.TLVRestBlock) ([]byte, error) {

	b, hasMsg := msg.Bytes(wire.ChatTLVMessageInfoText)
	if !hasMsg {
		return nil, errors.New("SNAC(0x0E,0x05) has no chat msg text TLV")
	}

	tok := html.NewTokenizer(bytes.NewBuffer(b))
	for {
		switch tok.Next() {
		case html.TextToken:
			return tok.Text(), nil
		case html.ErrorToken:
			err := tok.Err()
			if err == io.EOF {
				err = nil
			}
			return nil, err
		}
	}
}

// parseDiceCommand gets the number of dice and sides from a die roll command.
//
// The roll command is activated with //roll followed by up to two arguments to
// indicate die count and side count. By default, there are 2 dice and 6 sides.
//
//   - //roll               2x 6-sided dice
//   - //roll-dice4         4x 6-sided dice
//   - //roll-sides8        2x 8-sided dice
//   - //roll-dice4-sides8  4x 8-sided dice
//
// The -dice param can not exceed 15 and -sides param cannot exceed 999.
func parseDiceCommand(in []byte) (valid bool, dice int, sides int) {
	matches := rollDiceRgxp.FindSubmatch(in)
	if len(matches) == 0 {
		return false, 0, 0
	}

	args := matches[1:]
	if len(args[0]) > 0 && bytes.Equal(args[0], args[2]) {
		// "sides" or "dice" appears twice
		return false, 0, 0
	}

	dice = 2
	sides = 6

	for i := 0; i < len(args); i += 2 {
		cmd := string(args[i])
		val := string(args[i+1])

		switch cmd {
		case "sides":
			var err error
			sides, err = strconv.Atoi(val)
			if err != nil || sides == 0 || sides > 999 {
				return false, 0, 0
			}
		case "dice":
			var err error
			dice, err = strconv.Atoi(val)
			if err != nil || dice == 0 || dice > 15 {
				return false, 0, 0
			}
		}
	}

	return true, dice, sides
}

func setOnlineChatUsers(ctx context.Context, sess *state.Session, chatMessageRelayer ChatMessageRelayer) {
	snacPayloadOut := wire.SNAC_0x0E_0x03_ChatUsersJoined{}
	sessions := chatMessageRelayer.AllSessions(sess.ChatRoomCookie())

	for _, uSess := range sessions {
		snacPayloadOut.Users = append(snacPayloadOut.Users, uSess.TLVUserInfo())
	}

	chatMessageRelayer.RelayToScreenName(ctx, sess.ChatRoomCookie(), sess.IdentScreenName(), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Chat,
			SubGroup:  wire.ChatUsersJoined,
		},
		Body: snacPayloadOut,
	})
}

func alertUserJoined(ctx context.Context, sess *state.Session, chatMessageRelayer ChatMessageRelayer) {
	chatMessageRelayer.RelayToAllExcept(ctx, sess.ChatRoomCookie(), sess.IdentScreenName(), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Chat,
			SubGroup:  wire.ChatUsersJoined,
		},
		Body: wire.SNAC_0x0E_0x03_ChatUsersJoined{
			Users: []wire.TLVUserInfo{
				sess.TLVUserInfo(),
			},
		},
	})
}

func alertUserLeft(ctx context.Context, sess *state.Session, chatMessageRelayer ChatMessageRelayer) {
	chatMessageRelayer.RelayToAllExcept(ctx, sess.ChatRoomCookie(), sess.IdentScreenName(), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Chat,
			SubGroup:  wire.ChatUsersLeft,
		},
		Body: wire.SNAC_0x0E_0x04_ChatUsersLeft{
			Users: []wire.TLVUserInfo{
				sess.TLVUserInfo(),
			},
		},
	})
}

func sendChatRoomInfoUpdate(ctx context.Context, sess *state.Session, chatMessageRelayer ChatMessageRelayer, room state.ChatRoom) {
	chatMessageRelayer.RelayToScreenName(ctx, sess.ChatRoomCookie(), sess.IdentScreenName(), wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Chat,
			SubGroup:  wire.ChatRoomInfoUpdate,
		},
		Body: wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
			Exchange:       room.Exchange(),
			Cookie:         room.Cookie(),
			InstanceNumber: room.InstanceNumber(),
			DetailLevel:    room.DetailLevel(),
			TLVBlock: wire.TLVBlock{
				TLVList: room.TLVList(),
			},
		},
	})
}
