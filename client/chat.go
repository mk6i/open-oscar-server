package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/mk6i/open-oscar-server/wire"
)

// chatExchange is the exchange that hosts user-created chat rooms.
const chatExchange = 4

// ChatInvite is an invitation to a chat room.
type ChatInvite struct {
	From     string
	Message  string
	RoomName string
	room     wire.ICBMRoomInfo
}

// ChatRoom is a chat room the user is in.
type ChatRoom struct {
	client *Client
	conn   *conn
	name   string
	info   wire.ICBMRoomInfo

	mu    sync.Mutex
	users []string
}

// roomNameFromCookie extracts the room name from a chat room cookie of the
// form <exchange>-<instance>-<name>.
func roomNameFromCookie(cookie string) string {
	parts := strings.SplitN(cookie, "-", 3)
	if len(parts) < 3 {
		return cookie
	}
	return parts[2]
}

// Name returns the room name.
func (r *ChatRoom) Name() string {
	return r.name
}

// ID returns a string that uniquely identifies the room.
func (r *ChatRoom) ID() string {
	return r.info.Cookie
}

// Users returns the screen names of the users in the room.
func (r *ChatRoom) Users() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.users)
}

// Send sends a message to the room. The server reflects it back as a
// ChatMessageEvent.
func (r *ChatRoom) Send(message string) error {
	block := wire.TLVRestBlock{}
	block.Append(wire.NewTLVBE(wire.ChatTLVEnableReflectionFlag, uint8(1)))
	block.Append(wire.NewTLVBE(wire.ChatTLVPublicWhisperFlag, []byte{}))
	block.Append(wire.NewTLVBE(wire.ChatTLVMessageInfo, wire.TLVRestBlock{
		TLVList: wire.TLVList{
			wire.NewTLVBE(wire.ChatTLVMessageInfoText, message),
		},
	}))
	return r.conn.send(wire.Chat, wire.ChatChannelMsgToHost, wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
		Channel:      wire.ICBMChannelMIME,
		TLVRestBlock: block,
	})
}

// Invite invites a user to the room.
func (r *ChatRoom) Invite(ctx context.Context, screenName, message string) error {
	snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		ChannelID:  wire.ICBMChannelRendezvous,
		ScreenName: screenName,
	}
	snac.Append(wire.NewTLVBE(wire.ICBMTLVData, wire.ICBMCh2Fragment{
		Type:       wire.ICBMRdvMessagePropose,
		Capability: wire.CapChat,
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ICBMRdvTLVTagsSeqNum, uint16(1)),
				wire.NewTLVBE(wire.ICBMRdvTLVTagsInvitation, message),
				wire.NewTLVBE(wire.ICBMRdvTLVTagsInviteMIMECharset, "us-ascii"),
				wire.NewTLVBE(wire.ICBMRdvTLVTagsInviteMIMELang, "en"),
				wire.NewTLVBE(wire.ICBMRdvTLVTagsSvcData, r.info),
			},
		},
	}))
	snac.Append(wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}))
	_, err := r.client.bos.request(ctx, wire.ICBM, wire.ICBMChannelMsgToHost, snac)
	return err
}

// Leave leaves the room.
func (r *ChatRoom) Leave() {
	r.conn.Close()
}

// Chats returns the chat rooms the user is in.
func (c *Client) Chats() []*ChatRoom {
	c.mu.Lock()
	defer c.mu.Unlock()
	rooms := make([]*ChatRoom, 0, len(c.chats))
	for _, room := range c.chats {
		rooms = append(rooms, room)
	}
	return rooms
}

// JoinChat joins the chat room with the given name, creating it if it
// doesn't exist.
func (c *Client) JoinChat(ctx context.Context, name string) (*ChatRoom, error) {
	req := wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
		Exchange: chatExchange,
		Cookie:   "create",
		TLVBlock: wire.TLVBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ChatRoomTLVRoomName, name),
			},
		},
	}
	reply, err := c.bos.request(ctx, wire.ChatNav, wire.ChatNavCreateRoom, req)
	if err != nil {
		return nil, err
	}
	return c.joinFromNavInfo(ctx, reply)
}

// AcceptChatInvite joins the room an invitation is for.
func (c *Client) AcceptChatInvite(ctx context.Context, invite ChatInvite) (*ChatRoom, error) {
	reply, err := c.bos.request(ctx, wire.ChatNav, wire.ChatNavRequestRoomInfo, wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
		Exchange:       invite.room.Exchange,
		Cookie:         invite.room.Cookie,
		InstanceNumber: invite.room.Instance,
	})
	if err != nil {
		return nil, err
	}
	return c.joinFromNavInfo(ctx, reply)
}

// joinFromNavInfo connects to the room described by a ChatNav info reply.
func (c *Client) joinFromNavInfo(ctx context.Context, reply wire.SNACMessage) (*ChatRoom, error) {
	nav, ok := reply.Body.(wire.SNAC_0x0D_0x09_ChatNavNavInfo)
	if !ok {
		return nil, errors.New("unexpected chat room info reply")
	}
	b, ok := nav.Bytes(wire.ChatNavTLVRoomInfo)
	if !ok {
		return nil, errors.New("chat room info reply is missing room info")
	}
	roomInfo := wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{}
	if err := wire.UnmarshalBE(&roomInfo, bytes.NewReader(b)); err != nil {
		return nil, fmt.Errorf("unmarshal room info: %w", err)
	}
	name, ok := roomInfo.String(wire.ChatRoomTLVRoomName)
	if !ok {
		name = roomNameFromCookie(roomInfo.Cookie)
	}

	c.mu.Lock()
	existing, inRoom := c.chats[roomInfo.Cookie]
	c.mu.Unlock()
	if inRoom {
		return existing, nil
	}

	svcReq := wire.SNAC_0x01_0x04_OServiceServiceRequest{FoodGroup: wire.Chat}
	svcReq.Append(wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{
		Exchange:       roomInfo.Exchange,
		Cookie:         roomInfo.Cookie,
		InstanceNumber: roomInfo.InstanceNumber,
	}))
	reply, err := c.bos.request(ctx, wire.OService, wire.OServiceServiceRequest, svcReq)
	if err != nil {
		return nil, err
	}
	svc, ok := reply.Body.(wire.SNAC_0x01_0x05_OServiceServiceResponse)
	if !ok {
		return nil, errors.New("unexpected chat service reply")
	}
	addr, hasAddr := svc.String(wire.OServiceTLVTagsReconnectHere)
	cookie, hasCookie := svc.Bytes(wire.OServiceTLVTagsLoginCookie)
	if !hasAddr || !hasCookie {
		return nil, errors.New("chat service reply is missing the server address or cookie")
	}

	conn, err := connectService(ctx, addr, cookie, c.logger)
	if err != nil {
		return nil, fmt.Errorf("connect to chat server %s: %w", addr, err)
	}

	room := &ChatRoom{
		client: c,
		conn:   conn,
		name:   name,
		info: wire.ICBMRoomInfo{
			Exchange: roomInfo.Exchange,
			Cookie:   roomInfo.Cookie,
			Instance: roomInfo.InstanceNumber,
		},
	}

	c.mu.Lock()
	c.chats[room.ID()] = room
	c.mu.Unlock()

	conn.negotiate(ctx)
	if err := conn.clientOnline(); err != nil {
		conn.Close()
		c.mu.Lock()
		delete(c.chats, room.ID())
		c.mu.Unlock()
		return nil, err
	}

	c.emit(ChatJoinedEvent{Room: room})
	go room.read()
	return room, nil
}

// read handles SNACs from the chat room connection until it closes.
func (r *ChatRoom) read() {
	c := r.client
	for {
		select {
		case <-r.conn.Closed():
			c.mu.Lock()
			delete(c.chats, r.ID())
			c.mu.Unlock()
			err := r.conn.Err()
			if errors.Is(err, ErrClosed) {
				err = nil
			}
			c.emit(ChatClosedEvent{Room: r, Err: err})
			return
		case msg := <-r.conn.Messages():
			r.handle(msg)
		}
	}
}

func (r *ChatRoom) handle(msg wire.SNACMessage) {
	c := r.client
	switch body := msg.Body.(type) {
	case wire.SNAC_0x0E_0x03_ChatUsersJoined:
		names := userNames(body.Users)
		r.mu.Lock()
		for _, name := range names {
			if !slices.ContainsFunc(r.users, func(u string) bool {
				return NormalizeScreenName(u) == NormalizeScreenName(name)
			}) {
				r.users = append(r.users, name)
			}
		}
		r.mu.Unlock()
		c.emit(ChatUsersEvent{Room: r, Joined: true, Users: names})
	case wire.SNAC_0x0E_0x04_ChatUsersLeft:
		names := userNames(body.Users)
		r.mu.Lock()
		r.users = slices.DeleteFunc(r.users, func(u string) bool {
			return slices.ContainsFunc(names, func(name string) bool {
				return NormalizeScreenName(u) == NormalizeScreenName(name)
			})
		})
		r.mu.Unlock()
		c.emit(ChatUsersEvent{Room: r, Joined: false, Users: names})
	case wire.SNAC_0x0E_0x06_ChatChannelMsgToClient:
		ev := ChatMessageEvent{Room: r, Time: time.Now()}
		if b, ok := body.Bytes(wire.ChatTLVSenderInformation); ok {
			u := wire.TLVUserInfo{}
			if err := wire.UnmarshalBE(&u, bytes.NewReader(b)); err == nil {
				ev.From = u.ScreenName
			}
		}
		b, ok := body.Bytes(wire.ChatTLVMessageInfo)
		if !ok {
			return
		}
		text, err := wire.UnmarshalChatMessageText(b)
		if err != nil {
			c.logger.Debug("unable to decode chat message", "err", err.Error())
			return
		}
		ev.Message = text
		c.emit(ev)
	case wire.SNAC_0x01_0x0A_OServiceRateParamsChange:
		if body.Code == rateParamsChangeLimited {
			c.emit(RateLimitEvent{Limited: true})
		}
	default:
		c.logger.Debug("ignoring chat SNAC",
			"snac", wire.SubGroupName(msg.Frame.FoodGroup, msg.Frame.SubGroup))
	}
}

func userNames(users []wire.TLVUserInfo) []string {
	names := make([]string, 0, len(users))
	for _, u := range users {
		names = append(names, u.ScreenName)
	}
	return names
}
