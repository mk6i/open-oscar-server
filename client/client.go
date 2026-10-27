// Package client implements an OSCAR (AIM) client that is compatible with
// Open OSCAR Server.
//
// A Client signs on with BUCP (MD5 challenge) authentication, keeps the
// server-stored buddy list (feedbag) in sync, and reports activity such as
// buddy status changes and incoming messages as Events.
//
//	c, err := client.Dial(ctx, client.Config{
//		Server:     "127.0.0.1:5190",
//		ScreenName: "alice",
//		Password:   "secret",
//	})
//	if err != nil { ... }
//	defer c.Close()
//	for ev := range c.Events() { ... }
package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/wire"
)

// DefaultServer is the address of a locally running Open OSCAR Server.
const DefaultServer = "127.0.0.1:5190"

// eventQueueLimit is how many events are buffered for the consumer.
const eventQueueLimit = 512

// profileMIME is the MIME type sent with profiles and away messages.
const profileMIME = `text/aolrtf; charset="us-ascii"`

// rateParamsChangeLimited is the OServiceRateParamsChange code the server
// sends when one of the user's rate classes becomes limited.
const (
	rateParamsChangeLimited uint16 = 3
	rateParamsChangeClear   uint16 = 4
)

// Config configures a client connection.
type Config struct {
	// Server is the host:port of the OSCAR auth service.
	Server     string
	ScreenName string
	Password   string
	// ClientIdentity is the client name reported to the server. Defaults to
	// DefaultClientIdentity.
	ClientIdentity string
	// Profile is the profile to set at signon.
	Profile string
	// Logger receives debug logs. Defaults to discarding them.
	Logger *slog.Logger
}

// Client is a signed-on connection to an OSCAR server. Its methods are safe
// for concurrent use.
type Client struct {
	logger *slog.Logger
	bos    *conn
	events chan Event

	stop     chan struct{}
	stopOnce sync.Once

	mu       sync.Mutex
	self     UserInfo
	presence map[string]UserInfo
	fb       feedbag
	chats    map[string]*ChatRoom
	profile  string
	away     string

	// fbMu serializes feedbag changes, so that each is planned against the
	// result of the last.
	fbMu sync.Mutex
}

// Dial signs on to the server and returns a connected client.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Server == "" {
		cfg.Server = DefaultServer
	}
	if cfg.ClientIdentity == "" {
		cfg.ClientIdentity = DefaultClientIdentity
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	login, err := bucpLogin(ctx, cfg.Server, cfg.ScreenName, cfg.Password, cfg.ClientIdentity)
	if err != nil {
		return nil, err
	}

	bos, err := connectService(ctx, login.bosAddr, login.cookie, cfg.Logger)
	if err != nil {
		return nil, fmt.Errorf("connect to BOS server %s: %w", login.bosAddr, err)
	}

	c := &Client{
		logger:   cfg.Logger,
		bos:      bos,
		events:   make(chan Event, eventQueueLimit),
		stop:     make(chan struct{}),
		presence: make(map[string]UserInfo),
		chats:    make(map[string]*ChatRoom),
		profile:  cfg.Profile,
	}

	if err := c.signon(ctx); err != nil {
		bos.Close()
		return nil, err
	}

	go c.dispatch()
	return c, nil
}

// signon runs the BOS signon sequence: it loads the user's info and buddy
// list, sets the profile and capabilities, and tells the server the client is
// ready.
func (c *Client) signon(ctx context.Context) error {
	c.bos.negotiate(ctx)

	reply, err := c.bos.request(ctx, wire.OService, wire.OServiceUserInfoQuery, struct{}{})
	if err != nil {
		return fmt.Errorf("query user info: %w", err)
	}
	if info, ok := reply.Body.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate); ok && len(info.UserInfo) > 0 {
		c.self = newUserInfo(info.UserInfo[0])
	}

	// a large buddy list may arrive in several parts
	parts, err := c.bos.requestAll(ctx, wire.Feedbag, wire.FeedbagQuery, struct{}{})
	if err != nil {
		return fmt.Errorf("query buddy list: %w", err)
	}
	for _, part := range parts {
		if fb, ok := part.Body.(wire.SNAC_0x13_0x06_FeedbagReply); ok {
			c.fb.items = append(c.fb.items, fb.Items...)
		}
	}

	if err := c.bos.send(wire.Feedbag, wire.FeedbagUse, struct{}{}); err != nil {
		return err
	}

	info := wire.SNAC_0x02_0x04_LocateSetInfo{}
	info.AppendList([]wire.TLV{
		wire.NewTLVBE(wire.LocateTLVTagsInfoSigMime, profileMIME),
		wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, c.profile),
		wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []uuid.UUID{wire.CapChat}),
	})
	if err := c.bos.send(wire.Locate, wire.LocateSetInfo, info); err != nil {
		return err
	}

	return c.bos.clientOnline()
}

// Events returns the channel on which the client reports activity. The
// channel is never closed; a DisconnectedEvent is the last event delivered.
func (c *Client) Events() <-chan Event {
	return c.events
}

// emit delivers an event to the consumer unless the client is closed.
func (c *Client) emit(ev Event) {
	select {
	case c.events <- ev:
	case <-c.stop:
	}
}

// Close signs off and closes all connections.
func (c *Client) Close() {
	c.stopOnce.Do(func() { close(c.stop) })
	c.closeChats()
	c.bos.Close()
}

// Done returns a channel that is closed when the BOS connection closes.
func (c *Client) Done() <-chan struct{} {
	return c.bos.Closed()
}

func (c *Client) closeChats() {
	c.mu.Lock()
	rooms := make([]*ChatRoom, 0, len(c.chats))
	for _, room := range c.chats {
		rooms = append(rooms, room)
	}
	c.mu.Unlock()
	for _, room := range rooms {
		room.Leave()
	}
}

// dispatch handles server-initiated SNACs on the BOS connection.
func (c *Client) dispatch() {
	for {
		select {
		case <-c.bos.Closed():
			c.closeChats()
			c.emit(DisconnectedEvent{Err: c.bos.Err()})
			return
		case msg := <-c.bos.Messages():
			c.handleBOS(msg)
		}
	}
}

func (c *Client) handleBOS(msg wire.SNACMessage) {
	switch body := msg.Body.(type) {
	case wire.SNAC_0x03_0x0B_BuddyArrived:
		info := newUserInfo(body.TLVUserInfo)
		c.mu.Lock()
		c.presence[NormalizeScreenName(info.ScreenName)] = info
		c.mu.Unlock()
		c.emit(BuddyArrivedEvent{Info: info})
	case wire.SNAC_0x03_0x0C_BuddyDeparted:
		c.mu.Lock()
		delete(c.presence, NormalizeScreenName(body.ScreenName))
		c.mu.Unlock()
		c.emit(BuddyDepartedEvent{ScreenName: body.ScreenName})
	case wire.SNAC_0x04_0x07_ICBMChannelMsgToClient:
		c.handleICBM(body)
	case wire.SNAC_0x04_0x14_ICBMClientEvent:
		c.emit(TypingEvent{ScreenName: body.ScreenName, Status: body.Event})
	case wire.SNAC_0x01_0x10_OServiceEvilNotification:
		ev := WarnedEvent{NewLevel: int(body.NewEvil / 10)}
		if body.Snitcher != nil {
			ev.By = body.Snitcher.ScreenName
		}
		c.mu.Lock()
		c.self.WarningLevel = ev.NewLevel
		c.mu.Unlock()
		c.emit(ev)
	case wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate:
		if len(body.UserInfo) == 0 {
			return
		}
		info := newUserInfo(body.UserInfo[0])
		c.mu.Lock()
		c.self = info
		c.mu.Unlock()
		c.emit(SelfInfoEvent{Info: info})
	case wire.SNAC_0x01_0x0A_OServiceRateParamsChange:
		switch body.Code {
		case rateParamsChangeLimited:
			c.emit(RateLimitEvent{Limited: true})
		case rateParamsChangeClear:
			c.emit(RateLimitEvent{Limited: false})
		}
	case wire.SNAC_0x13_0x08_FeedbagInsertItem:
		c.applyRemoteFeedbag(false, body.Items)
	case wire.SNAC_0x13_0x09_FeedbagUpdateItem:
		c.applyRemoteFeedbag(false, body.Items)
	case wire.SNAC_0x13_0x0A_FeedbagDeleteItem:
		c.applyRemoteFeedbag(true, body.Items)
	default:
		c.logger.Debug("ignoring SNAC",
			"snac", wire.SubGroupName(msg.Frame.FoodGroup, msg.Frame.SubGroup))
	}
}

// applyRemoteFeedbag records a buddy list change made by another session of
// the same user.
func (c *Client) applyRemoteFeedbag(del bool, items []wire.FeedbagItem) {
	c.mu.Lock()
	c.fb.apply(del, items)
	c.mu.Unlock()
	c.emit(BuddyListEvent{})
}

func (c *Client) handleICBM(body wire.SNAC_0x04_0x07_ICBMChannelMsgToClient) {
	switch body.ChannelID {
	case wire.ICBMChannelIM:
		b, ok := body.Bytes(wire.ICBMTLVAOLIMData)
		if !ok {
			return
		}
		text, err := wire.UnmarshalICBMMessageText(b)
		if err != nil {
			c.logger.Debug("unable to decode IM", "err", err.Error())
			return
		}
		_, auto := body.Bytes(wire.ICBMTLVAutoResponse)
		c.emit(IMEvent{
			From:         newUserInfo(body.TLVUserInfo),
			Message:      text,
			AutoResponse: auto,
			Time:         time.Now(),
		})
	case wire.ICBMChannelRendezvous:
		b, ok := body.Bytes(wire.ICBMTLVData)
		if !ok {
			return
		}
		frag := wire.ICBMCh2Fragment{}
		if err := wire.UnmarshalBE(&frag, bytes.NewReader(b)); err != nil {
			return
		}
		if frag.Type != wire.ICBMRdvMessagePropose || uuid.UUID(frag.Capability) != wire.CapChat {
			return
		}
		svcData, ok := frag.Bytes(wire.ICBMRdvTLVTagsSvcData)
		if !ok {
			return
		}
		room := wire.ICBMRoomInfo{}
		if err := wire.UnmarshalBE(&room, bytes.NewReader(svcData)); err != nil {
			return
		}
		msg, _ := frag.String(wire.ICBMRdvTLVTagsInvitation)
		c.emit(ChatInviteEvent{Invite: ChatInvite{
			From:     body.ScreenName,
			Message:  msg,
			RoomName: roomNameFromCookie(room.Cookie),
			room:     room,
		}})
	}
}

// Self returns the user's own info.
func (c *Client) Self() UserInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.self
}

// SendIM sends an instant message, which is usually HTML. It returns an error
// if the recipient is offline or the message is refused.
func (c *Client) SendIM(ctx context.Context, to, message string) error {
	return c.sendIM(ctx, to, message, false)
}

// SendAutoResponse sends an automatic away reply.
func (c *Client) SendAutoResponse(ctx context.Context, to, message string) error {
	return c.sendIM(ctx, to, message, true)
}

func (c *Client) sendIM(ctx context.Context, to, message string, auto bool) error {
	frags, err := wire.ICBMFragmentList(message)
	if err != nil {
		return err
	}
	snac := wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
		Cookie:     rand.Uint64(),
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: to,
	}
	snac.Append(wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags))
	snac.Append(wire.NewTLVBE(wire.ICBMTLVRequestHostAck, []byte{}))
	if auto {
		snac.Append(wire.NewTLVBE(wire.ICBMTLVAutoResponse, []byte{}))
	}
	_, err = c.bos.request(ctx, wire.ICBM, wire.ICBMChannelMsgToHost, snac)
	return err
}

// SendTyping tells a correspondent about the user's typing status: 0 for
// idle, 1 for text entered and 2 for typing.
func (c *Client) SendTyping(to string, status uint16) error {
	return c.bos.send(wire.ICBM, wire.ICBMClientEvent, wire.SNAC_0x04_0x14_ICBMClientEvent{
		ChannelID:  wire.ICBMChannelIM,
		ScreenName: to,
		Event:      status,
	})
}

// UserInfo looks up a user's info, profile and away message. It returns a
// *SNACError with code wire.ErrorCodeNotLoggedOn if the user is offline.
func (c *Client) UserInfo(ctx context.Context, screenName string) (UserProfile, error) {
	reply, err := c.bos.request(ctx, wire.Locate, wire.LocateUserInfoQuery, wire.SNAC_0x02_0x05_LocateUserInfoQuery{
		Type:       uint16(wire.LocateTypeSig | wire.LocateTypeUnavailable),
		ScreenName: screenName,
	})
	if err != nil {
		return UserProfile{}, err
	}
	body, ok := reply.Body.(wire.SNAC_0x02_0x06_LocateUserInfoReply)
	if !ok {
		return UserProfile{}, errors.New("unexpected user info reply")
	}
	p := UserProfile{Info: newUserInfo(body.TLVUserInfo)}
	p.Profile, _ = body.LocateInfo.String(wire.LocateTLVTagsInfoSigData)
	p.AwayMessage, _ = body.LocateInfo.String(wire.LocateTLVTagsInfoUnavailableData)
	return p, nil
}

// Profile returns the profile last set by this client.
func (c *Client) Profile() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.profile
}

// SetProfile sets the user's profile, which is usually HTML.
func (c *Client) SetProfile(profile string) error {
	info := wire.SNAC_0x02_0x04_LocateSetInfo{}
	info.AppendList([]wire.TLV{
		wire.NewTLVBE(wire.LocateTLVTagsInfoSigMime, profileMIME),
		wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, profile),
	})
	if err := c.bos.send(wire.Locate, wire.LocateSetInfo, info); err != nil {
		return err
	}
	c.mu.Lock()
	c.profile = profile
	c.mu.Unlock()
	return nil
}

// AwayMessage returns the current away message, empty if not away.
func (c *Client) AwayMessage() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.away
}

// SetAway sets an away message. An empty message marks the user as back.
func (c *Client) SetAway(message string) error {
	info := wire.SNAC_0x02_0x04_LocateSetInfo{}
	info.AppendList([]wire.TLV{
		wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableMime, profileMIME),
		wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, message),
	})
	if err := c.bos.send(wire.Locate, wire.LocateSetInfo, info); err != nil {
		return err
	}
	c.mu.Lock()
	c.away = message
	c.mu.Unlock()
	return nil
}

// WarnResult is the outcome of a warning.
type WarnResult struct {
	// Delta is how much the warning raised the user's level, in percent.
	Delta int
	// NewLevel is the warned user's new level, in percent.
	NewLevel int
}

// Warn warns (evils) a user, anonymously if anon is set. Users can only be
// warned shortly after they sent the warner a message.
func (c *Client) Warn(ctx context.Context, screenName string, anon bool) (WarnResult, error) {
	req := wire.SNAC_0x04_0x08_ICBMEvilRequest{ScreenName: screenName}
	if anon {
		req.SendAs = 1
	}
	reply, err := c.bos.request(ctx, wire.ICBM, wire.ICBMEvilRequest, req)
	if err != nil {
		return WarnResult{}, err
	}
	body, ok := reply.Body.(wire.SNAC_0x04_0x09_ICBMEvilReply)
	if !ok {
		return WarnResult{}, errors.New("unexpected warn reply")
	}
	return WarnResult{
		Delta:    int(body.EvilDeltaApplied / 10),
		NewLevel: int(body.UpdatedEvilValue / 10),
	}, nil
}

// BuddyList returns the buddy list groups along with each buddy's presence.
func (c *Client) BuddyList() []BuddyGroup {
	c.mu.Lock()
	defer c.mu.Unlock()
	groups := c.fb.groups()
	for _, g := range groups {
		for i, b := range g.Buddies {
			if info, ok := c.presence[NormalizeScreenName(b.ScreenName)]; ok {
				g.Buddies[i].Online = true
				g.Buddies[i].Info = info
			}
		}
	}
	return groups
}

// BlockList returns the screen names the user blocks.
func (c *Client) BlockList() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fb.denied()
}

// IsBlocked reports whether the user blocks screenName.
func (c *Client) IsBlocked(screenName string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.fb.isDenied(screenName)
}

// AddBuddy adds a buddy to a group of the buddy list, creating the group if
// it doesn't exist. An empty group means DefaultBuddyGroup.
func (c *Client) AddBuddy(ctx context.Context, group, screenName string) error {
	if group == "" {
		group = DefaultBuddyGroup
	}
	return c.changeFeedbag(ctx, func(fb *feedbag) (feedbagChange, error) {
		return fb.planAddBuddy(group, screenName), nil
	})
}

// RemoveBuddy removes a buddy from every group of the buddy list.
func (c *Client) RemoveBuddy(ctx context.Context, screenName string) error {
	err := c.changeFeedbag(ctx, func(fb *feedbag) (feedbagChange, error) {
		return fb.planRemoveBuddy(screenName)
	})
	if err == nil {
		c.mu.Lock()
		delete(c.presence, NormalizeScreenName(screenName))
		c.mu.Unlock()
	}
	return err
}

// Block blocks a user, who can then no longer see the user online or message
// them.
func (c *Client) Block(ctx context.Context, screenName string) error {
	if NormalizeScreenName(screenName) == NormalizeScreenName(c.Self().ScreenName) {
		return errors.New("you can't block yourself")
	}
	return c.changeFeedbag(ctx, func(fb *feedbag) (feedbagChange, error) {
		return fb.planBlock(screenName), nil
	})
}

// Unblock unblocks a user.
func (c *Client) Unblock(ctx context.Context, screenName string) error {
	return c.changeFeedbag(ctx, func(fb *feedbag) (feedbagChange, error) {
		return fb.planUnblock(screenName)
	})
}

// changeFeedbag plans a buddy list change against the mirror, sends it to the
// server, and records it in the mirror once the server accepts it.
func (c *Client) changeFeedbag(ctx context.Context, plan func(fb *feedbag) (feedbagChange, error)) error {
	c.fbMu.Lock()
	defer c.fbMu.Unlock()

	c.mu.Lock()
	change, err := plan(&c.fb)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	if change.empty() {
		return nil
	}

	steps := []struct {
		subGroup uint16
		items    []wire.FeedbagItem
		body     any
		del      bool
	}{
		{wire.FeedbagDeleteItem, change.deletes, wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: change.deletes}, true},
		{wire.FeedbagInsertItem, change.inserts, wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: change.inserts}, false},
		{wire.FeedbagUpdateItem, change.updates, wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: change.updates}, false},
	}
	for _, step := range steps {
		if len(step.items) == 0 {
			continue
		}
		reply, err := c.bos.request(ctx, wire.Feedbag, step.subGroup, step.body)
		if err != nil {
			return err
		}
		status, ok := reply.Body.(wire.SNAC_0x13_0x0E_FeedbagStatus)
		if !ok {
			return errors.New("unexpected buddy list change reply")
		}
		if slices.ContainsFunc(status.Results, func(code uint16) bool { return code != 0 }) {
			return fmt.Errorf("server refused buddy list change (codes %v)", status.Results)
		}
		c.mu.Lock()
		c.fb.apply(step.del, step.items)
		c.mu.Unlock()
	}

	c.emit(BuddyListEvent{})
	return nil
}
