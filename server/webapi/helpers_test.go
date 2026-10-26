package webapi

import (
	"context"
	"log/slog"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// newTestIconSource returns a BuddyIconSource whose users have no buddy icon,
// for tests that are not exercising icons.
func newTestIconSource(t *testing.T) BuddyIconSource {
	iconRetriever := newMockBuddyIconRetriever(t)
	iconRetriever.EXPECT().BuddyIconMetadata(mock.Anything, mock.Anything).Return(nil, nil).Maybe()
	return BuddyIconSource{
		IconRetriever: iconRetriever,
		BARTService:   newMockBARTService(t),
		Logger:        slog.Default(),
	}
}

// newRunningSession builds a WebAPI session for "me" over conn and starts its
// goroutines, which stop at the end of the test.
func newRunningSession(t *testing.T, aimsid string, conn *fakeConn, events ...string) *Session {
	t.Helper()
	return newRunningSessionAs(t, aimsid, "me", conn, events...)
}

// newTestSessionAs builds a running WebAPI session for screenName over conn,
// subscribed to events.
func newTestSessionAs(t *testing.T, screenName state.DisplayScreenName, conn *fakeConn, events ...string) *Session {
	t.Helper()
	return newRunningSessionAs(t, "aimsid-1", screenName, conn, events...)
}

// newRunningSessionAs builds a WebAPI session for screenName over conn and
// starts its goroutines, which stop at the end of the test.
func newRunningSessionAs(t *testing.T, aimsid string, screenName state.DisplayScreenName, conn *fakeConn, events ...string) *Session {
	t.Helper()
	sess := newSession(aimsid, screenName, events, conn, wire.DefaultSNACRateLimits(), "http://localhost", slog.Default())
	sess.EventQueue = NewEventQueue(10)
	sess.BuddyIconURL = func(state.IdentScreenName, []byte) string { return "" }
	sess.Start()
	t.Cleanup(sess.Close)
	return sess
}

// newTestSession builds a running WebAPI session for "me" over conn,
// subscribed to events.
func newTestSession(t *testing.T, conn *fakeConn, events ...string) *Session {
	t.Helper()
	return newRunningSession(t, "aimsid-1", conn, events...)
}

// fakeConn stands in for a session's connection to the OSCAR server. It
// records the SNACs sent to it and answers each with the SNACs its responder
// returns. A reply without a request ID answers the request it was returned
// for.
type fakeConn struct {
	mu      sync.Mutex
	sent    []wire.SNACMessage
	respond func(req wire.SNACMessage) []wire.SNACMessage
	sendErr error

	msgs      chan wire.SNACMessage
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeConn() *fakeConn {
	return &fakeConn{
		msgs:   make(chan wire.SNACMessage, 100),
		closed: make(chan struct{}),
	}
}

// answering sets the responder that answers the SNACs sent to the
// connection.
func (c *fakeConn) answering(respond func(req wire.SNACMessage) []wire.SNACMessage) *fakeConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.respond = respond
	return c
}

func (c *fakeConn) SendSNAC(frame wire.SNACFrame, body any) error {
	c.mu.Lock()
	if c.sendErr != nil {
		c.mu.Unlock()
		return c.sendErr
	}
	req := wire.SNACMessage{Frame: frame, Body: body}
	c.sent = append(c.sent, req)
	respond := c.respond
	c.mu.Unlock()

	if respond != nil {
		for _, reply := range respond(req) {
			if reply.Frame.RequestID == 0 {
				reply.Frame.RequestID = frame.RequestID
			}
			c.msgs <- reply
		}
	}
	return nil
}

// push delivers a server-initiated SNAC.
func (c *fakeConn) push(msg wire.SNACMessage) {
	c.msgs <- msg
}

func (c *fakeConn) Messages() <-chan wire.SNACMessage {
	return c.msgs
}

func (c *fakeConn) Closed() <-chan struct{} {
	return c.closed
}

func (c *fakeConn) Close() {
	c.closeOnce.Do(func() {
		close(c.closed)
	})
}

// sentSNACs returns a copy of the SNACs sent so far.
func (c *fakeConn) sentSNACs() []wire.SNACMessage {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]wire.SNACMessage(nil), c.sent...)
}

// sentOf returns the bodies of the SNACs sent so far with the given food
// group and subgroup.
func (c *fakeConn) sentOf(foodGroup, subGroup uint16) []any {
	var bodies []any
	for _, msg := range c.sentSNACs() {
		if msg.Frame.FoodGroup == foodGroup && msg.Frame.SubGroup == subGroup {
			bodies = append(bodies, msg.Body)
		}
	}
	return bodies
}

// reply returns a SNAC answering the request it's returned for.
func reply(foodGroup, subGroup uint16, body any) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{FoodGroup: foodGroup, SubGroup: subGroup},
		Body:  body,
	}
}

// snacErr returns an error SNAC in foodGroup answering the request it's
// returned for.
func snacErr(foodGroup uint16, code uint16) wire.SNACMessage {
	return reply(foodGroup, snacErrorSubGroup, wire.SNACError{Code: code})
}

// firstAnswer returns a responder that answers each request with the first
// of responders that has an answer for it.
func firstAnswer(responders ...func(req wire.SNACMessage) []wire.SNACMessage) func(req wire.SNACMessage) []wire.SNACMessage {
	return func(req wire.SNACMessage) []wire.SNACMessage {
		for _, respond := range responders {
			if answer := respond(req); answer != nil {
				return answer
			}
		}
		return nil
	}
}

// locateReplies returns a responder that answers each locate user info query
// with the reply for its screen name, or a not-logged-on error for a name
// without one.
func locateReplies(replies map[string]wire.SNAC_0x02_0x06_LocateUserInfoReply) func(req wire.SNACMessage) []wire.SNACMessage {
	return func(req wire.SNACMessage) []wire.SNACMessage {
		query, ok := req.Body.(wire.SNAC_0x02_0x05_LocateUserInfoQuery)
		if !ok {
			return nil
		}
		if body, ok := replies[state.NewIdentScreenName(query.ScreenName).String()]; ok {
			return []wire.SNACMessage{reply(wire.Locate, wire.LocateUserInfoReply, body)}
		}
		return []wire.SNACMessage{snacErr(wire.Locate, wire.ErrorCodeNotLoggedOn)}
	}
}

// rateLimitEventStatuses returns the status string of every rateLimit event
// queued on the session, in order.
func rateLimitEventStatuses(t *testing.T, session *Session) []string {
	t.Helper()

	var statuses []string
	for _, event := range session.EventQueue.GetAllEvents() {
		if event.Type != EventTypeRateLimit {
			continue
		}
		payload, ok := event.Data.(RateLimitEvent)
		if !assert.True(t, ok, "rateLimit event carried %T", event.Data) {
			continue
		}
		if assert.Len(t, payload.Classes, 1) {
			statuses = append(statuses, payload.Classes[0].Status)
		}
	}
	return statuses
}

// buddyArrives feeds a BuddyArrived through the session's SNAC handler, which is
// how its presence view learns that a buddy is online.
func buddyArrives(sess *Session, info wire.TLVUserInfo) {
	sess.handleBuddyArrived(wire.SNACMessage{Body: wire.SNAC_0x03_0x0B_BuddyArrived{TLVUserInfo: info}})
}

// buddyDeparts feeds a BuddyDeparted through the session's SNAC handler.
func buddyDeparts(sess *Session, screenName string) {
	sess.handleBuddyDeparted(wire.SNACMessage{Body: wire.SNAC_0x03_0x0C_BuddyDeparted{
		TLVUserInfo: wire.TLVUserInfo{ScreenName: screenName},
	}})
}

// onlineBuddy is the user info an ordinary online buddy arrives with.
func onlineBuddy(screenName string) wire.TLVUserInfo {
	return wire.TLVUserInfo{ScreenName: screenName}
}

// bartBuddy is the user info a buddy arrives with when they advertise BART
// items, which carry the icon hash and the status message.
func bartBuddy(screenName string, ids ...wire.BARTID) wire.TLVUserInfo {
	info := wire.TLVUserInfo{ScreenName: screenName}
	info.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, ids))
	return info
}

// aliasFeedbagItems builds the buddy rows carrying the given aliases.
func aliasFeedbagItems(aliases map[string]string) []wire.FeedbagItem {
	items := make([]wire.FeedbagItem, 0, len(aliases))
	var itemID uint16
	for name, alias := range aliases {
		itemID++
		item := wire.FeedbagItem{ItemID: itemID, ClassID: wire.FeedbagClassIdBuddy, GroupID: 100, Name: name}
		item.TLVLBlock = wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, alias)}}
		items = append(items, item)
	}
	return items
}

// feedbagServer answers feedbag SNACs the way the OSCAR server does. It holds
// the owner's feedbag, answers queries with it, and applies each change before
// answering it with a FeedbagStatus.
type feedbagServer struct {
	mu    sync.Mutex
	items []wire.FeedbagItem
	// status, when set, answers changes in place of a FeedbagStatus that
	// accepts every item. A nil result leaves the change unanswered and
	// unapplied.
	status func(req wire.SNACMessage) []wire.SNACMessage
}

// newFeedbagServer returns a feedbagServer holding items.
func newFeedbagServer(items ...wire.FeedbagItem) *feedbagServer {
	return &feedbagServer{items: state.CloneFeedbagItems(items)}
}

func (f *feedbagServer) respond(req wire.SNACMessage) []wire.SNACMessage {
	if req.Frame.FoodGroup != wire.Feedbag {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	var items []wire.FeedbagItem
	switch body := req.Body.(type) {
	case wire.SNAC_0x13_0x08_FeedbagInsertItem:
		items = body.Items
	case wire.SNAC_0x13_0x09_FeedbagUpdateItem:
		items = body.Items
	case wire.SNAC_0x13_0x0A_FeedbagDeleteItem:
		items = body.Items
	default:
		if req.Frame.SubGroup == wire.FeedbagQuery {
			return []wire.SNACMessage{reply(wire.Feedbag, wire.FeedbagReply,
				wire.SNAC_0x13_0x06_FeedbagReply{Items: state.CloneFeedbagItems(f.items)})}
		}
		return nil
	}

	answer := acceptChange(req)
	if f.status != nil {
		answer = f.status(req)
	}
	if accepted(answer) {
		f.apply(req.Frame.SubGroup == wire.FeedbagDeleteItem, items)
	}
	return answer
}

// acceptChange answers a feedbag change with a FeedbagStatus accepting every
// item.
func acceptChange(req wire.SNACMessage) []wire.SNACMessage {
	var n int
	switch body := req.Body.(type) {
	case wire.SNAC_0x13_0x08_FeedbagInsertItem:
		n = len(body.Items)
	case wire.SNAC_0x13_0x09_FeedbagUpdateItem:
		n = len(body.Items)
	case wire.SNAC_0x13_0x0A_FeedbagDeleteItem:
		n = len(body.Items)
	}
	return []wire.SNACMessage{reply(wire.Feedbag, wire.FeedbagStatus,
		wire.SNAC_0x13_0x0E_FeedbagStatus{Results: make([]uint16, n)})}
}

// accepted reports whether answer is a FeedbagStatus.
func accepted(answer []wire.SNACMessage) bool {
	for _, msg := range answer {
		if _, ok := msg.Body.(wire.SNAC_0x13_0x0E_FeedbagStatus); ok {
			return true
		}
	}
	return false
}

// apply upserts items, or deletes them when del is true. Items match by
// group and item ID.
func (f *feedbagServer) apply(del bool, items []wire.FeedbagItem) {
	for _, item := range items {
		i := slices.IndexFunc(f.items, func(existing wire.FeedbagItem) bool {
			return existing.GroupID == item.GroupID && existing.ItemID == item.ItemID
		})
		switch {
		case del && i >= 0:
			f.items = slices.Delete(f.items, i, i+1)
		case !del && i >= 0:
			f.items[i] = item
		case !del:
			f.items = append(f.items, item)
		}
	}
}

// stored returns the feedbag the server holds.
func (f *feedbagServer) stored() []wire.FeedbagItem {
	f.mu.Lock()
	defer f.mu.Unlock()
	return state.CloneFeedbagItems(f.items)
}

// newFeedbagSession returns a running session for "me" whose OSCAR server is
// server, with its feedbag loaded, and the session's connection.
func newFeedbagSession(t *testing.T, server *feedbagServer, events ...string) (*Session, *fakeConn) {
	t.Helper()
	return newFeedbagSessionAs(t, "me", server, events...)
}

// newFeedbagSessionAs is newFeedbagSession for screenName.
func newFeedbagSessionAs(t *testing.T, screenName state.DisplayScreenName, server *feedbagServer, events ...string) (*Session, *fakeConn) {
	t.Helper()
	conn := newFakeConn().answering(server.respond)
	sess := newTestSessionAs(t, screenName, conn, events...)
	loadTestFeedbag(t, sess)
	return sess, conn
}

// loadTestFeedbag loads the session's feedbag from its OSCAR server.
func loadTestFeedbag(t *testing.T, sess *Session) {
	t.Helper()
	sess.feedbagMu.Lock()
	defer sess.feedbagMu.Unlock()
	require.NoError(t, sess.loadFeedbag(context.Background()))
}

// sentFeedbagChanges returns the feedbag changes sent to the OSCAR server, in
// order, as the subgroup and items of each.
func sentFeedbagChanges(conn *fakeConn) []feedbagChangeSent {
	var changes []feedbagChangeSent
	for _, msg := range conn.sentSNACs() {
		switch body := msg.Body.(type) {
		case wire.SNAC_0x13_0x08_FeedbagInsertItem:
			changes = append(changes, feedbagChangeSent{wire.FeedbagInsertItem, body.Items})
		case wire.SNAC_0x13_0x09_FeedbagUpdateItem:
			changes = append(changes, feedbagChangeSent{wire.FeedbagUpdateItem, body.Items})
		case wire.SNAC_0x13_0x0A_FeedbagDeleteItem:
			changes = append(changes, feedbagChangeSent{wire.FeedbagDeleteItem, body.Items})
		}
	}
	return changes
}

// feedbagChangeSent is a feedbag change a session sent.
type feedbagChangeSent struct {
	SubGroup uint16
	Items    []wire.FeedbagItem
}

// limitRateClass makes the session treat the rate class of SNACs of foodGroup
// and subGroup as announced limited.
func limitRateClass(session *Session, foodGroup, subGroup uint16) {
	class, _ := session.snacRateLimits.RateClassLookup(foodGroup, subGroup)
	session.rates.announce(rateParamsChangeLimited, wire.RateParamsSNAC{
		ID:           uint16(class),
		WindowSize:   20,
		ClearLevel:   5100,
		CurrentLevel: 4000,
	}, time.Now())
}
