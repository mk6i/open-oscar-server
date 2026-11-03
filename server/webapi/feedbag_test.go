package webapi

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/wire"
)

var (
	testGroup = wire.FeedbagItem{GroupID: 1, ClassID: wire.FeedbagClassIdGroup, Name: "Friends"}
	testBuddy = wire.FeedbagItem{GroupID: 1, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "pal"}
	// remoteBuddy is a buddy another of the owner's locations adds.
	remoteBuddy = wire.FeedbagItem{GroupID: 1, ItemID: 3, ClassID: wire.FeedbagClassIdBuddy, Name: "remote"}
)

// insertBuddy sends a change inserting testBuddy, holding the feedbag lock.
func insertBuddy(t *testing.T, sess *Session) ([]uint16, error) {
	t.Helper()
	_, err := sess.lockFeedbag(context.Background())
	require.NoError(t, err)
	defer sess.unlockFeedbag()
	return sess.changeFeedbag(context.Background(), wire.FeedbagInsertItem, []wire.FeedbagItem{testBuddy})
}

// remoteInsert is the relay of an insert made at another of the owner's
// locations.
func remoteInsert(items ...wire.FeedbagItem) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem, RequestID: wire.ReqIDFromServer},
		Body:  wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: items},
	}
}

func TestSession_changeFeedbag_confirmsAcceptedItems(t *testing.T) {
	server := newFeedbagServer(testGroup)
	server.status = func(req wire.SNACMessage) []wire.SNACMessage {
		return []wire.SNACMessage{reply(wire.Feedbag, wire.FeedbagStatus,
			wire.SNAC_0x13_0x0E_FeedbagStatus{Results: []uint16{feedbagResultAuthRequired}})}
	}
	sess, conn := newFeedbagSession(t, server)

	results, err := insertBuddy(t, sess)
	require.NoError(t, err)

	assert.Equal(t, []uint16{feedbagResultAuthRequired}, results)
	// The declined item isn't stored.
	assert.Equal(t, []wire.FeedbagItem{testGroup}, sess.Feedbag())
	assert.False(t, sess.feedbagStale.Load())
	assert.Equal(t, []feedbagChangeSent{{wire.FeedbagInsertItem, []wire.FeedbagItem{testBuddy}}}, sentFeedbagChanges(conn))
}

// A change the server doesn't confirm is discarded, and since the server may
// have applied it anyway, the next change reloads the feedbag first.
func TestSession_changeFeedbag_unconfirmedChangeReloadsBeforeNextChange(t *testing.T) {
	tests := []struct {
		name string
		// status answers the first change.
		status func(wire.SNACMessage) []wire.SNACMessage
		// appliedAnyway is whether the server applied the unconfirmed change.
		appliedAnyway bool
		wantErr       error
	}{
		{
			name:   "rejected",
			status: rejectChanges,
		},
		{
			name:          "unanswered",
			status:        func(wire.SNACMessage) []wire.SNACMessage { return nil },
			appliedAnyway: true,
			wantErr:       errNoReply,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newFeedbagServer(testGroup)
			server.status = tt.status
			sess, conn := newFeedbagSession(t, server)
			sess.requestTimeout = 20 * time.Millisecond

			_, err := insertBuddy(t, sess)
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.Equal(t, []wire.FeedbagItem{testGroup}, sess.Feedbag(), "the change is discarded")
			assert.True(t, sess.feedbagStale.Load())

			if tt.appliedAnyway {
				server.apply(false, []wire.FeedbagItem{testBuddy})
			}
			server.status = nil

			items, err := sess.lockFeedbag(context.Background())
			require.NoError(t, err)
			sess.unlockFeedbag()

			assert.Equal(t, server.stored(), items, "the next change diffs against the reloaded feedbag")
			assert.Equal(t, server.stored(), sess.Feedbag())
			assert.False(t, sess.feedbagStale.Load())
			assert.Len(t, conn.sentOf(wire.Feedbag, wire.FeedbagQuery), 2)
		})
	}
}

// A FeedbagStatus arriving after its change was given up on confirms nothing.
func TestSession_changeFeedbag_lateStatusIsIgnored(t *testing.T) {
	server := newFeedbagServer(testGroup)
	server.status = func(wire.SNACMessage) []wire.SNACMessage { return nil }
	sess, conn := newFeedbagSession(t, server)
	sess.requestTimeout = 20 * time.Millisecond

	_, err := insertBuddy(t, sess)
	require.ErrorIs(t, err, errNoReply)

	changes := conn.sentOf(wire.Feedbag, wire.FeedbagInsertItem)
	require.Len(t, changes, 1)
	var requestID uint32
	for _, msg := range conn.sentSNACs() {
		if msg.Frame.SubGroup == wire.FeedbagInsertItem {
			requestID = msg.Frame.RequestID
		}
	}

	late := reply(wire.Feedbag, wire.FeedbagStatus, wire.SNAC_0x13_0x0E_FeedbagStatus{Results: []uint16{0}})
	late.Frame.RequestID = requestID
	conn.push(late)
	// a later SNAC marks when the loop is past the late status
	conn.push(remoteInsert(remoteBuddy))

	require.Eventually(t, func() bool {
		return len(sess.Feedbag()) == 2
	}, time.Second, time.Millisecond)
	assert.Equal(t, []wire.FeedbagItem{testGroup, remoteBuddy}, sess.Feedbag())
	assert.True(t, sess.feedbagStale.Load())
}

// The server may have dropped feedbag changes while a rate class was limited,
// so a stale feedbag reloads when the class clears.
func TestSession_staleFeedbagReloadsWhenRateClassClears(t *testing.T) {
	server := newFeedbagServer(testGroup)
	server.status = func(wire.SNACMessage) []wire.SNACMessage { return nil }
	sess, conn := newFeedbagSession(t, server)
	sess.requestTimeout = 20 * time.Millisecond

	_, err := insertBuddy(t, sess)
	require.ErrorIs(t, err, errNoReply)
	require.True(t, sess.feedbagStale.Load())
	server.apply(false, []wire.FeedbagItem{testBuddy})

	class := classOf(t, sess, wire.Feedbag, wire.FeedbagInsertItem)
	conn.push(wire.SNACMessage{
		Frame: wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceRateParamChange},
		Body:  wire.SNAC_0x01_0x0A_OServiceRateParamsChange{Code: rateParamsChangeClear, Rate: wire.RateParamsSNAC{ID: uint16(class)}},
	})

	require.Eventually(t, func() bool {
		return !sess.feedbagStale.Load()
	}, time.Second, time.Millisecond)
	assert.Equal(t, server.stored(), sess.Feedbag())
	assert.Len(t, conn.sentOf(wire.Feedbag, wire.FeedbagQuery), 2)
}

func TestSession_currentFeedbagIsNotReloadedWhenRateClassClears(t *testing.T) {
	server := newFeedbagServer(testGroup)
	sess, conn := newFeedbagSession(t, server)

	conn.push(wire.SNACMessage{
		Frame: wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceRateParamChange},
		Body:  wire.SNAC_0x01_0x0A_OServiceRateParamsChange{Code: rateParamsChangeClear, Rate: wire.RateParamsSNAC{ID: 1}},
	})
	// a later SNAC marks when the loop is past the announcement
	conn.push(remoteInsert(remoteBuddy))

	require.Eventually(t, func() bool {
		return len(sess.Feedbag()) == 2
	}, time.Second, time.Millisecond)
	assert.Empty(t, sess.refreshCh)
	assert.Len(t, conn.sentOf(wire.Feedbag, wire.FeedbagQuery), 1)
}

// The server relays other locations' changes and answers a query from
// different goroutines, so a change can arrive before a reply that predates
// it.
func TestSession_loadFeedbag_keepsRemoteChangesThatArriveBeforeTheReply(t *testing.T) {
	conn := newFakeConn().answering(func(req wire.SNACMessage) []wire.SNACMessage {
		if req.Frame.SubGroup != wire.FeedbagQuery {
			return nil
		}
		return []wire.SNACMessage{
			remoteInsert(remoteBuddy),
			reply(wire.Feedbag, wire.FeedbagReply, wire.SNAC_0x13_0x06_FeedbagReply{Items: []wire.FeedbagItem{testGroup}}),
		}
	})
	sess := newTestSession(t, conn)

	loadTestFeedbag(t, sess)

	assert.Equal(t, []wire.FeedbagItem{testGroup, remoteBuddy}, sess.Feedbag())
}

func TestSession_loadFeedbag_failureLeavesFeedbagStale(t *testing.T) {
	conn := newFakeConn().answering(func(req wire.SNACMessage) []wire.SNACMessage {
		if req.Frame.SubGroup != wire.FeedbagQuery {
			return nil
		}
		return []wire.SNACMessage{
			remoteInsert(remoteBuddy),
			snacErr(wire.Feedbag, wire.ErrorCodeNotSupportedByHost),
		}
	})
	sess := newTestSession(t, conn)

	sess.feedbagMu.Lock()
	err := sess.loadFeedbag(context.Background())
	sess.feedbagMu.Unlock()

	assert.Error(t, err)
	assert.True(t, sess.feedbagStale.Load())
	// The remote change still applies on its own.
	assert.Equal(t, []wire.FeedbagItem{remoteBuddy}, sess.Feedbag())
	sess.feedbagQuery.mu.Lock()
	defer sess.feedbagQuery.mu.Unlock()
	assert.False(t, sess.feedbagQuery.active)
	assert.Empty(t, sess.feedbagQuery.remote)
}

func TestSession_remoteFeedbagChanges(t *testing.T) {
	aliased := testBuddy
	aliased.TLVLBlock = wire.TLVLBlock{TLVList: wire.TLVList{wire.NewTLVBE(wire.FeedbagAttributesAlias, "PAL")}}

	tests := []struct {
		name string
		msg  wire.SNACMessage
		want []wire.FeedbagItem
	}{
		{
			// The server relays an insert with an update body.
			name: "insert relayed with an update body",
			msg:  remoteInsert(remoteBuddy),
			want: []wire.FeedbagItem{testGroup, testBuddy, remoteBuddy},
		},
		{
			name: "insert",
			msg: wire.SNACMessage{
				Frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
				Body:  wire.SNAC_0x13_0x08_FeedbagInsertItem{Items: []wire.FeedbagItem{remoteBuddy}},
			},
			want: []wire.FeedbagItem{testGroup, testBuddy, remoteBuddy},
		},
		{
			name: "update",
			msg: wire.SNACMessage{
				Frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
				Body:  wire.SNAC_0x13_0x09_FeedbagUpdateItem{Items: []wire.FeedbagItem{aliased}},
			},
			want: []wire.FeedbagItem{testGroup, aliased},
		},
		{
			name: "delete",
			msg: wire.SNACMessage{
				Frame: wire.SNACFrame{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
				Body:  wire.SNAC_0x13_0x0A_FeedbagDeleteItem{Items: []wire.FeedbagItem{testBuddy}},
			},
			want: []wire.FeedbagItem{testGroup},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, _ := newFeedbagSession(t, newFeedbagServer(testGroup, testBuddy))

			sess.handleFeedbagMessage(tt.msg)

			assert.Equal(t, tt.want, sess.Feedbag())
		})
	}
}

func TestSession_changeFeedbag_heldBackWhileRateLimited(t *testing.T) {
	sess, conn := newFeedbagSession(t, newFeedbagServer(testGroup))
	limitRateClass(sess, wire.Feedbag, wire.FeedbagInsertItem)

	_, err := insertBuddy(t, sess)

	assert.ErrorIs(t, err, errRateLimited)
	assert.Empty(t, sentFeedbagChanges(conn))
	assert.Equal(t, []wire.FeedbagItem{testGroup}, sess.Feedbag())
	assert.False(t, sess.feedbagStale.Load(), "a change that was never sent changes nothing")
}

func TestSession_changeFeedbag_callerGivesUp(t *testing.T) {
	server := newFeedbagServer(testGroup)
	server.status = func(wire.SNACMessage) []wire.SNACMessage { return nil }
	sess, _ := newFeedbagSession(t, server)

	ctx, cancel := context.WithCancel(context.Background())
	_, err := sess.lockFeedbag(ctx)
	require.NoError(t, err)
	cancel()
	_, err = sess.changeFeedbag(ctx, wire.FeedbagInsertItem, []wire.FeedbagItem{testBuddy})
	sess.unlockFeedbag()

	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []wire.FeedbagItem{testGroup}, sess.Feedbag())
	assert.True(t, sess.feedbagStale.Load())
}

// A reply to a query the session gave up on reloads nothing: the feedbag is
// already stale and reloads before the next change.
func TestSession_applyFeedbagReply_ignoresAbandonedQuery(t *testing.T) {
	sess, _ := newFeedbagSession(t, newFeedbagServer(testGroup))

	sess.applyFeedbagReply([]wire.FeedbagItem{testBuddy})

	assert.Equal(t, []wire.FeedbagItem{testGroup}, sess.Feedbag())
}
