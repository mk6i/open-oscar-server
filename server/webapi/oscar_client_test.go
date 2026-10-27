package webapi

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// newStoppedSession builds a WebAPI session for "me" over conn whose
// goroutines aren't running, so the test can feed its inbound loop's steps
// directly.
func newStoppedSession(t *testing.T, conn *fakeConn) *Session {
	t.Helper()
	sess := newSession("aimsid-1", "me", nil, conn, wire.DefaultSNACRateLimits(), "", slog.Default())
	t.Cleanup(sess.Close)
	return sess
}

// classOf returns the rate class of SNACs of foodGroup and subGroup.
func classOf(t *testing.T, sess *Session, foodGroup, subGroup uint16) wire.RateLimitClassID {
	t.Helper()
	class, ok := sess.snacRateLimits.RateClassLookup(foodGroup, subGroup)
	require.True(t, ok)
	return class
}

// limitedParams are the rate parameters of a limited class that clears after
// 26s: ClearLevel*WindowSize - CurrentLevel*(WindowSize-1) ms.
func limitedParams(class wire.RateLimitClassID) wire.RateParamsSNAC {
	return wire.RateParamsSNAC{
		ID:           uint16(class),
		WindowSize:   20,
		ClearLevel:   5100,
		CurrentLevel: 4000,
	}
}

func TestSession_takeReply(t *testing.T) {
	userInfoReply := wire.SNAC_0x02_0x06_LocateUserInfoReply{TLVUserInfo: wire.TLVUserInfo{ScreenName: "buddy"}}

	tests := []struct {
		name string
		// waits makes the cached request one whose reply a caller waits for.
		waits bool
		// reply builds the SNAC that arrives, given the cached request's ID.
		reply func(requestID uint32) wire.SNACMessage
		// wantTaken is whether the SNAC answers the request.
		wantTaken bool
		// wantDelivered is whether the waiter receives the SNAC.
		wantDelivered bool
	}{
		{
			name:  "a reply with an awaited subgroup is delivered",
			waits: true,
			reply: func(id uint32) wire.SNACMessage {
				return wire.SNACMessage{
					Frame: wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply, RequestID: id},
					Body:  userInfoReply,
				}
			},
			wantTaken:     true,
			wantDelivered: true,
		},
		{
			name:  "an error in the request's food group is delivered",
			waits: true,
			reply: func(id uint32) wire.SNACMessage {
				return wire.SNACMessage{
					Frame: wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: snacErrorSubGroup, RequestID: id},
					Body:  wire.SNACError{Code: wire.ErrorCodeNotLoggedOn},
				}
			},
			wantTaken:     true,
			wantDelivered: true,
		},
		{
			name:  "a SNAC in another food group is not taken",
			waits: true,
			reply: func(id uint32) wire.SNACMessage {
				return wire.SNACMessage{
					Frame: wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMClientEvent, RequestID: id},
					Body:  wire.SNAC_0x04_0x14_ICBMClientEvent{ScreenName: "peer", Event: 0x0002},
				}
			},
		},
		{
			name:  "an error in another food group is not taken",
			waits: true,
			reply: func(id uint32) wire.SNACMessage {
				return wire.SNACMessage{
					Frame: wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: snacErrorSubGroup, RequestID: id},
					Body:  wire.SNACError{Code: wire.ErrorCodeNotLoggedOn},
				}
			},
		},
		{
			name:  "a SNAC with a subgroup the request doesn't await is not taken",
			waits: true,
			reply: func(id uint32) wire.SNACMessage {
				return wire.SNACMessage{
					Frame: wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateGetDirReply, RequestID: id},
					Body:  wire.SNAC_0x02_0x0C_LocateGetDirReply{},
				}
			},
		},
		{
			name:  "a SNAC with an unknown request ID is not taken",
			waits: true,
			reply: func(id uint32) wire.SNACMessage {
				return wire.SNACMessage{
					Frame: wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply, RequestID: id + 1},
					Body:  userInfoReply,
				}
			},
		},
		{
			name: "an error answering a sent SNAC is taken",
			reply: func(id uint32) wire.SNACMessage {
				return wire.SNACMessage{
					Frame: wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: snacErrorSubGroup, RequestID: id},
					Body:  wire.SNACError{Code: wire.ErrorCodeNotLoggedOn},
				}
			},
			wantTaken: true,
		},
		{
			name: "a reply to a sent SNAC is not taken",
			reply: func(id uint32) wire.SNACMessage {
				return wire.SNACMessage{
					Frame: wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply, RequestID: id},
					Body:  userInfoReply,
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess := newStoppedSession(t, newFakeConn())

			var waiter *replyWaiter
			frame := wire.SNACFrame{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery}
			if tt.waits {
				waiter = &replyWaiter{ch: make(chan wire.SNACMessage, 1), subGroups: []uint16{wire.LocateUserInfoReply}}
				sess.cache.Add(&frame, waiter)
			} else {
				sess.cache.Add(&frame, nil)
			}

			msg := tt.reply(frame.RequestID)
			assert.Equal(t, tt.wantTaken, sess.takeReply(msg))

			_, pending := sess.cache.Pending()[frame.RequestID]
			assert.Equal(t, !tt.wantTaken, pending, "a request stays pending until a SNAC answers it")

			if waiter == nil {
				return
			}
			select {
			case got := <-waiter.ch:
				assert.True(t, tt.wantDelivered, "delivered %v", got)
				assert.Equal(t, msg, got)
			default:
				assert.False(t, tt.wantDelivered, "the waiter received nothing")
			}
		})
	}
}

func TestSession_request(t *testing.T) {
	query := wire.SNAC_0x02_0x05_LocateUserInfoQuery{ScreenName: "buddy"}
	answer := wire.SNAC_0x02_0x06_LocateUserInfoReply{TLVUserInfo: wire.TLVUserInfo{ScreenName: "buddy"}}

	t.Run("the reply is returned and the request forgotten", func(t *testing.T) {
		conn := newFakeConn().answering(func(wire.SNACMessage) []wire.SNACMessage {
			return []wire.SNACMessage{reply(wire.Locate, wire.LocateUserInfoReply, answer)}
		})
		sess := newTestSession(t, conn)

		got, err := sess.request(context.Background(), wire.Locate, wire.LocateUserInfoQuery, query, wire.LocateUserInfoReply)
		require.NoError(t, err)
		assert.Equal(t, answer, got.Body)

		sent := conn.sentSNACs()
		require.Len(t, sent, 1)
		assert.Equal(t, query, sent[0].Body)
		assert.NotZero(t, sent[0].Frame.RequestID)
		assert.Equal(t, sent[0].Frame.RequestID, got.Frame.RequestID)
		assert.Empty(t, sess.cache.Pending())
	})

	t.Run("an error SNAC is returned as the reply", func(t *testing.T) {
		conn := newFakeConn().answering(func(wire.SNACMessage) []wire.SNACMessage {
			return []wire.SNACMessage{snacErr(wire.Locate, wire.ErrorCodeNotLoggedOn)}
		})
		sess := newTestSession(t, conn)

		got, err := sess.request(context.Background(), wire.Locate, wire.LocateUserInfoQuery, query, wire.LocateUserInfoReply)
		require.NoError(t, err)
		assert.Equal(t, wire.SNACError{Code: wire.ErrorCodeNotLoggedOn}, got.Body)
	})

	t.Run("relayed SNACs carrying the request's ID are translated, not returned", func(t *testing.T) {
		// The server relays a peer's typing event with the request ID the peer
		// chose, which can match one of ours.
		conn := newFakeConn().answering(func(req wire.SNACMessage) []wire.SNACMessage {
			return []wire.SNACMessage{
				{
					Frame: wire.SNACFrame{FoodGroup: wire.ICBM, SubGroup: wire.ICBMClientEvent, RequestID: req.Frame.RequestID},
					Body:  wire.SNAC_0x04_0x14_ICBMClientEvent{ScreenName: "peer", Event: 0x0002},
				},
				reply(wire.ICBM, wire.ICBMHostAck, wire.SNAC_0x04_0x0C_ICBMHostAck{ScreenName: "peer"}),
			}
		})
		sess := newTestSession(t, conn, "typing")

		got, err := sess.request(context.Background(), wire.ICBM, wire.ICBMChannelMsgToHost,
			wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{ScreenName: "peer"}, wire.ICBMHostAck)
		require.NoError(t, err)
		assert.Equal(t, wire.SNAC_0x04_0x0C_ICBMHostAck{ScreenName: "peer"}, got.Body)

		events := sess.EventQueue.GetAllEvents()
		require.Len(t, events, 1)
		assert.Equal(t, EventTypeTyping, events[0].Type)
	})

	t.Run("no reply in time", func(t *testing.T) {
		conn := newFakeConn()
		sess := newTestSession(t, conn)
		sess.requestTimeout = 10 * time.Millisecond

		_, err := sess.request(context.Background(), wire.Locate, wire.LocateUserInfoQuery, query, wire.LocateUserInfoReply)
		assert.ErrorIs(t, err, errNoReply)
		assert.Empty(t, sess.cache.Pending())
	})

	t.Run("the connection closes while waiting", func(t *testing.T) {
		conn := newFakeConn().answering(func(wire.SNACMessage) []wire.SNACMessage {
			return nil
		})
		sess := newStoppedSession(t, conn)
		conn.Close()

		_, err := sess.request(context.Background(), wire.Locate, wire.LocateUserInfoQuery, query, wire.LocateUserInfoReply)
		assert.ErrorIs(t, err, errOSCARClosed)
	})

	t.Run("the caller gives up", func(t *testing.T) {
		sess := newStoppedSession(t, newFakeConn())
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := sess.request(ctx, wire.Locate, wire.LocateUserInfoQuery, query, wire.LocateUserInfoReply)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("the request can't be sent", func(t *testing.T) {
		conn := newFakeConn()
		conn.sendErr = io.ErrClosedPipe
		sess := newStoppedSession(t, conn)

		_, err := sess.request(context.Background(), wire.Locate, wire.LocateUserInfoQuery, query, wire.LocateUserInfoReply)
		assert.ErrorIs(t, err, io.ErrClosedPipe)
		assert.Empty(t, sess.cache.Pending())
	})
}

func TestSession_send(t *testing.T) {
	body := wire.SNAC_0x04_0x14_ICBMClientEvent{ScreenName: "peer", Event: 0x0002}

	t.Run("the SNAC is sent and stays pending for an error", func(t *testing.T) {
		conn := newFakeConn()
		sess := newStoppedSession(t, conn)

		require.NoError(t, sess.send(wire.ICBM, wire.ICBMClientEvent, body))

		sent := conn.sentSNACs()
		require.Len(t, sent, 1)
		assert.Equal(t, body, sent[0].Body)
		assert.Contains(t, sess.cache.Pending(), sent[0].Frame.RequestID)
	})

	t.Run("the SNAC can't be sent", func(t *testing.T) {
		conn := newFakeConn()
		conn.sendErr = io.ErrClosedPipe
		sess := newStoppedSession(t, conn)

		assert.ErrorIs(t, sess.send(wire.ICBM, wire.ICBMClientEvent, body), io.ErrClosedPipe)
		assert.Empty(t, sess.cache.Pending())
	})
}

func TestSession_rateGate(t *testing.T) {
	setInfo := wire.SNAC_0x02_0x04_LocateSetInfo{}

	t.Run("a SNAC in a limited class is held back", func(t *testing.T) {
		conn := newFakeConn()
		sess := newStoppedSession(t, conn)
		limitRateClass(sess, wire.Locate, wire.LocateSetInfo)

		err := sess.send(wire.Locate, wire.LocateSetInfo, setInfo)
		var limited *rateLimitError
		require.ErrorAs(t, err, &limited)
		assert.ErrorIs(t, err, errRateLimited)
		assert.InDelta(t, 26*time.Second, limited.retryAfter, float64(time.Second))

		_, err = sess.request(context.Background(), wire.Locate, wire.LocateSetInfo, setInfo)
		assert.ErrorIs(t, err, errRateLimited)
		assert.Empty(t, conn.sentSNACs())
	})

	t.Run("a cleared class lets SNACs through", func(t *testing.T) {
		conn := newFakeConn()
		sess := newStoppedSession(t, conn)
		limitRateClass(sess, wire.Locate, wire.LocateSetInfo)
		class := classOf(t, sess, wire.Locate, wire.LocateSetInfo)
		sess.rates.announce(rateParamsChangeClear, wire.RateParamsSNAC{ID: uint16(class)}, time.Now())

		require.NoError(t, sess.send(wire.Locate, wire.LocateSetInfo, setInfo))
		assert.Len(t, conn.sentOf(wire.Locate, wire.LocateSetInfo), 1)
	})

	t.Run("the gate lapses once the class should have cleared", func(t *testing.T) {
		conn := newFakeConn()
		sess := newStoppedSession(t, conn)
		class := classOf(t, sess, wire.Locate, wire.LocateSetInfo)
		sess.rates.announce(rateParamsChangeLimited, limitedParams(class), time.Now().Add(-time.Minute))

		require.NoError(t, sess.send(wire.Locate, wire.LocateSetInfo, setInfo))
		assert.Len(t, conn.sentOf(wire.Locate, wire.LocateSetInfo), 1)
	})

	t.Run("exempt lookups go out while their class is limited", func(t *testing.T) {
		for _, snac := range RateLimitExempt {
			conn := newFakeConn()
			sess := newStoppedSession(t, conn)
			limitRateClass(sess, snac.FoodGroup, snac.SubGroup)

			assert.NoError(t, sess.send(snac.FoodGroup, snac.SubGroup, struct{}{}))
			assert.Len(t, conn.sentOf(snac.FoodGroup, snac.SubGroup), 1, wire.SubGroupName(snac.FoodGroup, snac.SubGroup))
		}
	})

	t.Run("a request unanswered while its class is limited was dropped", func(t *testing.T) {
		// The gate lapsed, but the class never cleared, so the server dropped
		// the request. The session holds SNACs back again.
		conn := newFakeConn()
		sess := newTestSession(t, conn)
		sess.requestTimeout = 10 * time.Millisecond
		class := classOf(t, sess, wire.Locate, wire.LocateSetDirInfo)
		sess.rates.announce(rateParamsChangeLimited, limitedParams(class), time.Now().Add(-time.Minute))

		_, err := sess.request(context.Background(), wire.Locate, wire.LocateSetDirInfo,
			wire.SNAC_0x02_0x09_LocateSetDirInfo{}, wire.LocateSetDirReply)
		var limited *rateLimitError
		require.ErrorAs(t, err, &limited)
		assert.Equal(t, 26*time.Second, limited.retryAfter)

		assert.ErrorIs(t, sess.send(wire.Locate, wire.LocateSetDirInfo, wire.SNAC_0x02_0x09_LocateSetDirInfo{}), errRateLimited)
		assert.Len(t, conn.sentOf(wire.Locate, wire.LocateSetDirInfo), 1)
	})
}

func TestRateLimitState(t *testing.T) {
	now := time.Now()
	const class = wire.RateLimitClassID(3)

	tests := []struct {
		name string
		// announce runs before the checks.
		announce  func(r *rateLimitState)
		at        time.Time
		wantWait  time.Duration
		wantLimit bool
	}{
		{
			name:     "an unannounced class is not limited",
			announce: func(*rateLimitState) {},
			at:       now,
		},
		{
			name: "a limited class waits until it should clear",
			announce: func(r *rateLimitState) {
				r.announce(rateParamsChangeLimited, limitedParams(class), now)
			},
			at:        now.Add(6 * time.Second),
			wantWait:  20 * time.Second,
			wantLimit: true,
		},
		{
			name: "the wait never drops below the minimum hint",
			announce: func(r *rateLimitState) {
				r.announce(rateParamsChangeLimited, limitedParams(class), now)
			},
			at:        now.Add(26*time.Second - time.Millisecond),
			wantWait:  minRetryAfter,
			wantLimit: true,
		},
		{
			name: "a limited class is no longer held back once it should have cleared",
			announce: func(r *rateLimitState) {
				r.announce(rateParamsChangeLimited, limitedParams(class), now)
			},
			at: now.Add(26 * time.Second),
		},
		{
			name: "a clear announcement lifts the limit",
			announce: func(r *rateLimitState) {
				r.announce(rateParamsChangeLimited, limitedParams(class), now)
				r.announce(rateParamsChangeClear, wire.RateParamsSNAC{ID: uint16(class)}, now)
			},
			at: now,
		},
		{
			name: "other classes are unaffected",
			announce: func(r *rateLimitState) {
				r.announce(rateParamsChangeLimited, limitedParams(class+1), now)
			},
			at: now,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r rateLimitState
			tt.announce(&r)

			wait, limited := r.limited(class, tt.at)
			assert.Equal(t, tt.wantLimit, limited)
			assert.Equal(t, tt.wantWait, wait)
		})
	}
}

func TestRateLimitState_timedOut(t *testing.T) {
	now := time.Now()
	const class = wire.RateLimitClassID(3)

	t.Run("a limited class is held back again", func(t *testing.T) {
		var r rateLimitState
		r.announce(rateParamsChangeLimited, limitedParams(class), now.Add(-time.Minute))
		_, limited := r.limited(class, now)
		require.False(t, limited)

		wait, limited := r.timedOut(class, now)
		assert.True(t, limited)
		assert.Equal(t, 26*time.Second, wait)

		wait, limited = r.limited(class, now.Add(time.Second))
		assert.True(t, limited)
		assert.Equal(t, 25*time.Second, wait)
	})

	t.Run("a class that isn't limited stays open", func(t *testing.T) {
		var r rateLimitState
		r.announce(rateParamsChangeClear, wire.RateParamsSNAC{ID: uint16(class)}, now)

		_, limited := r.timedOut(class, now)
		assert.False(t, limited)
		_, limited = r.timedOut(class+1, now)
		assert.False(t, limited)
		_, limited = r.limited(class, now)
		assert.False(t, limited)
	})
}

func TestRateLimitState_seed(t *testing.T) {
	now := time.Now()
	const class = wire.RateLimitClassID(3)
	params := func(dropping uint8) wire.RateParamsSNAC {
		p := limitedParams(class)
		p.V2Params = &struct {
			LastTime      uint32
			DroppingSNACs uint8
		}{DroppingSNACs: dropping}
		return p
	}

	t.Run("a class dropping SNACs is held back", func(t *testing.T) {
		var r rateLimitState
		r.seed([]wire.RateParamsSNAC{params(1)}, now)

		wait, limited := r.limited(class, now)
		assert.True(t, limited)
		assert.Equal(t, 26*time.Second, wait)
	})

	t.Run("other classes are open", func(t *testing.T) {
		var r rateLimitState
		r.seed([]wire.RateParamsSNAC{params(0), limitedParams(class + 1)}, now)

		_, limited := r.limited(class, now)
		assert.False(t, limited)
		_, limited = r.limited(class+1, now)
		assert.False(t, limited, "a reply without status params reports nothing")
	})

	t.Run("an announcement made before the reply arrived wins", func(t *testing.T) {
		var r rateLimitState
		r.announce(rateParamsChangeClear, wire.RateParamsSNAC{ID: uint16(class)}, now)
		r.seed([]wire.RateParamsSNAC{params(1)}, now)

		_, limited := r.limited(class, now)
		assert.False(t, limited)
	})
}

func TestSelfInfo(t *testing.T) {
	queried := wire.TLVUserInfo{ScreenName: "me", WarningLevel: 1}
	relayed := wire.TLVUserInfo{ScreenName: "me", WarningLevel: 2}

	t.Run("the reply sets the user info", func(t *testing.T) {
		var i selfInfo
		i.setReply(queried)
		assert.Equal(t, queried, i.userInfo())
	})

	t.Run("a relayed update replaces the reply", func(t *testing.T) {
		var i selfInfo
		i.setReply(queried)
		i.setRelayed(relayed)
		assert.Equal(t, relayed, i.userInfo())
	})

	t.Run("a reply arriving after a relayed update is older", func(t *testing.T) {
		var i selfInfo
		i.setRelayed(relayed)
		i.setReply(queried)
		assert.Equal(t, relayed, i.userInfo())
	})
}

func TestSession_signOn(t *testing.T) {
	ownInfo := wire.TLVUserInfo{ScreenName: "me", WarningLevel: 3}
	userInfoReply := reply(wire.OService, wire.OServiceUserInfoUpdate,
		wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{UserInfo: []wire.TLVUserInfo{ownInfo}})

	feedbag := []wire.FeedbagItem{{GroupID: 1, ItemID: 2, ClassID: wire.FeedbagClassIdBuddy, Name: "pal"}}
	feedbagReply := reply(wire.Feedbag, wire.FeedbagReply, wire.SNAC_0x13_0x06_FeedbagReply{Items: feedbag})

	// The IM class is dropping SNACs.
	imClass, ok := wire.DefaultSNACRateLimits().RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	require.True(t, ok)
	imRate := limitedParams(imClass)
	imRate.V2Params = &struct {
		LastTime      uint32
		DroppingSNACs uint8
	}{DroppingSNACs: 1}
	rateParamsReply := reply(wire.OService, wire.OServiceRateParamsReply,
		wire.SNAC_0x01_0x07_OServiceRateParamsReply{RateClasses: []wire.RateParamsSNAC{imRate}})

	// Going online, the server relays the arrival of the owner's online
	// buddy, then sets the report interval.
	wentOnline := []wire.SNACMessage{
		{
			Frame: wire.SNACFrame{FoodGroup: wire.Buddy, SubGroup: wire.BuddyArrived, RequestID: wire.ReqIDFromServer},
			Body:  wire.SNAC_0x03_0x0B_BuddyArrived{TLVUserInfo: wire.TLVUserInfo{ScreenName: "pal"}},
		},
		{
			Frame: wire.SNACFrame{FoodGroup: wire.Stats, SubGroup: wire.StatsSetMinReportInterval, RequestID: wire.ReqIDFromServer},
			Body:  wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{MinReportInterval: 1},
		},
	}

	// answer answers the user info query with userInfo and the feedbag query
	// with feedbagAnswer.
	answer := func(userInfo, feedbagAnswer wire.SNACMessage) func(req wire.SNACMessage) []wire.SNACMessage {
		return func(req wire.SNACMessage) []wire.SNACMessage {
			switch {
			case req.Frame.FoodGroup == wire.OService && req.Frame.SubGroup == wire.OServiceRateParamsQuery:
				return []wire.SNACMessage{rateParamsReply}
			case req.Frame.FoodGroup == wire.OService && req.Frame.SubGroup == wire.OServiceUserInfoQuery:
				return []wire.SNACMessage{userInfo}
			case req.Frame.FoodGroup == wire.Feedbag && req.Frame.SubGroup == wire.FeedbagQuery:
				return []wire.SNACMessage{feedbagAnswer}
			case req.Frame.FoodGroup == wire.OService && req.Frame.SubGroup == wire.OServiceClientOnline:
				return wentOnline
			}
			return nil
		}
	}

	type sentSNAC struct {
		FoodGroup, SubGroup uint16
		Body                any
	}
	sent := func(conn *fakeConn) []sentSNAC {
		var snacs []sentSNAC
		for _, msg := range conn.sentSNACs() {
			snacs = append(snacs, sentSNAC{msg.Frame.FoodGroup, msg.Frame.SubGroup, msg.Body})
		}
		return snacs
	}
	setup := []sentSNAC{
		{wire.OService, wire.OServiceRateParamsSubAdd, wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{ClassIDs: []uint16{1, 2, 3, 4, 5}}},
		{wire.Feedbag, wire.FeedbagUse, struct{}{}},
		{wire.Locate, wire.LocateSetInfo, wire.SNAC_0x02_0x04_LocateSetInfo{
			TLVRestBlock: wire.TLVRestBlock{TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, webAPICaps),
			}},
		}},
		{wire.OService, wire.OServiceClientVersions, wire.SNAC_0x01_0x17_OServiceClientVersions{Versions: []uint16{wire.OService, 3}}},
		{wire.OService, wire.OServiceRateParamsQuery, struct{}{}},
		{wire.OService, wire.OServiceUserInfoQuery, struct{}{}},
	}

	feedbagQuery := sentSNAC{wire.Feedbag, wire.FeedbagQuery, struct{}{}}

	t.Run("signs on and records the owner's user info and feedbag", func(t *testing.T) {
		conn := newFakeConn()
		conn.answering(func(req wire.SNACMessage) []wire.SNACMessage {
			if req.Frame.SubGroup != wire.OServiceClientOnline {
				return answer(userInfoReply, feedbagReply)(req)
			}
			// relayed a moment after the request, as the server's are
			go func() {
				time.Sleep(20 * time.Millisecond)
				for _, msg := range wentOnline {
					conn.push(msg)
				}
			}()
			return nil
		})
		sess := newTestSession(t, conn)

		require.NoError(t, sess.signOn(context.Background()))

		assert.Equal(t, append(setup,
			feedbagQuery,
			sentSNAC{wire.OService, wire.OServiceClientOnline, wire.SNAC_0x01_0x02_OServiceClientOnline{}},
		), sent(conn))
		assert.Equal(t, ownInfo, sess.self.userInfo())
		assert.Equal(t, feedbag, sess.Feedbag())
		_, limited := sess.rates.limited(imClass, time.Now())
		assert.True(t, limited, "the rate params reply seeds the dropping class")
		presence, ok := sess.BuddyPresence(state.NewIdentScreenName("pal"))
		assert.True(t, ok, "the buddies online at sign-on are known when it returns")
		assert.Equal(t, "online", presence.State)
	})

	t.Run("the server never finishes bringing the session online", func(t *testing.T) {
		conn := newFakeConn().answering(func(req wire.SNACMessage) []wire.SNACMessage {
			if req.Frame.SubGroup == wire.OServiceClientOnline {
				return wentOnline[:1]
			}
			return answer(userInfoReply, feedbagReply)(req)
		})
		sess := newTestSession(t, conn)
		sess.requestTimeout = 10 * time.Millisecond

		assert.ErrorIs(t, sess.signOn(context.Background()), errNoReply)
	})

	t.Run("the user info query is refused", func(t *testing.T) {
		conn := newFakeConn().answering(answer(snacErr(wire.OService, wire.ErrorCodeNotSupportedByHost), feedbagReply))
		sess := newTestSession(t, conn)

		assert.Error(t, sess.signOn(context.Background()))
		assert.Equal(t, setup, sent(conn), "the session must not go online")
	})

	t.Run("the user info reply carries no user info", func(t *testing.T) {
		conn := newFakeConn().answering(answer(reply(wire.OService, wire.OServiceUserInfoUpdate,
			wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{}), feedbagReply))
		sess := newTestSession(t, conn)

		assert.Error(t, sess.signOn(context.Background()))
		assert.Equal(t, setup, sent(conn), "the session must not go online")
	})

	t.Run("the feedbag query is refused", func(t *testing.T) {
		conn := newFakeConn().answering(answer(userInfoReply, snacErr(wire.Feedbag, wire.ErrorCodeNotSupportedByHost)))
		sess := newTestSession(t, conn)

		assert.Error(t, sess.signOn(context.Background()))
		assert.Equal(t, append(setup, feedbagQuery), sent(conn), "the session must not go online")
	})

	t.Run("the server never answers", func(t *testing.T) {
		conn := newFakeConn()
		sess := newTestSession(t, conn)
		sess.requestTimeout = 10 * time.Millisecond

		assert.ErrorIs(t, sess.signOn(context.Background()), errNoReply)
		// It gives up at the first request, the rate params query.
		assert.Equal(t, setup[:len(setup)-1], sent(conn), "the session must not go online")
	})

	t.Run("the connection is gone", func(t *testing.T) {
		conn := newFakeConn()
		conn.sendErr = io.ErrClosedPipe
		sess := newTestSession(t, conn)

		assert.ErrorIs(t, sess.signOn(context.Background()), io.ErrClosedPipe)
	})
}

func TestLimitLookups(t *testing.T) {
	sess := newStoppedSession(t, newFakeConn())

	var served int
	handler := limitLookups(slog.Default())(func(w http.ResponseWriter, r *http.Request, _ *Session) {
		served++
		SendOK(w, r, nil, slog.Default())
	})
	lookup := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		handler(rr, httptest.NewRequest(http.MethodGet, "/presence/get?f=json", nil), sess)
		return rr
	}

	for range lookupBurst {
		assert.Equal(t, http.StatusOK, envelopeStatus(t, lookup().Body.Bytes()))
	}
	rr := lookup()
	assert.Equal(t, statusRateLimited, envelopeStatus(t, rr.Body.Bytes()))
	assert.Equal(t, "1", rr.Header().Get("Retry-After"))
	assert.Equal(t, lookupBurst, served)
}

func TestSession_recvBOS_appliesServerSNACs(t *testing.T) {
	t.Run("a rate limit announcement gates its class", func(t *testing.T) {
		conn := newFakeConn()
		sess := newTestSession(t, conn)
		class := classOf(t, sess, wire.Locate, wire.LocateSetInfo)

		conn.push(wire.SNACMessage{
			Frame: wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceRateParamChange},
			Body:  wire.SNAC_0x01_0x0A_OServiceRateParamsChange{Code: rateParamsChangeLimited, Rate: limitedParams(class)},
		})

		assert.Eventually(t, func() bool {
			_, limited := sess.rates.limited(class, time.Now())
			return limited
		}, time.Second, time.Millisecond)
	})

	t.Run("a user info update replaces the owner's user info", func(t *testing.T) {
		conn := newFakeConn()
		sess := newTestSession(t, conn, "myInfo")
		updated := wire.TLVUserInfo{ScreenName: "me", WarningLevel: 7}

		conn.push(wire.SNACMessage{
			Frame: wire.SNACFrame{FoodGroup: wire.OService, SubGroup: wire.OServiceUserInfoUpdate},
			Body:  wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{UserInfo: []wire.TLVUserInfo{updated}},
		})

		events, err := sess.EventQueue.Fetch(context.Background(), 0, time.Second)
		require.NoError(t, err)
		require.Len(t, events, 1)
		assert.Equal(t, EventTypeMyInfo, events[0].Type)
		assert.Equal(t, updated, sess.self.userInfo())

		// The reply to an earlier query is older than the update.
		sess.self.setReply(wire.TLVUserInfo{ScreenName: "me"})
		assert.Equal(t, updated, sess.self.userInfo())
	})
}
