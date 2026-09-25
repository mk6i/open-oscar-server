package webapi

import (
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

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

// tightRateLimitClasses returns rate classes scaled down so tests run fast.
//
// OSCAR's moving average tracks the interval between requests in milliseconds,
// seeded at MaxLevel, and each back-to-back request halves it at WindowSize 2.
// So from 200 the sequence is 100 (clear), 50 (limited), 25, 12, 6 — the second
// request trips the limit, and none of the first five fall below the disconnect
// threshold. Recovering past ClearLevel takes a ~150ms pause rather than the
// several seconds the production classes would need.
func tightRateLimitClasses() wire.RateLimitClasses {
	var classes [5]wire.RateClass
	for i := range classes {
		classes[i] = wire.RateClass{
			ID:              wire.RateLimitClassID(i + 1),
			WindowSize:      2,
			ClearLevel:      100,
			AlertLevel:      80,
			LimitLevel:      70,
			DisconnectLevel: 2,
			MaxLevel:        200,
		}
	}
	return wire.NewRateLimitClasses(classes)
}

// newTestOSCARInstance builds an OSCAR session with rate limit state
// initialized, mirroring what RegisterBOSSession does at startSession time.
func newTestOSCARInstance(t *testing.T, classes wire.RateLimitClasses) *state.SessionInstance {
	t.Helper()

	instance := state.NewSession().AddInstance()
	instance.Session().SetIdentScreenName(state.NewIdentScreenName("me"))
	instance.Session().SetDisplayScreenName("me")
	instance.Session().SetRateClasses(time.Now(), classes)

	return instance
}

// newTestWebAPISessionOn builds a WebAPI session over an existing OSCAR
// instance. Two of them model two browser tabs signed in as the same account:
// each tab holds its own aimsid and its own Session, but the account has
// one OSCAR session and therefore one set of rate limit states.
func newTestWebAPISessionOn(aimsid string, instance *state.SessionInstance) *Session {
	return &Session{
		AimSID:       aimsid,
		ScreenName:   "me",
		OSCARSession: instance,
		EventQueue:   NewEventQueue(10),
	}
}

// newTestWebAPISession builds a WebAPI session backed by a real OSCAR session
// with rate limit state initialized.
func newTestWebAPISession(t *testing.T, classes wire.RateLimitClasses) *Session {
	t.Helper()

	return newTestWebAPISessionOn("aimsid-1", newTestOSCARInstance(t, classes))
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
