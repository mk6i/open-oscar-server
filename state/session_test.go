package state

import (
	"context"
	"math"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mk6i/open-oscar-server/wire"

	"github.com/stretchr/testify/assert"
)

func TestSession_IncrementAndGetWarning(t *testing.T) {
	s := NewInstance(NewSession())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.ScaleWarningAndRateLimit(1, 1)
		s.ScaleWarningAndRateLimit(2, 1)
		s.ScaleWarningAndRateLimit(3, 1)
	}()

	assert.Equal(t, uint16(1), <-s.WarningCh())
	assert.Equal(t, uint16(3), <-s.WarningCh())
	assert.Equal(t, uint16(6), <-s.WarningCh())

	wg.Wait()
}

func TestSession_SetAndGetInvisible(t *testing.T) {
	s := NewInstance(NewSession())
	assert.False(t, s.Invisible())
	s.SetUserStatusBitmask(wire.OServiceUserStatusInvisible)
	assert.True(t, s.Invisible())
}

func TestSession_SetAndGetScreenName(t *testing.T) {
	s := NewInstance(NewSession())
	assert.Empty(t, s.IdentScreenName())
	sn := NewIdentScreenName("user-screen-name")
	s.SetIdentScreenName(sn)
	assert.Equal(t, sn, s.IdentScreenName())
}

func TestSession_SetAndGetChatRoomCookie(t *testing.T) {
	s := NewInstance(NewSession())
	assert.Empty(t, s.ChatRoomCookie())
	sn := "the-chat-cookie"
	s.SetChatRoomCookie(sn)
	assert.Equal(t, sn, s.ChatRoomCookie())
}

func TestSession_SetAndGetUIN(t *testing.T) {
	s := NewInstance(NewSession())
	assert.Empty(t, s.UIN())
	uin := uint32(100003)
	s.SetUIN(uin)
	assert.Equal(t, uin, s.UIN())
}

func TestSession_SetAndGetClientID(t *testing.T) {
	s := NewInstance(NewSession())
	assert.Empty(t, s.ClientID())
	clientID := "AIM Client ID"
	s.SetClientID(clientID)
	assert.Equal(t, clientID, s.ClientID())
}

func TestSession_SetAndGetKerberosAuth(t *testing.T) {
	s := NewInstance(NewSession())
	assert.False(t, s.KerberosAuth())

	s.SetKerberosAuth(true)
	assert.True(t, s.KerberosAuth())

	s.SetKerberosAuth(false)
	assert.False(t, s.KerberosAuth())
}

func TestSession_SetAndGetRemoteAddr(t *testing.T) {
	s := NewInstance(NewSession())
	assert.Empty(t, s.RemoteAddr())
	remoteAddr, _ := netip.ParseAddrPort("1.2.3.4:1234")
	s.SetRemoteAddr(&remoteAddr)
	assert.Equal(t, &remoteAddr, s.RemoteAddr())
}

func TestSession_TLVUserInfo(t *testing.T) {
	tests := []struct {
		name           string
		givenSessionFn func() *SessionInstance
		want           wire.TLVUserInfo
	}{
		{
			name: "user is active and visible",
			givenSessionFn: func() *SessionInstance {
				s := NewInstance(NewSession())
				s.SetSignonTime(time.Unix(1, 0))
				s.SetIdentScreenName(NewIdentScreenName("xXAIMUSERXx"))
				s.SetDisplayScreenName("xXAIMUSERXx")
				s.ScaleWarningAndRateLimit(10, 1)
				s.SetUserInfoFlag(wire.OServiceUserFlagOSCARFree)
				return s
			},
			want: wire.TLVUserInfo{
				ScreenName:   "xXAIMUSERXx",
				WarningLevel: 10,
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1)),
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0x0010)),
						wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)),
					},
				},
			},
		},
		{
			name: "user is on ICQ",
			givenSessionFn: func() *SessionInstance {
				s := NewInstance(NewSession())
				s.SetSignonTime(time.Unix(1, 0))
				s.SetIdentScreenName(NewIdentScreenName("1000003"))
				s.SetDisplayScreenName("1000003")
				s.SetUserInfoFlag(wire.OServiceUserFlagICQ)

				return s
			},
			want: wire.TLVUserInfo{
				ScreenName: "1000003",
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1)),
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, wire.OServiceUserFlagOSCARFree|wire.OServiceUserFlagICQ),
						wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						wire.NewTLVBE(wire.OServiceUserInfoICQDC, wire.ICQDCInfo{}),
						wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)),
					},
				},
			},
		},
		{
			name: "user has away message set - all instances away",
			givenSessionFn: func() *SessionInstance {
				sg := NewSession()
				s := NewInstance(sg)
				s.SetSignonTime(time.Unix(1, 0))
				s.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				// Add a second instance that is also away
				s2 := NewInstance(sg)
				s2.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				return s
			},
			want: wire.TLVUserInfo{
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1)),
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0x30)),
						wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)),
					},
				},
			},
		},
		{
			name: "user has one instance away, one not away - away flag not set",
			givenSessionFn: func() *SessionInstance {
				sg := NewSession()
				// Create the NOT away instance first so it's used as the base
				s2 := NewInstance(sg)
				s2.SetSignonTime(time.Unix(1, 0))
				// s2 is NOT away - it has default flags only (OServiceUserFlagOSCARFree)
				// Now create the away instance
				s := NewInstance(sg)
				s.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				// Since s2 is the first instance and is not away, and allAway() returns false,
				// the unavailable flag should not be set
				return s
			},
			want: wire.TLVUserInfo{
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1)),
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0x10)),
						wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)),
					},
				},
			},
		},
		{
			name: "user has two instances away, second goes off away - away flag not set",
			givenSessionFn: func() *SessionInstance {
				sg := NewSession()
				sg.SetSignonTime(time.Unix(1, 0))
				// Set the first instance as away
				s1 := NewInstance(sg)
				s1.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				// Set the second instance as away
				s2 := NewInstance(sg)
				s2.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				// Make the second instance as not away
				s2.ClearUserInfoFlag(wire.OServiceUserFlagUnavailable)
				return s1
			},
			want: wire.TLVUserInfo{
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1)),
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0x10)),
						wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)),
					},
				},
			},
		},
		{
			name: "user is invisible",
			givenSessionFn: func() *SessionInstance {
				s := NewInstance(NewSession())
				s.SetSignonTime(time.Unix(1, 0))
				s.SetUserStatusBitmask(wire.OServiceUserStatusInvisible)
				return s
			},
			want: wire.TLVUserInfo{
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1)),
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0x0010)),
						wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0100)),
						wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)),
					},
				},
			},
		},
		{
			name: "user is idle",
			givenSessionFn: func() *SessionInstance {
				s := NewInstance(NewSession())
				// sign on at t=0m
				timeBegin := time.Unix(0, 0)
				s.SetSignonTime(timeBegin)
				// set idle for 1m at t=+5m (ergo user idled @ t=+4m)
				timeIdle := timeBegin.Add(5 * time.Minute)
				s.nowFn = func() time.Time { return timeIdle }
				s.SetIdle(1 * time.Minute)
				// now it's t=+10m, ergo idle time should be t10-t4=6m
				timeNow := timeBegin.Add(10 * time.Minute)
				s.nowFn = func() time.Time { return timeNow }
				return s
			},
			want: wire.TLVUserInfo{
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(0)),
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0x0010)),
						wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						wire.NewTLVBE(wire.OServiceUserInfoIdleTime, uint16(6)),
						wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)),
					},
				},
			},
		},
		{
			name: "user goes idle then returns",
			givenSessionFn: func() *SessionInstance {
				s := NewInstance(NewSession())
				s.SetSignonTime(time.Unix(1, 0))
				s.SetIdle(1 * time.Second)
				s.UnsetIdle()
				return s
			},
			want: wire.TLVUserInfo{
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1)),
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0x0010)),
						wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)),
					},
				},
			},
		},
		{
			name: "user has capabilities",
			givenSessionFn: func() *SessionInstance {
				s := NewInstance(NewSession())
				s.SetSignonTime(time.Unix(1, 0))
				s.SetCaps([][16]byte{
					{
						// chat: "748F2420-6287-11D1-8222-444553540000"
						0x74, 0x8f, 0x24, 0x20, 0x62, 0x87, 0x11, 0xd1,
						0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
					},
					{
						// chat2: "748F2420-6287-11D1-8222-444553540000"
						0x75, 0x8f, 0x24, 0x20, 0x62, 0x87, 0x11, 0xd1,
						0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x01,
					},
				})
				return s
			},
			want: wire.TLVUserInfo{
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1)),
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0x0010)),
						wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, []byte{
							// chat: "748F2420-6287-11D1-8222-444553540000"
							0x74, 0x8f, 0x24, 0x20, 0x62, 0x87, 0x11, 0xd1,
							0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
							// chat: "748F2420-6287-11D1-8222-444553540000"
							0x75, 0x8f, 0x24, 0x20, 0x62, 0x87, 0x11, 0xd1,
							0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x01,
						}),
						wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)),
					},
				},
			},
		},
		{
			name: "user has buddy icon",
			givenSessionFn: func() *SessionInstance {
				s := NewInstance(NewSession())
				s.SetSignonTime(time.Unix(1, 0))
				return s
			},
			want: wire.TLVUserInfo{
				WarningLevel: 0,
				TLVBlock: wire.TLVBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(1)),
						wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uint16(0x0010)),
						wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)),
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.givenSessionFn()
			assert.Equal(t, tt.want, s.TLVUserInfo())
		})
	}
}

func TestSession_SendAndRecvMessage_ExpectSessSendOK(t *testing.T) {
	s := NewInstance(NewSession())
	s.SetSignonComplete()

	msg := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
		},
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer s.CloseInstance()
		status := s.RelayMessage(msg)
		assert.Equal(t, SessSendOK, status)
	}()

loop:
	for {
		select {
		case m := <-s.ReceiveMessage():
			assert.Equal(t, msg, m)
		case <-s.Closed():
			break loop
		}
	}

	wg.Wait()
}

func TestSession_SendMessage_SessSendClosed(t *testing.T) {
	s := NewInstance(NewSession())
	s.CloseInstance()
	if res := s.RelayMessage(wire.SNACMessage{}); res != SessSendClosed {
		t.Fatalf("expected SessSendClosed, got %+v", res)
	}
}

func TestSession_SendMessage_SessQueueFull(t *testing.T) {
	s := NewInstance(NewSession())
	s.SetSignonComplete()
	// Fill up the message channel (default buffer size is 1000)
	for i := 0; i < 1000; i++ {
		assert.Equal(t, SessSendOK, s.RelayMessage(wire.SNACMessage{}))
	}
	assert.Equal(t, SessQueueFull, s.RelayMessage(wire.SNACMessage{}))
}

func TestSession_Close_Twice(t *testing.T) {
	s := NewInstance(NewSession())
	s.CloseInstance()
	s.CloseInstance() // make sure close is idempotent
	// Check that the session is closed by trying to relay a message
	if res := s.RelayMessage(wire.SNACMessage{}); res != SessSendClosed {
		t.Fatalf("expected SessSendClosed, got %+v", res)
	}
	select {
	case <-s.Closed():
	case <-time.After(1 * time.Second):
		t.Fatalf("channel is not closed")
	}
}

func TestSession_Closed(t *testing.T) {
	s := NewInstance(NewSession())
	select {
	case <-s.Closed():
		assert.Fail(t, "channel is closed")
	default:
		// channel is open by default
	}
	s.CloseSession()
	<-s.Closed()
}

func TestSession_EvaluateRateLimit_ObserveRateChanges(t *testing.T) {
	classParams := [5]wire.RateClass{
		{
			ID:              1,
			WindowSize:      80,
			ClearLevel:      2500,
			AlertLevel:      2000,
			LimitLevel:      1500,
			DisconnectLevel: 800,
			MaxLevel:        6000,
		},
		{
			ID:              2,
			WindowSize:      80,
			ClearLevel:      3000,
			AlertLevel:      2000,
			LimitLevel:      1500,
			DisconnectLevel: 1000,
			MaxLevel:        6000,
		},
		{
			ID:              3,
			WindowSize:      20,
			ClearLevel:      5100,
			AlertLevel:      5000,
			LimitLevel:      4000,
			DisconnectLevel: 3000,
			MaxLevel:        6000,
		},
		{
			ID:              4,
			WindowSize:      20,
			ClearLevel:      5500,
			AlertLevel:      5300,
			LimitLevel:      4200,
			DisconnectLevel: 3000,
			MaxLevel:        8000,
		},
		{
			ID:              5,
			WindowSize:      10,
			ClearLevel:      5500,
			AlertLevel:      5300,
			LimitLevel:      4200,
			DisconnectLevel: 3000,
			MaxLevel:        8000,
		},
	}
	rateClasses := wire.NewRateLimitClasses(classParams)

	t.Run("we can action every 5 seconds indefinitely without getting rate limited", func(t *testing.T) {
		now := time.Now()

		sess := NewInstance(NewSession())
		sess.SetRateClasses(now, rateClasses)

		rateClass := rateClasses.Get(3)
		sess.SubscribeRateLimits([]wire.RateLimitClassID{rateClass.ID})

		for i := 0; i < 100; i++ {
			now = now.Add(5 * time.Second)
			have := sess.EvaluateRateLimit(now, rateClass.ID)
			assert.Equal(t, wire.RateLimitStatusClear, have)
		}
	})

	t.Run("reach disconnect threshold", func(t *testing.T) {
		now := time.Now()

		sess := NewInstance(NewSession())
		sess.SetRateClasses(now, rateClasses)

		rateClass := rateClasses.Get(3)
		sess.SubscribeRateLimits([]wire.RateLimitClassID{rateClass.ID})

		// record some event in the rate limiter
		want := []wire.RateLimitStatus{
			wire.RateLimitStatusClear,
			wire.RateLimitStatusClear,
			wire.RateLimitStatusClear,
			wire.RateLimitStatusClear,
			wire.RateLimitStatusAlert,
			wire.RateLimitStatusAlert,
			wire.RateLimitStatusAlert,
			wire.RateLimitStatusAlert,
			wire.RateLimitStatusAlert,
			wire.RateLimitStatusLimited,
			wire.RateLimitStatusLimited,
			wire.RateLimitStatusLimited,
			wire.RateLimitStatusLimited,
			wire.RateLimitStatusLimited,
			wire.RateLimitStatusLimited,
			wire.RateLimitStatusLimited,
			wire.RateLimitStatusLimited,
			wire.RateLimitStatusDisconnect,
		}
		for i := 0; i < len(want); i++ {
			now = now.Add(1 * time.Second)
			have := sess.EvaluateRateLimit(now, rateClass.ID)
			assert.Equal(t, want[i], have)
		}

		select {
		case <-sess.Closed():
		default:
			t.Error("expected session to be closed")
		}
	})

	t.Run("reach rate limit threshold, wait for clear threshold", func(t *testing.T) {
		now := time.Now()

		sess := NewInstance(NewSession())
		sess.SetRateClasses(now, rateClasses)

		rateClass := rateClasses.Get(3)
		sess.SubscribeRateLimits([]wire.RateLimitClassID{rateClass.ID})

		// first reach the rate limit threshold
		want := []wire.RateLimitStatus{
			wire.RateLimitStatusClear,
			wire.RateLimitStatusClear,
			wire.RateLimitStatusClear,
			wire.RateLimitStatusClear,
			wire.RateLimitStatusAlert,
			wire.RateLimitStatusAlert,
			wire.RateLimitStatusAlert,
			wire.RateLimitStatusAlert,
			wire.RateLimitStatusAlert,
			wire.RateLimitStatusLimited,
		}
		for i := 0; i < len(want); i++ {
			now = now.Add(1 * time.Second)
			have := sess.EvaluateRateLimit(now, rateClass.ID)
			assert.Equal(t, want[i], have)

			if i > 0 && want[i-1] != want[i] {
				classChanges, rateChanges := sess.ObserveRateChanges(now)
				assert.Empty(t, classChanges)
				if assert.NotEmpty(t, rateChanges) {
					rateDelta := rateChanges[0]
					assert.Equal(t, rateClass, rateDelta.RateClass)
					assert.Equal(t, want[i], rateDelta.CurrentStatus)
					assert.True(t, rateDelta.Subscribed)
					if want[i] == wire.RateLimitStatusLimited {
						assert.True(t, rateDelta.LimitedNow)
					}
				}
			}
		}

		// this is a rearranged moving average formula that determines how many
		// milliseconds it will take to reach the clear threshold
		timeToRecover := int(math.Ceil((time.Duration(rateClass.ClearLevel*rateClass.WindowSize-sess.rateLimitStates[rateClass.ID-1].CurrentLevel*(rateClass.WindowSize-1)) * time.Millisecond).Seconds()))
		assert.True(t, timeToRecover > 0)

		// indicate the time rate limiting kicked in
		timeLimited := now

		for i := 0; i < timeToRecover; i++ {
			now = now.Add(1 * time.Second)
			classDelta, stateDelta := sess.ObserveRateChanges(now)
			assert.Empty(t, classDelta)

			if i == timeToRecover-1 {
				// assert that the clear threshold has been met.
				assert.ElementsMatch(t, stateDelta, []RateClassState{
					{
						RateClass:     rateClass,
						CurrentLevel:  5140,
						CurrentStatus: wire.RateLimitStatusClear,
						LastTime:      timeLimited,
						Subscribed:    true,
						LimitedNow:    false,
					}})
			} else {
				// assert that no changed have been observed, it's still rate-limited
				assert.Nil(t, stateDelta)
			}
		}
	})

	t.Run("observe a rate class change", func(t *testing.T) {
		now := time.Now()

		sess := NewInstance(NewSession())
		sess.SetRateClasses(now, rateClasses)

		rateClass := rateClasses.Get(3)
		sess.SubscribeRateLimits([]wire.RateLimitClassID{rateClass.ID})

		now = now.Add(1 * time.Second)
		classDelta, stateDelta := sess.ObserveRateChanges(now)
		assert.Empty(t, classDelta)
		assert.Empty(t, stateDelta)

		paramsCopy := classParams
		paramsCopy[rateClass.ID-1].LimitLevel++

		newRateClasses := wire.NewRateLimitClasses(paramsCopy)

		now = now.Add(1 * time.Second)
		sess.SetRateClasses(now, newRateClasses)

		now = now.Add(1 * time.Second)
		classDelta, stateDelta = sess.ObserveRateChanges(now)
		assert.Equal(t, classDelta[0].RateClass, newRateClasses.Get(rateClass.ID))
		assert.Empty(t, stateDelta)
	})

	t.Run("as a bot, I can action every second indefinitely without getting rate limited", func(t *testing.T) {
		now := time.Now()

		sess := NewInstance(NewSession())
		sess.SetUserInfoFlag(wire.OServiceUserFlagBot)
		sess.SetRateClasses(now, rateClasses)

		for i := 0; i < 100; i++ {
			now = now.Add(1 * time.Second)
			have := sess.EvaluateRateLimit(now, wire.RateLimitClassID(1))
			assert.Equal(t, wire.RateLimitStatusClear, have)
		}
	})
}

func TestSession_SetAndGetFoodGroupVersions(t *testing.T) {
	versions := [wire.MDir + 1]uint16{}
	versions[wire.Feedbag] = 1
	versions[wire.OService] = 2

	s := NewInstance(NewSession())
	s.SetFoodGroupVersions(versions)

	assert.Equal(t, versions, s.FoodGroupVersions())
}

func TestSession_SetAndGetTypingEventsEnabled(t *testing.T) {
	s := NewInstance(NewSession())
	assert.False(t, s.TypingEventsEnabled())
	s.SetTypingEventsEnabled(true)
	assert.True(t, s.TypingEventsEnabled())
	s.SetTypingEventsEnabled(false)
	assert.False(t, s.TypingEventsEnabled())
}

func TestSession_SetAndGetMultiConnFlag(t *testing.T) {
	s := NewInstance(NewSession())
	assert.Zero(t, s.MultiConnFlag())

	s.SetMultiConnFlag(wire.MultiConnFlagsOldClient)
	assert.Equal(t, wire.MultiConnFlagsOldClient, s.MultiConnFlag())

	s.SetMultiConnFlag(wire.MultiConnFlagsRecentClient)
	assert.Equal(t, wire.MultiConnFlagsRecentClient, s.MultiConnFlag())

	s.SetMultiConnFlag(wire.MultiConnFlagsSingleClient)
	assert.Equal(t, wire.MultiConnFlagsSingleClient, s.MultiConnFlag())
}

func TestSession_SetAndGetLastWarnLevel(t *testing.T) {
	s := NewInstance(NewSession())
	assert.Zero(t, s.Warning())

	level := uint16(500)
	s.SetWarning(level)
	assert.Equal(t, level, s.Warning())
}

func TestInstance_Active(t *testing.T) {
	tests := []struct {
		name           string
		setupInstance  func() *SessionInstance
		expectedActive bool
	}{
		{
			name: "active instance - not closed, not idle, no away message",
			setupInstance: func() *SessionInstance {
				sg := NewSession()
				instance := &SessionInstance{
					Session:        sg,
					closed:         false,
					idle:           false,
					awayMsg:        "",
					signonComplete: true,
				}
				return instance
			},
			expectedActive: true,
		},
		{
			name: "inactive instance - closed",
			setupInstance: func() *SessionInstance {
				sg := NewSession()
				instance := &SessionInstance{
					Session: sg,
					closed:  true,
					idle:    false,
					awayMsg: "",
				}
				return instance
			},
			expectedActive: false,
		},
		{
			name: "inactive instance - idle",
			setupInstance: func() *SessionInstance {
				sg := NewSession()
				instance := &SessionInstance{
					Session: sg,
					closed:  false,
					idle:    true,
					awayMsg: "",
				}
				return instance
			},
			expectedActive: false,
		},
		{
			name: "inactive instance - has away message",
			setupInstance: func() *SessionInstance {
				sg := NewSession()
				instance := &SessionInstance{
					Session:         sg,
					closed:          false,
					idle:            false,
					awayMsg:         "I'm away",
					userInfoBitmask: wire.OServiceUserFlagUnavailable,
				}
				return instance
			},
			expectedActive: false,
		},
		{
			name: "inactive instance - closed and idle",
			setupInstance: func() *SessionInstance {
				sg := NewSession()
				instance := &SessionInstance{
					Session: sg,
					closed:  true,
					idle:    true,
					awayMsg: "",
				}
				return instance
			},
			expectedActive: false,
		},
		{
			name: "inactive instance - closed and has away message",
			setupInstance: func() *SessionInstance {
				sg := NewSession()
				instance := &SessionInstance{
					Session:         sg,
					closed:          true,
					idle:            false,
					awayMsg:         "I'm away",
					userInfoBitmask: wire.OServiceUserFlagUnavailable,
				}
				return instance
			},
			expectedActive: false,
		},
		{
			name: "inactive instance - idle and has away message",
			setupInstance: func() *SessionInstance {
				sg := NewSession()
				instance := &SessionInstance{
					Session:         sg,
					closed:          false,
					idle:            true,
					awayMsg:         "I'm away",
					userInfoBitmask: wire.OServiceUserFlagUnavailable,
				}
				return instance
			},
			expectedActive: false,
		},
		{
			name: "inactive instance - closed, idle, and has away message",
			setupInstance: func() *SessionInstance {
				sg := NewSession()
				instance := &SessionInstance{
					Session:         sg,
					closed:          true,
					idle:            true,
					awayMsg:         "I'm away",
					userInfoBitmask: wire.OServiceUserFlagUnavailable,
				}
				return instance
			},
			expectedActive: false,
		},
		{
			name: "inactive instance - signon not complete",
			setupInstance: func() *SessionInstance {
				sg := NewSession()
				instance := &SessionInstance{
					Session:        sg,
					closed:         false,
					idle:           false,
					awayMsg:        "",
					signonComplete: false,
				}
				return instance
			},
			expectedActive: false,
		},
		{
			name: "inactive instance - signon not complete and idle",
			setupInstance: func() *SessionInstance {
				sg := NewSession()
				instance := &SessionInstance{
					Session:        sg,
					closed:         false,
					idle:           true,
					awayMsg:        "",
					signonComplete: false,
				}
				return instance
			},
			expectedActive: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := tt.setupInstance()
			assert.Equal(t, tt.expectedActive, instance.Active())
		})
	}
}

func TestSessionGroup_AllInactive(t *testing.T) {
	tests := []struct {
		name              string
		setupSessionGroup func() *Session
		expectedResult    bool
	}{
		{
			name: "no instances - should return true",
			setupSessionGroup: func() *Session {
				return NewSession()
			},
			expectedResult: true,
		},
		{
			name: "one active instance - should return false",
			setupSessionGroup: func() *Session {
				sg := NewSession()
				instance := &SessionInstance{
					Session:        sg,
					closed:         false,
					idle:           false,
					awayMsg:        "",
					signonComplete: true,
				}
				sg.AddInstance(instance)
				return sg
			},
			expectedResult: false,
		},
		{
			name: "one closed instance - should return true",
			setupSessionGroup: func() *Session {
				sg := NewSession()
				instance := &SessionInstance{
					Session: sg,
					closed:  true,
					idle:    false,
					awayMsg: "",
				}
				sg.AddInstance(instance)
				return sg
			},
			expectedResult: true,
		},
		{
			name: "one idle instance - should return true",
			setupSessionGroup: func() *Session {
				sg := NewSession()
				instance := &SessionInstance{
					Session: sg,
					closed:  false,
					idle:    true,
					awayMsg: "",
				}
				sg.AddInstance(instance)
				return sg
			},
			expectedResult: true,
		},
		{
			name: "one instance with away message - should return true",
			setupSessionGroup: func() *Session {
				sg := NewSession()
				instance := &SessionInstance{
					Session: sg,
					closed:  false,
					idle:    false,
					awayMsg: "I'm away",
				}
				sg.AddInstance(instance)
				return sg
			},
			expectedResult: true,
		},
		{
			name: "multiple instances - all inactive - should return true",
			setupSessionGroup: func() *Session {
				sg := NewSession()

				// Add closed instance
				instance1 := &SessionInstance{
					Session: sg,
					closed:  true,
					idle:    false,
					awayMsg: "",
				}
				sg.AddInstance(instance1)

				// Add idle instance
				instance2 := &SessionInstance{
					Session: sg,
					closed:  false,
					idle:    true,
					awayMsg: "",
				}
				sg.AddInstance(instance2)

				// Add instance with away message
				instance3 := &SessionInstance{
					Session: sg,
					closed:  false,
					idle:    false,
					awayMsg: "I'm away",
				}
				sg.AddInstance(instance3)

				return sg
			},
			expectedResult: true,
		},
		{
			name: "multiple instances - one active - should return false",
			setupSessionGroup: func() *Session {
				sg := NewSession()

				// Add closed instance
				instance1 := &SessionInstance{
					Session: sg,
					closed:  true,
					idle:    false,
					awayMsg: "",
				}
				sg.AddInstance(instance1)

				// Add active instance
				instance2 := &SessionInstance{
					Session:        sg,
					closed:         false,
					idle:           false,
					awayMsg:        "",
					signonComplete: true,
				}
				sg.AddInstance(instance2)

				// Add idle instance
				instance3 := &SessionInstance{
					Session: sg,
					closed:  false,
					idle:    true,
					awayMsg: "",
				}
				sg.AddInstance(instance3)

				return sg
			},
			expectedResult: false,
		},
		{
			name: "multiple instances - all active - should return false",
			setupSessionGroup: func() *Session {
				sg := NewSession()

				// Add first active instance
				instance1 := &SessionInstance{
					Session:        sg,
					closed:         false,
					idle:           false,
					awayMsg:        "",
					signonComplete: true,
				}
				sg.AddInstance(instance1)

				// Add second active instance
				instance2 := &SessionInstance{
					Session:        sg,
					closed:         false,
					idle:           false,
					awayMsg:        "",
					signonComplete: true,
				}
				sg.AddInstance(instance2)

				return sg
			},
			expectedResult: false,
		},
		{
			name: "mixed scenarios - some closed, some idle, some away, one active - should return false",
			setupSessionGroup: func() *Session {
				sg := NewSession()

				// Add closed instance
				instance1 := &SessionInstance{
					Session: sg,
					closed:  true,
					idle:    false,
					awayMsg: "",
				}
				sg.AddInstance(instance1)

				// Add idle instance
				instance2 := &SessionInstance{
					Session: sg,
					closed:  false,
					idle:    true,
					awayMsg: "",
				}
				sg.AddInstance(instance2)

				// Add instance with away message
				instance3 := &SessionInstance{
					Session: sg,
					closed:  false,
					idle:    false,
					awayMsg: "I'm away",
				}
				sg.AddInstance(instance3)

				// Add active instance
				instance4 := &SessionInstance{
					Session:        sg,
					closed:         false,
					idle:           false,
					awayMsg:        "",
					signonComplete: true,
				}
				sg.AddInstance(instance4)

				return sg
			},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sg := tt.setupSessionGroup()
			assert.Equal(t, tt.expectedResult, sg.AllInactive())
		})
	}
}

func TestSessionGroup_InstanceCount(t *testing.T) {
	tests := []struct {
		name          string
		setupGroup    func() *Session
		expectedCount int
	}{
		{
			name: "empty session group should return 0",
			setupGroup: func() *Session {
				return NewSession()
			},
			expectedCount: 0,
		},
		{
			name: "one instance should return 1",
			setupGroup: func() *Session {
				sg := NewSession()
				NewInstance(sg)
				return sg
			},
			expectedCount: 1,
		},
		{
			name: "multiple instances should return correct count",
			setupGroup: func() *Session {
				sg := NewSession()
				for i := 0; i < 3; i++ {
					NewInstance(sg)
				}
				return sg
			},
			expectedCount: 3,
		},
		{
			name: "instance count decreases after removal",
			setupGroup: func() *Session {
				sg := NewSession()
				NewInstance(sg)
				instance2 := NewInstance(sg)
				NewInstance(sg)
				// Remove one instance
				sg.RemoveInstance(instance2)
				return sg
			},
			expectedCount: 2,
		},
		{
			name: "instance count is correct after multiple add/remove operations",
			setupGroup: func() *Session {
				sg := NewSession()
				instance1 := NewInstance(sg)
				NewInstance(sg)
				sg.RemoveInstance(instance1)
				NewInstance(sg)
				return sg
			},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sg := tt.setupGroup()
			assert.Equal(t, tt.expectedCount, sg.InstanceCount())
		})
	}
}

func TestSessionGroup_Instances(t *testing.T) {
	tests := []struct {
		name          string
		setupGroup    func() *Session
		expectedCount int
		expectedAll   bool // whether all instances should be returned (including non-signed-in)
	}{
		{
			name: "empty session group should return empty slice",
			setupGroup: func() *Session {
				return NewSession()
			},
			expectedCount: 0,
			expectedAll:   true,
		},
		{
			name: "returns all instances including non-signed-in",
			setupGroup: func() *Session {
				sg := NewSession()
				instance1 := NewInstance(sg)
				instance1.SetSignonComplete()
				_ = NewInstance(sg)
				// instance2 has not completed signon
				return sg
			},
			expectedCount: 2,
			expectedAll:   true,
		},
		{
			name: "returns all instances with mixed signon states",
			setupGroup: func() *Session {
				sg := NewSession()
				instance1 := NewInstance(sg)
				instance1.SetSignonComplete()
				_ = NewInstance(sg)
				// instance2 has not completed signon
				instance3 := NewInstance(sg)
				instance3.SetSignonComplete()
				return sg
			},
			expectedCount: 3,
			expectedAll:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sg := tt.setupGroup()
			instances := sg.Instances()
			assert.Equal(t, tt.expectedCount, len(instances), "should return all instances")

			if tt.expectedAll {
				// Verify that instances() returns all instances regardless of their state
				// This is the key change: it should return all instances, not just live ones
				assert.Equal(t, sg.InstanceCount(), len(instances), "Instances() should return all instances")
			}
		})
	}
}

func TestSession_SetAndGetProfile(t *testing.T) {
	s := NewInstance(NewSession())
	profile := s.Profile()
	assert.Empty(t, profile.ProfileText)
	assert.Empty(t, profile.MIMEType)
	assert.True(t, profile.UpdateTime.IsZero())

	profileTime := time.Unix(1234567890, 0)
	newProfile := UserProfile{
		ProfileText: "My profile text",
		MIMEType:    "text/plain",
		UpdateTime:  profileTime,
	}
	s.SetProfile(newProfile)
	retrievedProfile := s.Profile()
	assert.Equal(t, newProfile, retrievedProfile)
	assert.Equal(t, "My profile text", retrievedProfile.ProfileText)
	assert.Equal(t, "text/plain", retrievedProfile.MIMEType)
	assert.Equal(t, profileTime, retrievedProfile.UpdateTime)
}

func TestSession_Profile(t *testing.T) {
	tests := []struct {
		name            string
		setupSession    func() *Session
		expectedProfile UserProfile
	}{
		{
			name: "no instances - returns empty profile",
			setupSession: func() *Session {
				return NewSession()
			},
			expectedProfile: UserProfile{},
		},
		{
			name: "one instance with empty profile - returns empty profile",
			setupSession: func() *Session {
				s := NewSession()
				NewInstance(s)
				return s
			},
			expectedProfile: UserProfile{},
		},
		{
			name: "one instance with non-empty profile - returns that profile",
			setupSession: func() *Session {
				s := NewSession()
				instance := NewInstance(s)
				profileTime := time.Unix(1234567890, 0)
				instance.SetProfile(UserProfile{
					ProfileText: "My profile",
					MIMEType:    "text/plain",
					UpdateTime:  profileTime,
				})
				return s
			},
			expectedProfile: UserProfile{
				ProfileText: "My profile",
				MIMEType:    "text/plain",
				UpdateTime:  time.Unix(1234567890, 0),
			},
		},
		{
			name: "multiple instances, all empty - returns empty profile",
			setupSession: func() *Session {
				s := NewSession()
				NewInstance(s)
				NewInstance(s)
				NewInstance(s)
				return s
			},
			expectedProfile: UserProfile{},
		},
		{
			name: "multiple instances, one non-empty - returns that one",
			setupSession: func() *Session {
				s := NewSession()
				NewInstance(s) // empty instance
				instance2 := NewInstance(s)
				instance2.SetProfile(UserProfile{
					ProfileText: "Profile 2",
					MIMEType:    "text/plain",
					UpdateTime:  time.Unix(1234567890, 0),
				})
				NewInstance(s) // empty instance
				return s
			},
			expectedProfile: UserProfile{
				ProfileText: "Profile 2",
				MIMEType:    "text/plain",
				UpdateTime:  time.Unix(1234567890, 0),
			},
		},
		{
			name: "multiple instances, multiple non-empty - returns most recent UpdateTime",
			setupSession: func() *Session {
				s := NewSession()
				instance1 := NewInstance(s)
				instance1.SetProfile(UserProfile{
					ProfileText: "Profile 1",
					MIMEType:    "text/plain",
					UpdateTime:  time.Unix(1234567900, 0), // later time - should be returned
				})
				instance2 := NewInstance(s)
				instance2.SetProfile(UserProfile{
					ProfileText: "Profile 2",
					MIMEType:    "text/plain",
					UpdateTime:  time.Unix(1234567890, 0), // earlier time
				})
				instance3 := NewInstance(s)
				instance3.SetProfile(UserProfile{
					ProfileText: "Profile 3",
					MIMEType:    "text/plain",
					UpdateTime:  time.Unix(1234567895, 0), // middle time
				})
				return s
			},
			expectedProfile: UserProfile{
				ProfileText: "Profile 1",
				MIMEType:    "text/plain",
				UpdateTime:  time.Unix(1234567900, 0),
			},
		},
		{
			name: "first instance empty, later instances have profiles - returns most recent non-empty",
			setupSession: func() *Session {
				s := NewSession()
				NewInstance(s) // empty instance
				instance2 := NewInstance(s)
				instance2.SetProfile(UserProfile{
					ProfileText: "Profile 2",
					MIMEType:    "text/plain",
					UpdateTime:  time.Unix(1234567890, 0), // earlier
				})
				instance3 := NewInstance(s)
				instance3.SetProfile(UserProfile{
					ProfileText: "Profile 3",
					MIMEType:    "text/plain",
					UpdateTime:  time.Unix(1234567900, 0), // later time - should be returned
				})
				return s
			},
			expectedProfile: UserProfile{
				ProfileText: "Profile 3",
				MIMEType:    "text/plain",
				UpdateTime:  time.Unix(1234567900, 0),
			},
		},
		{
			name: "profile with empty ProfileText is considered empty",
			setupSession: func() *Session {
				s := NewSession()
				instance := NewInstance(s)
				instance.SetProfile(UserProfile{
					ProfileText: "",
					MIMEType:    "text/plain",
					UpdateTime:  time.Unix(1234567890, 0),
				})
				return s
			},
			expectedProfile: UserProfile{},
		},
		{
			name: "profile with null byte ProfileText is considered empty",
			setupSession: func() *Session {
				s := NewSession()
				instance := NewInstance(s)
				instance.SetProfile(UserProfile{
					ProfileText: "\x00",
					MIMEType:    "text/plain",
					UpdateTime:  time.Unix(1234567890, 0),
				})
				return s
			},
			expectedProfile: UserProfile{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := tt.setupSession()
			profile := s.Profile()
			assert.Equal(t, tt.expectedProfile, profile)
		})
	}
}

func TestSession_SetAndGetMemberSince(t *testing.T) {
	s := NewInstance(NewSession())
	assert.True(t, s.MemberSince().IsZero())

	memberTime := time.Unix(1234567890, 0)
	s.SetMemberSince(memberTime)
	assert.Equal(t, memberTime, s.MemberSince())
}

func TestSession_SetAndGetOfflineMsgCount(t *testing.T) {
	s := NewInstance(NewSession())
	assert.Zero(t, s.OfflineMsgCount())

	count := 5
	s.SetOfflineMsgCount(count)
	assert.Equal(t, count, s.OfflineMsgCount())

	count = 10
	s.SetOfflineMsgCount(count)
	assert.Equal(t, count, s.OfflineMsgCount())
}

func TestSession_ScaleWarningAndRateLimit(t *testing.T) {
	t.Run("scale up", func(t *testing.T) {
		classParams := [5]wire.RateClass{
			{},
			{},
			{
				ID:              3,
				WindowSize:      20,
				ClearLevel:      5100,
				AlertLevel:      5000,
				LimitLevel:      4000,
				DisconnectLevel: 3000,
				MaxLevel:        6000,
			},
			{},
			{},
		}
		rateClasses := wire.NewRateLimitClasses(classParams)

		now := time.Now()

		sess := NewInstance(NewSession())
		sess.SetRateClasses(now, rateClasses)

		var wg sync.WaitGroup
		wg.Add(1)

		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-sess.WarningCh():
				}
			}
		}()

		assert.Equal(t, int32(5000), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5100), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4000), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5085), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5175), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4185), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5170), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5250), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4370), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5255), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5325), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4555), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5340), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5400), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4740), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5425), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5475), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4925), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5510), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5550), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5110), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5595), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5625), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5295), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5680), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5700), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5480), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5765), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5775), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5665), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(100, 3)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].LimitLevel)

		cancel()
		wg.Wait()
	})

	t.Run("scale down", func(t *testing.T) {
		currentClassParams := [5]wire.RateClass{
			{},
			{},
			{
				ID:              3,
				WindowSize:      20,
				ClearLevel:      5100,
				AlertLevel:      5000,
				LimitLevel:      4000,
				DisconnectLevel: 3000,
				MaxLevel:        6000,
			},
			{},
			{},
		}
		rateClasses := wire.NewRateLimitClasses(currentClassParams)

		now := time.Now()

		sess := NewInstance(NewSession())
		sess.SetRateClasses(now, rateClasses)

		var wg sync.WaitGroup
		wg.Add(1)

		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-sess.WarningCh():
				}
			}
		}()

		for i := 0; i < 10; i++ {
			sess.ScaleWarningAndRateLimit(100, 3)
		}

		assert.Equal(t, int32(5850), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5765), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5775), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5665), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5680), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5700), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5480), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5595), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5625), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5295), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5510), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5550), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5110), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5425), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5475), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4925), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5340), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5400), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4740), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5255), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5325), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4555), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5170), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5250), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4370), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5085), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5175), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4185), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5000), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5100), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4000), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(-100, 3)
		assert.Equal(t, int32(5000), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5100), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4000), sess.rateLimitStates[2].LimitLevel)

		cancel()
		wg.Wait()
	})

	t.Run("increment 100%", func(t *testing.T) {
		classParams := [5]wire.RateClass{
			{},
			{},
			{
				ID:              3,
				WindowSize:      20,
				ClearLevel:      5100,
				AlertLevel:      5000,
				LimitLevel:      4000,
				DisconnectLevel: 3000,
				MaxLevel:        6000,
			},
			{},
			{},
		}
		rateClasses := wire.NewRateLimitClasses(classParams)

		now := time.Now()

		sess := NewInstance(NewSession())
		sess.SetRateClasses(now, rateClasses)

		var wg sync.WaitGroup
		wg.Add(1)

		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-sess.WarningCh():
				}
			}
		}()

		assert.Equal(t, int32(5000), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5100), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(4000), sess.rateLimitStates[2].LimitLevel)

		sess.ScaleWarningAndRateLimit(1000, 3)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].AlertLevel)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].ClearLevel)
		assert.Equal(t, int32(5850), sess.rateLimitStates[2].LimitLevel)

		cancel()
		wg.Wait()
	})
}

func TestSession_RunOnce(t *testing.T) {
	t.Run("runs function on first call", func(t *testing.T) {
		s := NewSession()
		callCount := 0

		err := s.RunOnce(func() error {
			callCount++
			return nil
		})

		assert.NoError(t, err)
		assert.Equal(t, 1, callCount)
	})

	t.Run("does not run function on subsequent calls", func(t *testing.T) {
		s := NewSession()
		callCount := 0

		// First call
		err1 := s.RunOnce(func() error {
			callCount++
			return nil
		})

		// Second call
		err2 := s.RunOnce(func() error {
			callCount++
			return nil
		})

		// Third call
		err3 := s.RunOnce(func() error {
			callCount++
			return nil
		})

		assert.NoError(t, err1)
		assert.NoError(t, err2)
		assert.NoError(t, err3)
		assert.Equal(t, 1, callCount, "function should only be called once")
	})

	t.Run("returns error from function", func(t *testing.T) {
		s := NewSession()
		expectedErr := assert.AnError

		err := s.RunOnce(func() error {
			return expectedErr
		})

		assert.Error(t, err)
		assert.Equal(t, expectedErr, err)
	})
}

func TestSession_CloseInstance(t *testing.T) {
	s := NewSession()
	sessionCloseCount := 0

	s.OnSessionClose(func() {
		sessionCloseCount++
	})

	instance1CloseCount := 0
	instance2CloseCount := 0
	instance3CloseCount := 0

	instance1 := NewInstance(s)
	instance2 := NewInstance(s)
	instance3 := NewInstance(s)

	instance1.OnInstanceClose(func() {
		instance1CloseCount++
	})
	instance2.OnInstanceClose(func() {
		instance2CloseCount++
	})
	instance3.OnInstanceClose(func() {
		instance3CloseCount++
	})

	// Close instance1 (instances 2 and 3 remain)
	instance1.CloseInstance()
	instance2.CloseInstance()
	instance3.CloseInstance()

	assert.Equal(t, 1, instance1CloseCount, "instance1 onInstanceCloseFn should only be called once")
	assert.Equal(t, 1, instance2CloseCount, "instance2 onInstanceCloseFn should only be called once")
	assert.Equal(t, 0, instance3CloseCount, "instance3 onInstanceCloseFn should not be called because it's the last instance")
	assert.Equal(t, 1, sessionCloseCount, "session onSessCloseFn should not be called")
}

func TestSession_CloseSession(t *testing.T) {
	s := NewSession()
	sessionCloseCount := 0

	s.OnSessionClose(func() {
		sessionCloseCount++
	})

	instance1CloseCount := 0
	instance2CloseCount := 0
	instance3CloseCount := 0

	instance1 := NewInstance(s)
	instance2 := NewInstance(s)
	instance3 := NewInstance(s)

	instance1.OnInstanceClose(func() {
		instance1CloseCount++
	})
	instance2.OnInstanceClose(func() {
		instance2CloseCount++
	})
	instance3.OnInstanceClose(func() {
		instance3CloseCount++
	})

	s.CloseSession()

	assert.Equal(t, 0, instance1CloseCount, "instance1 onInstanceCloseFn should not be called")
	assert.Equal(t, 0, instance2CloseCount, "instance2 onInstanceCloseFn should not be called")
	assert.Equal(t, 0, instance3CloseCount, "instance3 onInstanceCloseFn should not be called")
	assert.Equal(t, 1, sessionCloseCount, "session onSessCloseFn should only be called once")
}

func TestSession_AwayMessage(t *testing.T) {
	tests := []struct {
		name           string
		setupSession   func() *Session
		expectedResult string
	}{
		{
			name: "no instances - should return empty string",
			setupSession: func() *Session {
				return NewSession()
			},
			expectedResult: "",
		},
		{
			name: "one instance not away - should return empty string",
			setupSession: func() *Session {
				sg := NewSession()
				_ = NewInstance(sg)
				// instance has no away message and is not set as away
				return sg
			},
			expectedResult: "",
		},
		{
			name: "one instance away via SetUserInfoFlag - should return away message",
			setupSession: func() *Session {
				sg := NewSession()
				instance := NewInstance(sg)
				instance.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance.SetAwayMessage("I'm away")
				return sg
			},
			expectedResult: "I'm away",
		},
		{
			name: "one instance away via SetUserStatusBitmask - should return away message",
			setupSession: func() *Session {
				sg := NewSession()
				instance := NewInstance(sg)
				instance.SetUserStatusBitmask(wire.OServiceUserStatusAway)
				instance.SetAwayMessage("I'm away")
				return sg
			},
			expectedResult: "I'm away",
		},
		{
			name: "multiple instances - not all away - should return away message from away instance",
			setupSession: func() *Session {
				sg := NewSession()
				instance1 := NewInstance(sg)
				instance1.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance1.SetAwayMessage("I'm away")
				_ = NewInstance(sg)
				// instance2 has no away message and is not set as away
				return sg
			},
			expectedResult: "I'm away",
		},
		{
			name: "multiple instances - all away - should return latest away message",
			setupSession: func() *Session {
				sg := NewSession()
				baseTime := time.Now()
				callCount := 0
				sg.nowFn = func() time.Time {
					callCount++
					return baseTime.Add(time.Duration(callCount) * time.Second)
				}
				instance1 := NewInstance(sg)
				instance1.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance1.SetAwayMessage("First away message")
				instance2 := NewInstance(sg)
				instance2.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance2.SetAwayMessage("Second away message")
				return sg
			},
			expectedResult: "Second away message",
		},
		{
			name: "multiple instances - all away after multiple updates - should return latest away message",
			setupSession: func() *Session {
				sg := NewSession()
				baseTime := time.Now()
				callCount := 0
				sg.nowFn = func() time.Time {
					callCount++
					return baseTime.Add(time.Duration(callCount) * time.Second)
				}
				instance1 := NewInstance(sg)
				instance1.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance1.SetAwayMessage("First away message")
				instance2 := NewInstance(sg)
				instance2.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance2.SetAwayMessage("Second away message")
				// Update instance1's away status again (this will update awayTime)
				instance1.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance1.SetAwayMessage("Third away message")
				return sg
			},
			expectedResult: "Third away message",
		},
		{
			name: "multiple instances - different away methods - should return latest away message",
			setupSession: func() *Session {
				sg := NewSession()
				baseTime := time.Now()
				callCount := 0
				sg.nowFn = func() time.Time {
					callCount++
					return baseTime.Add(time.Duration(callCount) * time.Second)
				}
				instance1 := NewInstance(sg)
				instance1.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance1.SetAwayMessage("First away message")
				instance2 := NewInstance(sg)
				instance2.SetUserStatusBitmask(wire.OServiceUserStatusAway)
				instance2.SetAwayMessage("Second away message")
				return sg
			},
			expectedResult: "Second away message",
		},
		{
			name: "instance sets away message then clears message - should return empty string",
			setupSession: func() *Session {
				sg := NewSession()
				instance := NewInstance(sg)
				instance.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance.SetAwayMessage("I'm away")
				instance.SetAwayMessage("") // clear away message (but still away)
				return sg
			},
			expectedResult: "",
		},
		{
			name: "instance sets away message then clears away status - should return empty string",
			setupSession: func() *Session {
				sg := NewSession()
				instance := NewInstance(sg)
				instance.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance.SetAwayMessage("I'm away")
				instance.ClearUserInfoFlag(wire.OServiceUserFlagUnavailable) // clear away status
				return sg
			},
			expectedResult: "",
		},
		{
			name: "multiple instances - one away with message, one away without message - should return message from most recent",
			setupSession: func() *Session {
				sg := NewSession()
				baseTime := time.Now()
				callCount := 0
				sg.nowFn = func() time.Time {
					callCount++
					return baseTime.Add(time.Duration(callCount) * time.Second)
				}
				instance1 := NewInstance(sg)
				instance1.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance1.SetAwayMessage("I'm away")
				instance2 := NewInstance(sg)
				instance2.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				// instance2 is away but has no message, and was set away after instance1
				return sg
			},
			expectedResult: "", // instance2 has more recent awayTime but no message
		},
		{
			name: "multiple instances - one away with message set later - should return that message",
			setupSession: func() *Session {
				sg := NewSession()
				baseTime := time.Now()
				callCount := 0
				sg.nowFn = func() time.Time {
					callCount++
					return baseTime.Add(time.Duration(callCount) * time.Second)
				}
				instance1 := NewInstance(sg)
				instance1.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				instance1.SetAwayMessage("I'm away")
				instance2 := NewInstance(sg)
				instance2.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				// instance2 is away but has no message
				// Now update instance1's away status to make it more recent
				instance1.SetUserInfoFlag(wire.OServiceUserFlagUnavailable)
				return sg
			},
			expectedResult: "I'm away", // instance1 has more recent awayTime and has a message
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sg := tt.setupSession()
			result := sg.AwayMessage()
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
