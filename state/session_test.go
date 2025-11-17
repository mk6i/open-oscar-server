package state

import (
	"context"
	"math"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/mk6i/retro-aim-server/wire"

	"github.com/stretchr/testify/assert"
)

func TestSession_SetAndGetAwayMessage(t *testing.T) {
	s := NewSession()
	assert.Empty(t, s.AwayMessage())

	msg := "here's my message"
	s.SetAwayMessage(msg)
	assert.Equal(t, msg, s.AwayMessage())
}

func TestSession_IncrementAndGetWarning(t *testing.T) {
	s := NewSession()

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
	s := NewSession()
	assert.False(t, s.Invisible())
	s.SetUserStatusBitmask(wire.OServiceUserStatusInvisible)
	assert.True(t, s.Invisible())
}

func TestSession_SetAndGetScreenName(t *testing.T) {
	s := NewSession()
	assert.Empty(t, s.IdentScreenName())
	sn := NewIdentScreenName("user-screen-name")
	s.SetIdentScreenName(sn)
	assert.Equal(t, sn, s.IdentScreenName())
}

func TestSession_SetAndGetChatRoomCookie(t *testing.T) {
	s := NewSession()
	assert.Empty(t, s.ChatRoomCookie())
	sn := "the-chat-cookie"
	s.SetChatRoomCookie(sn)
	assert.Equal(t, sn, s.ChatRoomCookie())
}

func TestSession_SetAndGetUIN(t *testing.T) {
	s := NewSession()
	assert.Empty(t, s.UIN())
	uin := uint32(100003)
	s.SetUIN(uin)
	assert.Equal(t, uin, s.UIN())
}

func TestSession_SetAndGetClientID(t *testing.T) {
	s := NewSession()
	assert.Empty(t, s.ClientID())
	clientID := "AIM Client ID"
	s.SetClientID(clientID)
	assert.Equal(t, clientID, s.ClientID())
}

func TestSession_SetAndGetKerberosAuth(t *testing.T) {
	s := NewSession()
	assert.False(t, s.KerberosAuth())

	s.SetKerberosAuth(true)
	assert.True(t, s.KerberosAuth())

	s.SetKerberosAuth(false)
	assert.False(t, s.KerberosAuth())
}

func TestSession_SetAndGetRemoteAddr(t *testing.T) {
	s := NewSession()
	assert.Empty(t, s.RemoteAddr())
	remoteAddr, _ := netip.ParseAddrPort("1.2.3.4:1234")
	s.SetRemoteAddr(&remoteAddr)
	assert.Equal(t, &remoteAddr, s.RemoteAddr())
}

func TestSession_TLVUserInfo(t *testing.T) {
	tests := []struct {
		name           string
		givenSessionFn func() *Session
		want           wire.TLVUserInfo
	}{
		{
			name: "user is active and visible",
			givenSessionFn: func() *Session {
				s := NewSession()
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
			givenSessionFn: func() *Session {
				s := NewSession()
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
			name: "user has away message set",
			givenSessionFn: func() *Session {
				s := NewSession()
				s.SetSignonTime(time.Unix(1, 0))
				s.SetAwayMessage("here's my away message")
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
			name: "user is invisible",
			givenSessionFn: func() *Session {
				s := NewSession()
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
			givenSessionFn: func() *Session {
				s := NewSession()
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
			givenSessionFn: func() *Session {
				s := NewSession()
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
			givenSessionFn: func() *Session {
				s := NewSession()
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
			givenSessionFn: func() *Session {
				s := NewSession()
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
	s := NewSession()

	msg := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
		},
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer s.Close()
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
	s := Session{
		msgCh:  make(chan wire.SNACMessage, 1),
		stopCh: make(chan struct{}),
	}
	s.Close()
	if res := s.RelayMessage(wire.SNACMessage{}); res != SessSendClosed {
		t.Fatalf("expected SessSendClosed, got %+v", res)
	}
}

func TestSession_SendMessage_SessQueueFull(t *testing.T) {
	bufSize := 10
	s := Session{
		msgCh:  make(chan wire.SNACMessage, bufSize),
		stopCh: make(chan struct{}),
	}
	for i := 0; i < bufSize; i++ {
		assert.Equal(t, SessSendOK, s.RelayMessage(wire.SNACMessage{}))
	}
	assert.Equal(t, SessQueueFull, s.RelayMessage(wire.SNACMessage{}))
}

func TestSession_Close_Twice(t *testing.T) {
	s := Session{
		stopCh: make(chan struct{}),
	}
	s.Close()
	s.Close() // make sure close is idempotent
	if !s.closed {
		t.Fatal("expected session to be closed")
	}
	select {
	case <-s.Closed():
	case <-time.After(1 * time.Second):
		t.Fatalf("channel is not closed")
	}
}

func TestSession_Close(t *testing.T) {
	s := NewSession()
	select {
	case <-s.Closed():
		assert.Fail(t, "channel is closed")
	default:
		// channel is open by default
	}
	s.Close()
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

		sess := NewSession()
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

		sess := NewSession()
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

		sess := NewSession()
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

		sess := NewSession()
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

		sess := NewSession()
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

	s := NewSession()
	s.SetFoodGroupVersions(versions)

	assert.Equal(t, versions, s.FoodGroupVersions())
}

func TestSession_SetAndGetTypingEventsEnabled(t *testing.T) {
	s := NewSession()
	assert.False(t, s.TypingEventsEnabled())
	s.SetTypingEventsEnabled(true)
	assert.True(t, s.TypingEventsEnabled())
	s.SetTypingEventsEnabled(false)
	assert.False(t, s.TypingEventsEnabled())
}

func TestSession_SetAndGetMultiConnFlag(t *testing.T) {
	s := NewSession()
	assert.Zero(t, s.MultiConnFlag())

	s.SetMultiConnFlag(wire.MultiConnFlagsOldClient)
	assert.Equal(t, wire.MultiConnFlagsOldClient, s.MultiConnFlag())

	s.SetMultiConnFlag(wire.MultiConnFlagsRecentClient)
	assert.Equal(t, wire.MultiConnFlagsRecentClient, s.MultiConnFlag())

	s.SetMultiConnFlag(wire.MultiConnFlagsSingleClient)
	assert.Equal(t, wire.MultiConnFlagsSingleClient, s.MultiConnFlag())
}

func TestSession_SetAndGetLastWarnLevel(t *testing.T) {
	s := NewSession()
	assert.Zero(t, s.Warning())

	level := uint16(500)
	s.SetWarning(level)
	assert.Equal(t, level, s.Warning())
}

func TestSession_SetAndGetProfile(t *testing.T) {
	s := NewSession()
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

func TestSession_SetAndGetMemberSince(t *testing.T) {
	s := NewSession()
	assert.True(t, s.MemberSince().IsZero())

	memberTime := time.Unix(1234567890, 0)
	s.SetMemberSince(memberTime)
	assert.Equal(t, memberTime, s.MemberSince())
}

func TestSession_SetAndGetOfflineMsgCount(t *testing.T) {
	s := NewSession()
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

		sess := NewSession()
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

		sess := NewSession()
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

		sess := NewSession()
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
