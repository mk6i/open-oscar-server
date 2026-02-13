package toc

import (
	"context"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

type adminParams struct {
	infoChangeRequestParams
}

type infoChangeRequestParams []struct {
	me     state.IdentScreenName
	inBody wire.SNAC_0x07_0x04_AdminInfoChangeRequest
	msg    wire.SNACMessage
	err    error
}

type addBuddiesParams []struct {
	me     state.IdentScreenName
	inBody wire.SNAC_0x03_0x04_BuddyAddBuddies
	err    error
}

type broadcastBuddyDepartedParams []struct {
	me  state.IdentScreenName
	err error
}

type delBuddiesParams []struct {
	me     state.IdentScreenName
	inBody wire.SNAC_0x03_0x05_BuddyDelBuddies
	err    error
}

type buddyParams struct {
	addBuddiesParams
	broadcastBuddyDepartedParams
	delBuddiesParams
}

type chatParams struct {
	channelMsgToHostParamsChat
}

type createRoomParams []struct {
	me     state.IdentScreenName
	inBody wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate
	msg    wire.SNACMessage
	err    error
}

type requestRoomInfoParams []struct {
	inBody wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo
	msg    wire.SNACMessage
	err    error
}

type chatNavParams struct {
	createRoomParams
	requestRoomInfoParams
}

type channelMsgToHostParamsChat []struct {
	sender state.IdentScreenName
	inBody wire.SNAC_0x0E_0x05_ChatChannelMsgToHost
	result *wire.SNACMessage
	err    error
}

type channelMsgToHostParamsICBM []struct {
	sender  state.IdentScreenName
	inFrame wire.SNACFrame
	inBody  wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
	result  *wire.SNACMessage
	err     error
}

type evilRequestParams []struct {
	me     state.IdentScreenName
	inBody wire.SNAC_0x04_0x08_ICBMEvilRequest
	msg    wire.SNACMessage
	err    error
}

type icbmParams struct {
	channelMsgToHostParamsICBM
	evilRequestParams
}

type clientOnlineParams []struct {
	body    wire.SNAC_0x01_0x02_OServiceClientOnline
	me      state.IdentScreenName
	service uint16
	err     error
}

type idleNotificationParams []struct {
	me     state.IdentScreenName
	bodyIn wire.SNAC_0x01_0x11_OServiceIdleNotification
	err    error
}

type serviceRequestParams []struct {
	me     state.IdentScreenName
	bodyIn wire.SNAC_0x01_0x04_OServiceServiceRequest
	msg    wire.SNACMessage
	err    error
}

type oServiceParams struct {
	clientOnlineParams
	idleNotificationParams
	serviceRequestParams
}

type flapLoginParams []struct {
	frame wire.FLAPSignonFrame
	tlv   wire.TLVRestBlock
	err   error
}

type registerBOSSessionParams []struct {
	authCookie state.ServerCookie
	instance   *state.SessionInstance
	err        error
}

type registerChatSessionParams []struct {
	authCookie state.ServerCookie
	instance   *state.SessionInstance
	err        error
}

type signoutParams []struct {
	me state.IdentScreenName
}

type signoutChatParams []struct {
	me state.IdentScreenName
}

type authParams struct {
	crackCookieParams
	flapLoginParams
	registerBOSSessionParams
	registerChatSessionParams
	signoutParams
	signoutChatParams
}

type crackCookieParams []struct {
	cookieIn  []byte
	cookieOut state.ServerCookie
	err       error
}

type setDirInfoParams []struct {
	me     state.IdentScreenName
	inBody wire.SNAC_0x02_0x09_LocateSetDirInfo
	msg    wire.SNACMessage
	err    error
}

type setInfoParams []struct {
	me     state.IdentScreenName
	inBody wire.SNAC_0x02_0x04_LocateSetInfo
	err    error
}

type userInfoQueryParams []struct {
	me     state.IdentScreenName
	inBody wire.SNAC_0x02_0x05_LocateUserInfoQuery
	msg    wire.SNACMessage
	err    error
}

type dirInfoParams []struct {
	body wire.SNAC_0x02_0x0B_LocateGetDirInfo
	msg  wire.SNACMessage
	err  error
}

type locateParams struct {
	setDirInfoParams
	setInfoParams
	userInfoQueryParams
	dirInfoParams
}

type infoQueryParams []struct {
	inBody wire.SNAC_0x0F_0x02_InfoQuery
	msg    wire.SNACMessage
	err    error
}

type dirSearchParams struct {
	infoQueryParams
}

type addDenyListEntriesParams []struct {
	me   state.IdentScreenName
	body wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries
	err  error
}

type addPermListEntriesParams []struct {
	me   state.IdentScreenName
	body wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries
	err  error
}

type permitDenyParams struct {
	addDenyListEntriesParams
	addPermListEntriesParams
}

type registerBuddyListParams []struct {
	user state.IdentScreenName
	err  error
}

type unregisterBuddyListParams []struct {
	user state.IdentScreenName
	err  error
}

type buddyListRegistryParams struct {
	registerBuddyListParams
	unregisterBuddyListParams
}

type setTOCConfigParams []struct {
	user   state.IdentScreenName
	config string
	err    error
}

type userParams []struct {
	screenName   state.IdentScreenName
	returnedUser *state.User
	err          error
}

type retrieveSessionParams []struct {
	screenName      state.IdentScreenName
	returnedSession *state.Session
}

type sessionRetrieverParams struct {
	retrieveSessionParams
}

type tocConfigParams struct {
	setTOCConfigParams
	userParams
}

type feedBagParams struct {
	useFeedbagParams
	feedbagParams
	feedbagServiceUpsertItemParams
	feedbagServiceDeleteItemParams
}

type useFeedbagParams []struct {
	me  state.IdentScreenName
	err error
}

// feedbagParams is the list of parameters passed at the mock
// FeedbagManager.Feedbag call site (e.g. for NewBuddies).
type feedbagParams []struct {
	screenName state.IdentScreenName
	results    []wire.FeedbagItem
	err        error
}

// feedbagServiceUpsertItemParams is the list of parameters for each expected
// FeedbagService.UpsertItem call. Frame is the expected SNACFrame, items is the
// exact slice of feedbag items (order of params = order of calls).
type feedbagServiceUpsertItemParams []struct {
	frame wire.SNACFrame
	items []wire.FeedbagItem
	msg   *wire.SNACMessage
	err   error
}

// feedbagServiceDeleteItemParams is the list of parameters for each expected
// FeedbagService.DeleteItem call.
type feedbagServiceDeleteItemParams []struct {
	frame  wire.SNACFrame
	inBody wire.SNAC_0x13_0x0A_FeedbagDeleteItem
	msg    *wire.SNACMessage
	err    error
}

type mockParams struct {
	adminParams
	authParams
	buddyListRegistryParams
	buddyParams
	chatNavParams
	chatParams
	cookieBakerParams
	dirSearchParams
	icbmParams
	locateParams
	oServiceParams
	feedBagParams
	permitDenyParams
	sessionRetrieverParams
	tocConfigParams
}

// issueParams holds multiple scenarios for the Issue method.
type issueParams []struct {
	data       []byte
	returnData []byte
	returnErr  error
}

// cookieBakerParams groups the method scenarios for a CookieBaker.
type cookieBakerParams struct {
	issueParams issueParams
}

// matchSession matches a mock call based session ident screen name.
func matchSession(mustMatch state.IdentScreenName) interface{} {
	return mock.MatchedBy(func(s *state.SessionInstance) bool {
		return mustMatch == s.IdentScreenName()
	})
}

// newTestSession creates a session object with 0 or more functional options
// applied
func newTestSession(screenName state.DisplayScreenName, options ...func(instance *state.SessionInstance)) *state.SessionInstance {
	s := state.NewSession().AddInstance()
	s.Session().SetIdentScreenName(screenName.IdentScreenName())
	s.Session().SetDisplayScreenName(screenName)
	s.SetSignonComplete()
	s.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses([5]wire.RateClass{
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
	}))
	for _, op := range options {
		op(s)
	}
	return s
}

// matchContext matches any instance of Context interface.
func matchContext() interface{} {
	return mock.MatchedBy(func(ctx any) bool {
		_, ok := ctx.(context.Context)
		return ok
	})
}
