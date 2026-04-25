package icq_legacy

import (
	"context"
	"net"
	"strconv"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
	"github.com/stretchr/testify/mock"
)

// mockParams is a helper struct that centralizes mock function call parameters
// in one place for a table test
type mockParams struct {
	userManagerParams
	accountManagerParams
	sessionRetrieverParams
	messageRelayerParams
	buddyBroadcasterParams
	offlineMessageManagerParams
	icqUserFinderParams
	icqUserUpdaterParams
	feedbagManagerParams
	relationshipFetcherParams
	icbmFoodgroupParams
}

// icbmFoodgroupParams is a helper struct that contains mock parameters for
// ICBMService methods
type icbmFoodgroupParams struct {
	channelMsgToHostParams
}

// channelMsgToHostParams is the list of parameters passed at the mock
// ICBMService.ChannelMsgToHost call site
type channelMsgToHostParams []struct {
	screenName state.IdentScreenName
	inFrame    wire.SNACFrame
	inBody     wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
	result     *wire.SNACMessage
	err        error
}

// userManagerParams is a helper struct that contains mock parameters for
// UserManager methods
type userManagerParams struct {
	userParams
	insertUserParams
	deleteUserParams
}

// userParams is the list of parameters passed at the mock
// UserManager.User call site
type userParams []struct {
	screenName state.IdentScreenName
	result     *state.User
	err        error
}

// insertUserParams is the list of parameters passed at the mock
// UserManager.InsertUser call site
type insertUserParams []struct {
	user state.User
	err  error
}

// deleteUserParams is the list of parameters passed at the mock
// UserManager.DeleteUser call site
type deleteUserParams []struct {
	screenName state.IdentScreenName
	err        error
}

// accountManagerParams is a helper struct that contains mock parameters for
// AccountManager methods
type accountManagerParams struct {
	setUserPasswordParams
}

// setUserPasswordParams is the list of parameters passed at the mock
// AccountManager.SetUserPassword call site
type setUserPasswordParams []struct {
	screenName  state.IdentScreenName
	newPassword string
	err         error
}

// sessionRetrieverParams is a helper struct that contains mock parameters for
// SessionRetriever methods
type sessionRetrieverParams struct {
	retrieveSessionParams
}

// retrieveSessionParams is the list of parameters passed at the mock
// SessionRetriever.RetrieveSession call site
type retrieveSessionParams []struct {
	screenName state.IdentScreenName
	result     *state.Session
}

// messageRelayerParams is a helper struct that contains mock parameters for
// MessageRelayer methods
type messageRelayerParams struct {
	relayToScreenNameParams
}

// relayToScreenNameParams is the list of parameters passed at the mock
// MessageRelayer.RelayToScreenName call site
type relayToScreenNameParams []struct {
	screenName state.IdentScreenName
	message    wire.SNACMessage
}

// buddyBroadcasterParams is a helper struct that contains mock parameters for
// BuddyBroadcaster methods
type buddyBroadcasterParams struct {
	broadcastBuddyArrivedParams
	broadcastBuddyDepartedParams
}

// broadcastBuddyArrivedParams is the list of parameters passed at the mock
// BuddyBroadcaster.BroadcastBuddyArrived call site
type broadcastBuddyArrivedParams []struct {
	screenName state.IdentScreenName
	userInfo   wire.TLVUserInfo
	err        error
}

// broadcastBuddyDepartedParams is the list of parameters passed at the mock
// BuddyBroadcaster.BroadcastBuddyDeparted call site
type broadcastBuddyDepartedParams []struct {
	instance *state.SessionInstance
	err      error
}

// offlineMessageManagerParams is a helper struct that contains mock parameters for
// OfflineMessageManager methods
type offlineMessageManagerParams struct {
	deleteMessagesParams
	retrieveMessagesParams
	saveMessageParams
}

// deleteMessagesParams is the list of parameters passed at the mock
// OfflineMessageManager.DeleteMessages call site
type deleteMessagesParams []struct {
	recip state.IdentScreenName
	err   error
}

// retrieveMessagesParams is the list of parameters passed at the mock
// OfflineMessageManager.RetrieveMessages call site
type retrieveMessagesParams []struct {
	recip    state.IdentScreenName
	messages []state.OfflineMessage
	err      error
}

// saveMessageParams is the list of parameters passed at the mock
// OfflineMessageManager.SaveMessage call site
type saveMessageParams []struct {
	offlineMessage state.OfflineMessage
	count          int
	err            error
}

// icqUserFinderParams is a helper struct that contains mock parameters for
// ICQUserFinder methods
type icqUserFinderParams struct {
	findByUINParams
	findByICQEmailParams
	findByICQNameParams
	findByICQInterestsParams
	findByICQKeywordParams
}

// findByUINParams is the list of parameters passed at the mock
// ICQUserFinder.FindByUIN call site
type findByUINParams []struct {
	UIN    uint32
	result state.User
	err    error
}

// findByICQEmailParams is the list of parameters passed at the mock
// ICQUserFinder.FindByICQEmail call site
type findByICQEmailParams []struct {
	email  string
	result state.User
	err    error
}

// findByICQNameParams is the list of parameters passed at the mock
// ICQUserFinder.FindByICQName call site
type findByICQNameParams []struct {
	firstName string
	lastName  string
	nickName  string
	result    []state.User
	err       error
}

// findByICQInterestsParams is the list of parameters passed at the mock
// ICQUserFinder.FindByICQInterests call site
type findByICQInterestsParams []struct {
	code     uint16
	keywords []string
	result   []state.User
	err      error
}

// findByICQKeywordParams is the list of parameters passed at the mock
// ICQUserFinder.FindByICQKeyword call site
type findByICQKeywordParams []struct {
	keyword string
	result  []state.User
	err     error
}

// icqUserUpdaterParams is a helper struct that contains mock parameters for
// ICQUserUpdater methods
type icqUserUpdaterParams struct {
	setBasicInfoParams
	setWorkInfoParams
	setMoreInfoParams
	setInterestsParams
	setAffiliationsParams
	setUserNotesParams
	setPermissionsParams
	setHomepageCategoryParams
}

// setBasicInfoParams is the list of parameters passed at the mock
// ICQUserUpdater.SetBasicInfo call site
type setBasicInfoParams []struct {
	name state.IdentScreenName
	data state.ICQBasicInfo
	err  error
}

// setWorkInfoParams is the list of parameters passed at the mock
// ICQUserUpdater.SetWorkInfo call site
type setWorkInfoParams []struct {
	name state.IdentScreenName
	data state.ICQWorkInfo
	err  error
}

// setMoreInfoParams is the list of parameters passed at the mock
// ICQUserUpdater.SetMoreInfo call site
type setMoreInfoParams []struct {
	name state.IdentScreenName
	data state.ICQMoreInfo
	err  error
}

// setInterestsParams is the list of parameters passed at the mock
// ICQUserUpdater.SetInterests call site
type setInterestsParams []struct {
	name state.IdentScreenName
	data state.ICQInterests
	err  error
}

// setAffiliationsParams is the list of parameters passed at the mock
// ICQUserUpdater.SetAffiliations call site
type setAffiliationsParams []struct {
	name state.IdentScreenName
	data state.ICQAffiliations
	err  error
}

// setUserNotesParams is the list of parameters passed at the mock
// ICQUserUpdater.SetUserNotes call site
type setUserNotesParams []struct {
	name state.IdentScreenName
	data state.ICQUserNotes
	err  error
}

// setPermissionsParams is the list of parameters passed at the mock
// ICQUserUpdater.SetPermissions call site
type setPermissionsParams []struct {
	name state.IdentScreenName
	data state.ICQPermissions
	err  error
}

// setHomepageCategoryParams is the list of parameters passed at the mock
// ICQUserUpdater.SetHomepageCategory call site
type setHomepageCategoryParams []struct {
	name state.IdentScreenName
	data state.ICQHomepageCategory
	err  error
}

// feedbagManagerParams is a helper struct that contains mock parameters for
// FeedbagManager methods
type feedbagManagerParams struct {
	feedbagParams
}

// feedbagParams is the list of parameters passed at the mock
// FeedbagManager.Feedbag call site
type feedbagParams []struct {
	screenName state.IdentScreenName
	results    []wire.FeedbagItem
	err        error
}

// relationshipFetcherParams is a helper struct that contains mock parameters
// for RelationshipFetcher methods
type relationshipFetcherParams struct {
	allRelationshipsParams
	relationshipParams
}

// allRelationshipsParams is the list of parameters passed at the mock
// RelationshipFetcher.AllRelationships call site
type allRelationshipsParams []struct {
	me     state.IdentScreenName
	filter []state.IdentScreenName
	result []state.Relationship
	err    error
}

// relationshipParams is the list of parameters passed at the mock
// RelationshipFetcher.Relationship call site
type relationshipParams []struct {
	me     state.IdentScreenName
	them   state.IdentScreenName
	result state.Relationship
	err    error
}

// newTestLegacySession creates a *LegacySession with configurable fields for
// use in table-driven tests. Fields not set remain at their zero values.
func newTestLegacySession(uin uint32, opts ...func(*LegacySession)) *LegacySession {
	legacySess := &LegacySession{
		UIN:  uin,
		Addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4000},
	}
	for _, opt := range opts {
		opt(legacySess)
	}
	return legacySess
}

// legacySessionOptAddr sets the UDP address on the legacy session.
func legacySessionOptOSCARSess(s *LegacySession) {
	oscarSess := state.NewSession()
	oscarSess.SetUIN(s.UIN)
	oscarSess.SetDisplayScreenName(state.DisplayScreenName(strconv.FormatUint(uint64(s.UIN), 10)))
	oscarSess.SetIdentScreenName(oscarSess.DisplayScreenName().IdentScreenName())
	s.Instance = oscarSess.AddInstance()
}

// legacySessionOptVersion sets the protocol version on the legacy session.
func legacySessionOptVersion(version uint16) func(*LegacySession) {
	return func(s *LegacySession) {
		s.Version = version
	}
}

// legacySessionOptStatus sets the status on the legacy session.
func legacySessionOptStatus(status uint32) func(*LegacySession) {
	return func(s *LegacySession) {
		s.Status = status
	}
}

// legacySessionOptContactList sets the contact list on the legacy session.
func legacySessionOptContactList(contacts []uint32) func(*LegacySession) {
	return func(s *LegacySession) {
		s.ContactList = make([]uint32, len(contacts))
		copy(s.ContactList, contacts)
	}
}

// legacySessionOptVisibleList sets the visible list on the legacy session.
func legacySessionOptVisibleList(visible []uint32) func(*LegacySession) {
	return func(s *LegacySession) {
		s.VisibleList = make([]uint32, len(visible))
		copy(s.VisibleList, visible)
	}
}

// legacySessionOptInvisibleList sets the invisible list on the legacy session.
func legacySessionOptInvisibleList(invisible []uint32) func(*LegacySession) {
	return func(s *LegacySession) {
		s.InvisibleList = make([]uint32, len(invisible))
		copy(s.InvisibleList, invisible)
	}
}

// legacySessionOptAddr sets the UDP address on the legacy session.
func legacySessionOptAddr(addr *net.UDPAddr) func(*LegacySession) {
	return func(s *LegacySession) {
		s.Addr = addr
	}
}

// matchContext matches any instance of context.Context interface.
func matchContext() interface{} {
	return mock.MatchedBy(func(ctx any) bool {
		_, ok := ctx.(context.Context)
		return ok
	})
}

// matchSession matches a mock call based session ident screen name.
func matchSession(mustMatch state.IdentScreenName) interface{} {
	return mock.MatchedBy(func(s *state.SessionInstance) bool {
		return mustMatch == s.IdentScreenName()
	})
}
