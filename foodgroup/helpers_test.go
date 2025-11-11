package foodgroup

import (
	"context"
	"net/mail"
	"net/netip"
	"time"

	"github.com/stretchr/testify/mock"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

// mockParams is a helper struct that centralizes mock function call parameters
// in one place for a table test
type mockParams struct {
	accountManagerParams
	bartItemManagerParams
	buddyBroadcasterParams
	relationshipFetcherParams
	chatMessageRelayerParams
	chatRoomRegistryParams
	cookieBakerParams
	feedbagManagerParams
	icqUserFinderParams
	icqUserUpdaterParams
	clientSideBuddyListManagerParams
	messageRelayerParams
	offlineMessageManagerParams
	profileManagerParams
	sessionRegistryParams
	sessionRetrieverParams
	userManagerParams
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
	screenName state.IdentScreenName
	filter     []state.IdentScreenName
	result     []state.Relationship
	err        error
}

// relationshipParams is the list of parameters passed at the mock
// RelationshipFetcher.Relationship call site
type relationshipParams []struct {
	me     state.IdentScreenName
	them   state.IdentScreenName
	result state.Relationship
	err    error
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
	recipIn state.IdentScreenName
	err     error
}

// deleteMessagesParams is the list of parameters passed at the mock
// OfflineMessageManager.RetrieveMessages call site
type retrieveMessagesParams []struct {
	recipIn     state.IdentScreenName
	messagesOut []state.OfflineMessage
	err         error
}

// deleteMessagesParams is the list of parameters passed at the mock
// OfflineMessageManager.SaveMessage call site
type saveMessageParams []struct {
	offlineMessageIn state.OfflineMessage
	err              error
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

// icqUserFinderParams is a helper struct that contains mock parameters for
// ICQUserFinder methods
type icqUserFinderParams struct {
	findByDetailsParams
	findByEmailParams
	findByInterestsParams
	findByKeywordParams
	findByUINParams
}

// findByKeywordParams is the list of parameters passed at the mock
// ICQUserFinder.FindByKeyword call site
type findByKeywordParams []struct {
	keyword string
	result  []state.User
	err     error
}

// findByUINParams is the list of parameters passed at the mock
// ICQUserFinder.FindByUIN call site
type findByUINParams []struct {
	UIN    uint32
	result state.User
	err    error
}

// findByEmailParams is the list of parameters passed at the mock
// ICQUserFinder.FindByEmail call site
type findByEmailParams []struct {
	email  string
	result state.User
	err    error
}

// setBasicInfoParams is the list of parameters passed at the mock
// ICQUserFinder.FindByDetails call site
type findByDetailsParams []struct {
	firstName string
	lastName  string
	nickName  string
	result    []state.User
	err       error
}

// setBasicInfoParams is the list of parameters passed at the mock
// ICQUserFinder.FindByInterests call site
type findByInterestsParams []struct {
	code     uint16
	keywords []string
	result   []state.User
	err      error
}

// icqUserUpdaterParams is a helper struct that contains mock parameters for
// ICQUserUpdater methods
type icqUserUpdaterParams struct {
	setAffiliationsParams
	setBasicInfoParams
	setInterestsParams
	setMoreInfoParams
	setUserNotesParams
	setWorkInfoParams
}

// setAffiliationsParams is the list of parameters passed at the mock
// ICQUserUpdater.SetAffiliations call site
type setAffiliationsParams []struct {
	name state.IdentScreenName
	data state.ICQAffiliations
	err  error
}

// setInterestsParams is the list of parameters passed at the mock
// ICQUserUpdater.SetInterests call site
type setInterestsParams []struct {
	name state.IdentScreenName
	data state.ICQInterests
	err  error
}

// setUserNotesParams is the list of parameters passed at the mock
// ICQUserUpdater.SetUserNotes call site
type setUserNotesParams []struct {
	name state.IdentScreenName
	data state.ICQUserNotes
	err  error
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

// bartItemManagerParams is a helper struct that contains mock parameters for
// BARTItemManager methods
type bartItemManagerParams struct {
	bartItemManagerRetrieveParams
	bartItemManagerUpsertParams
	buddyIconMetadataParams
}

// bartItemManagerRetrieveParams is the list of parameters passed at the mock
// BARTItemManager.BuddyIcon call site
type bartItemManagerRetrieveParams []struct {
	itemHash []byte
	result   []byte
	err      error
}

// bartItemManagerUpsertParams is the list of parameters passed at the mock
// BARTItemManager.SetBuddyIcon call site
type bartItemManagerUpsertParams []struct {
	itemHash []byte
	payload  []byte
	bartType uint16
	err      error
}

// buddyIconMetadataParams is the list of parameters passed at the mock
// BARTItemManager.BuddyIconMetadata call site
type buddyIconMetadataParams []struct {
	screenName state.IdentScreenName
	result     *wire.BARTID
	err        error
}

// userManagerParams is a helper struct that contains mock parameters for
// UserManager methods
type userManagerParams struct {
	getUserParams
	insertUserParams
}

// getUserParams is the list of parameters passed at the mock
// UserManager.User call site
type getUserParams []struct {
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

// sessionRegistryParams is a helper struct that contains mock parameters for
// SessionRegistry methods
type sessionRegistryParams struct {
	addSessionParams
	removeSessionParams
}

// addSessionParams is the list of parameters passed at the mock
// SessionRegistry.AddSession call site
type addSessionParams []struct {
	screenName state.DisplayScreenName
	result     *state.Session
	err        error
}

// removeSessionParams is the list of parameters passed at the mock
// SessionRegistry.RemoveSession call site
type removeSessionParams []struct {
	screenName state.IdentScreenName
}

// feedbagManagerParams is a helper struct that contains mock parameters for
// FeedbagManager methods
type feedbagManagerParams struct {
	adjacentUsersParams
	feedbagUpsertParams
	buddiesParams
	feedbagParams
	feedbagLastModifiedParams
	feedbagDeleteParams
	useParams
}

// adjacentUsersParams is the list of parameters passed at the mock
// FeedbagManager.AdjacentUsers call site
type adjacentUsersParams []struct {
	screenName state.IdentScreenName
	users      []state.IdentScreenName
	err        error
}

// feedbagUpsertParams is the list of parameters passed at the mock
// FeedbagManager.FeedbagUpsert call site
type feedbagUpsertParams []struct {
	screenName state.IdentScreenName
	items      []wire.FeedbagItem
}

// buddiesParams is the list of parameters passed at the mock
// FeedbagManager.Buddies call site
type buddiesParams []struct {
	screenName state.IdentScreenName
	results    []state.IdentScreenName
}

// useParams is the list of parameters passed at the mock
// FeedbagManager.Use call site
type useParams []struct {
	screenName state.IdentScreenName
}

// feedbagParams is the list of parameters passed at the mock
// FeedbagManager.Feedbag call site
type feedbagParams []struct {
	screenName state.IdentScreenName
	results    []wire.FeedbagItem
}

// feedbagLastModifiedParams is the list of parameters passed at the mock
// FeedbagManager.FeedbagLastModified call site
type feedbagLastModifiedParams []struct {
	screenName state.IdentScreenName
	result     time.Time
}

// feedbagDeleteParams is the list of parameters passed at the mock
// FeedbagManager.FeedbagDelete call site
type feedbagDeleteParams []struct {
	screenName state.IdentScreenName
	items      []wire.FeedbagItem
}

// messageRelayerParams is a helper struct that contains mock parameters for
// MessageRelayer methods
type messageRelayerParams struct {
	relayToScreenNamesParams
	relayToScreenNameParams
}

// relayToScreenNamesParams is the list of parameters passed at the mock
// MessageRelayer.RelayToScreenNames call site
type relayToScreenNamesParams []struct {
	screenNames []state.IdentScreenName
	message     wire.SNACMessage
}

// relayToScreenNameParams is the list of parameters passed at the mock
// MessageRelayer.RelayToScreenName call site
type relayToScreenNameParams []struct {
	screenName state.IdentScreenName
	message    wire.SNACMessage
}

// profileManagerParams is a helper struct that contains mock parameters for
// ProfileManager methods
type profileManagerParams struct {
	findByAIMEmailParams
	findByAIMKeywordParams
	findByAIMNameAndAddrParams
	getUserParams
	interestListParams
	retrieveProfileParams
	setDirectoryInfoParams
	setKeywordsParams
	setProfileParams
}

// findByAIMEmailParams is the list of parameters passed at the mock
// ProfileManager.FindByAIMEmail call site
type findByAIMEmailParams []struct {
	email  string
	result state.User
	err    error
}

// findByAIMKeywordParams is the list of parameters passed at the mock
// ProfileManager.FindByAIMKeyword call site
type findByAIMKeywordParams []struct {
	keyword string
	result  []state.User
	err     error
}

// findByAIMNameAndAddrParams is the list of parameters passed at the mock
// ProfileManager.FindByAIMNameAndAddr call site
type findByAIMNameAndAddrParams []struct {
	info   state.AIMNameAndAddr
	result []state.User
	err    error
}

// interestListParams is the list of parameters passed at the mock
// ProfileManager.InterestList call site
type interestListParams []struct {
	result []wire.ODirKeywordListItem
	err    error
}

// setDirectoryInfoParams is the list of parameters passed at the mock
// ProfileManager.SetDirectoryInfo call site
type setDirectoryInfoParams []struct {
	screenName state.IdentScreenName
	info       state.AIMNameAndAddr
	err        error
}

// retrieveProfileParams is the list of parameters passed at the mock
// ProfileManager.Profile call site
type retrieveProfileParams []struct {
	screenName state.IdentScreenName
	result     state.UserProfile
	err        error
}

// setProfileParams is the list of parameters passed at the mock
// ProfileManager.SetProfile call site
type setProfileParams []struct {
	screenName state.IdentScreenName
	body       state.UserProfile
}

// setKeywordsParams is the list of parameters passed at the mock
// ProfileManager.SetKeywords call site
type setKeywordsParams []struct {
	screenName state.IdentScreenName
	keywords   [5]string
	err        error
}

// chatMessageRelayerParams is a helper struct that contains mock parameters
// for ChatMessageRelayer methods
type chatMessageRelayerParams struct {
	chatAllSessionsParams
	chatRelayToAllExceptParams
	chatRelayToScreenNameParams
}

// chatAllSessionsParams is the list of parameters passed at the mock
// ChatMessageRelayer.AllSessions call site
type chatAllSessionsParams []struct {
	cookie   string
	sessions []*state.Session
	err      error
}

// chatRelayToAllExceptParams is the list of parameters passed at the mock
// ChatMessageRelayer.RelayToAllExcept call site
type chatRelayToAllExceptParams []struct {
	cookie     string
	screenName state.IdentScreenName
	message    wire.SNACMessage
	err        error
}

// chatRelayToScreenNameParams is the list of parameters passed at the mock
// ChatMessageRelayer.RelayToScreenName call site
type chatRelayToScreenNameParams []struct {
	cookie     string
	screenName state.IdentScreenName
	message    wire.SNACMessage
	err        error
}

// clientSideBuddyListManagerParams is a helper struct that contains mock
// parameters for ClientSideBuddyListManager methods
type clientSideBuddyListManagerParams struct {
	addBuddyParams
	deleteBuddyParams
	denyBuddyParams
	permitBuddyParams
	removeDenyBuddyParams
	removePermitBuddyParams
	setPDModeParams
}

// legacyBuddiesParams is the list of parameters passed at the mock
// ClientSideBuddyListManager.AddBuddy call site
type addBuddyParams []struct {
	me   state.IdentScreenName
	them state.IdentScreenName
	err  error
}

// legacyBuddiesParams is the list of parameters passed at the mock
// ClientSideBuddyListManager.RemoveBuddy call site
type deleteBuddyParams []struct {
	me   state.IdentScreenName
	them state.IdentScreenName
	err  error
}

// deleteUserParams is the list of parameters passed at the mock
// ClientSideBuddyListManager.RemoveBuddy call site
type denyBuddyParams []struct {
	me   state.IdentScreenName
	them state.IdentScreenName
	err  error
}

// permitBuddyParams is the list of parameters passed at the mock
// ClientSideBuddyListManager.PermitBuddy call site
type permitBuddyParams []struct {
	me   state.IdentScreenName
	them state.IdentScreenName
	err  error
}

// removeDenyBuddyParams is the list of parameters passed at the mock
// ClientSideBuddyListManager.RemoveDenyBuddy call site
type removeDenyBuddyParams []struct {
	me   state.IdentScreenName
	them state.IdentScreenName
	err  error
}

// removePermitBuddyParams is the list of parameters passed at the mock
// ClientSideBuddyListManager.RemovePermitBuddy call site
type removePermitBuddyParams []struct {
	me   state.IdentScreenName
	them state.IdentScreenName
	err  error
}

// setPDModeParams is the list of parameters passed at the mock
// ClientSideBuddyListManager.SetPDMode call site
type setPDModeParams []struct {
	userScreenName state.IdentScreenName
	pdMode         wire.FeedbagPDMode
	err            error
}

// cookieBakerParams is a helper struct that contains mock parameters for
// CookieBaker methods
type cookieBakerParams struct {
	cookieCrackParams
	cookieIssueParams
}

// cookieCrackParams is the list of parameters passed at the mock
// CookieBaker.Crack call site
type cookieCrackParams []struct {
	cookieIn []byte
	dataOut  []byte
	err      error
}

// cookieIssueParams is the list of parameters passed at the mock
// CookieBaker.Issue call site
type cookieIssueParams []struct {
	dataIn    []byte
	cookieOut []byte
	err       error
}

// accountManagerParams is a helper struct that contains mock parameters for
// accountManager methods
type accountManagerParams struct {
	accountManagerUpdateDisplayScreenNameParams
	accountManagerUpdateEmailAddressParams
	accountManagerEmailAddressParams
	accountManagerUpdateRegStatusParams
	accountManagerRegStatusParams
	accountManagerUpdateConfirmStatusParams
	accountManagerConfirmStatusParams
	accountManagerUserParams
	accountManagerSetUserPasswordParams
}

// accountManagerUpdateDisplayScreenNameParams is the list of parameters passed at the mock
// accountManager.UpdateDisplayScreenName call site
type accountManagerUpdateDisplayScreenNameParams []struct {
	displayScreenName state.DisplayScreenName
	err               error
}

// accountManagerUpdateEmailAddressParams is the list of parameters passed at the mock
// accountManager.UpdateEmailAddress call site
type accountManagerUpdateEmailAddressParams []struct {
	emailAddress *mail.Address
	screenName   state.IdentScreenName
	err          error
}

// accountManagerEmailAddressParams is the list of parameters passed at the mock
// accountManager.EmailAddress call site
type accountManagerEmailAddressParams []struct {
	screenName   state.IdentScreenName
	emailAddress *mail.Address
	err          error
}

// accountManagerUpdateRegStatusParams is the list of parameters passed at the mock
// accountManager.UpdateRegStatus call site
type accountManagerUpdateRegStatusParams []struct {
	regStatus  uint16
	screenName state.IdentScreenName
	err        error
}

// accountManagerRegStatusParams is the list of parameters passed at the mock
// accountManager.RegStatus call site
type accountManagerRegStatusParams []struct {
	screenName state.IdentScreenName
	regStatus  uint16
	err        error
}

// accountManagerUpdateConfirmStatusParams is the list of parameters passed at the mock
// accountManager.UpdateConfirmStatus call site
type accountManagerUpdateConfirmStatusParams []struct {
	confirmStatus bool
	screenName    state.IdentScreenName
	err           error
}

// accountManagerConfirmStatusParams is the list of parameters passed at the mock
// accountManager.ConfirmStatus call site
type accountManagerConfirmStatusParams []struct {
	screenName    state.IdentScreenName
	confirmStatus bool
	err           error
}

// accountManagerUserParams is the list of parameters passed at the mock
// accountManager.User call site
type accountManagerUserParams []struct {
	screenName state.IdentScreenName
	result     *state.User
	err        error
}

// accountManagerSetUserPasswordParams is the list of parameters passed at the mock
// accountManager.SetUserPassword call site
type accountManagerSetUserPasswordParams []struct {
	screenName state.IdentScreenName
	password   string
	err        error
}

// buddyBroadcasterParams is a helper struct that contains mock parameters for
// buddyBroadcaster methods
type buddyBroadcasterParams struct {
	broadcastBuddyArrivedParams
	broadcastBuddyDepartedParams
	broadcastVisibilityParams
}

// broadcastVisibilityParams is the list of parameters passed at the mock
// buddyBroadcaster.BroadcastVisibility call site
type broadcastVisibilityParams []struct {
	from             state.IdentScreenName
	filter           []state.IdentScreenName
	doSendDepartures bool
	err              error
}

// broadcastBuddyArrivedParams is the list of parameters passed at the mock
// buddyBroadcaster.BroadcastBuddyArrived call site
type broadcastBuddyArrivedParams []struct {
	screenName  state.DisplayScreenName
	err         error
	bodyMatcher func(snac wire.TLVUserInfo) bool
}

// broadcastBuddyDepartedParams is the list of parameters passed at the mock
// buddyBroadcaster.BroadcastBuddyDeparted call site
type broadcastBuddyDepartedParams []struct {
	screenName state.IdentScreenName
	err        error
}

// chatRoomRegistryParams is a helper struct that contains mock parameters for
// ChatRoomRegistry methods
type chatRoomRegistryParams struct {
	chatRoomByCookieParams
	chatRoomByNameParams
	createChatRoomParams
}

// chatRoomByCookieParams is the list of parameters passed at the mock
// ChatRoomRegistry.ChatRoomByCookie call site
type chatRoomByCookieParams []struct {
	cookie string
	room   state.ChatRoom
	err    error
}

// chatRoomByCookieParams is the list of parameters passed at the mock
// ChatRoomRegistry.ChatRoomByName call site
type chatRoomByNameParams []struct {
	exchange uint16
	name     string
	room     state.ChatRoom
	err      error
}

// createChatRoomParams is the list of parameters passed at the mock
// ChatRoomRegistry.CreateChatRoom call site
type createChatRoomParams []struct {
	room *state.ChatRoom
	err  error
}

// sessOptWarning sets a warning level on the session object
func sessOptWarning(level int16) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetWarning(uint16(level))
	}
}

// sessOptCannedAwayMessage sets a canned away message ("this is my away
// message!") on the session object
func sessOptCannedAwayMessage(session *state.Session) {
	session.SetAwayMessage("this is my away message!")
}

// sessOptCannedSignonTime sets a canned sign-on time (1696790127565) on the
// session object
func sessOptCannedSignonTime(session *state.Session) {
	session.SetSignonTime(time.UnixMilli(1696790127565))
}

// sessOptChatRoomCookie sets cookie on the session object
func sessOptChatRoomCookie(cookie string) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetChatRoomCookie(cookie)
	}
}

// sessOptBot sets the bot flag to true on the session
// object
func sessOptBot(session *state.Session) {
	session.SetUserInfoFlag(wire.OServiceUserFlagBot)
}

// sessOptInvisible sets the invisible flag to true on the session
// object
func sessOptInvisible(session *state.Session) {
	session.SetUserStatusBitmask(wire.OServiceUserStatusInvisible)
}

// sessOptIdle sets the idle flag to dur on the session object
func sessOptIdle(dur time.Duration) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetIdle(dur)
	}
}

// sessOptSignonComplete sets the sign on complete flag to true
func sessOptSignonComplete(session *state.Session) {
	session.SetSignonComplete()
}

// sessOptCaps sets caps
func sessOptUIN(UIN uint32) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetUIN(UIN)
	}
}

// sessOptCaps sets caps
func sessOptWantTypingEvents(session *state.Session) {
	session.SetTypingEventsEnabled(true)
}

// sessOptSetFoodGroupVersion sets food group versions
func sessOptSetFoodGroupVersion(foodGroup uint16, version uint16) func(session *state.Session) {
	return func(session *state.Session) {
		var versions [wire.MDir + 1]uint16
		versions[foodGroup] = version
		session.SetFoodGroupVersions(versions)
	}
}

// sessOptSetRateClasses sets rate limit classes
func sessOptSetRateClasses(classes wire.RateLimitClasses) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetRateClasses(time.Now(), classes)
	}
}

// sessOptMemberSince sets the member since timestamp on the session object.
func sessOptMemberSince(t time.Time) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetMemberSince(t)
	}
}

// sessOptSignonTime sets the sign-on time on the session object.
func sessOptSignonTime(t time.Time) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetSignonTime(t)
	}
}

// sessOptProfile sets profile
func sessOptProfile(profile state.UserProfile) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetProfile(profile)
	}
}

// sessOptKerberosAuth indicates the session signed on
func sessOptKerberosAuth(session *state.Session) {
	session.SetKerberosAuth(true)
}

// sessClientID sets the client ID
func sessClientID(clientID string) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetClientID(clientID)
	}
}

// sessRemoteAddr sets the client's ip address / port
func sessRemoteAddr(remoteAddr netip.AddrPort) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetRemoteAddr(&remoteAddr)
	}
}

// sessBuddyIcon sets session buddy icon
func sessOptBuddyIcon(icon wire.BARTID) func(session *state.Session) {
	return func(session *state.Session) {
		session.SetBuddyIcon(icon)
	}
}

// newTestSession creates a session object with 0 or more functional options
// applied
func newTestSession(screenName state.DisplayScreenName, options ...func(session *state.Session)) *state.Session {
	s := state.NewSession()
	s.SetIdentScreenName(screenName.IdentScreenName())
	s.SetDisplayScreenName(screenName)
	s.SetRateClasses(time.Now(), wire.DefaultRateLimitClasses())
	for _, op := range options {
		op(s)
	}
	return s
}

func userInfoWithBARTIcon(sess *state.Session, bid wire.BARTID) wire.TLVUserInfo {
	info := sess.TLVUserInfo()
	info.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, bid))
	return info
}

// matchSession matches a mock call based session ident screen name.
func matchSession(mustMatch state.IdentScreenName) interface{} {
	return mock.MatchedBy(func(s *state.Session) bool {
		return mustMatch == s.IdentScreenName()
	})
}

// matchContext matches any instance of Context interface.
func matchContext() interface{} {
	return mock.MatchedBy(func(ctx any) bool {
		_, ok := ctx.(context.Context)
		return ok
	})
}
