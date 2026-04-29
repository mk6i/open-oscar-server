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
	sessionRetrieverParams
	offlineMessageManagerParams
	icqUserFinderParams
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
	deleteUserParams
}

// userParams is the list of parameters passed at the mock
// UserManager.User call site
type userParams []struct {
	screenName state.IdentScreenName
	result     *state.User
	err        error
}

// deleteUserParams is the list of parameters passed at the mock
// UserManager.DeleteUser call site
type deleteUserParams []struct {
	screenName state.IdentScreenName
	err        error
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

// offlineMessageManagerParams is a helper struct that contains mock parameters for
// OfflineMessageManager methods
type offlineMessageManagerParams struct {
	retrieveMessagesParams
}

// retrieveMessagesParams is the list of parameters passed at the mock
// OfflineMessageManager.RetrieveMessages call site
type retrieveMessagesParams []struct {
	recip    state.IdentScreenName
	messages []state.OfflineMessage
	err      error
}

// icqUserFinderParams is a helper struct that contains mock parameters for
// ICQUserFinder methods
type icqUserFinderParams struct {
	findByUINParams
	findByICQEmailParams
	findByICQNameParams
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

// legacySessionOptVersion sets the protocol version on the legacy session.
func legacySessionOptVersion(version uint16) func(*LegacySession) {
	return func(s *LegacySession) {
		s.Version = version
	}
}

// legacySessionOptOSCARSess attaches an OSCAR session instance for tests that need Instance set.
func legacySessionOptOSCARSess(s *LegacySession) {
	oscarSess := state.NewSession()
	oscarSess.SetUIN(s.UIN)
	oscarSess.SetDisplayScreenName(state.DisplayScreenName(strconv.FormatUint(uint64(s.UIN), 10)))
	oscarSess.SetIdentScreenName(oscarSess.DisplayScreenName().IdentScreenName())
	s.Instance = oscarSess.AddInstance()
}

func newTestOSCARInstance(screenName state.DisplayScreenName) *state.SessionInstance {
	oscarSess := state.NewSession()
	oscarSess.SetDisplayScreenName(screenName)
	oscarSess.SetIdentScreenName(screenName.IdentScreenName())
	return oscarSess.AddInstance()
}

// legacySessionOptContactList sets the contact list on the legacy session.
func legacySessionOptContactList(contacts []uint32) func(*LegacySession) {
	return func(s *LegacySession) {
		s.ContactList = make([]uint32, len(contacts))
		copy(s.ContactList, contacts)
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
