package http

import (
	"context"
	"net/mail"

	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

type mockParams struct {
	accountManagerParams
	bartAssetManagerParams
	buddyBroadcasterParams
	chatRoomDeleterParams
	chatRoomRetrieverParams
	chatSessionRetrieverParams
	directoryManagerParams
	feedBagRetrieverParams
	feedbagManagerParams
	messageRelayerParams
	profileRetrieverParams
	sessionRetrieverParams
	userManagerParams
}

// accountManagerParams is a helper struct that contains mock parameters for
// accountManager methods
type accountManagerParams struct {
	EmailAddressParams
	RegStatusParams
	ConfirmStatusParams
	updateSuspendedStatusParams
	setBotStatusParams
}

// EmailAddressParams is the list of parameters passed at the mock
// accountManager.EmailAddress call site
type EmailAddressParams []struct {
	screenName state.IdentScreenName
	result     *mail.Address
	err        error
}

// RegStatusParams is the list of parameters passed at the mock
// accountManager.RegStatus call site
type RegStatusParams []struct {
	screenName state.IdentScreenName
	result     uint16
	err        error
}

// ConfirmStatusParams is the list of parameters passed at the mock
// accountManager.ConfirmStatus call site
type ConfirmStatusParams []struct {
	screenName state.IdentScreenName
	result     bool
	err        error
}

// updateSuspendedStatus is the list of parameters passed at the mock
// accountManager.updateSuspendedStatus call site
type updateSuspendedStatusParams []struct {
	suspendedStatus uint16
	screenName      state.IdentScreenName
	err             error
}

// setBotStatusParams is the list of parameters passed at the mock
// accountManager.SetBotStatus call site
type setBotStatusParams []struct {
	isBot      bool
	screenName state.IdentScreenName
	err        error
}

// bartAssetManagerParams is a helper struct that contains mock parameters for
// BARTAssetManager methods
type bartAssetManagerParams struct {
	bartItemParams
	insertBARTItemParams
	listBARTItemsParams
	deleteBARTItemParams
}

// bartItemParams is the list of parameters passed at the mock
// BARTAssetManager.BARTItem call site
type bartItemParams []struct {
	hash   []byte
	result []byte
	err    error
}

// insertBARTItemParams is the list of parameters passed at the mock
// BARTAssetManager.InsertBARTItem call site
type insertBARTItemParams []struct {
	hash     []byte
	blob     []byte
	itemType uint16
	err      error
}

// listBARTItemsParams is the list of parameters passed at the mock
// BARTAssetManager.ListBARTItems call site
type listBARTItemsParams []struct {
	itemType uint16
	result   []state.BARTItem
	err      error
}

// deleteBARTItemParams is the list of parameters passed at the mock
// BARTAssetManager.DeleteBARTItem call site
type deleteBARTItemParams []struct {
	hash []byte
	err  error
}

// buddyBroadcasterParams is a helper struct that contains mock parameters for
// BuddyBroadcaster methods
type buddyBroadcasterParams struct {
	broadcastVisibilityParams
}

// broadcastVisibilityParams is the list of parameters passed at the mock
// BuddyBroadcaster.BroadcastVisibility call site
type broadcastVisibilityParams []struct {
	you            *state.SessionInstance
	filter         []state.IdentScreenName
	sendDepartures bool
	err            error
}

// chatRoomRetrieverParams is a helper struct that contains mock parameters for
// ChatRoomRetriever methods
type chatRoomRetrieverParams struct {
	allChatRoomsParams
}

// allChatRoomsParams is the list of parameters passed at the mock
// ChatRoomRetriever.AllChatRooms call site
type allChatRoomsParams []struct {
	exchange uint16
	result   []state.ChatRoom
	err      error
}

// chatRoomDeleterParams is a helper struct that contains mock parameters for
// ChatRoomDeleter methods
type chatRoomDeleterParams struct {
	deleteChatRoomsParams
}

// deleteChatRoomsParams is the list of parameters passed at the mock
// ChatRoomDeleter.DeleteChatRooms call site
type deleteChatRoomsParams []struct {
	exchange uint16
	names    []string
	err      error
}

// chatSessionRetrieverParams is a helper struct that contains mock parameters for
// ChatSessionRetriever methods
type chatSessionRetrieverParams struct {
	chatSessionRetrieverAllSessionsParams
}

// chatSessionRetrieverAllSessionsParams is the list of parameters passed at the mock
// ChatSessionRetriever.AllSessions call site
type chatSessionRetrieverAllSessionsParams []struct {
	cookie string
	result []*state.Session
}

type directoryManagerParams struct {
	categoriesParams
	createCategoryParams
	createKeywordParams
	deleteCategoryParams
	deleteKeywordParams
	keywordsByCategoryParams
}

// categoriesParams is the list of parameters passed at the mock
// DirectoryManager.Categories call site
type categoriesParams []struct {
	result []state.Category
	err    error
}

// createCategoryParams is the list of parameters passed at the mock
// DirectoryManager.CreateCategory call site
type createCategoryParams []struct {
	name   string
	result state.Category
	err    error
}

// createKeywordParams is the list of parameters passed at the mock
// DirectoryManager.CreateKeyword call site
type createKeywordParams []struct {
	name       string
	categoryID uint8
	result     state.Keyword
	err        error
}

// deleteCategoryParams is the list of parameters passed at the mock
// DirectoryManager.DeleteCategory call site
type deleteCategoryParams []struct {
	categoryID uint8
	err        error
}

// deleteKeywordParams is the list of parameters passed at the mock
// DirectoryManager.DeleteKeyword call site
type deleteKeywordParams []struct {
	id  uint8
	err error
}

// keywordsByCategoryParams is the list of parameters passed at the mock
// DirectoryManager.KeywordsByCategory call site
type keywordsByCategoryParams []struct {
	categoryID uint8
	result     []state.Keyword
	err        error
}

// feedBagRetrieverParams is a helper struct that contains mock parameters for
// FeedBagRetriever methods
type feedBagRetrieverParams struct {
	buddyIconMetadataParams
}

// buddyIconMetadataParams is the list of parameters passed at the mock
// FeedBagRetriever.BuddyIconMetadataParams call site
type buddyIconMetadataParams []struct {
	screenName state.IdentScreenName
	result     *wire.BARTID
	err        error
}

// feedbagManagerParams is a helper struct that contains mock parameters for
// FeedbagManager methods
type feedbagManagerParams struct {
	feedbagParams
	feedbagUpsertParams
	feedbagDeleteParams
}

// feedbagParams is the list of parameters passed at the mock
// FeedbagManager.Feedbag call site
type feedbagParams []struct {
	screenName state.IdentScreenName
	result     wire.FeedbagItems
	err        error
}

// feedbagUpsertParams is the list of parameters passed at the mock
// FeedbagManager.FeedbagUpsert call site
type feedbagUpsertParams []struct {
	screenName state.IdentScreenName
	items      wire.FeedbagItems
	err        error
}

// feedbagDeleteParams is the list of parameters passed at the mock
// FeedbagManager.FeedbagDelete call site
type feedbagDeleteParams []struct {
	screenName state.IdentScreenName
	items      wire.FeedbagItems
	err        error
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
	msg        wire.SNACMessage
}

// profileRetrieverParams is a helper struct that contains mock parameters for
// ProfileRetriever methods
type profileRetrieverParams struct {
	retrieveProfileParams
}

// retrieveProfileParams is the list of parameters passed at the mock
// ProfileRetriever.Profile call site
type retrieveProfileParams []struct {
	screenName state.IdentScreenName
	result     state.UserProfile
	err        error
}

// sessionRetrieverParams is a helper struct that contains mock parameters for
// SessionRetriever methods
type sessionRetrieverParams struct {
	sessionRetrieverAllSessionsParams
	retrieveSessionByNameParams
}

// sessionRetrieverAllSessionsParams is the list of parameters passed at the mock
// SessionRetriever.AllSessions call site
type sessionRetrieverAllSessionsParams []struct {
	result []*state.Session
}

// retrieveSessionByNameParams is the list of parameters passed at the mock
// SessionRetriever.RetrieveSession call site
type retrieveSessionByNameParams []struct {
	screenName state.IdentScreenName
	result     *state.Session
}

// userManagerParams is a helper struct that contains mock parameters for
// UserManager methods
type userManagerParams struct {
	allUsersParams
	deleteUserParams
	getUserParams
	setUserPasswordParams
}

// allUsersParams is the list of parameters passed at the mock
// UserManager.AllUsers call site
type allUsersParams []struct {
	result []state.User
	err    error
}

// deleteUserParams is the list of parameters passed at the mock
// UserManager.DeleteUser call site
type deleteUserParams []struct {
	screenName state.IdentScreenName
	err        error
}

// getUserParams is the list of parameters passed at the mock
// UserManager.User call site
type getUserParams []struct {
	screenName state.IdentScreenName
	result     *state.User
	err        error
}

// setUserPasswordParams is the list of parameters passed at the mock
// UserManager.SetUserPassword call site
type setUserPasswordParams []struct {
	screenName  state.IdentScreenName
	newPassword string
	err         error
}

// matchContext matches any instance of Context interface.
func matchContext() interface{} {
	return mock.MatchedBy(func(ctx any) bool {
		_, ok := ctx.(context.Context)
		return ok
	})
}
