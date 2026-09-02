package webapi

import (
	"context"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// SessionResolver resolves and refreshes Web API sessions by aimsid.
type SessionResolver interface {
	GetSession(ctx context.Context, aimsid string) (*Session, error)
	TouchSession(ctx context.Context, aimsid string) error
}

// APIKeyValidator validates the dev_key a client sends as its "k" parameter.
type APIKeyValidator interface {
	GetAPIKeyByDevKey(ctx context.Context, devKey string) (*state.WebAPIKey, error)
}

// AuthService cracks auth cookies and registers the BOS sessions they name.
type AuthService interface {
	CrackCookie(authCookie []byte) (state.ServerCookie, time.Time, error)
	FLAPLogin(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error)
	RegisterBOSSession(ctx context.Context, authCookie state.ServerCookie, conf func(sess *state.Session)) (*state.SessionInstance, error)
	Signout(ctx context.Context, session *state.Session)
}

// BARTService stores and retrieves BART (buddy art) assets by content hash.
type BARTService interface {
	RetrieveItem(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x04_BARTDownloadQuery) (wire.SNACMessage, error)
	UpsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x02_BARTUploadQuery) (wire.SNACMessage, error)
}

// BuddyBroadcaster announces a user's arrival and departure to their watchers.
type BuddyBroadcaster interface {
	BroadcastBuddyArrived(ctx context.Context, screenName state.IdentScreenName, userInfo wire.TLVUserInfo) error
	BroadcastBuddyDeparted(ctx context.Context, screenName state.IdentScreenName) error
}

// DirSearchService runs ODir member-directory searches.
type DirSearchService interface {
	InfoQuery(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0F_0x02_InfoQuery) (wire.SNACMessage, error)
}

// FeedbagService reads and edits the server-stored buddy list.
type FeedbagService interface {
	DeleteItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x0A_FeedbagDeleteItem) (*wire.SNACMessage, error)
	PreAuthorizeBuddy(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x14_FeedbagPreAuthorizeBuddy) (*wire.SNACMessage, error)
	Query(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) (wire.SNACMessage, error)
	UpsertItem(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, items []wire.FeedbagItem) (*wire.SNACMessage, error)
	Use(ctx context.Context, instance *state.SessionInstance) error
}

// ICBMService sends instant messages and typing events and drains offline ones.
type ICBMService interface {
	ChannelMsgToHost(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error)
	ClientEvent(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x14_ICBMClientEvent) error
	OfflineRetrieve(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) (wire.SNACMessage, error)
}

// LocateService reads and writes user profiles and directory info.
type LocateService interface {
	SetDirInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x09_LocateSetDirInfo) (wire.SNACMessage, error)
	SetInfo(ctx context.Context, instance *state.SessionInstance, inBody wire.SNAC_0x02_0x04_LocateSetInfo) error
	UserInfoQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x05_LocateUserInfoQuery) (wire.SNACMessage, error)
	DirInfo(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x0B_LocateGetDirInfo) (wire.SNACMessage, error)
}

// OServiceService completes sign-on and manages rate limit subscriptions.
type OServiceService interface {
	ClientOnline(ctx context.Context, service uint16, inBody wire.SNAC_0x01_0x02_OServiceClientOnline, instance *state.SessionInstance) error
	MonitorRateLimits(ctx context.Context, session *state.Session)
	RateParamsSubAdd(ctx context.Context, instance *state.SessionInstance, inBody wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd)
}

// BuddyIconRetriever resolves a user's icon reference from their feedbag, which
// is where it lives, so it resolves for offline users too.
type BuddyIconRetriever interface {
	BuddyIconMetadata(ctx context.Context, screenName state.IdentScreenName) (*wire.BARTID, error)
}

// BuddyListRegistry registers a user's buddy list, making them and the users on
// it visible to each other.
type BuddyListRegistry interface {
	RegisterBuddyList(ctx context.Context, user state.IdentScreenName) error
	UnregisterBuddyList(ctx context.Context, user state.IdentScreenName) error
}

// ChatSessionManager removes a departing user from every chat room they joined.
type ChatSessionManager interface {
	RemoveUserFromAllChats(user state.IdentScreenName)
}
