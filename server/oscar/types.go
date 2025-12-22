package oscar

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// OnlineNotifier returns a OServiceHostOnline SNAC that is sent to the client
// at the beginning of the protocol sequence which lists all food groups
// managed by the server.
type OnlineNotifier interface {
	HostOnline(service uint16) wire.SNACMessage
}

// BuddyListRegistry is the interface for keeping track of users with active
// buddy lists. Once registered, a user becomes visible to other users' buddy
// lists and vice versa.
type BuddyListRegistry interface {
	ClearBuddyListRegistry(ctx context.Context) error
	RegisterBuddyList(ctx context.Context, user state.IdentScreenName) error
	UnregisterBuddyList(ctx context.Context, user state.IdentScreenName) error
}

// DepartureNotifier is the interface for sending buddy departure notifications
// when a client disconnects.
type DepartureNotifier interface {
	BroadcastBuddyArrived(ctx context.Context, screenName state.IdentScreenName, userInfo wire.TLVUserInfo) error
	BroadcastBuddyDeparted(ctx context.Context, sess *state.Session) error
}

// ChatSessionManager is the interface for closing chat sessions
// when a client disconnects.
type ChatSessionManager interface {
	RemoveUserFromAllChats(user state.IdentScreenName)
}

// RateLimitUpdater provides rate limit updates for subscribed rate limit classes.
type RateLimitUpdater interface {
	RateLimitUpdates(ctx context.Context, sess *state.Session, now time.Time) []wire.SNACMessage
}

type AuthService interface {
	BUCPChallenge(ctx context.Context, bodyIn wire.SNAC_0x17_0x06_BUCPChallengeRequest, newUUID func() uuid.UUID) (wire.SNACMessage, error)
	BUCPLogin(ctx context.Context, bodyIn wire.SNAC_0x17_0x02_BUCPLoginRequest, newUserFn func(screenName state.DisplayScreenName) (state.User, error), here string) (wire.SNACMessage, error)
	CrackCookie(authCookie []byte) (state.ServerCookie, error)
	FLAPLogin(ctx context.Context, frame wire.FLAPSignonFrame, newUserFn func(screenName state.DisplayScreenName) (state.User, error), here string) (wire.TLVRestBlock, error)
	KerberosLogin(ctx context.Context, inBody wire.SNAC_0x050C_0x0002_KerberosLoginRequest, newUserFn func(screenName state.DisplayScreenName) (state.User, error), advertisedHost string) (wire.SNACMessage, error)
	RegisterBOSSession(ctx context.Context, authCookie state.ServerCookie) (*state.Session, error)
	RegisterChatSession(ctx context.Context, authCookie state.ServerCookie) (*state.Session, error)
	RetrieveBOSSession(ctx context.Context, authCookie state.ServerCookie) (*state.Session, error)
	Signout(ctx context.Context, sess *state.Session)
	SignoutChat(ctx context.Context, sess *state.Session)
}

type AdminService interface {
	ConfirmRequest(ctx context.Context, sess *state.Session, frame wire.SNACFrame) (wire.SNACMessage, error)
	InfoQuery(ctx context.Context, sess *state.Session, frame wire.SNACFrame, body wire.SNAC_0x07_0x02_AdminInfoQuery) (wire.SNACMessage, error)
	InfoChangeRequest(ctx context.Context, sess *state.Session, frame wire.SNACFrame, body wire.SNAC_0x07_0x04_AdminInfoChangeRequest) (wire.SNACMessage, error)
}

type BARTService interface {
	UpsertItem(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x02_BARTUploadQuery) (wire.SNACMessage, error)
	RetrieveItem(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x04_BARTDownloadQuery) (wire.SNACMessage, error)
	RetrieveItemV2(ctx context.Context, frame wire.SNACFrame, body wire.SNAC_0x10_0x06_BARTDownload2Query) ([]wire.SNACMessage, error)
}

type BuddyService interface {
	RightsQuery(ctx context.Context, inFrame wire.SNACFrame) wire.SNACMessage
	AddBuddies(ctx context.Context, sess *state.Session, inBody wire.SNAC_0x03_0x04_BuddyAddBuddies) error
	DelBuddies(_ context.Context, sess *state.Session, inBody wire.SNAC_0x03_0x05_BuddyDelBuddies) error
	AddTempBuddies(ctx context.Context, sess *state.Session, snac wire.SNAC_0x03_0x0F_BuddyAddTempBuddies) error
	DelTempBuddies(ctx context.Context, sess *state.Session, snac wire.SNAC_0x03_0x10_BuddyDelTempBuddies) error
}

type ChatService interface {
	ChannelMsgToHost(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x0E_0x05_ChatChannelMsgToHost) (*wire.SNACMessage, error)
}

type ChatNavService interface {
	CreateRoom(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate) (wire.SNACMessage, error)
	ExchangeInfo(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0D_0x03_ChatNavRequestExchangeInfo) (wire.SNACMessage, error)
	RequestChatRights(ctx context.Context, inFrame wire.SNACFrame) wire.SNACMessage
	RequestRoomInfo(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo) (wire.SNACMessage, error)
}

type FeedbagService interface {
	DeleteItem(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x0A_FeedbagDeleteItem) (wire.SNACMessage, error)
	Query(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame) (wire.SNACMessage, error)
	QueryIfModified(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x05_FeedbagQueryIfModified) (wire.SNACMessage, error)
	RespondAuthorizeToHost(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost) error
	RightsQuery(ctx context.Context, inFrame wire.SNACFrame) wire.SNACMessage
	StartCluster(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x13_0x11_FeedbagStartCluster)
	UpsertItem(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, items []wire.FeedbagItem) (wire.SNACMessage, error)
	Use(ctx context.Context, sess *state.Session) error
}

type ICBMService interface {
	ChannelMsgToHost(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x06_ICBMChannelMsgToHost) (*wire.SNACMessage, error)
	ClientErr(ctx context.Context, sess *state.Session, frame wire.SNACFrame, body wire.SNAC_0x04_0x0B_ICBMClientErr) error
	ClientEvent(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x14_ICBMClientEvent) error
	EvilRequest(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x04_0x08_ICBMEvilRequest) (wire.SNACMessage, error)
	OfflineRetrieve(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame) (wire.SNACMessage, error)
	ParameterQuery(ctx context.Context, inFrame wire.SNACFrame) wire.SNACMessage
	RestoreWarningLevel(ctx context.Context, sess *state.Session) error
	UpdateWarnLevel(ctx context.Context, sess *state.Session)
}

type ICQService interface {
	DeleteMsgReq(ctx context.Context, sess *state.Session, seq uint16) error
	FindByICQName(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0515_DBQueryMetaReqSearchByDetails, seq uint16) error
	FindByICQEmail(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0529_DBQueryMetaReqSearchByEmail, seq uint16) error
	FindByEmail3(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0573_DBQueryMetaReqSearchByEmail3, seq uint16) error
	FindByICQInterests(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0533_DBQueryMetaReqSearchWhitePages, seq uint16) error
	FindByUIN(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN, seq uint16) error
	FindByUIN2(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2, seq uint16) error
	FindByWhitePages2(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2, seq uint16) error
	FullUserInfo(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN, seq uint16) error
	OfflineMsgReq(ctx context.Context, sess *state.Session, seq uint16) error
	SetAffiliations(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations, seq uint16) error
	SetBasicInfo(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo, seq uint16) error
	SetEmails(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x040B_DBQueryMetaReqSetEmails, seq uint16) error
	SetInterests(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests, seq uint16) error
	SetMoreInfo(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo, seq uint16) error
	SetPermissions(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions, seq uint16) error
	SetUserNotes(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes, seq uint16) error
	SetWorkInfo(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo, seq uint16) error
	ShortUserInfo(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x04BA_DBQueryMetaReqShortInfo, seq uint16) error
	XMLReqData(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0898_DBQueryMetaReqXMLReq, seq uint16) error
}

type LocateService interface {
	DirInfo(ctx context.Context, frame wire.SNACFrame, body wire.SNAC_0x02_0x0B_LocateGetDirInfo) (wire.SNACMessage, error)
	RightsQuery(ctx context.Context, inFrame wire.SNACFrame) wire.SNACMessage
	SetDirInfo(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x09_LocateSetDirInfo) (wire.SNACMessage, error)
	SetInfo(ctx context.Context, sess *state.Session, inBody wire.SNAC_0x02_0x04_LocateSetInfo) error
	SetKeywordInfo(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, body wire.SNAC_0x02_0x0F_LocateSetKeywordInfo) (wire.SNACMessage, error)
	UserInfoQuery(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x05_LocateUserInfoQuery) (wire.SNACMessage, error)
}

type ODirService interface {
	InfoQuery(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0F_0x02_InfoQuery) (wire.SNACMessage, error)
	KeywordListQuery(context.Context, wire.SNACFrame) (wire.SNACMessage, error)
}

type OServiceService interface {
	ClientOnline(ctx context.Context, service uint16, bodyIn wire.SNAC_0x01_0x02_OServiceClientOnline, sess *state.Session) error
	ClientVersions(ctx context.Context, sess *state.Session, frame wire.SNACFrame, bodyIn wire.SNAC_0x01_0x17_OServiceClientVersions) wire.SNACMessage
	HostOnline(service uint16) wire.SNACMessage
	IdleNotification(ctx context.Context, sess *state.Session, bodyIn wire.SNAC_0x01_0x11_OServiceIdleNotification) error
	RateParamsQuery(ctx context.Context, sess *state.Session, frame wire.SNACFrame) wire.SNACMessage
	RateParamsSubAdd(context.Context, *state.Session, wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd)
	ServiceRequest(ctx context.Context, service uint16, sess *state.Session, frame wire.SNACFrame, bodyIn wire.SNAC_0x01_0x04_OServiceServiceRequest, advertisedHost config.Listener) (wire.SNACMessage, error)
	SetPrivacyFlags(ctx context.Context, bodyIn wire.SNAC_0x01_0x14_OServiceSetPrivacyFlags)
	SetUserInfoFields(ctx context.Context, sess *state.Session, frame wire.SNACFrame, bodyIn wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields) (wire.SNACMessage, error)
	UserInfoQuery(ctx context.Context, sess *state.Session, frame wire.SNACFrame) wire.SNACMessage
}

type PermitDenyService interface {
	AddDenyListEntries(ctx context.Context, sess *state.Session, body wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries) error
	AddPermListEntries(ctx context.Context, sess *state.Session, body wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries) error
	DelDenyListEntries(ctx context.Context, sess *state.Session, body wire.SNAC_0x09_0x08_PermitDenyDelDenyListEntries) error
	DelPermListEntries(ctx context.Context, sess *state.Session, body wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries) error
	RightsQuery(_ context.Context, frame wire.SNACFrame) wire.SNACMessage
}

type UserLookupService interface {
	FindByEmail(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0A_0x02_UserLookupFindByEmail) (wire.SNACMessage, error)
}

type StatsService interface {
	ReportEvents(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0B_0x03_StatsReportEvents) wire.SNACMessage
}
