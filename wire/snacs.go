package wire

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

//
// Food Group Codes
//

const (
	BOS         uint16 = 0x0000
	OService    uint16 = 0x0001
	Locate      uint16 = 0x0002
	Buddy       uint16 = 0x0003
	ICBM        uint16 = 0x0004
	Advert      uint16 = 0x0005
	Invite      uint16 = 0x0006
	Admin       uint16 = 0x0007
	Popup       uint16 = 0x0008
	PermitDeny  uint16 = 0x0009
	UserLookup  uint16 = 0x000A
	Stats       uint16 = 0x000B
	Translate   uint16 = 0x000C
	ChatNav     uint16 = 0x000D
	Chat        uint16 = 0x000E
	ODir        uint16 = 0x000F
	BART        uint16 = 0x0010
	Feedbag     uint16 = 0x0013
	ICQ         uint16 = 0x0015
	BUCP        uint16 = 0x0017
	Alert       uint16 = 0x0018
	Plugin      uint16 = 0x0022
	UnnamedFG24 uint16 = 0x0024
	MDir        uint16 = 0x0025
	ARS         uint16 = 0x044A
	Kerberos    uint16 = 0x050C
)

//
// General Error Codes
//

const (
	ErrorCodeInvalidSnac          uint16 = 0x01
	ErrorCodeRateToHost           uint16 = 0x02
	ErrorCodeRateToClient         uint16 = 0x03
	ErrorCodeNotLoggedOn          uint16 = 0x04
	ErrorCodeServiceUnavailable   uint16 = 0x05
	ErrorCodeServiceNotDefined    uint16 = 0x06
	ErrorCodeObsoleteSnac         uint16 = 0x07
	ErrorCodeNotSupportedByHost   uint16 = 0x08
	ErrorCodeNotSupportedByClient uint16 = 0x09
	ErrorCodeRefusedByClient      uint16 = 0x0A
	ErrorCodeReplyTooBig          uint16 = 0x0B
	ErrorCodeResponsesLost        uint16 = 0x0C
	ErrorCodeRequestDenied        uint16 = 0x0D
	ErrorCodeBustedSnacPayload    uint16 = 0x0E
	ErrorCodeInsufficientRights   uint16 = 0x0F
	ErrorCodeInLocalPermitDeny    uint16 = 0x10
	ErrorCodeTooEvilSender        uint16 = 0x11
	ErrorCodeTooEvilReceiver      uint16 = 0x12
	ErrorCodeUserTempUnavail      uint16 = 0x13
	ErrorCodeNoMatch              uint16 = 0x14
	ErrorCodeListOverflow         uint16 = 0x15
	ErrorCodeRequestAmbigous      uint16 = 0x16
	ErrorCodeQueueFull            uint16 = 0x17
	ErrorCodeNotWhileOnAol        uint16 = 0x18
	ErrorCodeQueryFail            uint16 = 0x19
	ErrorCodeTimeout              uint16 = 0x1A
	ErrorCodeErrorText            uint16 = 0x1B
	ErrorCodeGeneralFailure       uint16 = 0x1C
	ErrorCodeProgress             uint16 = 0x1D
	ErrorCodeInFreeArea           uint16 = 0x1E
	ErrorCodeRestrictedByPc       uint16 = 0x1F
	ErrorCodeRemoteRestrictedByPc uint16 = 0x20

	ErrorTLVFailURL        uint16 = 0x0004 // URL with more detail
	ErrorTLVErrorSubcode   uint16 = 0x0008 // Foodgroup-specific error code
	ErrorTLVErrorText      uint16 = 0x001B // String error message text
	ErrorTLVErrorInfoCLSID uint16 = 0x0029 // UUID specifying format of ERROR_INFO_DATA data
	ErrorTLVErrorInfoData  uint16 = 0x002A // Extra information describing error
)

//
// Authentication
//

const (
	LoginTLVTagsScreenName              uint16 = 0x01
	LoginTLVTagsRoastedPassword         uint16 = 0x02
	LoginTLVTagsClientIdentity          uint16 = 0x03
	LoginTLVTagsReconnectHere           uint16 = 0x05
	LoginTLVTagsAuthorizationCookie     uint16 = 0x06
	LoginTLVTagsErrorSubcode            uint16 = 0x08
	LoginTLVTagsPasswordHash            uint16 = 0x25
	LoginTLVTagsMultiConnFlags          uint16 = 0x4A
	LoginTLVTagsRoastedKerberosPassword uint16 = 0x1335
	LoginTLVTagsRoastedTOCPassword      uint16 = 0x1337
	LoginTLVTagsPlaintextPassword       uint16 = 0x1338
)

const (
	LoginErrInvalidUsernameOrPassword uint16 = 0x0001
	LoginErrInvalidPassword           uint16 = 0x0005 // invalid password
	LoginErrInvalidAccount            uint16 = 0x0007
	LoginErrDeletedAccount            uint16 = 0x0008
	LoginErrExpiredAccount            uint16 = 0x0009
	LoginErrSuspendedAccount          uint16 = 0x0011 // suspended account
	LoginErrTooHeavilyWarned          uint16 = 0x0019
	LoginErrRateLimitExceeded         uint16 = 0x001D
	LoginErrInvalidSecureID           uint16 = 0x0020
	LoginErrSuspendedAccountAge       uint16 = 0x0022 // suspended due to age (age < 13 years)

	LoginErrICQUserErr uint16 = 0x0008 // ICQ user doesn't exist

)

type MultiConnFlag uint8

const (
	MultiConnFlagsOldClient    MultiConnFlag = 0x0 // client doesn't support multi-conn
	MultiConnFlagsRecentClient MultiConnFlag = 0x1 // client supports multi-conn
	MultiConnFlagsSingleClient MultiConnFlag = 0x3 // client supports multi-conn but only wants 1 concurrent session
)

//
// Capability IDs
//

var (
	// CapChat is the UUID that represents an OSCAR client's ability to chat
	CapChat = uuid.MustParse("748F2420-6287-11D1-8222-444553540000")
	// CapFileTransfer is the UUID that represents an OSCAR client's ability to send files
	CapFileTransfer = uuid.MustParse("09461343-4C7F-11D1-8222-444553540000")
)

//
// 0x01: OService
//

const (
	OServiceErr               uint16 = 0x0001
	OServiceClientOnline      uint16 = 0x0002
	OServiceHostOnline        uint16 = 0x0003
	OServiceServiceRequest    uint16 = 0x0004
	OServiceServiceResponse   uint16 = 0x0005
	OServiceRateParamsQuery   uint16 = 0x0006
	OServiceRateParamsReply   uint16 = 0x0007
	OServiceRateParamsSubAdd  uint16 = 0x0008
	OServiceRateDelParamSub   uint16 = 0x0009
	OServiceRateParamChange   uint16 = 0x000A
	OServicePauseReq          uint16 = 0x000B
	OServicePauseAck          uint16 = 0x000C
	OServiceResume            uint16 = 0x000D
	OServiceUserInfoQuery     uint16 = 0x000E
	OServiceUserInfoUpdate    uint16 = 0x000F
	OServiceEvilNotification  uint16 = 0x0010
	OServiceIdleNotification  uint16 = 0x0011
	OServiceMigrateGroups     uint16 = 0x0012
	OServiceMotd              uint16 = 0x0013
	OServiceSetPrivacyFlags   uint16 = 0x0014
	OServiceWellKnownUrls     uint16 = 0x0015
	OServiceNoop              uint16 = 0x0016
	OServiceClientVersions    uint16 = 0x0017
	OServiceHostVersions      uint16 = 0x0018
	OServiceMaxConfigQuery    uint16 = 0x0019
	OServiceMaxConfigReply    uint16 = 0x001A
	OServiceStoreConfig       uint16 = 0x001B
	OServiceConfigQuery       uint16 = 0x001C
	OServiceConfigReply       uint16 = 0x001D
	OServiceSetUserInfoFields uint16 = 0x001E
	OServiceProbeReq          uint16 = 0x001F
	OServiceProbeAck          uint16 = 0x0020
	OServiceBartReply         uint16 = 0x0021
	OServiceBartQuery2        uint16 = 0x0022
	OServiceBartReply2        uint16 = 0x0023

	OServiceUserInfoUserFlags       uint16 = 0x01
	OServiceUserInfoSignonTOD       uint16 = 0x03
	OServiceUserInfoIdleTime        uint16 = 0x04
	OServiceUserInfoMemberSince     uint16 = 0x05
	OServiceUserInfoStatus          uint16 = 0x06
	OServiceUserInfoICQDC           uint16 = 0x0C
	OServiceUserInfoOscarCaps       uint16 = 0x0D
	OServiceUserInfoOnlineTime      uint16 = 0x0F
	OServiceUserInfoBARTInfo        uint16 = 0x1D
	OServiceUserInfoMySubscriptions uint16 = 0x1E
	OServiceUserInfoUserFlags2      uint16 = 0x1F
	OServiceUserInfoMyInstanceNum   uint16 = 0x14
	OServiceUserInfoSigTime         uint16 = 0x26
	OServiceUserInfoPrimaryInstance uint16 = 0x28

	OServiceUserStatusAvailable         uint32 = 0x00000000 // user is available
	OServiceUserStatusAway              uint32 = 0x00000001 // user is away
	OServiceUserStatusDND               uint32 = 0x00000002 // don't disturb user
	OServiceUserStatusOut               uint32 = 0x00000004 // user is not available
	OServiceUserStatusBusy              uint32 = 0x00000010 // user is busy
	OServiceUserStatusChat              uint32 = 0x00000020 // user is available to chat
	OServiceUserStatusInvisible         uint32 = 0x00000100 // user is invisible
	OServiceUserStatusWebAware          uint32 = 0x00010000
	OServiceUserStatusHideIP            uint32 = 0x00020000
	OServiceUserStatusBirthday          uint32 = 0x00080000 // user is having a birthday :DDD
	OServiceUserStatusICQHomePage       uint32 = 0x00200000
	OServiceUserStatusDirectRequireAuth uint32 = 0x10000000

	OServiceUserFlagUnconfirmed    uint16 = 0x0001 // Unconfirmed account
	OServiceUserFlagAdministrator  uint16 = 0x0002 // Server Administrator
	OServiceUserFlagAOL            uint16 = 0x0004 // AOL (staff?) account
	OServiceUserFlagOSCARPay       uint16 = 0x0008 // Commercial account
	OServiceUserFlagOSCARFree      uint16 = 0x0010 // AIM (not AOL) account
	OServiceUserFlagUnavailable    uint16 = 0x0020 // user is away
	OServiceUserFlagICQ            uint16 = 0x0040 // ICQ user (OServiceUserFlagOSCARFree should also be set)
	OServiceUserFlagWireless       uint16 = 0x0080 // On mobile device
	OServiceUserFlagInternal       uint16 = 0x0100 // Internal account
	OServiceUserFlagFish           uint16 = 0x0200 // IM forwarding enabled
	OServiceUserFlagBot            uint16 = 0x0400 // Bot account
	OServiceUserFlagBeast          uint16 = 0x0800 // Unknown
	OServiceUserFlagOneWayWireless uint16 = 0x1000 // On one way mobile device
	OServiceUserFlagOfficial       uint16 = 0x2000 // Unknown

	OServiceUserFlag2BuddyMatchDirect   uint32 = 0x00010000 // Unknown
	OServiceUserFlag2BuddyMatchIndirect uint32 = 0x00020000 // Unknown
	OServiceUserFlag2NoKnockKnock       uint32 = 0x00040000 // Sender is safe
	OServiceUserFlag2ForwardMobile      uint32 = 0x00080000 // Forward to mobile if no acive session

	OServicePrivacyFlagIdle   uint32 = 0x00000001
	OServicePrivacyFlagMember uint32 = 0x00000002

	OServiceTLVTagsReconnectHere uint16 = 0x05
	OServiceTLVTagsLoginCookie   uint16 = 0x06
	OServiceTLVTagsGroupID       uint16 = 0x0D
	OServiceTLVTagsSSLCertName   uint16 = 0x8D
	OServiceTLVTagsSSLState      uint16 = 0x8E
	OserviceTLVTagsSSLUseSSL     uint16 = 0x8C

	OServiceDiscErrNewLogin   uint8 = 0x01
	OServiceDiscErrAccDeleted uint8 = 0x02

	OServiceServiceResponseSSLStateNotUsed uint8 = 0x00 // SSL is not supported or not requested for this connection
	OServiceServiceResponseSSLStateUse     uint8 = 0x01 // SSL is being used
	OServiceServiceResponseSSLStateResume  uint8 = 0x02 // SSL is being used and SSL resume is supported if desired

)

type SNAC_0x01_0x02_OServiceClientOnline struct {
	GroupVersions []struct {
		FoodGroup   uint16
		Version     uint16
		ToolID      uint16
		ToolVersion uint16
	}
}

type SNAC_0x01_0x03_OServiceHostOnline struct {
	FoodGroups []uint16
}

type SNAC_0x01_0x04_OServiceServiceRequest struct {
	FoodGroup uint16
	TLVRestBlock
}

type SNAC_0x01_0x04_TLVRoomInfo struct {
	Exchange       uint16
	Cookie         string `oscar:"len_prefix=uint8"`
	InstanceNumber uint16
}

type SNAC_0x01_0x05_OServiceServiceResponse struct {
	TLVRestBlock
}

type RateParamsSNAC struct {
	ID              uint16
	WindowSize      uint32
	ClearLevel      uint32
	AlertLevel      uint32
	LimitLevel      uint32
	DisconnectLevel uint32
	CurrentLevel    uint32
	MaxLevel        uint32
	V2Params        *struct {
		LastTime      uint32
		DroppingSNACs uint8
	} `oscar:"optional"`
}

//	SNAC_0x01_0x07_OServiceRateParamsReply contains rate limits for rate classes and groups.
//
// Rate Classes:
//   - ID: Unique identifier for the rate class.
//   - WindowSize: The number of previously sent commands included in calculating
//     the current "rate average."
//   - ClearLevel: The threshold the average must reach to clear a rate limit.
//   - AlertLevel: The threshold for triggering an alert that tells the client
//     that it's getting close to the limit.
//   - LimitLevel: SNACs will be dropped if the rate falls below this value.
//   - DisconnectLevel: Server will disconnect if the rate falls below this value.
//   - CurrentLevel: The current value for the class; higher values are preferable.
//     Represents the current "rate average," resembling a moving average of the
//     times between each of the last WindowSize commands.
//   - MaxLevel: The maximum rate value; if the current value surpasses this,
//     it should be reset. The upper limit for a rate average.
//   - LastTime: Time elapsed since the last message was received by the server.
//   - CurrentStatus: Indicates whether the server is dropping SNACs for this rate class.
//
// Rate Groups:
//   - ID: Unique identifier for the rate group.
//   - Pairs: List of SNAC types associated with the rate group, including FoodGroup
//     (e.g., wire.ICBM) and SubGroup (e.g., wire.ICBMChannelMsgToHost).
type SNAC_0x01_0x07_OServiceRateParamsReply struct {
	RateClasses []RateParamsSNAC `oscar:"count_prefix=uint16"`
	RateGroups  []struct {
		ID    uint16
		Pairs []struct {
			FoodGroup uint16
			SubGroup  uint16
		} `oscar:"count_prefix=uint16"`
	}
}

type SNAC_0x01_0x0A_OServiceRateParamsChange struct {
	Code uint16
	Rate RateParamsSNAC
}

type SNAC_0x01_0x08_OServiceRateParamsSubAdd struct {
	ClassIDs []uint16
}

type SNAC_0x01_0x0F_OServiceUserInfoUpdate struct {
	UserInfo []TLVUserInfo
}

type SNAC_0x01_0x10_OServiceEvilNotification struct {
	NewEvil uint16
	// Snitcher specifies the user who sent the warning. Nil pointer indicates
	// an anonymous warning.
	Snitcher *struct {
		TLVUserInfo
	} `oscar:"optional"`
}

type SNAC_0x01_0x11_OServiceIdleNotification struct {
	IdleTime uint32
}

type SNAC_0x01_0x14_OServiceSetPrivacyFlags struct {
	PrivacyFlags uint32
}

// IdleFlag returns whether other AIM users can see how long the user has been
// idle.
func (s SNAC_0x01_0x14_OServiceSetPrivacyFlags) IdleFlag() bool {
	return s.PrivacyFlags&OServicePrivacyFlagIdle == OServicePrivacyFlagIdle
}

// MemberFlag returns whether other AIM users can see how long the user has been
// a member.
func (s SNAC_0x01_0x14_OServiceSetPrivacyFlags) MemberFlag() bool {
	return s.PrivacyFlags&OServicePrivacyFlagMember == OServicePrivacyFlagMember
}

type SNAC_0x01_0x17_OServiceClientVersions struct {
	Versions []uint16
}

type SNAC_0x01_0x18_OServiceHostVersions struct {
	Versions []uint16
}

type SNAC_0x01_0x1E_OServiceSetUserInfoFields struct {
	TLVRestBlock
}

type SNAC_0x01_0x21_OServiceBARTReply struct {
	BARTID
}

type SNAC_0x01_0x23_OServiceBART2Reply struct {
	ReplyID []BartQueryReplyID
}

//
// 0x02: Locate
//

const (
	LocateErr                  uint16 = 0x0001
	LocateRightsQuery          uint16 = 0x0002
	LocateRightsReply          uint16 = 0x0003
	LocateSetInfo              uint16 = 0x0004
	LocateUserInfoQuery        uint16 = 0x0005
	LocateUserInfoReply        uint16 = 0x0006
	LocateWatcherSubRequest    uint16 = 0x0007
	LocateWatcherNotification  uint16 = 0x0008
	LocateSetDirInfo           uint16 = 0x0009
	LocateSetDirReply          uint16 = 0x000A
	LocateGetDirInfo           uint16 = 0x000B
	LocateGetDirReply          uint16 = 0x000C
	LocateGroupCapabilityQuery uint16 = 0x000D
	LocateGroupCapabilityReply uint16 = 0x000E
	LocateSetKeywordInfo       uint16 = 0x000F
	LocateSetKeywordReply      uint16 = 0x0010
	LocateGetKeywordInfo       uint16 = 0x0011
	LocateGetKeywordReply      uint16 = 0x0012
	LocateFindListByEmail      uint16 = 0x0013
	LocateFindListReply        uint16 = 0x0014
	LocateUserInfoQuery2       uint16 = 0x0015

	LocateTypeSig          uint32 = 0x00000001
	LocateTypeUnavailable  uint32 = 0x00000002
	LocateTypeCapabilities uint32 = 0x00000004
	LocateTypeCerts        uint32 = 0x00000008
	LocateTypeHtmlInfo     uint32 = 0x00000400

	LocateTLVTagsInfoSigMime         uint16 = 0x01
	LocateTLVTagsInfoSigData         uint16 = 0x02
	LocateTLVTagsInfoUnavailableMime uint16 = 0x03
	LocateTLVTagsInfoUnavailableData uint16 = 0x04
	LocateTLVTagsInfoCapabilities    uint16 = 0x05
	LocateTLVTagsInfoCerts           uint16 = 0x06
	LocateTLVTagsInfoSigTime         uint16 = 0x0A
	LocateTLVTagsInfoUnavailableTime uint16 = 0x0B
	LocateTLVTagsInfoSupportHostSig  uint16 = 0x0C
	LocateTLVTagsInfoHtmlInfoData    uint16 = 0x0E
	LocateTLVTagsInfoHtmlInfoType    uint16 = 0x0D

	// LocateTLVTagsRightsMaxSigLen is the max signature length
	LocateTLVTagsRightsMaxSigLen uint16 = 0x01
	// LocateTLVTagsRightsMaxCapabilitiesLen is the max allowed # of full UUID capabilities
	LocateTLVTagsRightsMaxCapabilitiesLen uint16 = 0x02
	// LocateTLVTagsRightsMaxFindByEmailList is the maximum # of email addresses to look up at once
	LocateTLVTagsRightsMaxFindByEmailList uint16 = 0x03
	// LocateTLVTagsRightsMaxCertsLen is the largest CERT length for e2e crypto
	LocateTLVTagsRightsMaxCertsLen uint16 = 0x04
	// LocateTLVTagsRightsMaxMaxShortCapabilities is the max allowed # of short UUID capabilities allowed
	LocateTLVTagsRightsMaxMaxShortCapabilities uint16 = 0x05

	LocateGetDirReplyOK          uint16 = 0x01 // Directory info lookup succeeded
	LocateGetDirReplyUnavailable uint16 = 0x02 // Directory info lookup unavailable
)

type SNAC_0x02_0x03_LocateRightsReply struct {
	TLVRestBlock
}

type SNAC_0x02_0x04_LocateSetInfo struct {
	TLVRestBlock
}

type SNAC_0x02_0x06_LocateUserInfoReply struct {
	TLVUserInfo
	LocateInfo TLVRestBlock
}

type SNAC_0x02_0x09_LocateSetDirInfo struct {
	TLVRestBlock
}

type SNAC_0x02_0x0A_LocateSetDirReply struct {
	Result uint16
}

type SNAC_0x02_0x0B_LocateGetDirInfo struct {
	ScreenName string `oscar:"len_prefix=uint8"`
}

type SNAC_0x02_0x0C_LocateGetDirReply struct {
	Status uint16
	TLVBlock
}

type SNAC_0x02_0x0F_LocateSetKeywordInfo struct {
	TLVRestBlock
}

type SNAC_0x02_0x10_LocateSetKeywordReply struct {
	// Unknown is a field whose purpose is not known
	Unknown uint16
}

type SNAC_0x02_0x05_LocateUserInfoQuery struct {
	Type       uint16
	ScreenName string `oscar:"len_prefix=uint8"`
}

func (s SNAC_0x02_0x05_LocateUserInfoQuery) RequestProfile() bool {
	return s.Type&uint16(LocateTypeSig) == uint16(LocateTypeSig)
}

func (s SNAC_0x02_0x05_LocateUserInfoQuery) RequestAwayMessage() bool {
	return s.Type&uint16(LocateTypeUnavailable) == uint16(LocateTypeUnavailable)
}

type SNAC_0x02_0x15_LocateUserInfoQuery2 struct {
	Type2      uint32
	ScreenName string `oscar:"len_prefix=uint8"`
}

//
// 0x03: Buddy
//

const (
	BuddyErr                 uint16 = 0x0001
	BuddyRightsQuery         uint16 = 0x0002
	BuddyRightsReply         uint16 = 0x0003
	BuddyAddBuddies          uint16 = 0x0004
	BuddyDelBuddies          uint16 = 0x0005
	BuddyWatcherListQuery    uint16 = 0x0006
	BuddyWatcherListResponse uint16 = 0x0007
	BuddyWatcherSubRequest   uint16 = 0x0008
	BuddyWatcherNotification uint16 = 0x0009
	BuddyRejectNotification  uint16 = 0x000A
	BuddyArrived             uint16 = 0x000B
	BuddyDeparted            uint16 = 0x000C
	BuddyAddTempBuddies      uint16 = 0x000F
	BuddyDelTempBuddies      uint16 = 0x0010

	BuddyTLVTagsParmMaxBuddies     uint16 = 0x01
	BuddyTLVTagsParmMaxWatchers    uint16 = 0x02
	BuddyTLVTagsParmMaxIcqBroad    uint16 = 0x03
	BuddyTLVTagsParmMaxTempBuddies uint16 = 0x04
)

type SNAC_0x03_0x02_BuddyRightsQuery struct {
	TLVRestBlock
}

type SNAC_0x03_0x03_BuddyRightsReply struct {
	TLVRestBlock
}

type SNAC_0x03_0x04_BuddyAddBuddies struct {
	Buddies []struct {
		ScreenName string `oscar:"len_prefix=uint8"`
	}
}

type SNAC_0x03_0x05_BuddyDelBuddies struct {
	Buddies []struct {
		ScreenName string `oscar:"len_prefix=uint8"`
	}
}

type SNAC_0x03_0x0B_BuddyArrived struct {
	TLVUserInfo
}

type SNAC_0x03_0x0C_BuddyDeparted struct {
	TLVUserInfo
}

type SNAC_0x03_0x0F_BuddyAddTempBuddies struct {
	Buddies []struct {
		ScreenName string `oscar:"len_prefix=uint8"`
	}
}

type SNAC_0x03_0x10_BuddyDelTempBuddies struct {
	Buddies []struct {
		ScreenName string `oscar:"len_prefix=uint8"`
	}
}

//
// 0x04: ICBM
//

const (
	ICBMErr                  uint16 = 0x0001
	ICBMAddParameters        uint16 = 0x0002
	ICBMDelParameters        uint16 = 0x0003
	ICBMParameterQuery       uint16 = 0x0004
	ICBMParameterReply       uint16 = 0x0005
	ICBMChannelMsgToHost     uint16 = 0x0006
	ICBMChannelMsgToClient   uint16 = 0x0007
	ICBMEvilRequest          uint16 = 0x0008
	ICBMEvilReply            uint16 = 0x0009
	ICBMMissedCalls          uint16 = 0x000A
	ICBMClientErr            uint16 = 0x000B
	ICBMHostAck              uint16 = 0x000C
	ICBMSinStored            uint16 = 0x000D
	ICBMSinListQuery         uint16 = 0x000E
	ICBMSinListReply         uint16 = 0x000F
	ICBMOfflineRetrieve      uint16 = 0x0010
	ICBMSinDelete            uint16 = 0x0011
	ICBMNotifyRequest        uint16 = 0x0012
	ICBMNotifyReply          uint16 = 0x0013
	ICBMClientEvent          uint16 = 0x0014
	ICBMOfflineRetrieveReply uint16 = 0x0017

	ICBMTLVAOLIMData      uint16 = 0x02
	ICBMTLVRequestHostAck uint16 = 0x03
	ICBMTLVAutoResponse   uint16 = 0x04
	ICBMTLVData           uint16 = 0x05
	ICBMTLVStore          uint16 = 0x06
	ICBMTLVICQBlob        uint16 = 0x07
	ICBMTLVAvatarInfo     uint16 = 0x08
	ICBMTLVWantAvatar     uint16 = 0x09
	ICBMTLVMultiUser      uint16 = 0x0A
	ICBMTLVWantEvents     uint16 = 0x0B
	ICBMTLVSubscriptions  uint16 = 0x0C
	ICBMTLVBART           uint16 = 0x0D
	ICBMTLVHostImID       uint16 = 0x10
	ICBMTLVHostImArgs     uint16 = 0x11
	ICBMTLVSendTime       uint16 = 0x16
	ICBMTLVFriendlyName   uint16 = 0x17
	ICBMTLVAnonymous      uint16 = 0x18
	ICBMTLVWidgetName     uint16 = 0x19

	ICBMMessageEncodingASCII   uint16 = 0x00 // ANSI ASCII -- ISO 646
	ICBMMessageEncodingUnicode uint16 = 0x02 // ISO 10646.USC-2 Unicode
	ICBMMessageEncodingLatin1  uint16 = 0x03 // ISO 8859-1

	ICBMExtendedMsgTypePlain    uint8 = 0x01 // Plain text (simple) message
	ICBMExtendedMsgTypeChat     uint8 = 0x02 // Chat request message
	ICBMExtendedMsgTypeFileReq  uint8 = 0x03 // File request / file ok message
	ICBMExtendedMsgTypeURL      uint8 = 0x04 // URL message (0xFE formatted)
	ICBMExtendedMsgTypeAuthReq  uint8 = 0x06 // Authorization request message (0xFE formatted)
	ICBMExtendedMsgTypeAuthDeny uint8 = 0x07 // Authorization denied message (0xFE formatted)
	ICBMExtendedMsgTypeAuthOK   uint8 = 0x08 // Authorization given message (empty)
	ICBMExtendedMsgTypeServer   uint8 = 0x09 // Message from OSCAR server (0xFE formatted)
	ICBMExtendedMsgTypeAdded    uint8 = 0x0C // "You-were-added" message (0xFE formatted)
	ICBMExtendedMsgTypeWWP      uint8 = 0x0D // Web pager message (0xFE formatted)
	ICBMExtendedMsgTypeExpress  uint8 = 0x0E // Email express message (0xFE formatted)
	ICBMExtendedMsgTypeContacts uint8 = 0x13 // Contact list message
	ICBMExtendedMsgTypePlugin   uint8 = 0x1A // Plugin message described by text string
	ICBMExtendedMsgTypeAutoAway uint8 = 0xE8 // Auto away message
	ICBMExtendedMsgTypeAutoBusy uint8 = 0xE9 // Auto occupied message
	ICBMExtendedMsgTypeAutoNA   uint8 = 0xEA // Auto not available message
	ICBMExtendedMsgTypeAutoDND  uint8 = 0xEB // Auto do not disturb message
	ICBMExtendedMsgTypeAutoFFC  uint8 = 0xEC // Auto free for chat message

	ICBMChannelIM         uint16 = 0x01
	ICBMChannelRendezvous uint16 = 0x02
	ICBMChannelMIME       uint16 = 0x03
	ICBMChannelICQ        uint16 = 0x04
	ICBMChannelCoBrowser  uint16 = 0x05

	ICBMMsgTypePlain    uint8 = 0x01 // Plain text (simple) message
	ICBMMsgTypeChat     uint8 = 0x02 // Chat request message
	ICBMMsgTypeFileReq  uint8 = 0x03 // File request / file ok message
	ICBMMsgTypeUrl      uint8 = 0x04 // URL message (0xFE formatted)
	ICBMMsgTypeAuthReq  uint8 = 0x06 // Authorization request message (0xFE formatted)
	ICBMMsgTypeAuthDeny uint8 = 0x07 // Authorization denied message (0xFE formatted)
	ICBMMsgTypeAuthOK   uint8 = 0x08 // Authorization given message (empty)
	ICBMMsgTypeServer   uint8 = 0x09 // Message from OSCAR server (0xFE formatted)
	ICBMMsgTypeAdded    uint8 = 0x0C // "You-were-added" message (0xFE formatted)
	ICBMMsgTypeWWP      uint8 = 0x0D // Web pager message (0xFE formatted)
	ICBMMsgTypeEExpress uint8 = 0x0E // Email express message (0xFE formatted)
	ICBMMsgTypeContacts uint8 = 0x13 // Contact list message
	ICBMMsgTypePlugin   uint8 = 0x1A // Plugin message described by text string
	ICBMMsgTypeAutoAway uint8 = 0xE8 // Auto away message
	ICBMMsgTypeAutoBusy uint8 = 0xE9 // Auto occupied message
	ICBMMsgTypeAutoNA   uint8 = 0xEA // Auto not available message
	ICBMMsgTypeAutoDND  uint8 = 0xEB // Auto do not disturb message
	ICBMMsgTypeAutoFFC  uint8 = 0xEC // Auto free for chat message

	ICBMRdvMessagePropose uint16 = 0x00 //	Propose a rendezvous
	ICBMRdvMessageCancel  uint16 = 0x01 //	Cancel a proposal you generated
	ICBMRdvMessageAccept  uint16 = 0x02 //	Accept a proposal someone else generated
	ICBMRdvMessageNak     uint16 = 0x03 //	NOT CURRENTLY DOCUMENTED

	ICBMRdvCancelReasonsUnknown           uint16 = 0x00 // Reason not specified
	ICBMRdvCancelReasonsUserCancel        uint16 = 0x01 // Recipient user declined
	ICBMRdvCancelReasonsTimeout           uint16 = 0x02 // Timeout
	ICBMRdvCancelReasonsAcceptedElsewhere uint16 = 0x03 // Proposal was accepted by a different instance of the user

	ICBMRdvTLVTagsRdvChan             uint16 = 0x0001 //	uint16 (word)	ICBM channel on which the rendezvous is to occur
	ICBMRdvTLVTagsRdvIP               uint16 = 0x0002 //	uint32 (dword)	IP address proposed for the rendezvous
	ICBMRdvTLVTagsRequesterIP         uint16 = 0x0003 //	uint32 (dword)	IP address of the proposing client
	ICBMRdvTLVTagsVerifiedIP          uint16 = 0x0004 //	uint32 (dword)	IP address of the proposing client as seen by server; NOTE - this TLV may only be added by the server
	ICBMRdvTLVTagsPort                uint16 = 0x0005 //	uint16 (word)	Port value of the client for rendezvous
	ICBMRdvTLVTagsDownloadURL         uint16 = 0x0006 //	string	URL for downloading software to support the service
	ICBMRdvTLVTagsDownloadURL2        uint16 = 0x0007 //	string	NOT CURRENTLY DOCUMENTED
	ICBMRdvTLVTagsVerifiedDownloadURL uint16 = 0x0008 //	string	Same as DOWNLOAD_URL, but added by server if the service is well known; Note - this TLV may only be added by the server
	ICBMRdvTLVTagsSeqNum              uint16 = 0x000A // uint16 (word)	Identifies which proposal this is in the rendezvous conversation; the initial proposal has sequence_num 1; NOTE - this tag is required in *all* rendezvous *proposal* payloads and may only occur in proposal payloads; each proposal applying to a given rendezvous cookie increments the sequence_num by one
	ICBMRdvTLVTagsCancelReason        uint16 = 0x000B // uint16 (word)	[Class: ICBM__RENDEZVOUS_CANCEL_REASONS] Reason for cancelling a rendezvous; this tag must be present in all RENDEZVOUS_CANCEL payloads.
	ICBMRdvTLVTagsInvitation          uint16 = 0x000C // string	Text inviting the other player to join
	ICBMRdvTLVTagsInviteMIMECharset   uint16 = 0x000D // string	Charset used by the data
	ICBMRdvTLVTagsInviteMIMELang      uint16 = 0x000E // string	Language used by the data
	ICBMRdvTLVTagsRequestHostChk      uint16 = 0x000F // empty	Requests that the server check caps for recipient
	ICBMRdvTLVTagsUseARS              uint16 = 0x0010 // empty	Requests that the Rendezvous Server be used as a transport for the data
	ICBMRdvTLVTagsRequestSecure       uint16 = 0x0011 // empty	Requests that SSL be used for the connection
	ICBMRdvTLVTagsMaxProtoVersion     uint16 = 0x0012 // uint16 (word)	Maximum application protocol version supported
	ICBMRdvTLVTagsMinProtoVersion     uint16 = 0x0013 // uint16 (word)	Minimum application protocol version supported
	ICBMRdvTLVTagsCounterReason       uint16 = 0x0014 // uint16 (word)	Reason for a counter proposal
	ICBMRdvTLVTagsInviteMIMEType      uint16 = 0x0015 // string	Content-type used by the data
	ICBMRdvTLVTagsIPXOR               uint16 = 0x0016 // uint32 (dword)	Contains IP_ADDR ^ 0xFFFFFFFF - Used with recent clients to ensure that the IP_ADDR tlv is not tampered with or modified by a NAT since some NATs will change the IP_ADDR tlv when the proposal is sent
	ICBMRdvTLVTagsPortXOR             uint16 = 0x0017 // uint16 (word)	PORT ^ 0xFFFF - Used with recent clients to ensure that the PORT tlv is not tampered with or modified by a NAT since some NATs will change the PORT tlv when the proposal is sent
	ICBMRdvTLVTagsAddrList            uint16 = 0x0018 // Array of string08	List of "IP port" pairs to try
	ICBMRdvTLVTagsSessID              uint16 = 0x0019 // string	Identifier for session
	ICBMRdvTLVTagsRolloverID          uint16 = 0x001A // string	Identifier of session to rollover
	ICBMRdvTLVTagsSvcData             uint16 = 0x2711 //	blob	Service specific data

	ICBMSubErrRemoteIMOff            uint16 = 0x0001 // Used with NOT_LOGGED_ON
	ICBMSubErrRemoteRestrictedByPC   uint16 = 0x0002 // Used with NOT_LOGGED_ON; the remote side denied because of parental controls
	ICBMSubErrNeedSMSLegalToSend     uint16 = 0x0003 // User tried to send a message to an SMS user and is required to accept the legal text first
	ICBMSubErrSMSWithoutDisclaimer   uint16 = 0x0004 // Client tried to send a message to an SMS user without the character counter being displayed
	ICBMSubErrSMSCountryNotAllowed   uint16 = 0x0005 // Client tried to send a message to an SMS user but the SMS matrix said the country code combination not permitted
	ICBMSubErrSMSUnknownCountry      uint16 = 0x0008 // Client tried to send to an SMS user but the server could not determine the country
	ICBMSubErrCannotInitiateIM       uint16 = 0x0009 // An IM cannot be initiated by a BOT
	ICBMSubErrIMNotAllowed           uint16 = 0x000A // An IM is not allowed by a consumer BOT to a user
	ICBMSubErrCannotIMUsageLimited   uint16 = 0x000B // An IM is not allowed by a consumer BOT due to reaching a generic usage limit
	ICBMSubErrCannotIMDailyLimited   uint16 = 0x000C // An IM is not allowed by a consumer BOT due to reaching the daily usage limit
	ICBMSubErrCannotIMMonthlyLimited uint16 = 0x000D // An IM is not allowed by a consumer BOT due to reaching the monthly usage limit
	ICBMSubErrOfflineIMNotAccepted   uint16 = 0x000E // User does not accept offline IMs
	ICBMSubErrOfflineIMExceedMax     uint16 = 0x000F // Exceeded max storage limit
)

// ICBMCh1Fragment represents an ICBM channel 1 (instant message) message
// component.
type ICBMCh1Fragment struct {
	ID      uint8
	Version uint8
	Payload []byte `oscar:"len_prefix=uint16"`
}

type ICBMCh2Fragment struct {
	Type       uint16
	Cookie     [8]byte
	Capability [16]byte
	TLVRestBlock
}

type ICBMRoomInfo struct {
	Exchange uint16
	Cookie   string `oscar:"len_prefix=uint8"`
	Instance uint16
}

// ICBMCh1Message represents the text component of an ICBM channel 1 (instant
// message) message.
type ICBMCh1Message struct {
	Charset  uint16
	Language uint16
	Text     []byte
}

// ICBMCh4Message represents an ICBM channel 4 (ICQ) message component.
type ICBMCh4Message struct {
	UIN         uint32
	MessageType uint8
	Flags       uint8
	Message     string `oscar:"len_prefix=uint16,nullterm"`
}

type SNAC_0x04_0x02_ICBMAddParameters struct {
	Channel              uint16
	ICBMFlags            uint32
	MaxIncomingICBMLen   uint16
	MaxSourceEvil        uint16
	MaxDestinationEvil   uint16
	MinInterICBMInterval uint32
}

type SNAC_0x04_0x05_ICBMParameterReply struct {
	MaxSlots             uint16
	ICBMFlags            uint32
	MaxIncomingICBMLen   uint16
	MaxSourceEvil        uint16
	MaxDestinationEvil   uint16
	MinInterICBMInterval uint32
}

type SNAC_0x04_0x06_ICBMChannelMsgToHost struct {
	Cookie     uint64
	ChannelID  uint16
	ScreenName string `oscar:"len_prefix=uint8"`
	TLVRestBlock
}

type SNAC_0x04_0x07_ICBMChannelMsgToClient struct {
	Cookie    uint64
	ChannelID uint16
	TLVUserInfo
	TLVRestBlock
}

// ICBMFragmentList creates an ICBM fragment list for an instant message
// payload.
func ICBMFragmentList(text string) ([]ICBMCh1Fragment, error) {
	msg := ICBMCh1Message{
		Charset:  ICBMMessageEncodingASCII,
		Language: 0, // not clear what this means, but it works
		Text:     []byte(text),
	}
	msgBuf := bytes.Buffer{}
	if err := MarshalBE(msg, &msgBuf); err != nil {
		return nil, fmt.Errorf("unable to marshal ICBM message: %w", err)
	}

	return []ICBMCh1Fragment{
		{
			ID:      5, // 5 = capabilities
			Version: 1,
			Payload: []byte{1, 1, 2}, // 1 = text
		},
		{
			ID:      1, // 1 = message text
			Version: 1,
			Payload: msgBuf.Bytes(),
		},
	}, nil
}

// UnmarshalICBMMessageText extracts message text from an ICBM fragment list.
// Param b is a slice from TLV wire.ICBMTLVAOLIMData.
func UnmarshalICBMMessageText(b []byte) (string, error) {
	var frags []ICBMCh1Fragment
	if err := UnmarshalBE(&frags, bytes.NewBuffer(b)); err != nil {
		return "", fmt.Errorf("unable to unmarshal ICBM fragment: %w", err)
	}

	for _, frag := range frags {
		if frag.ID == 1 { // 1 = message text
			msg := ICBMCh1Message{}
			err := UnmarshalBE(&msg, bytes.NewBuffer(frag.Payload))
			if err != nil {
				err = fmt.Errorf("unable to unmarshal ICBM message: %w", err)
			}
			return string(msg.Text), err
		}
	}

	return "", errors.New("unable to find message fragment")
}

type SNAC_0x04_0x08_ICBMEvilRequest struct {
	SendAs     uint16
	ScreenName string `oscar:"len_prefix=uint8"`
}

type SNAC_0x04_0x09_ICBMEvilReply struct {
	EvilDeltaApplied uint16
	UpdatedEvilValue uint16
}

type SNAC_0x04_0x0B_ICBMClientErr struct {
	Cookie     uint64
	ChannelID  uint16
	ScreenName string `oscar:"len_prefix=uint8"`
	Code       uint16
	ErrInfo    []byte
}

type SNAC_0x04_0x0C_ICBMHostAck struct {
	Cookie     uint64
	ChannelID  uint16
	ScreenName string `oscar:"len_prefix=uint8"`
}

type SNAC_0x04_0x14_ICBMClientEvent struct {
	Cookie     uint64
	ChannelID  uint16
	ScreenName string `oscar:"len_prefix=uint8"`
	Event      uint16
}

type SNAC_0x04_0x0A_ICBMOfflineRetrieve struct{}

type SNAC_0x04_0x17_ICBMOfflineRetrieveReply struct{}

//
// 0x05: Advert
//

const (
	AdvertErr      uint16 = 0x0001
	AdvertAdsQuery uint16 = 0x0002
	AdvertAdsReply uint16 = 0x0003
)

//
// 0x06: Invite
//

const (
	InviteErr          uint16 = 0x0001
	InviteRequestQuery uint16 = 0x0002
	InviteRequestReply uint16 = 0x0003
)

//
// 0x07: Admin
//

const (
	AdminErr                uint16 = 0x0001
	AdminInfoQuery          uint16 = 0x0002
	AdminInfoReply          uint16 = 0x0003
	AdminInfoChangeRequest  uint16 = 0x0004
	AdminInfoChangeReply    uint16 = 0x0005
	AdminAcctConfirmRequest uint16 = 0x0006
	AdminAcctConfirmReply   uint16 = 0x0007
	AdminAcctDeleteRequest  uint16 = 0x0008
	AdminAcctDeleteReply    uint16 = 0x0009

	AdminInfoErrorValidateNickName              uint16 = 0x0001
	AdminInfoErrorValidatePassword              uint16 = 0x0002
	AdminInfoErrorValidateEmail                 uint16 = 0x0003
	AdminInfoErrorServiceTempUnavailable        uint16 = 0x0004
	AdminInfoErrorFieldChangeTempUnavailable    uint16 = 0x0005
	AdminInfoErrorInvalidNickName               uint16 = 0x0006
	AdminInfoErrorInvalidPassword               uint16 = 0x0007
	AdminInfoErrorInvalidEmail                  uint16 = 0x0008
	AdminInfoErrorInvalidRegistrationPreference uint16 = 0x0009
	AdminInfoErrorInvalidOldPassword            uint16 = 0x000A
	AdminInfoErrorInvalidNickNameLength         uint16 = 0x000B
	AdminInfoErrorInvalidPasswordLength         uint16 = 0x000C
	AdminInfoErrorInvalidEmailLength            uint16 = 0x000D
	AdminInfoErrorInvalidOldPasswordLength      uint16 = 0x000E
	AdminInfoErrorNeedOldPassword               uint16 = 0x000F
	AdminInfoErrorReadOnlyField                 uint16 = 0x0010
	AdminInfoErrorWriteOnlyField                uint16 = 0x0011
	AdminInfoErrorUnsupportedType               uint16 = 0x0012
	AdminInfoErrorAllOtherErrors                uint16 = 0x0013
	AdminInfoErrorBadSnac                       uint16 = 0x0014
	AdminInfoErrorInvalidAccount                uint16 = 0x0015
	AdminInfoErrorDeletedAccount                uint16 = 0x0016
	AdminInfoErrorExpiredAccount                uint16 = 0x0017
	AdminInfoErrorNoDatabaseAccess              uint16 = 0x0018
	AdminInfoErrorInvalidDatabaseFields         uint16 = 0x0019
	AdminInfoErrorBadDatabaseStatus             uint16 = 0x001A
	AdminInfoErrorMigrationCancel               uint16 = 0x001B
	AdminInfoErrorInternalError                 uint16 = 0x001C
	AdminInfoErrorPendingRequest                uint16 = 0x001D
	AdminInfoErrorNotDTStatus                   uint16 = 0x001E
	AdminInfoErrorOutstandingConfirm            uint16 = 0x001F
	AdminInfoErrorNoEmailAddress                uint16 = 0x0020
	AdminInfoErrorOverLimit                     uint16 = 0x0021
	AdminInfoErrorEmailHostFail                 uint16 = 0x0022
	AdminInfoErrorDNSFail                       uint16 = 0x0023

	AdminInfoRegStatusNoDisclosure    uint16 = 0x01
	AdminInfoRegStatusLimitDisclosure uint16 = 0x02
	AdminInfoRegStatusFullDisclosure  uint16 = 0x03

	AdminInfoPermissionsReadOnly1 uint16 = 0x01
	AdminInfoPermissionsReadOnly2 uint16 = 0x02
	AdminInfoPermissionsReadWrite uint16 = 0x03

	AdminAcctConfirmStatusEmailSent        uint16 = 0x00
	AdminAcctConfirmStatusAlreadyConfirmed uint16 = 0x1E
	AdminAcctConfirmStatusServerError      uint16 = 0x23

	AdminTLVScreenNameFormatted uint16 = 0x01
	AdminTLVNewPassword         uint16 = 0x02
	AdminTLVUrl                 uint16 = 0x04
	AdminTLVErrorCode           uint16 = 0x08
	AdminTLVEmailAddress        uint16 = 0x11
	AdminTLVOldPassword         uint16 = 0x12
	AdminTLVRegistrationStatus  uint16 = 0x13
)

// Used when client wants to get its account information
// - AdminTLVScreenNameFormatted
// - AdminTLVEmailAddress
// - AdminTLVRegistrationStatus
type SNAC_0x07_0x02_AdminInfoQuery struct {
	TLVRestBlock
}

type SNAC_0x07_0x03_AdminInfoReply struct {
	Permissions uint16
	TLVBlock
}

// AdminTLVScreenNameFormatted - change screenname formatting
// AdminTLVEmailAddress - change account email
// AdminTLVRegistrationStatus - change registration status
// AdminTLVNewPassword, AdminTLVOldPassword - change password
type SNAC_0x07_0x04_AdminInfoChangeRequest struct {
	TLVRestBlock
}

type SNAC_0x07_0x05_AdminChangeReply struct {
	Permissions uint16
	TLVBlock
}

type SNAC_0x07_0x06_AdminConfirmRequest struct{}

type SNAC_0x07_0x07_AdminConfirmReply struct {
	Status uint16
	TLV
}

//
// 0x08: Popup
//

const (
	PopupErr     uint16 = 0x0001
	PopupDisplay uint16 = 0x0002
)

//
// 0x09: PermitDeny
//

const (
	PermitDenyErr                      uint16 = 0x0001
	PermitDenyRightsQuery              uint16 = 0x0002
	PermitDenyRightsReply              uint16 = 0x0003
	PermitDenySetGroupPermitMask       uint16 = 0x0004
	PermitDenyAddPermListEntries       uint16 = 0x0005
	PermitDenyDelPermListEntries       uint16 = 0x0006
	PermitDenyAddDenyListEntries       uint16 = 0x0007
	PermitDenyDelDenyListEntries       uint16 = 0x0008
	PermitDenyBosErr                   uint16 = 0x0009
	PermitDenyAddTempPermitListEntries uint16 = 0x000A
	PermitDenyDelTempPermitListEntries uint16 = 0x000B

	PermitDenyTLVMaxPermits     uint16 = 0x01
	PermitDenyTLVMaxDenies      uint16 = 0x02
	PermitDenyTLVMaxTempPermits uint16 = 0x03
)

type SNAC_0x09_0x03_PermitDenyRightsReply struct {
	TLVRestBlock
}

type SNAC_0x09_0x05_PermitDenyAddPermListEntries struct {
	Users []struct {
		ScreenName string `oscar:"len_prefix=uint8"`
	}
}

type SNAC_0x09_0x06_PermitDenyDelPermListEntries struct {
	Users []struct {
		ScreenName string `oscar:"len_prefix=uint8"`
	}
}

type SNAC_0x09_0x07_PermitDenyAddDenyListEntries struct {
	Users []struct {
		ScreenName string `oscar:"len_prefix=uint8"`
	}
}

type SNAC_0x09_0x08_PermitDenyDelDenyListEntries struct {
	Users []struct {
		ScreenName string `oscar:"len_prefix=uint8"`
	}
}

type SNAC_0x09_0x04_PermitDenySetGroupPermitMask struct {
	PermMask uint32
}

func (s SNAC_0x09_0x04_PermitDenySetGroupPermitMask) IsFlagSet(flag uint16) bool {
	return flag&uint16(s.PermMask) == flag
}

//
// 0x0A: UserLookup
//

const (
	UserLookupErr         uint16 = 0x0001
	UserLookupFindByEmail uint16 = 0x0002
	UserLookupFindReply   uint16 = 0x0003

	UserLookupErrNoUserFound uint16 = 0x0014

	UserLookupTLVEmailAddress uint16 = 0x0001
)

type SNAC_0x0A_0x02_UserLookupFindByEmail struct {
	Email []byte
}

type SNAC_0x0A_0x03_UserLookupFindReply struct {
	TLVRestBlock
}

//
// 0x0B: Stats
//

const (
	StatsErr                  uint16 = 0x0001
	StatsSetMinReportInterval uint16 = 0x0002
	StatsReportEvents         uint16 = 0x0003
	StatsReportAck            uint16 = 0x0004
)

type SNAC_0x0B_0x02_StatsSetMinReportInterval struct {
	MinReportInterval uint16
}

type SNAC_0x0B_0x03_StatsReportEvents struct {
	TLVRestBlock
}

type SNAC_0x0B_0x04_StatsReportAck struct {
}

//
// 0x0C: Translate
//

const (
	TranslateErr     uint16 = 0x0001
	TranslateRequest uint16 = 0x0002
	TranslateReply   uint16 = 0x0003
)

//
// 0x0D: ChatNav
//

const (
	ChatNavErr                 uint16 = 0x0001
	ChatNavRequestChatRights   uint16 = 0x0002
	ChatNavRequestExchangeInfo uint16 = 0x0003
	ChatNavRequestRoomInfo     uint16 = 0x0004
	ChatNavRequestMoreRoomInfo uint16 = 0x0005
	ChatNavRequestOccupantList uint16 = 0x0006
	ChatNavSearchForRoom       uint16 = 0x0007
	ChatNavCreateRoom          uint16 = 0x0008
	ChatNavNavInfo             uint16 = 0x0009

	ChatNavTLVMaxConcurrentRooms uint16 = 0x0002
	ChatNavTLVExchangeInfo       uint16 = 0x0003
	ChatNavTLVRoomInfo           uint16 = 0x0004
)

type SNAC_0x0D_0x03_ChatNavRequestExchangeInfo struct {
	Exchange uint16
}

type SNAC_0x0D_0x04_ChatNavRequestRoomInfo struct {
	Exchange       uint16
	Cookie         string `oscar:"len_prefix=uint8"`
	InstanceNumber uint16
	DetailLevel    uint8
}

type SNAC_0x0D_0x09_ChatNavNavInfo struct {
	TLVRestBlock
}

type SNAC_0x0D_0x09_TLVExchangeInfo struct {
	Identifier uint16
	TLVBlock
}

//
// 0x0E: Chat
//

const (
	ChatErr                uint16 = 0x0001
	ChatRoomInfoUpdate     uint16 = 0x0002
	ChatUsersJoined        uint16 = 0x0003
	ChatUsersLeft          uint16 = 0x0004
	ChatChannelMsgToHost   uint16 = 0x0005
	ChatChannelMsgToClient uint16 = 0x0006
	ChatEvilRequest        uint16 = 0x0007
	ChatEvilReply          uint16 = 0x0008
	ChatClientErr          uint16 = 0x0009
	ChatPauseRoomReq       uint16 = 0x000A
	ChatPauseRoomAck       uint16 = 0x000B
	ChatResumeRoom         uint16 = 0x000C
	ChatShowMyRow          uint16 = 0x000D
	ChatShowRowByUsername  uint16 = 0x000E
	ChatShowRowByNumber    uint16 = 0x000F
	ChatShowRowByName      uint16 = 0x0010
	ChatRowInfo            uint16 = 0x0011
	ChatListRows           uint16 = 0x0012
	ChatRowListInfo        uint16 = 0x0013
	ChatMoreRows           uint16 = 0x0014
	ChatMoveToRow          uint16 = 0x0015
	ChatToggleChat         uint16 = 0x0016
	ChatSendQuestion       uint16 = 0x0017
	ChatSendComment        uint16 = 0x0018
	ChatTallyVote          uint16 = 0x0019
	ChatAcceptBid          uint16 = 0x001A
	ChatSendInvite         uint16 = 0x001B
	ChatDeclineInvite      uint16 = 0x001C
	ChatAcceptInvite       uint16 = 0x001D
	ChatNotifyMessage      uint16 = 0x001E
	ChatGotoRow            uint16 = 0x001F
	ChatStageUserJoin      uint16 = 0x0020
	ChatStageUserLeft      uint16 = 0x0021
	ChatUnnamedSnac22      uint16 = 0x0022
	ChatClose              uint16 = 0x0023
	ChatUserBan            uint16 = 0x0024
	ChatUserUnban          uint16 = 0x0025
	ChatJoined             uint16 = 0x0026
	ChatUnnamedSnac27      uint16 = 0x0027
	ChatUnnamedSnac28      uint16 = 0x0028
	ChatUnnamedSnac29      uint16 = 0x0029
	ChatRoomInfoOwner      uint16 = 0x0030

	ChatTLVPublicWhisperFlag    uint16 = 0x01
	ChatTLVWhisperToUser        uint16 = 0x02
	ChatTLVSenderInformation    uint16 = 0x03
	ChatTLVMessageInfo          uint16 = 0x05
	ChatTLVEnableReflectionFlag uint16 = 0x06

	ChatTLVMessageInfoEncoding uint16 = 0x02
	ChatTLVMessageInfoLang     uint16 = 0x03
	ChatTLVMessageInfoText     uint16 = 0x01

	// referenced from protocols/oscar/family_chatnav.c in lib purple
	ChatRoomTLVClassPerms         uint16 = 0x02
	ChatRoomTLVMaxConcurrentRooms uint16 = 0x03 // required by aim 2.x-3.x
	ChatRoomTLVMaxNameLen         uint16 = 0x04
	ChatRoomTLVFullyQualifiedName uint16 = 0x6A
	ChatRoomTLVCreateTime         uint16 = 0xCA
	ChatRoomTLVFlags              uint16 = 0xC9
	ChatRoomTLVMaxMsgLen          uint16 = 0xD1
	ChatRoomTLVMaxOccupancy       uint16 = 0xD2
	ChatRoomTLVRoomName           uint16 = 0xD3
	ChatRoomTLVNavCreatePerms     uint16 = 0xD5
	ChatRoomTLVCharSet1           uint16 = 0xD6
	ChatRoomTLVLang1              uint16 = 0xD7
	ChatRoomTLVCharSet2           uint16 = 0xD8
	ChatRoomTLVLang2              uint16 = 0xD9
	ChatRoomTLVMaxMsgVisLen       uint16 = 0xDA
)

type SNAC_0x0E_0x02_ChatRoomInfoUpdate struct {
	Exchange       uint16
	Cookie         string `oscar:"len_prefix=uint8"`
	InstanceNumber uint16
	DetailLevel    uint8
	TLVBlock
}

type SNAC_0x0E_0x03_ChatUsersJoined struct {
	Users []TLVUserInfo
}

type SNAC_0x0E_0x04_ChatUsersLeft struct {
	Users []TLVUserInfo
}

type SNAC_0x0E_0x05_ChatChannelMsgToHost struct {
	Cookie  uint64
	Channel uint16
	TLVRestBlock
}

type SNAC_0x0E_0x06_ChatChannelMsgToClient struct {
	Cookie  uint64
	Channel uint16
	TLVRestBlock
}

// UnmarshalChatMessageText extracts message text from a chat message. Param b
// is a slice from TLV wire.ChatTLVMessageInfo.
func UnmarshalChatMessageText(b []byte) (string, error) {
	block := TLVRestBlock{}
	if err := UnmarshalBE(&block, bytes.NewReader(b)); err != nil {
		return "", fmt.Errorf("UnmarshalBE: %w", err)
	}

	b, hasMsg := block.Bytes(ChatTLVMessageInfoText)
	if !hasMsg {
		return "", errors.New("SNAC(0x0E,0x05) has no chat msg text TLV")
	}

	return string(b), nil
}

//
// 0x0F: ODir
//

const (
	ODirErr              uint16 = 0x0001
	ODirInfoQuery        uint16 = 0x0002
	ODirInfoReply        uint16 = 0x0003
	ODirKeywordListQuery uint16 = 0x0004
	ODirKeywordListReply uint16 = 0x0005

	ODirTLVFirstName    uint16 = 0x0001 // The first name of the individual being searched.
	ODirTLVLastName     uint16 = 0x0002 // The last name of the individual being searched.
	ODirTLVMiddleName   uint16 = 0x0003 // The middle name of the individual being searched.
	ODirTLVMaidenName   uint16 = 0x0004 // The maiden name of the individual being searched.
	ODirTLVEmailAddress uint16 = 0x0005 // The email address you're searching for.
	ODirTLVCountry      uint16 = 0x0006 // The country where the individual resides.
	ODirTLVState        uint16 = 0x0007 // The state where the individual resides.
	ODirTLVCity         uint16 = 0x0008 // The city where the individual resides.
	ODirTLVScreenName   uint16 = 0x0009 // The screen name of the individual being searched.
	ODirTLVSearchType   uint16 = 0x000a // Likely denotes the search type: 0x0000 for "name and other criteria" search, 0x0001 for "email address" or "interest" search.
	ODirTLVInterest     uint16 = 0x000b // The interest or hobby of the individual being searched.
	ODirTLVNickName     uint16 = 0x000c // The nickname of the individual being searched.
	ODirTLVZIP          uint16 = 0x000d // The ZIP code where the individual resides.
	ODirTLVRegion       uint16 = 0x001c // Encodes region information, possibly as 8 bytes in "us-ascii."
	ODirTLVAddress      uint16 = 0x0021 // The street address where the individual resides.

	ODirKeywordCategory uint8 = 0x01
	ODirKeyword         uint8 = 0x02

	ODirSearchByNameAndAddress  uint16 = 0x0000
	ODirSearchByEmailOrInterest uint16 = 0x0001

	ODirSearchResponseUnavailable1   uint16 = 0x01 // Search is unavailable
	ODirSearchResponseUnavailable2   uint16 = 0x02 // Search is unavailable (same as above)
	ODirSearchResponseTooManyResults uint16 = 0x03 // Too many results returned, narrow search
	ODirSearchResponseNameMissing    uint16 = 0x04 // Missing first or last name
	ODirSearchResponseOK             uint16 = 0x05 // Successful search
)

type SNAC_0x0F_0x02_InfoQuery struct {
	TLVRestBlock
}

type SNAC_0x0F_0x03_InfoReply struct {
	Status  uint16
	Unknown uint16
	Results struct {
		List []TLVBlock `oscar:"count_prefix=uint16"`
	} `oscar:"count_prefix=uint16"`
}

type SNAC_0x0F_0x04_KeywordListQuery struct{}

type SNAC_0x0F_0x04_KeywordListReply struct {
	Status    uint16
	Interests []ODirKeywordListItem `oscar:"count_prefix=uint16"`
}

type ODirKeywordListItem struct {
	// Type is the item type (parent category = 1, keyword = 2).
	Type uint8
	// ID is the ID of the keyword or category. If item type is category, then
	// it's the category ID. If item type is keyword, then it's the parent
	// category ID. If it's a top-level keyword, value is 0.
	ID uint8
	// Name is the keyword or category name.
	Name string `oscar:"len_prefix=uint16"`
}

//
// 0x10: BART
//
//

const (
	BARTTypesBuddyIconSmall      uint16 = 0x00
	BARTTypesBuddyIcon           uint16 = 0x01
	BARTTypesStatusStr           uint16 = 0x02
	BARTTypesArriveSound         uint16 = 0x03
	BARTTypesRichName            uint16 = 0x04
	BARTTypesSuperIcon           uint16 = 0x05
	BARTTypesRadioStation        uint16 = 0x06
	BARTTypesSuperIconTrigger    uint16 = 0x07
	BARTTypesStatusTextLink      uint16 = 0x09
	BARTTypesLocation            uint16 = 0x0B
	BARTTypesBuddyIconBig        uint16 = 0x0C
	BARTTypesStatusTextTimestamp uint16 = 0x0D
	BARTTypesCurrentAvtrack      uint16 = 0x0F
	BARTTypesDepartSound         uint16 = 0x60
	BARTTypesImBackground        uint16 = 0x80
	BARTTypesImChrome            uint16 = 0x81
	BARTTypesImSkin              uint16 = 0x82
	BARTTypesImSound             uint16 = 0x83
	BARTTypesBadge               uint16 = 0x84
	BARTTypesBadgeUrl            uint16 = 0x85
	BARTTypesImInitialSound      uint16 = 0x86
	BARTTypesFlashWallpaper      uint16 = 0x88
	BARTTypesImmersiveWallpaper  uint16 = 0x89
	BARTTypesBuddylistBackground uint16 = 0x100
	BARTTypesBuddylistImage      uint16 = 0x101
	BARTTypesBuddylistSkin       uint16 = 0x102
	BARTTypesSmileySet           uint16 = 0x400
	BARTTypesEncrCertChain       uint16 = 0x402
	BARTTypesSignCertChain       uint16 = 0x403
	BARTTypesGatewayCert         uint16 = 0x404
)

const (
	BARTErr            uint16 = 0x0001
	BARTUploadQuery    uint16 = 0x0002
	BARTUploadReply    uint16 = 0x0003
	BARTDownloadQuery  uint16 = 0x0004
	BARTDownloadReply  uint16 = 0x0005
	BARTDownload2Query uint16 = 0x0006
	BARTDownload2Reply uint16 = 0x0007
)

const (
	BARTFlagsKnown    uint8 = 0x00
	BARTFlagsCustom   uint8 = 0x01
	BARTFlagsUrl      uint8 = 0x02
	BARTFlagsData     uint8 = 0x04
	BARTFlagsUnknown  uint8 = 0x40
	BARTFlagsRedirect uint8 = 0x80
	BARTFlagsBanned   uint8 = 0xC0
)

const (
	BARTReplyCodesSuccess     uint8 = 0x00
	BARTReplyCodesInvalid     uint8 = 0x01
	BARTReplyCodesNoCustom    uint8 = 0x02
	BARTReplyCodesTooSmall    uint8 = 0x03
	BARTReplyCodesTooBig      uint8 = 0x04
	BARTReplyCodesInvalidType uint8 = 0x05
	BARTReplyCodesBanned      uint8 = 0x06
	BARTReplyCodesNotfound    uint8 = 0x07
)

// GetClearIconHash returns an opaque value set in BARTID hash that indicates
// the user wants to clear their buddy icon.
func GetClearIconHash() []byte {
	return []byte{0x02, 0x01, 0xd2, 0x04, 0x72}
}

// BARTInfo represents a BART feedbag item
type BARTInfo struct {
	Flags uint8
	Hash  []byte `oscar:"len_prefix=uint8"`
}

// HasClearIconHash reports whether the BART ID hash contains the
// ClearIconHash sentinel value.
func (h BARTInfo) HasClearIconHash() bool {
	return bytes.Equal(h.Hash, GetClearIconHash())
}

type BARTID struct {
	Type uint16
	BARTInfo
}

type BartIDsWName struct {
	ScreenName string   `oscar:"len_prefix=uint8"`
	IDs        []BARTID `oscar:"len_prefix=uint8"`
}
type BartQueryReplyID struct {
	QueryID BARTID
	Code    uint8
	ReplyID BARTID
}

type SNAC_0x10_0x02_BARTUploadQuery struct {
	Type uint16
	Data []byte `oscar:"len_prefix=uint16"`
}

type SNAC_0x10_0x03_BARTUploadReply struct {
	Code uint8
	ID   BARTID
}

type SNAC_0x10_0x04_BARTDownloadQuery struct {
	ScreenName string `oscar:"len_prefix=uint8"`
	Command    uint8
	BARTID
}

type SNAC_0x10_0x05_BARTDownloadReply struct {
	ScreenName string `oscar:"len_prefix=uint8"`
	BARTID     BARTID
	Data       []byte `oscar:"len_prefix=uint16"`
}

type SNAC_0x10_0x06_BARTDownload2Query struct {
	ScreenName string   `oscar:"len_prefix=uint8"`
	IDs        []BARTID `oscar:"count_prefix=uint8"`
}

type SNAC_0x10_0x07_BARTDownload2Reply struct {
	ScreenName string `oscar:"len_prefix=uint8"`
	ReplyID    BartQueryReplyID
	Data       []byte `oscar:"len_prefix=uint16"`
}

//
// 0x13: Feedbag
//

const (
	FeedbagClassIdBuddy            uint16 = 0x0000
	FeedbagClassIdGroup            uint16 = 0x0001
	FeedbagClassIDPermit           uint16 = 0x0002
	FeedbagClassIDDeny             uint16 = 0x0003
	FeedbagClassIdPdinfo           uint16 = 0x0004
	FeedbagClassIdBuddyPrefs       uint16 = 0x0005
	FeedbagClassIdNonbuddy         uint16 = 0x0006
	FeedbagClassIdTpaProvider      uint16 = 0x0007
	FeedbagClassIdTpaSubscription  uint16 = 0x0008
	FeedbagClassIdClientPrefs      uint16 = 0x0009
	FeedbagClassIdStock            uint16 = 0x000A
	FeedbagClassIdWeather          uint16 = 0x000B
	FeedbagClassIdWatchList        uint16 = 0x000D
	FeedbagClassIdIgnoreList       uint16 = 0x000E
	FeedbagClassIdDateTime         uint16 = 0x000F
	FeedbagClassIdExternalUser     uint16 = 0x0010
	FeedbagClassIdRootCreator      uint16 = 0x0011
	FeedbagClassIdFish             uint16 = 0x0012
	FeedbagClassIdImportTimestamp  uint16 = 0x0013
	FeedbagClassIdBart             uint16 = 0x0014
	FeedbagClassIdRbOrder          uint16 = 0x0015
	FeedbagClassIdPersonality      uint16 = 0x0016
	FeedbagClassIdAlProf           uint16 = 0x0017
	FeedbagClassIdAlInfo           uint16 = 0x0018
	FeedbagClassIdInteraction      uint16 = 0x0019
	FeedbagClassIdVanityInfo       uint16 = 0x001D
	FeedbagClassIdFavoriteLocation uint16 = 0x001E
	FeedbagClassIdBartPdinfo       uint16 = 0x001F
	FeedbagClassIdCustomEmoticons  uint16 = 0x0024
	FeedbagClassIdMaxPredefined    uint16 = 0x0024
	FeedbagClassIdXIcqStatusNote   uint16 = 0x015C
	FeedbagClassIdMin              uint16 = 0x0400

	FeedbagAttributesShared                  uint16 = 0x0064
	FeedbagAttributesInvited                 uint16 = 0x0065
	FeedbagAttributesPending                 uint16 = 0x0066
	FeedbagAttributesTimeT                   uint16 = 0x0067
	FeedbagAttributesDenied                  uint16 = 0x0068
	FeedbagAttributesSwimIndex               uint16 = 0x0069
	FeedbagAttributesRecentBuddy             uint16 = 0x006A
	FeedbagAttributesAutoBot                 uint16 = 0x006B
	FeedbagAttributesInteraction             uint16 = 0x006D
	FeedbagAttributesMegaBot                 uint16 = 0x006F
	FeedbagAttributesOrder                   uint16 = 0x00C8
	FeedbagAttributesBuddyPrefs              uint16 = 0x00C9
	FeedbagAttributesPdMode                  uint16 = 0x00CA
	FeedbagAttributesPdMask                  uint16 = 0x00CB
	FeedbagAttributesPdFlags                 uint16 = 0x00CC
	FeedbagAttributesClientPrefs             uint16 = 0x00CD
	FeedbagAttributesLanguage                uint16 = 0x00CE
	FeedbagAttributesFishUri                 uint16 = 0x00CF
	FeedbagAttributesWirelessPdMode          uint16 = 0x00D0
	FeedbagAttributesWirelessIgnoreMode      uint16 = 0x00D1
	FeedbagAttributesFishPdMode              uint16 = 0x00D2
	FeedbagAttributesFishIgnoreMode          uint16 = 0x00D3
	FeedbagAttributesCreateTime              uint16 = 0x00D4
	FeedbagAttributesBartInfo                uint16 = 0x00D5
	FeedbagAttributesBuddyPrefsValid         uint16 = 0x00D6
	FeedbagAttributesBuddyPrefs2             uint16 = 0x00D7
	FeedbagAttributesBuddyPrefs2Valid        uint16 = 0x00D8
	FeedbagAttributesBartList                uint16 = 0x00D9
	FeedbagAttributesArriveSound             uint16 = 0x012C
	FeedbagAttributesLeaveSound              uint16 = 0x012D
	FeedbagAttributesImage                   uint16 = 0x012E
	FeedbagAttributesColorBg                 uint16 = 0x012F
	FeedbagAttributesColorFg                 uint16 = 0x0130
	FeedbagAttributesAlias                   uint16 = 0x0131
	FeedbagAttributesPassword                uint16 = 0x0132
	FeedbagAttributesDisabled                uint16 = 0x0133
	FeedbagAttributesCollapsed               uint16 = 0x0134
	FeedbagAttributesUrl                     uint16 = 0x0135
	FeedbagAttributesActiveList              uint16 = 0x0136
	FeedbagAttributesEmailAddr               uint16 = 0x0137
	FeedbagAttributesPhoneNumber             uint16 = 0x0138
	FeedbagAttributesCellPhoneNumber         uint16 = 0x0139
	FeedbagAttributesSmsPhoneNumber          uint16 = 0x013A
	FeedbagAttributesWireless                uint16 = 0x013B
	FeedbagAttributesNote                    uint16 = 0x013C
	FeedbagAttributesAlertPrefs              uint16 = 0x013D
	FeedbagAttributesBudalertSound           uint16 = 0x013E
	FeedbagAttributesStockalertValue         uint16 = 0x013F
	FeedbagAttributesTpalertEditUrl          uint16 = 0x0140
	FeedbagAttributesTpalertDeleteUrl        uint16 = 0x0141
	FeedbagAttributesTpprovMorealertsUrl     uint16 = 0x0142
	FeedbagAttributesFish                    uint16 = 0x0143
	FeedbagAttributesXunconfirmedxLastAccess uint16 = 0x0145
	FeedbagAttributesImSent                  uint16 = 0x0150
	FeedbagAttributesOnlineTime              uint16 = 0x0151
	FeedbagAttributesAwayMsg                 uint16 = 0x0152
	FeedbagAttributesImReceived              uint16 = 0x0153
	FeedbagAttributesBuddyfeedView           uint16 = 0x0154
	FeedbagAttributesWorkPhoneNumber         uint16 = 0x0158
	FeedbagAttributesOtherPhoneNumber        uint16 = 0x0159
	FeedbagAttributesWebPdMode               uint16 = 0x015F
	FeedbagAttributesFirstCreationTimeXc     uint16 = 0x0167
	FeedbagAttributesPdModeXc                uint16 = 0x016E

	FeedbagBuddyPrefsWantsTypingEvents uint32 = 0x400000 // user wants to send and receive typing events
	FeedbagBuddyPrefsAcceptOfflineIM   uint16 = 0x34     // user wants to send and receive typing events

	FeedbagRightsMaxClassAttrs       uint16 = 0x02
	FeedbagRightsMaxItemAttrs        uint16 = 0x03
	FeedbagRightsMaxItemsByClass     uint16 = 0x04
	FeedbagRightsMaxClientItems      uint16 = 0x05
	FeedbagRightsMaxItemNameLen      uint16 = 0x06
	FeedbagRightsMaxRecentBuddies    uint16 = 0x07
	FeedbagRightsInteractionBuddies  uint16 = 0x08
	FeedbagRightsInteractionHalfLife uint16 = 0x09
	FeedbagRightsInteractionMaxScore uint16 = 0x0A
	FeedbagRightsMaxUnknown0b        uint16 = 0x0B
	FeedbagRightsMaxBuddiesPerGroup  uint16 = 0x0C
	FeedbagRightsMaxMegaBots         uint16 = 0x0D
	FeedbagRightsMaxSmartGroups      uint16 = 0x0E

	FeedbagErr                      uint16 = 0x0001
	FeedbagRightsQuery              uint16 = 0x0002
	FeedbagRightsReply              uint16 = 0x0003
	FeedbagQuery                    uint16 = 0x0004
	FeedbagQueryIfModified          uint16 = 0x0005
	FeedbagReply                    uint16 = 0x0006
	FeedbagUse                      uint16 = 0x0007
	FeedbagInsertItem               uint16 = 0x0008
	FeedbagUpdateItem               uint16 = 0x0009
	FeedbagDeleteItem               uint16 = 0x000A
	FeedbagInsertClass              uint16 = 0x000B
	FeedbagUpdateClass              uint16 = 0x000C
	FeedbagDeleteClass              uint16 = 0x000D
	FeedbagStatus                   uint16 = 0x000E
	FeedbagReplyNotModified         uint16 = 0x000F
	FeedbagDeleteUser               uint16 = 0x0010
	FeedbagStartCluster             uint16 = 0x0011
	FeedbagEndCluster               uint16 = 0x0012
	FeedbagAuthorizeBuddy           uint16 = 0x0013
	FeedbagPreAuthorizeBuddy        uint16 = 0x0014
	FeedbagPreAuthorizedBuddy       uint16 = 0x0015
	FeedbagRemoveMe                 uint16 = 0x0016
	FeedbagRemoveMe2                uint16 = 0x0017
	FeedbagRequestAuthorizeToHost   uint16 = 0x0018
	FeedbagRequestAuthorizeToClient uint16 = 0x0019
	FeedbagRespondAuthorizeToHost   uint16 = 0x001A
	FeedbagRespondAuthorizeToClient uint16 = 0x001B
	FeedbagBuddyAdded               uint16 = 0x001C
	FeedbagRequestAuthorizeToBadog  uint16 = 0x001D
	FeedbagRespondAuthorizeToBadog  uint16 = 0x001E
	FeedbagBuddyAddedToBadog        uint16 = 0x001F
	FeedbagTestSnac                 uint16 = 0x0021
	FeedbagForwardMsg               uint16 = 0x0022
	FeedbagIsAuthRequiredQuery      uint16 = 0x0023
	FeedbagIsAuthRequiredReply      uint16 = 0x0024
	FeedbagRecentBuddyUpdate        uint16 = 0x0025
)

// FeedbagPDMode represents a buddy list permit/deny mode setting that
// determines who can interact with a user.
type FeedbagPDMode uint8

const (
	// FeedbagPDModePermitAll allows all users to see and talk to user. This is
	// the session default.
	FeedbagPDModePermitAll FeedbagPDMode = 0x01
	// FeedbagPDModeDenyAll blocks all users from communicating with user.
	FeedbagPDModeDenyAll FeedbagPDMode = 0x02
	// FeedbagPDModePermitSome only allows a specified list of users to see and
	// talk to user and blocks all others from communicating.
	FeedbagPDModePermitSome FeedbagPDMode = 0x03
	// FeedbagPDModeDenySome blocks a list of users from seeing and talking to
	// user and allows all others to communicate.
	FeedbagPDModeDenySome FeedbagPDMode = 0x04
	// FeedbagPDModePermitOnList only allows communication with users on buddy
	// list and blocks all others from communicating.
	FeedbagPDModePermitOnList FeedbagPDMode = 0x05
)

type SNAC_0x13_0x02_FeedbagRightsQuery struct {
	TLVRestBlock
}

type SNAC_0x13_0x03_FeedbagRightsReply struct {
	TLVRestBlock
}

type SNAC_0x13_0x05_FeedbagQueryIfModified struct {
	LastUpdate uint32
	Count      uint8
}

type SNAC_0x13_0x06_FeedbagReply struct {
	Version    uint8
	Items      []FeedbagItem `oscar:"count_prefix=uint16"`
	LastUpdate uint32
}

type SNAC_0x13_0x08_FeedbagInsertItem struct {
	Items []FeedbagItem
}

type SNAC_0x13_0x09_FeedbagUpdateItem struct {
	Items []FeedbagItem
}

type SNAC_0x13_0x0A_FeedbagDeleteItem struct {
	Items []FeedbagItem
}

type SNAC_0x13_0x0E_FeedbagStatus struct {
	Results []uint16
}

type SNAC_0x13_0x11_FeedbagStartCluster struct {
	TLVRestBlock
}

type SNAC_0x13_0x18_FeedbagRequestAuthorizationToHost struct {
	ScreenName string `oscar:"len_prefix=uint8"`
	Reason     string `oscar:"len_prefix=uint16"`
	Unknown    uint16
}

type SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost struct {
	ScreenName string `oscar:"len_prefix=uint8"`
	Accepted   uint8
	Reason     string `oscar:"len_prefix=uint16"`
}

type SNAC_0x13_0x1B_FeedbagRespondAuthorizeToClient struct {
	ScreenName string `oscar:"len_prefix=uint8"`
	Accepted   uint8
	Reason     string `oscar:"len_prefix=uint16"`
}

//
// 0x15: ICQ
//

const (
	ICQErr     uint16 = 0x0001
	ICQDBQuery uint16 = 0x0002
	ICQDBReply uint16 = 0x0003

	ICQTLVTagsMetadata                  uint16 = 0x0001
	ICQTLVTagsUIN                       uint16 = 0x0136 // User UIN (search)
	ICQTLVTagsFirstName                 uint16 = 0x0140 // User first name
	ICQTLVTagsLastName                  uint16 = 0x014A // User last name
	ICQTLVTagsNickname                  uint16 = 0x0154 // User nickname
	ICQTLVTagsEmail                     uint16 = 0x015E // User email
	ICQTLVTagsAgeRangeSearch            uint16 = 0x0168 // Age range to search (search)
	ICQTLVTagsAge                       uint16 = 0x0172 // User age
	ICQTLVTagsGender                    uint16 = 0x017C // User gender
	ICQTLVTagsSpokenLanguage            uint16 = 0x0186 // User spoken language
	ICQTLVTagsHomeCityName              uint16 = 0x0190 // User home city name
	ICQTLVTagsHomeStateAbbr             uint16 = 0x019A // User home state abbreviation
	ICQTLVTagsHomeCountryCode           uint16 = 0x01A4 // User home country code
	ICQTLVTagsWorkCompanyName           uint16 = 0x01AE // User work company name
	ICQTLVTagsWorkDepartmentName        uint16 = 0x01B8 // User work department name
	ICQTLVTagsWorkPositionTitle         uint16 = 0x01C2 // User work position (title)
	ICQTLVTagsWorkOccupationCode        uint16 = 0x01CC // User work occupation code
	ICQTLVTagsAffiliationsNode          uint16 = 0x01D6 // User affiliations node
	ICQTLVTagsInterestsNode             uint16 = 0x01EA // User interests node
	ICQTLVTagsPastInfoNode              uint16 = 0x01FE // User past info node
	ICQTLVTagsHomepageCategoryKeywords  uint16 = 0x0212 // User homepage category/keywords
	ICQTLVTagsHomepageURL               uint16 = 0x0213 // User homepage URL
	ICQTLVTagsWhitepagesSearchKeywords  uint16 = 0x0226 // Whitepages search keywords string (search)
	ICQTLVTagsSearchOnlineUsersFlag     uint16 = 0x0230 // Search only online users flag (search)
	ICQTLVTagsBirthdayInfo              uint16 = 0x023A // User birthday info (year, month, day)
	ICQTLVTagsNotesText                 uint16 = 0x0258 // User notes (about) text
	ICQTLVTagsHomeStreetAddress         uint16 = 0x0262 // User home street address
	ICQTLVTagsHomeZipCode               uint16 = 0x026C // User home zip code
	ICQTLVTagsHomePhoneNumber           uint16 = 0x0276 // User home phone number
	ICQTLVTagsHomeFaxNumber             uint16 = 0x0280 // User home fax number
	ICQTLVTagsHomeCellularPhoneNumber   uint16 = 0x028A // User home cellular phone number
	ICQTLVTagsWorkStreetAddress         uint16 = 0x0294 // User work street address
	ICQTLVTagsWorkCityName              uint16 = 0x029E // User work city name
	ICQTLVTagsWorkStateName             uint16 = 0x02A8 // User work state name
	ICQTLVTagsWorkCountryCode           uint16 = 0x02B2 // User work country code
	ICQTLVTagsWorkZipCode               uint16 = 0x02BC // User work zip code
	ICQTLVTagsWorkPhoneNumber           uint16 = 0x02C6 // User work phone number
	ICQTLVTagsWorkFaxNumber             uint16 = 0x02D0 // User work fax number
	ICQTLVTagsWorkWebpageURL            uint16 = 0x02DA // User work webpage URL
	ICQTLVTagsShowWebStatusPermissions  uint16 = 0x02F8 // User 'show web status' permissions
	ICQTLVTagsAuthorizationPermissions  uint16 = 0x030C // User authorization permissions
	ICQTLVTagsGMTOffset                 uint16 = 0x0316 // User GMT offset
	ICQTLVTagsOriginallyFromCity        uint16 = 0x0320 // User originally from city
	ICQTLVTagsOriginallyFromState       uint16 = 0x032A // User originally from state
	ICQTLVTagsOriginallyFromCountryCode uint16 = 0x0334 // User originally from country (code)

	ICQStatusCodeOK   uint8 = 0x0A
	ICQStatusCodeFail uint8 = 0x32
	ICQStatusCodeErr  uint8 = 0x14

	ICQDBQueryOfflineMsgReq       uint16 = 0x003C
	ICQDBQueryOfflineMsgReply     uint16 = 0x0041
	ICQDBQueryOfflineMsgReplyLast uint16 = 0x0042
	ICQDBQueryDeleteMsgReq        uint16 = 0x003E
	ICQDBQueryMetaReq             uint16 = 0x07D0
	ICQDBQueryMetaReply           uint16 = 0x07DA
)

const (
	ICQUserFlagPublishEmailYes uint8 = 0
	ICQUserFlagPublishEmailNo  uint8 = 1
)

const (
	ICQDBQueryMetaReqSetBasicInfo      uint16 = 0x03EA
	ICQDBQueryMetaReqSetWorkInfo       uint16 = 0x03F3
	ICQDBQueryMetaReqSetMoreInfo       uint16 = 0x03FD
	ICQDBQueryMetaReqSetNotes          uint16 = 0x0406
	ICQDBQueryMetaReqSetEmails         uint16 = 0x040B
	ICQDBQueryMetaReqSetInterests      uint16 = 0x0410
	ICQDBQueryMetaReqSetAffiliations   uint16 = 0x041A
	ICQDBQueryMetaReqSetPermissions    uint16 = 0x0424
	ICQDBQueryMetaReqShortInfo         uint16 = 0x04BA
	ICQDBQueryMetaReqFullInfo          uint16 = 0x04B2
	ICQDBQueryMetaReqFullInfo2         uint16 = 0x04D0
	ICQDBQueryMetaReqSearchByDetails   uint16 = 0x0515
	ICQDBQueryMetaReqSearchByUIN       uint16 = 0x051F
	ICQDBQueryMetaReqSearchByEmail     uint16 = 0x0529
	ICQDBQueryMetaReqSearchWhitePages  uint16 = 0x0533
	ICQDBQueryMetaReqSearchWhitePages2 uint16 = 0x055F
	ICQDBQueryMetaReqSearchByUIN2      uint16 = 0x0569
	ICQDBQueryMetaReqSearchByEmail3    uint16 = 0x0573
	ICQDBQueryMetaReqStat0758          uint16 = 0x0758
	ICQDBQueryMetaReqXMLReq            uint16 = 0x0898
	ICQDBQueryMetaReqStat0a8c          uint16 = 0x0A8C
	ICQDBQueryMetaReqStat0a96          uint16 = 0x0A96
	ICQDBQueryMetaReqStat0aaa          uint16 = 0x0AAA
	ICQDBQueryMetaReqStat0ab4          uint16 = 0x0AB4
	ICQDBQueryMetaReqStat0ab9          uint16 = 0x0AB9
	ICQDBQueryMetaReqStat0abe          uint16 = 0x0ABE
	ICQDBQueryMetaReqStat0ac8          uint16 = 0x0AC8
	ICQDBQueryMetaReqStat0acd          uint16 = 0x0ACD
	ICQDBQueryMetaReqStat0ad2          uint16 = 0x0AD2
	ICQDBQueryMetaReqStat0ad7          uint16 = 0x0AD7

	ICQDBQueryMetaReplySetBasicInfo    uint16 = 0x0064
	ICQDBQueryMetaReplySetWorkInfo     uint16 = 0x006E
	ICQDBQueryMetaReplySetMoreInfo     uint16 = 0x0078
	ICQDBQueryMetaReplySetNotes        uint16 = 0x0082
	ICQDBQueryMetaReplySetEmails       uint16 = 0x0087
	ICQDBQueryMetaReplySetInterests    uint16 = 0x008C
	ICQDBQueryMetaReplySetAffiliations uint16 = 0x0096
	ICQDBQueryMetaReplySetPermissions  uint16 = 0x00A0
	ICQDBQueryMetaReplyBasicInfo       uint16 = 0x00C8
	ICQDBQueryMetaReplyWorkInfo        uint16 = 0x00D2
	ICQDBQueryMetaReplyMoreInfo        uint16 = 0x00DC
	ICQDBQueryMetaReplyNotes           uint16 = 0x00E6
	ICQDBQueryMetaReplyExtEmailInfo    uint16 = 0x00EB
	ICQDBQueryMetaReplyInterests       uint16 = 0x00F0
	ICQDBQueryMetaReplyAffiliations    uint16 = 0x00FA
	ICQDBQueryMetaReplyShortInfo       uint16 = 0x0104
	ICQDBQueryMetaReplyHomePageCat     uint16 = 0x010E
	ICQDBQueryMetaReplyUserFound       uint16 = 0x01A4
	ICQDBQueryMetaReplyLastUserFound   uint16 = 0x01AE
	ICQDBQueryMetaReplyXMLData         uint16 = 0x08A2
)

type SNAC_0x15_0x02_BQuery struct {
	TLVRestBlock
}

type ICQ_0x07D0_0x04BA_DBQueryMetaReqShortInfo struct {
	UIN uint32
}

type ICQ_0x07D0_0x0898_DBQueryMetaReqXMLReq struct {
	XMLRequest string `oscar:"len_prefix=uint16,nullterm"`
}

type ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions struct {
	Authorization uint8 // (1-required, 0-not required)
	WebAware      uint8 // webaware (0-no, 1-yes)
	DCPerms       uint8 // dc_perms (0-any, 1-contact, 2-authorization)
	Unknown       uint8
}

type ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN struct {
	UIN uint32
}

type ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2 struct {
	TLVRestBlock
}

type ICQ_0x07D0_0x0529_DBQueryMetaReqSearchByEmail struct {
	Email string `oscar:"len_prefix=uint16,nullterm"`
}

type ICQ_0x07D0_0x0573_DBQueryMetaReqSearchByEmail3 struct {
	TLVRestBlock
}

type ICQ_0x07D0_0x0515_DBQueryMetaReqSearchByDetails struct {
	FirstName string `oscar:"len_prefix=uint16,nullterm"`
	LastName  string `oscar:"len_prefix=uint16,nullterm"`
	NickName  string `oscar:"len_prefix=uint16,nullterm"`
}

type ICQInterests struct {
	Code    uint16
	Keyword string `oscar:"len_prefix=uint16,nullterm"`
}

type ICQEmail struct {
	Email string `oscar:"len_prefix=uint16,nullterm"`
}

type ICQ_0x07D0_0x0533_DBQueryMetaReqSearchWhitePages struct {
	FirstName           string `oscar:"len_prefix=uint16,nullterm"`
	LastName            string `oscar:"len_prefix=uint16,nullterm"`
	Nickname            string `oscar:"len_prefix=uint16,nullterm"`
	Email               string `oscar:"len_prefix=uint16,nullterm"`
	MinAge              uint16
	MaxAge              uint16
	Gender              uint8
	SpeakingLang        uint8
	City                string `oscar:"len_prefix=uint16,nullterm"`
	State               string `oscar:"len_prefix=uint16,nullterm"`
	CountryCode         uint16
	Company             string `oscar:"len_prefix=uint16,nullterm"`
	Department          string `oscar:"len_prefix=uint16,nullterm"`
	Position            string `oscar:"len_prefix=uint16,nullterm"`
	OccupationCode      uint16
	PastCode            uint16
	PastKeywords        string `oscar:"len_prefix=uint16,nullterm"`
	InterestsCode       uint16
	InterestsKeyword    string `oscar:"len_prefix=uint16,nullterm"`
	AffiliationsCode    uint16
	AffiliationsKeyword string `oscar:"len_prefix=uint16,nullterm"`
	HomePageCode        uint16
	HomePageKeywords    string `oscar:"len_prefix=uint16,nullterm"`
	SearchScope         uint8
}

type ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2 struct {
	TLVRestBlock
}

type ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo struct {
	Age          uint8 // not used because age is calculated from birthdate
	Gender       uint16
	HomePageAddr string `oscar:"len_prefix=uint16,nullterm"`
	BirthYear    uint16
	BirthMonth   uint8
	BirthDay     uint8
	Lang1        uint8
	Lang2        uint8
	Lang3        uint8
}

type ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo struct {
	City           string `oscar:"len_prefix=uint16,nullterm"`
	State          string `oscar:"len_prefix=uint16,nullterm"`
	Phone          string `oscar:"len_prefix=uint16,nullterm"`
	Fax            string `oscar:"len_prefix=uint16,nullterm"`
	Address        string `oscar:"len_prefix=uint16,nullterm"`
	ZIP            string `oscar:"len_prefix=uint16,nullterm"`
	CountryCode    uint16
	Company        string `oscar:"len_prefix=uint16,nullterm"`
	Department     string `oscar:"len_prefix=uint16,nullterm"`
	Position       string `oscar:"len_prefix=uint16,nullterm"`
	OccupationCode uint16
	WebPage        string `oscar:"len_prefix=uint16,nullterm"`
}

type ICQ_0x07D0_0x040B_DBQueryMetaReqSetEmails struct {
	Emails []struct {
		Publish uint8
		Email   string `oscar:"len_prefix=uint16,nullterm"`
	} `oscar:"count_prefix=uint8"`
}

type ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes struct {
	Notes string `oscar:"len_prefix=uint16,nullterm"`
}

type ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests struct {
	Interests []struct {
		Code    uint16
		Keyword string `oscar:"len_prefix=uint16,nullterm"`
	} `oscar:"count_prefix=uint8"`
}

type ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations struct {
	PastAffiliations []struct {
		Code    uint16
		Keyword string `oscar:"len_prefix=uint16,nullterm"`
	} `oscar:"count_prefix=uint8"`
	Affiliations []struct {
		Code    uint16
		Keyword string `oscar:"len_prefix=uint16,nullterm"`
	} `oscar:"count_prefix=uint8"`
}

type ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo struct {
	Nickname     string `oscar:"len_prefix=uint16,nullterm"`
	FirstName    string `oscar:"len_prefix=uint16,nullterm"`
	LastName     string `oscar:"len_prefix=uint16,nullterm"`
	EmailAddress string `oscar:"len_prefix=uint16,nullterm"`
	City         string `oscar:"len_prefix=uint16,nullterm"`
	State        string `oscar:"len_prefix=uint16,nullterm"`
	Phone        string `oscar:"len_prefix=uint16,nullterm"`
	Fax          string `oscar:"len_prefix=uint16,nullterm"`
	HomeAddress  string `oscar:"len_prefix=uint16,nullterm"`
	CellPhone    string `oscar:"len_prefix=uint16,nullterm"`
	ZIP          string `oscar:"len_prefix=uint16,nullterm"`
	CountryCode  uint16
	GMTOffset    uint8
	PublishEmail uint8
}

type SNAC_0x15_0x02_DBReply struct {
	TLVRestBlock
}

type ICQ_0x07DA_0x010E_DBQueryMetaReplyHomePageCat struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	Enabled    uint8
	CatCode    uint16
	Keywords   string `oscar:"len_prefix=uint16,nullterm"`
	Unknown    uint8
}

type ICQ_0x07DA_0x08A2_DBQueryMetaReplyXMLData struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	XML        string `oscar:"len_prefix=uint16,nullterm"`
}

type ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo
	Unknown     uint16
	City        string `oscar:"len_prefix=uint16,nullterm"`
	State       string `oscar:"len_prefix=uint16,nullterm"`
	CountryCode uint16
	TimeZone    uint8
}

type ICQ_0x07DA_0x00EB_DBQueryMetaReplyExtEmailInfo struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	Emails     []struct {
		Flag  uint8  // (0-publish, 1-don't)
		Email string `oscar:"len_prefix=uint16,nullterm"`
	} `oscar:"count_prefix=uint8"`
}

type ICQ_0x07DA_0x00D2_DBQueryMetaReplyWorkInfo struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo
}

type ICQ_0x07DA_0x00F0_DBQueryMetaReplyInterests struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	Interests  []struct {
		Code    uint16
		Keyword string `oscar:"len_prefix=uint16,nullterm"`
	} `oscar:"count_prefix=uint8"`
}

type ICQ_0x07DA_0x00E6_DBQueryMetaReplyNotes struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes
}

type ICQ_0x07DA_0x00FA_DBQueryMetaReplyAffiliations struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations
}

type ICQ_0x07DA_0x00C8_DBQueryMetaReplyBasicInfo struct {
	ICQMetadata
	ReqSubType   uint16
	Success      uint8
	Nickname     string `oscar:"len_prefix=uint16,nullterm"`
	FirstName    string `oscar:"len_prefix=uint16,nullterm"`
	LastName     string `oscar:"len_prefix=uint16,nullterm"`
	Email        string `oscar:"len_prefix=uint16,nullterm"`
	City         string `oscar:"len_prefix=uint16,nullterm"`
	State        string `oscar:"len_prefix=uint16,nullterm"`
	Phone        string `oscar:"len_prefix=uint16,nullterm"`
	Fax          string `oscar:"len_prefix=uint16,nullterm"`
	Address      string `oscar:"len_prefix=uint16,nullterm"`
	CellPhone    string `oscar:"len_prefix=uint16,nullterm"`
	ZIP          string `oscar:"len_prefix=uint16,nullterm"`
	CountryCode  uint16
	GMTOffset    uint8
	AuthFlag     uint8
	WebAware     uint8
	DCPerms      uint8
	PublishEmail uint8
}

type ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound struct {
	ICQMetadata
	ReqSubType uint16
	Success    uint8
	Details    ICQUserSearchRecord `oscar:"len_prefix=uint16"`
	// LastMessageFooter is set only on the last message in the batch
	LastMessageFooter *struct {
		FoundUsersLeft uint32
	} `oscar:"optional"`
}

// LastResult flags the message as the last message in the search results.
func (s *ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound) LastResult() {
	s.ReqSubType = ICQDBQueryMetaReplyLastUserFound
	s.LastMessageFooter = &struct {
		FoundUsersLeft uint32
	}{
		FoundUsersLeft: 0,
	}
}

type ICQ_0x07DA_0x0104_DBQueryMetaReplyShortInfo struct {
	ICQMetadata
	ReqSubType    uint16
	Success       uint8
	Nickname      string `oscar:"len_prefix=uint16,nullterm"`
	FirstName     string `oscar:"len_prefix=uint16,nullterm"`
	LastName      string `oscar:"len_prefix=uint16,nullterm"`
	Email         string `oscar:"len_prefix=uint16,nullterm"`
	Authorization uint8
	Unknown       uint8
	Gender        uint8
}

type ICQ_0x0041_DBQueryOfflineMsgReply struct {
	ICQMetadata
	SenderUIN uint32
	Year      uint16
	Month     uint8
	Day       uint8
	Hour      uint8
	Minute    uint8
	MsgType   uint8
	Flags     uint8
	Message   string `oscar:"len_prefix=uint16,nullterm"`
}

type ICQ_0x0042_DBQueryOfflineMsgReplyLast struct {
	ICQMetadata
	DroppedMessages uint8
}

type ICQMetadataWithSubType struct {
	ICQMetadata
	Optional *struct {
		ReqSubType uint16
	} `oscar:"optional"`
}

type ICQMetadata struct {
	UIN     uint32
	ReqType uint16
	Seq     uint16
}

// ICQMessageRequestEnvelope is a helper struct that provides syntactic sugar for
// unmarshaling an ICQ message into a little-endian byte array.
type ICQMessageRequestEnvelope struct {
	Body []byte `oscar:"len_prefix=uint16"`
}

// ICQMessageReplyEnvelope is a helper struct that provides syntactic sugar for
// marshaling an ICQ message into a little-endian byte array.
type ICQMessageReplyEnvelope struct {
	Message any `oscar:"len_prefix=uint16"`
}

type ICQUserSearchRecord struct {
	UIN           uint32
	Nickname      string `oscar:"len_prefix=uint16,nullterm"`
	FirstName     string `oscar:"len_prefix=uint16,nullterm"`
	LastName      string `oscar:"len_prefix=uint16,nullterm"`
	Email         string `oscar:"len_prefix=uint16,nullterm"`
	Authorization uint8
	OnlineStatus  uint16
	Gender        uint8
	Age           uint16
}

//
// 0x17: BUCP
//

const (
	BUCPErr                      uint16 = 0x0001
	BUCPLoginRequest             uint16 = 0x0002
	BUCPLoginResponse            uint16 = 0x0003
	BUCPRegisterRequest          uint16 = 0x0004
	BUCPChallengeRequest         uint16 = 0x0006
	BUCPChallengeResponse        uint16 = 0x0007
	BUCPAsasnRequest             uint16 = 0x0008
	BUCPSecuridRequest           uint16 = 0x000A
	BUCPRegistrationImageRequest uint16 = 0x000C
)

type SNAC_0x17_0x02_BUCPLoginRequest struct {
	TLVRestBlock
}

type SNAC_0x17_0x03_BUCPLoginResponse struct {
	TLVRestBlock
}

type SNAC_0x17_0x06_BUCPChallengeRequest struct {
	TLVRestBlock
}

type SNAC_0x17_0x07_BUCPChallengeResponse struct {
	AuthKey string `oscar:"len_prefix=uint16"`
}

//
// 0x18: Alert
//

const (
	AlertErr                       uint16 = 0x0001
	AlertSetAlertRequest           uint16 = 0x0002
	AlertSetAlertReply             uint16 = 0x0003
	AlertGetSubsRequest            uint16 = 0x0004
	AlertGetSubsResponse           uint16 = 0x0005
	AlertNotifyCapabilities        uint16 = 0x0006
	AlertNotify                    uint16 = 0x0007
	AlertGetRuleRequest            uint16 = 0x0008
	AlertGetRuleReply              uint16 = 0x0009
	AlertGetFeedRequest            uint16 = 0x000A
	AlertGetFeedReply              uint16 = 0x000B
	AlertRefreshFeed               uint16 = 0x000D
	AlertEvent                     uint16 = 0x000E
	AlertQogSnac                   uint16 = 0x000F
	AlertRefreshFeedStock          uint16 = 0x0010
	AlertNotifyTransport           uint16 = 0x0011
	AlertSetAlertRequestV2         uint16 = 0x0012
	AlertSetAlertReplyV2           uint16 = 0x0013
	AlertTransitReply              uint16 = 0x0014
	AlertNotifyAck                 uint16 = 0x0015
	AlertNotifyDisplayCapabilities uint16 = 0x0016
	AlertUserOnline                uint16 = 0x0017
)

//
// Kerberos Auth (AIM 6+)
//

const (
	KerberosLoginRequest             uint16 = 0x0002
	KerberosLoginSuccessResponse     uint16 = 0x0003
	KerberosKerberosLoginErrResponse uint16 = 0x0004

	KerberosTLVTicketRequest uint16 = 0x0002
	KerberosTLVBOSServerInfo uint16 = 0x0003
	KerberosTLVHostname      uint16 = 0x0005
	KerberosTLVCookie        uint16 = 0x0006
	KerberosTLVConnSettings  uint16 = 0x008E

	KerberosConnUseSSL uint16 = 0x0002

	KerberosErrAuthFailure uint16 = 0x0401
)

// SNAC_0x050C_0x0002_KerberosLoginRequest represents a Kerberos-like login request
// sent by the AIM client as part of the OSCAR authentication handshake using SNAC(0x050C, 0x0002).
type SNAC_0x050C_0x0002_KerberosLoginRequest struct {
	// RequestID is a client-generated identifier that matches the one echoed in the server response.
	RequestID uint32

	// ClientIP is the client's IPv4 address in network byte order.
	ClientIP uint32

	// ClientCOOLVersionMajor is the major version of the AIM client "COOL" protocol.
	ClientCOOLVersionMajor uint32

	// ClientCOOLVersionMinor is the minor version of the AIM client "COOL" protocol.
	ClientCOOLVersionMinor uint32

	// PaddingOrZero is always observed as 0x00000000 and may be reserved/padding.
	PaddingOrZero uint32

	// KerberosPayload contains TLV-encoded data, typically including the AP-REQ (TLV 0x0005).
	KerberosPayload TLVBlock

	// LocaleFlags1 appears to contain locale or encoding hints, possibly bitflags.
	LocaleFlags1 uint32

	// LocaleFlags2 is another locale- or feature-related field, typically zero.
	LocaleFlags2 uint32

	// CountryCode is the user's ISO 3166-1 alpha-2 country code (e.g., "US").
	CountryCode string `oscar:"len_prefix=uint16"`

	// LanguageCode is the user's ISO 639-1 language code (e.g., "en").
	LanguageCode string `oscar:"len_prefix=uint16"`

	// ServiceContextBlock is a TLV block containing client realm and service info.
	ServiceContextBlock TLVBlock

	// VersionOrFlags is likely a protocol feature version or flag mask (exact meaning unknown).
	VersionOrFlags uint32

	// AuthType is a 1-byte value (usually 0x00 or 0x01), possibly denoting password type or encoding.
	AuthType byte

	// ClientPrincipal is the Kerberos principal name (username).
	ClientPrincipal string `oscar:"len_prefix=uint16"`

	// ServicePrincipal is the Kerberos service string (e.g., "im/boss").
	ServicePrincipal string `oscar:"len_prefix=uint16"`

	// Reserved1 is typically zero; possibly a padding or reserved field.
	Reserved1 uint32

	// RealmCount is typically 0x0002; may indicate how many realms or tickets are requested.
	RealmCount uint16

	// TicketRequestMetadata is a TLV block describing requested tickets (e.g., realm, lifetime, enctype).
	TicketRequestMetadata TLVBlock
}

// SNAC_0x050C_0x0003_KerberosLoginSuccessResponse represents the server's response to a successful
// Kerberos-like login request in AIM's OSCAR protocol. It includes the client identity and issued tickets.
type SNAC_0x050C_0x0003_KerberosLoginSuccessResponse struct {
	// RequestID matches the KerberosRequestID from the original client request (for correlation).
	RequestID uint32

	// Epoch is a server-issued timestamp indicating when the client was authenticated.
	// This is often used as the start time for ticket validity.
	Epoch uint32

	// Reserved is a 4-byte field, usually zero. Possibly reserved for future use or alignment.
	Reserved uint32

	// ClientPrincipal is the Kerberos principal name of the authenticated client.
	ClientPrincipal string `oscar:"len_prefix=uint16"`

	// ClientRealm is the Kerberos realm in which the client was authenticated (e.g., "AOL").
	ClientRealm string `oscar:"len_prefix=uint16"`

	// Tickets contains one or more issued Kerberos tickets, including service tickets and/or a TGT.
	// These are encoded in ASN.1 DER and include session keys, expiration, and encrypted blobs.
	Tickets []KerberosTicket `oscar:"count_prefix=uint16"`

	// Extensions is a TLVBlock containing optional metadata. May include:
	// - Client capabilities
	// - Locales or language tags
	// - Echoed usernames
	// - Additional authentication hints
	Extensions TLVBlock
}

// SNAC_0x050C_0x0004_KerberosLoginErrResponse represents a login failure response
// sent by the AIM server in reply to a Kerberos-style login attempt (SNAC 0x050C/0x0002).
//
// This SNAC is typically sent when authentication fails due to an invalid password,
// unknown screen name, or protocol-level issues. It includes a human-readable message
// and an error code, along with optional TLV metadata.
type SNAC_0x050C_0x0004_KerberosLoginErrResponse struct {
	// KerbRequestID matches the KerberosRequestID from the original login request,
	// allowing the client to correlate the response to the appropriate attempt.
	KerbRequestID uint32

	// ScreenName is the screen name the client attempted to authenticate as.
	// This is echoed back by the server for clarity/debugging.
	ScreenName string `oscar:"len_prefix=uint16"`

	// ErrCode is a 2-byte error code indicating the reason for login failure.
	// The only supported value is 0x0401, which indicates an invalid username
	// or password.
	ErrCode uint16

	// Message is a UTF-8 string providing a user-facing explanation of the error
	// (e.g., "Invalid screen name or password").
	Message string `oscar:"len_prefix=uint16"`

	// Unknown1 is an unknown flag.
	Unknown1 uint32

	// Metadata is a TLVBlock that may contain additional metadata about the failure.
	Metadata TLVBlock
}

// KerberosLoginRequestTicket appears inside TLV 0x0002 of the
// Ticket-Request Metadata block that the AIM client bundles into
// its "Kerberos Login Request" (SNAC 0x050C/0x0002).
type KerberosLoginRequestTicket struct {
	// Marker might indicate the payload type.
	Marker uint32

	// Version might indicate the internal structure version.
	Version uint16

	// Flags contains unknown flags.
	Flags uint32

	// Unknown is an unknown field.
	Unknown uint16

	// Password holds the user’s password.
	Password []byte `oscar:"len_prefix=uint16"`

	// PasswordMetadata may hold additional metadata about the password.
	PasswordMetadata TLVBlock
}

// KerberosTicket represents one service ticket returned inside the
// SNAC(0x050C, 0x0003) "Kerberos Login Success" response.
//
// TicketBlob follows the general layout of an RFC 4120 Ticket,
// but is delivered in AIM’s TLV wrapper rather than a full KRB-TGS-REP.
type KerberosTicket struct {
	// PVNO is the Kerberos protocol-version number carried
	// in the ticket header.  In Kerberos V5 this is always 0x0005.
	PVNO uint16

	// EncTicket is the raw ASN.1 DER-encoded Ticket structure
	// (encrypted to the service key).  Length is given by the preceding
	// uint16 in the OSCAR stream.
	EncTicket []byte `oscar:"len_prefix=uint16"`

	// TicketRealm is the realm to which the service principal belongs
	// (e.g. "AOL").
	TicketRealm string `oscar:"len_prefix=uint16"`

	// ServicePrincipal is the complete service-principal name for which
	// the ticket is valid (e.g. "im/boss").
	ServicePrincipal string `oscar:"len_prefix=uint16"`

	// ClientRealm is the Kerberos realm of the authenticated user.
	ClientRealm string `oscar:"len_prefix=uint16"`

	// ClientPrincipal is the principal name inside that realm.
	ClientPrincipal string `oscar:"len_prefix=uint16"`

	// KVNO (Key Version Number) tells the service which
	// long-term key to use when decrypting EncTicket.
	KVNO uint8

	// SessionKey is the clear-text session key that the KDC also placed,
	// encrypted, inside EncTicket.  Provided here for the client’s
	// convenience so it doesn’t have to decrypt the ticket itself.
	SessionKey []byte `oscar:"len_prefix=uint16"`

	// Unknown1 is typically zero. Possibly reserved or unused.
	Unknown1 uint32

	// Unknown2 is a possible bitfield.
	Unknown2 uint32

	// AuthTime is the time when the initial authentication occurred (UNIX epoch).
	AuthTime uint32

	// StartTime is when the ticket becomes valid (UNIX epoch).
	StartTime uint32

	// EndTime is when the ticket expires (UNIX epoch).
	EndTime uint32

	// RenewTill is likely the latest time the ticket can be renewed (UNIX epoch).
	RenewTill uint32

	// Unknown5 is a possible bitfield.
	Unknown4 uint32

	// Unknown5 is a possible bitfield.
	Unknown5 uint32

	// Unknown6 is a possible bitfield.
	Unknown6 uint32

	// ConnectionMetadata holds metadata used for the next connection (IP address, cookie, etc).
	ConnectionMetadata TLVBlock
}

// KerberosBOSServerInfo provides the client with connection parameters for contacting
// the BOS (Basic OSCAR Service) server.
//
// This TLV is typically returned by the server inside a successful Kerberos login response
// (SNAC 0x050C/0x0003).
type KerberosBOSServerInfo struct {
	// Unknown may signify a version or feature flag block.
	Unknown uint16

	// ConnectionInfo is a TLV block defining the next server to contact (BOS).
	// Includes IP address, port, session cookie, and other required fields for login.
	ConnectionInfo TLVBlock
}

//
// Misc
//

type TLVUserInfo struct {
	ScreenName   string `oscar:"len_prefix=uint8"`
	WarningLevel uint16
	TLVBlock
}

func (t TLVUserInfo) IsAway() bool {
	flags, _ := t.Uint16BE(OServiceUserInfoUserFlags)
	return flags&OServiceUserFlagUnavailable == OServiceUserFlagUnavailable
}

type FeedbagItem struct {
	Name    string `oscar:"len_prefix=uint16"`
	GroupID uint16
	ItemID  uint16
	ClassID uint16
	TLVLBlock
}

// ICQDCInfo represents ICQ direct connect settings.
type ICQDCInfo struct {
	IP                      uint32
	Port                    uint32
	DCType                  uint8
	ProtoVersion            uint16
	AuthCookie              uint32
	WebPort                 uint32
	ClientFutures           uint32
	LastUpdateTime          uint32
	LastExtInfoUpdateTime   uint32
	LastExtStatusUpdateTime uint32
	Unknown                 uint16
}
