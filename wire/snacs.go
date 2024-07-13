package wire

import (
	"bytes"
	"errors"
	"fmt"
)

//
// Food Group Codes
//

const (
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
)

//
// Authentication
//

const (
	LoginTLVTagsScreenName          uint16 = 0x01
	LoginTLVTagsRoastedPassword     uint16 = 0x02
	LoginTLVTagsReconnectHere       uint16 = 0x05
	LoginTLVTagsAuthorizationCookie uint16 = 0x06
	LoginTLVTagsErrorSubcode        uint16 = 0x08
	LoginTLVTagsPasswordHash        uint16 = 0x25
)

const (
	LoginErrInvalidUsernameOrPassword uint16 = 0x01
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

	OServiceUserInfoUserFlags  uint16 = 0x01
	OServiceUserInfoSignonTOD  uint16 = 0x03
	OServiceUserInfoIdleTime   uint16 = 0x04
	OServiceUserInfoStatus     uint16 = 0x06
	OServiceUserInfoOscarCaps  uint16 = 0x0D
	OServiceUserInfoBARTInfo   uint16 = 0x1D
	OServiceUserInfoUserFlags2 uint16 = 0x1F

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
//   - CurrentState: Indicates whether the server is dropping SNACs for this rate class.
//
// Rate Groups:
//   - ID: Unique identifier for the rate group.
//   - Pairs: List of SNAC types associated with the rate group, including FoodGroup
//     (e.g., wire.ICBM) and SubGroup (e.g., wire.ICBMChannelMsgToHost).
type SNAC_0x01_0x07_OServiceRateParamsReply struct {
	RateClasses []struct {
		ID              uint16
		WindowSize      uint32
		ClearLevel      uint32
		AlertLevel      uint32
		LimitLevel      uint32
		DisconnectLevel uint32
		CurrentLevel    uint32
		MaxLevel        uint32
		LastTime        uint32
		CurrentState    uint8
	} `oscar:"count_prefix=uint16"`
	RateGroups []struct {
		ID    uint16
		Pairs []struct {
			FoodGroup uint16
			SubGroup  uint16
		} `oscar:"count_prefix=uint16"`
	}
}

type SNAC_0x01_0x08_OServiceRateParamsSubAdd struct {
	TLVRestBlock
}

type SNAC_0x01_0x0F_OServiceUserInfoUpdate struct {
	TLVUserInfo
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
	WatcherScreenNames string `oscar:"len_prefix=uint8"`
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

//
// 0x04: ICBM
//

const (
	ICBMErr                uint16 = 0x0001
	ICBMAddParameters      uint16 = 0x0002
	ICBMDelParameters      uint16 = 0x0003
	ICBMParameterQuery     uint16 = 0x0004
	ICBMParameterReply     uint16 = 0x0005
	ICBMChannelMsgToHost   uint16 = 0x0006
	ICBMChannelMsgToClient uint16 = 0x0007
	ICBMEvilRequest        uint16 = 0x0008
	ICBMEvilReply          uint16 = 0x0009
	ICBMMissedCalls        uint16 = 0x000A
	ICBMClientErr          uint16 = 0x000B
	ICBMHostAck            uint16 = 0x000C
	ICBMSinStored          uint16 = 0x000D
	ICBMSinListQuery       uint16 = 0x000E
	ICBMSinListReply       uint16 = 0x000F
	ICBMSinRetrieve        uint16 = 0x0010
	ICBMSinDelete          uint16 = 0x0011
	ICBMNotifyRequest      uint16 = 0x0012
	ICBMNotifyReply        uint16 = 0x0013
	ICBMClientEvent        uint16 = 0x0014
	ICBMSinReply           uint16 = 0x0017

	ICBMTLVAOLIMData      uint16 = 0x02
	ICBMTLVRequestHostAck uint16 = 0x03
	ICBMTLVAutoResponse   uint16 = 0x04
	ICBMTLVData           uint16 = 0x05
	ICBMTLVStore          uint16 = 0x06
	ICBMTLVICQblob        uint16 = 0x07
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
)

// ICBMFragment represents an ICBM message component.
type ICBMFragment struct {
	ID      uint8
	Version uint8
	Payload []byte `oscar:"len_prefix=uint16"`
}

// ICBMMessage represents the text component of an ICBM message.
type ICBMMessage struct {
	Charset  uint16
	Language uint16
	Text     []byte
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
func ICBMFragmentList(text string) ([]ICBMFragment, error) {
	msg := ICBMMessage{
		Charset:  ICBMMessageEncodingASCII,
		Language: 0, // not clear what this means, but it works
		Text:     []byte(text),
	}
	msgBuf := bytes.Buffer{}
	if err := MarshalBE(msg, &msgBuf); err != nil {
		return nil, fmt.Errorf("unable to marshal ICBM message: %w", err)
	}

	return []ICBMFragment{
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
	var frags []ICBMFragment
	if err := UnmarshalBE(&frags, bytes.NewBuffer(b)); err != nil {
		return "", fmt.Errorf("unable to unmarshal ICBM fragment: %w", err)
	}

	for _, frag := range frags {
		if frag.ID == 1 { // 1 = message text
			msg := ICBMMessage{}
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
	ChatTLVSenderInformation    uint16 = 0x03
	ChatTLVMessageInformation   uint16 = 0x05
	ChatTLVEnableReflectionFlag uint16 = 0x06

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

type TLVUserInfo struct {
	ScreenName   string `oscar:"len_prefix=uint8"`
	WarningLevel uint16
	TLVBlock
}

type FeedbagItem struct {
	Name    string `oscar:"len_prefix=uint16"`
	GroupID uint16
	ItemID  uint16
	ClassID uint16
	TLVLBlock
}
