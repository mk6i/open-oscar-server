package wire

import (
	"iter"
	"time"
)

type (
	// RateLimitClassID identifies a rate limit class.
	RateLimitClassID uint16

	// RateLimitStatus represents a session's current rate limiting state.
	RateLimitStatus uint8
)

const (
	// RateLimitStatusLimited indicates the session is currently rate-limited
	// and should not send further messages in this class.
	RateLimitStatusLimited RateLimitStatus = 1

	// RateLimitStatusAlert indicates the session is approaching the rate limit threshold
	// and may soon be limited if activity continues.
	RateLimitStatusAlert RateLimitStatus = 2

	// RateLimitStatusClear indicates the session is under the limit and in good standing.
	RateLimitStatusClear RateLimitStatus = 3

	// RateLimitStatusDisconnect indicates the session has exceeded a critical threshold
	// and should be forcibly disconnected.
	RateLimitStatusDisconnect RateLimitStatus = 4
)

// NewRateLimitClasses creates a new RateLimitClasses instance from a fixed array
// of 5 RateClass definitions.
//
// Each RateClass must have a unique ID from 1 to 5, and the array is expected
// to be ordered such that classes[ID-1] corresponds to RateClass.ID == ID.
// No validation is performed on the input.
func NewRateLimitClasses(classes [5]RateClass) RateLimitClasses {
	return RateLimitClasses{
		classes: classes,
	}
}

// DefaultRateLimitClasses returns the default SNAC rate limit classes used at
// one point by the original AIM service, as memorialized by the iserverd
// project.
func DefaultRateLimitClasses() RateLimitClasses {
	return RateLimitClasses{
		classes: [5]RateClass{
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
		},
	}
}

// RateLimitClasses stores a fixed set of rate limit class definitions.
//
// Each RateClass defines thresholds and behavior for computing moving-average-based
// rate limits. This struct provides access to individual classes by ID
// or to the full set.
type RateLimitClasses struct {
	classes [5]RateClass // Indexed by class ID - 1
}

// Get returns the RateClass associated with the given class ID.
//
// The class ID must be between 1 and 5 inclusive. Calling Get with an invalid
// ID will panic.
func (r RateLimitClasses) Get(ID RateLimitClassID) RateClass {
	return r.classes[ID-1]
}

// All returns all defined RateClass entries in order of their class IDs.
func (r RateLimitClasses) All() [5]RateClass {
	return r.classes
}

// DefaultSNACRateLimits returns the default SNAC rate limit mapping used at
// one point by the original AIM service, as memorialized by the iserverd
// project.
func DefaultSNACRateLimits() SNACRateLimits {
	return SNACRateLimits{
		lookup: map[uint16]map[uint16]RateLimitClassID{
			OService: {
				OServiceErr:               1,
				OServiceClientOnline:      1,
				OServiceHostOnline:        1,
				OServiceServiceRequest:    1,
				OServiceServiceResponse:   1,
				OServiceRateParamsQuery:   1,
				OServiceRateParamsReply:   1,
				OServiceRateParamsSubAdd:  1,
				OServiceRateDelParamSub:   1,
				OServiceRateParamChange:   1,
				OServicePauseReq:          1,
				OServicePauseAck:          1,
				OServiceResume:            1,
				OServiceUserInfoQuery:     1,
				OServiceUserInfoUpdate:    1,
				OServiceEvilNotification:  1,
				OServiceIdleNotification:  1,
				OServiceMigrateGroups:     1,
				OServiceMotd:              1,
				OServiceSetPrivacyFlags:   1,
				OServiceWellKnownUrls:     1,
				OServiceNoop:              1,
				OServiceClientVersions:    1,
				OServiceHostVersions:      1,
				OServiceMaxConfigQuery:    1,
				OServiceMaxConfigReply:    1,
				OServiceStoreConfig:       1,
				OServiceConfigQuery:       1,
				OServiceConfigReply:       1,
				OServiceSetUserInfoFields: 1,
				OServiceProbeReq:          1,
				OServiceProbeAck:          1,
				OServiceBartReply:         1,
				OServiceBartQuery2:        1,
				OServiceBartReply2:        1,
			},
			Locate: {
				LocateErr:                  1,
				LocateRightsQuery:          1,
				LocateRightsReply:          1,
				LocateSetInfo:              1,
				LocateUserInfoQuery:        3,
				LocateUserInfoReply:        1,
				LocateWatcherSubRequest:    1,
				LocateWatcherNotification:  1,
				LocateSetDirInfo:           4,
				LocateSetDirReply:          1,
				LocateGetDirInfo:           4,
				LocateGetDirReply:          1,
				LocateGroupCapabilityQuery: 1,
				LocateGroupCapabilityReply: 1,
				LocateSetKeywordInfo:       1,
				LocateSetKeywordReply:      1,
				LocateGetKeywordInfo:       1,
				LocateGetKeywordReply:      1,
				LocateFindListByEmail:      1,
				LocateFindListReply:        1,
				LocateUserInfoQuery2:       1,
			},
			Buddy: {
				BuddyErr:                 1,
				BuddyRightsQuery:         1,
				BuddyRightsReply:         1,
				BuddyAddBuddies:          2,
				BuddyDelBuddies:          2,
				BuddyWatcherListQuery:    1,
				BuddyWatcherListResponse: 1,
				BuddyWatcherSubRequest:   1,
				BuddyWatcherNotification: 1,
				BuddyRejectNotification:  1,
				BuddyArrived:             1,
				BuddyDeparted:            1,
				BuddyAddTempBuddies:      1,
				BuddyDelTempBuddies:      1,
			},
			ICBM: {
				ICBMErr:                1,
				ICBMAddParameters:      1,
				ICBMDelParameters:      1,
				ICBMParameterQuery:     1,
				ICBMParameterReply:     1,
				ICBMChannelMsgToHost:   3,
				ICBMChannelMsgToClient: 1,
				ICBMEvilRequest:        1,
				ICBMEvilReply:          1,
				ICBMMissedCalls:        1,
				ICBMClientErr:          1,
				ICBMHostAck:            1,
				ICBMSinStored:          1,
				ICBMSinListQuery:       1,
				ICBMSinListReply:       1,
				ICBMOfflineRetrieve:    1,
				ICBMSinDelete:          1,
				ICBMNotifyRequest:      1,
				ICBMNotifyReply:        1,
				ICBMClientEvent:        1,
			},
			Advert: {
				AdvertErr:      1,
				AdvertAdsQuery: 1,
				AdvertAdsReply: 1,
			},
			Invite: {
				InviteErr:          1,
				InviteRequestQuery: 1,
				InviteRequestReply: 1,
			},
			Admin: {
				AdminErr:                1,
				AdminInfoQuery:          1,
				AdminInfoReply:          1,
				AdminInfoChangeRequest:  1,
				AdminInfoChangeReply:    1,
				AdminAcctConfirmRequest: 1,
				AdminAcctConfirmReply:   1,
				AdminAcctDeleteRequest:  1,
				AdminAcctDeleteReply:    1,
			},
			Popup: {
				PopupErr:     1,
				PopupDisplay: 1,
			},
			PermitDeny: {
				PermitDenyErr:                      1,
				PermitDenyRightsQuery:              1,
				PermitDenyRightsReply:              1,
				PermitDenySetGroupPermitMask:       1,
				PermitDenyAddPermListEntries:       2,
				PermitDenyDelPermListEntries:       2,
				PermitDenyAddDenyListEntries:       2,
				PermitDenyDelDenyListEntries:       2,
				PermitDenyBosErr:                   1,
				PermitDenyAddTempPermitListEntries: 1,
				PermitDenyDelTempPermitListEntries: 1,
			},
			UserLookup: {
				UserLookupErr:         1,
				UserLookupFindByEmail: 1,
				UserLookupFindReply:   1,
			},
			Stats: {
				StatsErr:                  1,
				StatsSetMinReportInterval: 1,
				StatsReportEvents:         1,
				StatsReportAck:            1,
			},
			Translate: {
				TranslateErr:     1,
				TranslateRequest: 1,
				TranslateReply:   1,
			},
			ChatNav: {
				ChatNavErr:                 1,
				ChatNavRequestChatRights:   1,
				ChatNavRequestExchangeInfo: 1,
				ChatNavRequestRoomInfo:     1,
				ChatNavRequestMoreRoomInfo: 1,
				ChatNavRequestOccupantList: 1,
				ChatNavSearchForRoom:       1,
				ChatNavCreateRoom:          1,
				ChatNavNavInfo:             1,
			},
			Chat: {
				ChatErr:                1,
				ChatRoomInfoUpdate:     1,
				ChatUsersJoined:        1,
				ChatUsersLeft:          1,
				ChatChannelMsgToHost:   2,
				ChatChannelMsgToClient: 1,
				ChatEvilRequest:        1,
				ChatEvilReply:          1,
				ChatClientErr:          1,
			},
			ODir: {
				ODirErr:              1,
				ODirInfoQuery:        1,
				ODirInfoReply:        1,
				ODirKeywordListQuery: 1,
			},
			BART: {
				BARTErr:            1,
				BARTUploadQuery:    1,
				BARTDownloadQuery:  1,
				BARTDownload2Query: 1,
			},
			Feedbag: {
				FeedbagErr:                      1,
				FeedbagRightsQuery:              1,
				FeedbagRightsReply:              1,
				FeedbagQuery:                    1,
				FeedbagQueryIfModified:          1,
				FeedbagReply:                    1,
				FeedbagUse:                      1,
				FeedbagInsertItem:               1,
				FeedbagUpdateItem:               1,
				FeedbagDeleteItem:               1,
				FeedbagInsertClass:              1,
				FeedbagUpdateClass:              1,
				FeedbagDeleteClass:              1,
				FeedbagStatus:                   1,
				FeedbagReplyNotModified:         1,
				FeedbagDeleteUser:               1,
				FeedbagStartCluster:             1,
				FeedbagEndCluster:               1,
				FeedbagAuthorizeBuddy:           1,
				FeedbagPreAuthorizeBuddy:        1,
				FeedbagPreAuthorizedBuddy:       1,
				FeedbagRemoveMe:                 1,
				FeedbagRemoveMe2:                1,
				FeedbagRequestAuthorizeToHost:   1,
				FeedbagRequestAuthorizeToClient: 1,
				FeedbagRespondAuthorizeToHost:   1,
				FeedbagRespondAuthorizeToClient: 1,
				FeedbagBuddyAdded:               1,
				FeedbagRequestAuthorizeToBadog:  1,
				FeedbagRespondAuthorizeToBadog:  1,
				FeedbagBuddyAddedToBadog:        1,
				0x0020:                          1, // unknown
				FeedbagTestSnac:                 1,
				FeedbagForwardMsg:               1,
				FeedbagIsAuthRequiredQuery:      1,
				FeedbagIsAuthRequiredReply:      1,
				FeedbagRecentBuddyUpdate:        1,
				0x0026:                          1, // unknown
				0x0027:                          1, // unknown
				0x0028:                          1, // unknown
			},
			ICQ: {
				ICQErr:     1,
				ICQDBQuery: 1,
				ICQDBReply: 1,
			},
			BUCP: {
				BUCPErr:                      1,
				BUCPLoginRequest:             1,
				BUCPRegisterRequest:          1,
				BUCPChallengeRequest:         1,
				BUCPAsasnRequest:             1,
				BUCPSecuridRequest:           1,
				BUCPRegistrationImageRequest: 1,
			},
			Alert: {
				AlertErr:                       1,
				AlertSetAlertRequest:           1,
				AlertGetSubsRequest:            1,
				AlertNotifyCapabilities:        1,
				AlertNotify:                    1,
				AlertGetRuleRequest:            1,
				AlertGetFeedRequest:            1,
				AlertRefreshFeed:               1,
				AlertEvent:                     1,
				AlertQogSnac:                   1,
				AlertRefreshFeedStock:          1,
				AlertNotifyTransport:           1,
				AlertSetAlertRequestV2:         1,
				AlertNotifyAck:                 1,
				AlertNotifyDisplayCapabilities: 1,
				AlertUserOnline:                1,
			},
		},
	}
}

// SNACRateLimits maps SNACs to rate limit classes.
type SNACRateLimits struct {
	lookup map[uint16]map[uint16]RateLimitClassID
}

// All returns an iterator over all SNAC message types and their associated
// rate limit classes.
func (rg SNACRateLimits) All() iter.Seq[struct {
	FoodGroup      uint16
	SubGroup       uint16
	RateLimitClass RateLimitClassID
}] {
	return func(yield func(struct {
		FoodGroup      uint16
		SubGroup       uint16
		RateLimitClass RateLimitClassID
	}) bool) {
		for foodGroup, subGroups := range rg.lookup {
			for subGroup, classID := range subGroups {
				match := struct {
					FoodGroup      uint16
					SubGroup       uint16
					RateLimitClass RateLimitClassID
				}{
					FoodGroup:      foodGroup,
					SubGroup:       subGroup,
					RateLimitClass: classID,
				}
				if !yield(match) {
					return
				}
			}
		}
	}
}

// RateClassLookup returns the RateLimitClassID associated with the given SNAC
// food group and subgroup.
//
// If a match is found, it returns the associated rate class ID and true.
// If not found, it returns false.
func (rg SNACRateLimits) RateClassLookup(foodGroup uint16, subGroup uint16) (RateLimitClassID, bool) {
	group, ok := rg.lookup[foodGroup]
	if !ok {
		return 0, false
	}
	class, ok := group[subGroup]
	if !ok {
		return 0, false
	}
	return class, true
}

// RateClass defines the configuration for computing rate-limiting behavior
// using an exponential moving average over time.
//
// Each incoming event contributes a time delta (in ms), and the average inter-event
// time is calculated over a moving window of the most recent N events (`WindowSize`).
// The resulting average is compared against threshold levels to determine the
// current rate status (e.g., limited, alert, clear, or disconnect).
type RateClass struct {
	ID              RateLimitClassID // Unique identifier for this rate class.
	WindowSize      int32            // Number of samples used in the moving average calculation.
	ClearLevel      int32            // If rate-limited and average exceeds this, rate-limiting is lifted.
	AlertLevel      int32            // If average is below this, an alert state is triggered.
	LimitLevel      int32            // If average is below this, rate-limiting is triggered.
	DisconnectLevel int32            // If average is below this, the session should be disconnected.
	MaxLevel        int32            // Maximum allowed value for the moving average.
}

// CheckRateLimit calculates a rate limit status and a new moving average based on
// the time elapsed between the last event and the current event, a specified rate
// class, and whether the system is currently limited.
//
// Parameters:
//
//	lastTime:    The timestamp of the previous event.
//	currentTime: The current timestamp.
//	rateClass:   Configuration for rate limiting thresholds and window size.
//	currentAvg:  The current moving average of the elapsed time between events.
//	limitedNow:  Indicates if the system is currently under a rate limit.
//
// Returns:
//
//	status: The new RateLimitStatus, which can be one of:
//	        - RateLimitStatusDisconnect (when the moving average is smallest)
//	        - RateLimitStatusLimited
//	        - RateLimitStatusAlert
//	        - RateLimitStatusClear (when the moving average is largest)
//	newAvg:  The updated moving average of the elapsed time.
//
// The function updates currentAvg by combining the current interval (the difference
// between currentTime and lastTime, in milliseconds) with the previous average. If
// the system was already limited (limitedNow == true), the function checks whether
// currentAvg has risen above the ClearLevel threshold to move the status back to
// RateLimitStatusClear. If not, it keeps the status at RateLimitStatusLimited.
//
// If the system was not already limited, the updated currentAvg is compared against
// DisconnectLevel, LimitLevel, and AlertLevel thresholds of the provided RateClass
// to determine the appropriate rate limit status.
func CheckRateLimit(
	lastTime time.Time,
	currentTime time.Time,
	rateClass RateClass,
	currentAvg int32,
	limitedNow bool,
) (RateLimitStatus, int32) {

	// calculate the time elapsed in milliseconds since the last event
	elapsedMs := int32(currentTime.Sub(lastTime).Milliseconds())

	// update the moving average
	newAvg := (currentAvg*(rateClass.WindowSize-1) + elapsedMs) / rateClass.WindowSize

	// clamp the moving average to the maximum allowable level
	if newAvg > rateClass.MaxLevel {
		newAvg = rateClass.MaxLevel
	}

	var status RateLimitStatus

	switch {
	case newAvg < rateClass.DisconnectLevel:
		status = RateLimitStatusDisconnect
	case limitedNow && newAvg >= rateClass.ClearLevel:
		status = RateLimitStatusClear
	case limitedNow:
		status = RateLimitStatusLimited
	case newAvg < rateClass.LimitLevel:
		status = RateLimitStatusLimited
	case newAvg < rateClass.AlertLevel:
		status = RateLimitStatusAlert
	default:
		status = RateLimitStatusClear
	}

	return status, newAvg
}
