package foodgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// OServiceService provides functionality for the OService food group, which
// provides an assortment of services useful across multiple food groups.
type OServiceService struct {
	buddyBroadcaster buddyBroadcaster
	cfg              config.Config // todo remove
	logger           *slog.Logger
	snacRateLimits   wire.SNACRateLimits
	timeNow          func() time.Time

	chatRoomManager       ChatRoomRegistry
	cookieIssuer          CookieBaker
	messageRelayer        MessageRelayer
	chatMessageRelayer    ChatMessageRelayer
	profileManager        ProfileManager
	offlineMessageManager OfflineMessageManager
}

// NewOServiceService creates a new instance of NewOServiceService.
func NewOServiceService(
	cfg config.Config,
	messageRelayer MessageRelayer,
	logger *slog.Logger,
	cookieIssuer CookieBaker,
	chatRoomManager ChatRoomRegistry,
	relationshipFetcher RelationshipFetcher,
	sessionRetriever SessionRetriever,
	bartItemManager BARTItemManager,
	snacRateLimits wire.SNACRateLimits,
	chatMessageRelayer ChatMessageRelayer,
	profileManager ProfileManager,
	offlineMessageManager OfflineMessageManager,
) *OServiceService {
	return &OServiceService{
		cookieIssuer:          cookieIssuer,
		messageRelayer:        messageRelayer,
		buddyBroadcaster:      newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		cfg:                   cfg,
		logger:                logger,
		snacRateLimits:        snacRateLimits,
		timeNow:               time.Now,
		chatRoomManager:       chatRoomManager,
		chatMessageRelayer:    chatMessageRelayer,
		profileManager:        profileManager,
		offlineMessageManager: offlineMessageManager,
	}
}

// ClientVersions informs the server what food group versions the client
// supports and returns to the client what food group versions it supports.
// This method simply regurgitates versions supplied by the client in inBody
// back to the client in a OServiceHostVersions SNAC. The server doesn't
// attempt to accommodate any particular food group version. The server
// implicitly accommodates any food group version for Windows AIM clients 5.x.
// It returns SNAC wire.OServiceHostVersions containing the server's supported
// food group versions followed by SNAC wire.OServiceMotd containing Message of
// the Day. MOTD is sent here because some clients such as Jimm wait for it
// before sending RateParamsQuery, causing the login flow to stall if omitted.
// todo this documentation
func (s OServiceService) ClientVersions(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x01_0x17_OServiceClientVersions) []wire.SNACMessage {
	var versions [wire.MDir + 1]uint16

	if len(inBody.Versions)%2 != 0 {
		s.logger.ErrorContext(ctx, "got uneven food group length")
		return nil
	}

	for i := 0; i < len(inBody.Versions); i += 2 {
		fg := inBody.Versions[i]
		if fg < wire.OService || fg > wire.MDir {
			s.logger.ErrorContext(ctx, "invalid food group ID", "id", fg)
			continue
		}
		ver := inBody.Versions[i+1]
		if ver < 1 {
			s.logger.ErrorContext(ctx, "invalid food group version", "version", ver)
			continue
		}
		versions[fg] = ver
	}

	instance.SetFoodGroupVersions(versions)

	return []wire.SNACMessage{
		{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostVersions,
				RequestID: inFrame.RequestID,
			},
			Body: wire.SNAC_0x01_0x18_OServiceHostVersions{
				Versions: inBody.Versions,
			},
		},
		{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceMotd,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x13_OServiceMOTD{
				MessageType: 0x0004,
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceTLVTagsMOTDMessage, "Welcome to Open OSCAR Server"),
					},
				},
			},
		},
	}
}

// RateParamsQuery returns SNAC rate limits. It returns SNAC
// wire.OServiceRateParamsReply containing rate limits for all food groups
// supported by this server.
//
// The purpose of this method is to convey per-SNAC server-side rate limits to
// the client. The response consists of two main parts: rate classes and rate
// groups. Rate classes define limits based on specific parameters, while rate
// groups associate these limits with relevant SNAC types.
//
// The current implementation does not enforce server-side rate limiting.
// Instead, the provided values inform the client about the recommended
// client-side rate limits.
//
// AIM clients silently fail when they expect a rate limit rule that does not
// exist in this response. When support for a new food group is added to the
// server, update this function accordingly.
func (s OServiceService) RateParamsQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) wire.SNACMessage {
	// not contain LastTime and CurrentStatus fields.
	var limits = wire.SNAC_0x01_0x07_OServiceRateParamsReply{
		RateClasses: []wire.RateParamsSNAC{},
		RateGroups: []struct {
			ID    uint16
			Pairs []struct {
				FoodGroup uint16
				SubGroup  uint16
			} `oscar:"count_prefix=uint16"`
		}{
			{
				ID: 1,
				Pairs: []struct {
					FoodGroup uint16
					SubGroup  uint16
				}{},
			},
			{
				ID: 2,
				Pairs: []struct {
					FoodGroup uint16
					SubGroup  uint16
				}{},
			},
			{
				ID: 3,
				Pairs: []struct {
					FoodGroup uint16
					SubGroup  uint16
				}{},
			},
			{
				ID: 4,
				Pairs: []struct {
					FoodGroup uint16
					SubGroup  uint16
				}{},
			},
			{
				ID: 5,
				Pairs: []struct {
					FoodGroup uint16
					SubGroup  uint16
				}{},
			},
		},
	}

	for _, class := range instance.RateLimitStates() {
		str := wire.RateParamsSNAC{
			ID:              uint16(class.ID),
			WindowSize:      uint32(class.WindowSize),
			ClearLevel:      uint32(class.ClearLevel),
			AlertLevel:      uint32(class.AlertLevel),
			LimitLevel:      uint32(class.LimitLevel),
			DisconnectLevel: uint32(class.DisconnectLevel),
			CurrentLevel:    uint32(class.CurrentLevel),
			MaxLevel:        uint32(class.MaxLevel),
		}
		if instance.FoodGroupVersions()[wire.OService] > 1 {
			str.V2Params = &struct {
				LastTime      uint32
				DroppingSNACs uint8
			}{
				LastTime: uint32(s.timeNow().Add(-time.Second).Unix()),
			}
		}
		limits.RateClasses = append(limits.RateClasses, str)
	}

	for snacClass := range s.snacRateLimits.All() {
		classID := int(snacClass.RateLimitClass) - 1
		limits.RateGroups[classID].Pairs = append(limits.RateGroups[classID].Pairs,
			struct {
				FoodGroup uint16
				SubGroup  uint16
			}{FoodGroup: snacClass.FoodGroup, SubGroup: snacClass.SubGroup})
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceRateParamsReply,
			RequestID: inFrame.RequestID,
		},
		Body: limits,
	}
}

// UserInfoQuery returns SNAC wire.OServiceUserInfoUpdate containing
// the user's info.
func (s OServiceService) UserInfoQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceUserInfoUpdate,
			RequestID: inFrame.RequestID,
		},
		Body: newOServiceUserInfoUpdate(instance),
	}
}

// SetUserInfoFields updates user info fields (e.g., invisible, away) and broadcasts
// presence changes to buddies. Returns an updated user info message.
func (s OServiceService) SetUserInfoFields(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields) (wire.SNACMessage, error) {
	if status, hasStatus := inBody.Uint32BE(wire.OServiceUserInfoStatus); hasStatus {
		instance.SetUserStatusBitmask(status)

		if instance.Session().Invisible() {
			if err := s.buddyBroadcaster.BroadcastBuddyDeparted(ctx, instance); err != nil {
				return wire.SNACMessage{}, err
			}
		} else {
			if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), instance.Session().TLVUserInfo()); err != nil {
				return wire.SNACMessage{}, err
			}
		}
	}

	// reflect the status of this instance back to the caller, even though
	// it does not reflect aggregated state of the session. this is necessary
	// for the "invisible" button to properly toggle on the client.
	info := instance.Session().TLVUserInfo()
	info.Replace(wire.NewTLVBE(wire.OServiceUserInfoStatus, instance.UserStatusBitmask()))

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceUserInfoUpdate,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{
			UserInfo: []wire.TLVUserInfo{info},
		},
	}, nil
}

// IdleNotification sets the user idle time.
// Set session idle time to the value of bodyIn.IdleTime. Return a user arrival
// message to all users who have this user on their buddy list.
func (s OServiceService) IdleNotification(ctx context.Context, instance *state.SessionInstance, inBody wire.SNAC_0x01_0x11_OServiceIdleNotification) error {
	if inBody.IdleTime == 0 {
		instance.UnsetIdle()
	} else {
		instance.SetIdle(time.Duration(inBody.IdleTime) * time.Second)
	}
	return s.buddyBroadcaster.BroadcastBuddyArrived(ctx, instance.IdentScreenName(), instance.Session().TLVUserInfo())
}

// SetPrivacyFlags sets client privacy settings. Currently, there's no action
// to take when these flags are set. This method simply logs the flags set by
// the client.
func (s OServiceService) SetPrivacyFlags(ctx context.Context, inBody wire.SNAC_0x01_0x14_OServiceSetPrivacyFlags) {
	attrs := slog.Group("request",
		slog.String("food_group", wire.FoodGroupName(wire.OService)),
		slog.String("sub_group", wire.SubGroupName(wire.OService, wire.OServiceSetPrivacyFlags)))

	if inBody.MemberFlag() {
		s.logger.LogAttrs(ctx, slog.LevelDebug, "client set member privacy flag, but we're not going to do anything", attrs)
	}
	if inBody.IdleFlag() {
		s.logger.LogAttrs(ctx, slog.LevelDebug, "client set idle privacy flag, but we're not going to do anything", attrs)
	}
}

// ProbeReq responds to client probe requests. Some ICQ clients send probe
// requests to test server connectivity before authenticating. This returns a
// simple ProbeAck to indicate the server is responsive.
func (s OServiceService) ProbeReq(ctx context.Context, inFrame wire.SNACFrame) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceProbeAck,
			RequestID: inFrame.RequestID,
		},
	}
}

// RateParamsSubAdd subscribes to rate parameter changes. AOL's OSCAR spec says
// that notifications will be queued after calling this method. I don't see the
// point of doing that since all clients appear to call RateParamsQuery at
// sign-on for all rate classes.
func (s OServiceService) RateParamsSubAdd(ctx context.Context, instance *state.SessionInstance, inBody wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd) {
	ids := make([]wire.RateLimitClassID, 0, len(inBody.ClassIDs))

	for _, id := range inBody.ClassIDs {
		if id < 1 || id > 5 {
			s.logger.DebugContext(ctx, "snac class ID out of range")
			continue
		}
		ids = append(ids, wire.RateLimitClassID(id))
	}

	if len(ids) == 0 {
		return
	}

	s.logger.DebugContext(ctx, "subscribing to rate limit updates", "classes", ids)
	instance.Session().SubscribeRateLimits(ids)
}

// HostOnline returns SNAC wire.OServiceHostOnline containing the list of food
// groups supported by the particular service.
func (s OServiceService) HostOnline(service uint16) wire.SNACMessage {
	switch service {
	case wire.Admin:
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
				FoodGroups: []uint16{
					wire.OService,
					wire.Admin,
				},
			},
		}
	case wire.Alert:
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
				FoodGroups: []uint16{
					wire.Alert,
					wire.OService,
				},
			},
		}
	case wire.BART:
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
				FoodGroups: []uint16{
					wire.BART,
					wire.OService,
				},
			},
		}
	case wire.BOS:
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
				FoodGroups: []uint16{
					wire.Alert,
					wire.BART,
					wire.Buddy,
					wire.Feedbag,
					wire.ICBM,
					wire.ICQ,
					wire.Locate,
					wire.OService,
					wire.PermitDeny,
					wire.UserLookup,
					wire.Invite,
					wire.Popup,
					wire.Stats,
				},
			},
		}
	case wire.Chat:
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
				FoodGroups: []uint16{
					wire.OService,
					wire.Chat,
				},
			},
		}
	case wire.ChatNav:
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
				FoodGroups: []uint16{
					wire.ChatNav,
					wire.OService,
				},
			},
		}
	case wire.ODir:
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostOnline,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
				FoodGroups: []uint16{
					wire.ODir,
					wire.OService,
				},
			},
		}
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceErr,
		},
	}
}

// RateLimitUpdates produces update messages reflecting any recent changes in
// rate limit class params or rate limit states for the current session.
// Changes are reported relative to the previous invocation for this session.
// Only newly observed transitions or updated rate parameters will be included.
func (s OServiceService) RateLimitUpdates(ctx context.Context, instance *state.SessionInstance, now time.Time) []wire.SNACMessage {
	msgs := make([]wire.SNACMessage, 0, 5)
	classDelta, stateDelta := instance.Session().ObserveRateChanges(now)

	for _, curRate := range classDelta {
		s.logger.DebugContext(ctx, "rate limit class changed", "class", curRate.ID)
		msgs = append(msgs, buildRateLimitUpdate(1, curRate, instance, now))
	}

	for _, curRate := range stateDelta {
		s.logger.DebugContext(ctx, "rate limit state changed",
			"class", curRate.ID,
			"state", curRate.CurrentStatus)
		var code uint16
		switch curRate.CurrentStatus {
		case wire.RateLimitStatusLimited:
			code = 3
		case wire.RateLimitStatusAlert:
			code = 2
		case wire.RateLimitStatusClear:
			code = 4
		case wire.RateLimitStatusDisconnect:
			s.logger.DebugContext(ctx, "rate limit status disconnected, no point in returning status update")
			continue
		}

		msgs = append(msgs, buildRateLimitUpdate(code, curRate, instance, now))
	}

	return msgs
}

// buildRateLimitUpdate constructs a SNAC message notifying the client of a rate limit
// threshold update or a change in rate limiting status for a specific class.
//
// The message format varies depending on the client's supported protocol version.
// If OService version 2 or higher is supported, additional metadata such as
// time since last status change and whether SNACs are currently being dropped
// will be included.
func buildRateLimitUpdate(code uint16, curRate state.RateClassState, instance *state.SessionInstance, now time.Time) wire.SNACMessage {
	var droppingSNACs uint8
	if curRate.CurrentStatus == wire.RateLimitStatusLimited {
		droppingSNACs = 1
	}

	rate := wire.RateParamsSNAC{
		ID:              uint16(curRate.ID),
		WindowSize:      uint32(curRate.WindowSize),
		ClearLevel:      uint32(curRate.ClearLevel),
		AlertLevel:      uint32(curRate.AlertLevel),
		LimitLevel:      uint32(curRate.LimitLevel),
		DisconnectLevel: uint32(curRate.DisconnectLevel),
		CurrentLevel:    uint32(curRate.CurrentLevel),
		MaxLevel:        uint32(curRate.MaxLevel),
	}

	if instance.FoodGroupVersions()[wire.OService] > 1 {
		rate.V2Params = &struct {
			LastTime      uint32
			DroppingSNACs uint8
		}{
			LastTime:      uint32(max(0, now.Unix()-curRate.LastTime.Unix())),
			DroppingSNACs: droppingSNACs,
		}
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceRateParamChange,
			RequestID: wire.ReqIDFromServer,
		},
		Body: wire.SNAC_0x01_0x0A_OServiceRateParamsChange{
			Code: code,
			Rate: rate,
		},
	}
}

// ServiceRequest handles service discovery, providing a host name and metadata
// for connecting to the food group service specified in inFrame.
func (s OServiceService) ServiceRequest(ctx context.Context, service uint16, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x01_0x04_OServiceServiceRequest, listener config.Listener) (wire.SNACMessage, error) {
	if service != wire.BOS {
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceErr,
				RequestID: inFrame.RequestID,
			},
			Body: wire.SNACError{
				Code: wire.ErrorCodeNotSupportedByHost,
			},
		}, nil
	}

	if inBody.HasTag(wire.OserviceTLVTagsSSLUseSSL) && !listener.HasSSL {
		s.logger.DebugContext(ctx, "service request for SSL but the listener doesn't support SSL")
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceErr,
				RequestID: inFrame.RequestID,
			},
			Body: wire.SNACError{
				Code: wire.ErrorCodeGeneralFailure,
			},
		}, nil
	}

	fnIssueCookie := func(val any) ([]byte, error) {
		buf := &bytes.Buffer{}
		if err := wire.MarshalBE(val, buf); err != nil {
			return nil, err
		}
		return s.cookieIssuer.Issue(buf.Bytes())
	}

	cookie, err := func() ([]byte, error) {
		switch inBody.FoodGroup {
		case wire.Admin, wire.Alert, wire.BART, wire.ChatNav, wire.ODir:
			return fnIssueCookie(state.ServerCookie{
				Service:    inBody.FoodGroup,
				ScreenName: instance.DisplayScreenName(),
				SessionNum: instance.Num(),
			})
		case wire.Chat:
			roomMeta, ok := inBody.Bytes(0x01)
			if !ok {
				return nil, errors.New("missing room info")
			}

			roomSNAC := wire.SNAC_0x01_0x04_TLVRoomInfo{}
			if err := wire.UnmarshalBE(&roomSNAC, bytes.NewBuffer(roomMeta)); err != nil {
				return nil, err
			}

			room, err := s.chatRoomManager.ChatRoomByCookie(ctx, roomSNAC.Cookie)
			if err != nil {
				return nil, fmt.Errorf("unable to retrieve room info: %w", err)
			}

			return fnIssueCookie(state.ServerCookie{
				Service:    wire.Chat,
				ChatCookie: room.Cookie(),
				ScreenName: instance.DisplayScreenName(),
				SessionNum: instance.Num(),
			})
		default:
			return nil, nil
		}
	}()

	if err != nil {
		return wire.SNACMessage{}, err
	}

	if cookie == nil {
		s.logger.InfoContext(ctx, "client service request for unsupported service", "food_group", wire.FoodGroupName(inBody.FoodGroup))
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceErr,
				RequestID: inFrame.RequestID,
			},
			Body: wire.SNACError{
				Code: wire.ErrorCodeServiceUnavailable,
			},
		}, nil
	}

	host := listener.BOSAdvertisedHostPlain
	stateCode := wire.OServiceServiceResponseSSLStateNotUsed

	if inBody.HasTag(wire.OserviceTLVTagsSSLUseSSL) {
		host = listener.BOSAdvertisedHostSSL
		stateCode = wire.OServiceServiceResponseSSLStateResume
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceServiceResponse,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.OServiceTLVTagsGroupID, inBody.FoodGroup),
					wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, host),
					wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, cookie),
					wire.NewTLVBE(wire.OServiceTLVTagsSSLState, stateCode),
				},
			},
		},
	}, nil
}

// ClientOnline runs when the current user is ready to join.
// If BOS:
//   - Announce current user's arrival to users who have the current user on their buddy list
//
// If Chat:
//   - Send current user the chat room metadata
//   - Announce current user's arrival to other chat room participants
//   - Send current user the chat room participant list
func (s OServiceService) ClientOnline(ctx context.Context, service uint16, inBody wire.SNAC_0x01_0x02_OServiceClientOnline, instance *state.SessionInstance) error {
	instance.SetSignonComplete()

	switch service {
	case wire.BOS:
		if err := s.buddyBroadcaster.BroadcastVisibility(ctx, instance, nil, false); err != nil {
			return fmt.Errorf("unable to send buddy arrival notification: %w", err)
		}

		msg := wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Stats,
				SubGroup:  wire.StatsSetMinReportInterval,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{
				MinReportInterval: 1,
			},
		}
		s.messageRelayer.RelayToScreenName(ctx, instance.IdentScreenName(), msg)

		// set stored profile
		if instance.KerberosAuth() {
			// normally, the SupportHostSig TLV indicates that the profile should
			// be stored server-side. however, some AIM 6 clients expect server-side
			// profiles but do not send this TLV. in order to cover all bases, just
			// save the profile for all kerberos-based clients.
			profile, err := s.profileManager.Profile(ctx, instance.IdentScreenName())
			if err != nil {
				return fmt.Errorf("unable to reload profile: %w", err)
			}

			if !profile.IsZero() {
				instance.SetProfile(profile)

				// notify client that the server-side profile is ready for retrieval
				s.messageRelayer.RelayToSelf(ctx, instance, wire.SNACMessage{
					Frame: wire.SNACFrame{
						FoodGroup: wire.OService,
						SubGroup:  wire.OServiceUserInfoUpdate,
					},
					Body: newOServiceUserInfoUpdate(instance),
				})
			}
		}

		if instance.OfflineMsgCount() > 0 {
			if err := s.sendOfflineMessageNotification(ctx, instance); err != nil {
				return fmt.Errorf("send offline message notification: %w", err)
			}
		}

		if !s.cfg.DisableMultiLoginNotif && instance.Session().InstanceCount() > 1 {
			if err := s.sendMultipleInstanceNotification(ctx, instance); err != nil {
				return fmt.Errorf("send multiple instance notification: %w", err)
			}
		}

		return nil
	case wire.Chat:
		room, err := s.chatRoomManager.ChatRoomByCookie(ctx, instance.ChatRoomCookie())
		if err != nil {
			return fmt.Errorf("error getting chat room: %w", err)
		}

		// Do not change the order of the following 3 methods. macOS client v4.0.9
		// requires this exact sequence, otherwise the chat session prematurely
		// closes seconds after users join a chat room.
		setOnlineChatUsers(ctx, instance, s.chatMessageRelayer)
		sendChatRoomInfoUpdate(ctx, instance, s.chatMessageRelayer, room)
		alertUserJoined(ctx, instance, s.chatMessageRelayer)
		return nil
	default:
		s.logger.DebugContext(ctx, "client is online", "group_versions", inBody.GroupVersions)
		return nil
	}
}

// sendOfflineMessageNotification sends an IM notifying the user of their
// offline message count and resets the count to zero.
func (s OServiceService) sendOfflineMessageNotification(ctx context.Context, instance *state.SessionInstance) error {
	if err := s.offlineMessageManager.SetOfflineMsgCount(ctx, instance.IdentScreenName(), 0); err != nil {
		return fmt.Errorf("deleting offline messages: %w", err)
	}

	msg := fmt.Sprintf("You just received %d IM(s) while you were offline. If you do "+
		"not wish to receive offline messages, please go to "+
		"<a href=\"https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=RDdQw4w9WgXcQ&start_radio=1&pp=ygUJcmljayByb2xsoAcB\">IM Settings</a>.", instance.OfflineMsgCount())

	message, err := systemMessage(msg)
	if err != nil {
		return err
	}

	s.messageRelayer.RelayToScreenName(ctx, instance.IdentScreenName(), message)

	instance.Session().SetOfflineMsgCount(0)

	return nil
}

// sendMultipleInstanceNotification sends an IM notifying the user that their
// account is signed in to multiple locations.
func (s OServiceService) sendMultipleInstanceNotification(ctx context.Context, instance *state.SessionInstance) error {
	msg := fmt.Sprintf("Your screen name (%s) is now signed into Open OSCAR Server in %d locations. Click "+
		"<a href=\"https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=RDdQw4w9WgXcQ&start_radio=1&pp=ygUJcmljayByb2xsoAcB\">here</a> "+
		"for more information.", instance.DisplayScreenName(), instance.Session().InstanceCount())

	message, err := systemMessage(msg)
	if err != nil {
		return err
	}

	s.messageRelayer.RelayToOtherInstances(ctx, instance, message)

	return nil
}

func systemMessage(msg string) (wire.SNACMessage, error) {
	frags, err := wire.ICBMFragmentList(msg)
	if err != nil {
		return wire.SNACMessage{}, fmt.Errorf("creating ICBM fragments: %w", err)
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICBM,
			SubGroup:  wire.ICBMChannelMsgToClient,
			RequestID: wire.ReqIDFromServer,
		},
		Body: wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
			ChannelID: wire.ICBMChannelIM,
			TLVUserInfo: wire.TLVUserInfo{
				ScreenName: "OOS System Msg",
			},
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: []wire.TLV{
					wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags),
				},
			},
		},
	}, nil
}

// newOServiceUserInfoUpdate constructs SNAC(0x01,0x0F) for user info updates.
// For OService version 4 and above, it appends a duplicate TLVUserInfo block.
// AIM 6+ expects at least two user info blocks to support multi-session:
// the first represents overall state; subsequent ones represent client instances.
func newOServiceUserInfoUpdate(instance *state.SessionInstance) wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate {
	info := instance.Session().TLVUserInfo()
	userInfo := []wire.TLVUserInfo{info}

	// set registration date
	userInfo[0].Append(wire.NewTLVBE(wire.OServiceUserInfoMemberSince, uint32(instance.Session().MemberSince().Unix())))
	// set sign-on time
	userInfo[0].Append(wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(instance.SignonTime().Unix())))
	// set current session length (seconds)
	userInfo[0].Append(wire.NewTLVBE(wire.OServiceUserInfoOnlineTime, uint32(time.Since(instance.SignonTime()).Seconds())))

	if instance.FoodGroupVersions()[wire.OService] >= 4 {

		userInfo[0].Append(wire.NewTLVBE(wire.OServiceUserInfoMyInstanceNum, []byte{instance.Num()}))

		for _, instance := range instance.Session().Instances() {
			instanceInfo := wire.TLVUserInfo{
				ScreenName:   instance.DisplayScreenName().String(),
				WarningLevel: instance.Warning(),
			}

			// sign-in timestamp
			instanceInfo.Append(wire.NewTLVBE(wire.OServiceUserInfoSignonTOD, uint32(instance.SignonTime().Unix())))

			// use the first instance as a template
			uFlags := instance.UserInfoBitmask()

			if instance.Session().Away() {
				uFlags |= wire.OServiceUserFlagUnavailable
			}
			instanceInfo.Append(wire.NewTLVBE(wire.OServiceUserInfoUserFlags, uFlags))

			// user status flags - user-level (shared)
			var statusBitmask uint32
			if instance.Invisible() {
				statusBitmask |= wire.OServiceUserStatusInvisible
			}
			instanceInfo.Append(wire.NewTLVBE(wire.OServiceUserInfoStatus, statusBitmask))

			if instance == instance {
				if icon, hasIcon := instance.Session().BuddyIcon(); hasIcon {
					// set buddy icon metadata, if user has buddy icon
					if icon.Type != 0 {
						instanceInfo.Append(wire.NewTLVBE(wire.OServiceUserInfoBARTInfo, icon))
					}
				}
			}

			//Get the best instance for each TLV value
			//mostCapableCaps := instance.getMostCapableCaps()
			//capabilities - show most capable instance (union of all capabilities)
			instanceInfo.Append(wire.NewTLVBE(wire.OServiceUserInfoOscarCaps, instance.Session().Caps()))

			instanceInfo.Append(wire.NewTLVBE(wire.OServiceUserInfoMySubscriptions, uint32(0)))

			if instance == instance {
				profile := instance.Profile()
				if !profile.UpdateTime.IsZero() {
					// set profile update time if the profile was set
					instanceInfo.Append(wire.NewTLVBE(wire.OServiceUserInfoSigTime, uint32(profile.UpdateTime.Unix())))
				}
			}

			instanceInfo.Append(wire.NewTLVBE(wire.OServiceUserInfoPrimaryInstance, []byte{instance.Num()}))

			userInfo = append(userInfo, instanceInfo)
		}
	}

	return wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{
		UserInfo: userInfo,
	}
}
