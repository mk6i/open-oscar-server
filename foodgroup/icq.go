package foodgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
	"golang.org/x/text/encoding"
)

var errICQBadRequest = errors.New("bad ICQ request")

// NewICQService creates an instance of ICQService.
func NewICQService(
	messageRelayer MessageRelayer,
	finder ICQUserFinder,
	userUpdater ICQUserUpdater,
	logger *slog.Logger,
	sessionRetriever SessionRetriever,
	offlineMessageManager OfflineMessageManager,
	legacyCharset encoding.Encoding,
) *ICQService {
	return &ICQService{
		messageRelayer:        messageRelayer,
		userFinder:            finder,
		userUpdater:           userUpdater,
		logger:                logger,
		sessionRetriever:      sessionRetriever,
		offlineMessageManager: offlineMessageManager,
		legacyCharset:         legacyCharset,
		timeNow:               time.Now,
		forwardICQAuthEvents: func(ctx context.Context, sender state.IdentScreenName, recipient state.IdentScreenName, authMsg wire.ICBMCh4Message) error {
			return fmt.Errorf("no ICBMService available")
		},
	}
}

// ICQService provides functionality for the ICQ food group.
type ICQService struct {
	userFinder            ICQUserFinder
	logger                *slog.Logger
	messageRelayer        MessageRelayer
	sessionRetriever      SessionRetriever
	userUpdater           ICQUserUpdater
	timeNow               func() time.Time
	offlineMessageManager OfflineMessageManager
	legacyCharset         encoding.Encoding
	forwardICQAuthEvents  func(ctx context.Context, sender state.IdentScreenName, recipient state.IdentScreenName, authMsg wire.ICBMCh4Message) error
}

// BridgeFeedbagService enables the ICBMService to forward legacy ICQ events to
// the ICBM service.
func (s *ICQService) BridgeFeedbagService(service *FeedbagService) {
	s.forwardICQAuthEvents = service.ForwardICQAuthEvents
}

func (s *ICQService) DeleteMsgReq(ctx context.Context, instance *state.SessionInstance, seq uint16) error {
	if err := s.offlineMessageManager.DeleteMessages(ctx, instance.IdentScreenName()); err != nil {
		return fmt.Errorf("deleting messages: %w", err)
	}
	return nil
}

func (s *ICQService) FindByICQName(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0515_DBQueryMetaReqSearchByDetails, seq uint16) error {
	res, err := s.userFinder.FindByICQName(ctx, inBody.FirstName, inBody.LastName, inBody.NickName)

	if err != nil {
		s.logger.Error("FindByICQName failed", "err", err.Error())
		return s.reportSearchFailure(ctx, instance, seq, inFrame.RequestID)
	}
	if len(res) == 0 {
		return s.reportNoSearchResults(ctx, instance, seq, inFrame.RequestID)
	}

	for i := 0; i < len(res); i++ {
		last := i == len(res)-1
		resp := s.createResult(res[i])
		if err := s.replySearchHit(ctx, instance, resp, inFrame.RequestID, last, seq); err != nil {
			return err
		}
	}

	return nil
}

func (s *ICQService) FindByICQEmail(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0529_DBQueryMetaReqSearchByEmail, seq uint16) error {
	res, err := s.userFinder.FindByICQEmail(ctx, inBody.Email)

	switch {
	case errors.Is(err, state.ErrNoUser):
		return s.reportNoSearchResults(ctx, instance, seq, inFrame.RequestID)
	case err != nil:
		return s.reportSearchFailure(ctx, instance, seq, inFrame.RequestID)
	default:
		return s.replySearchHit(ctx, instance, s.createResult(res), inFrame.RequestID, true, seq)
	}
}

func (s *ICQService) FindByEmail3(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0573_DBQueryMetaReqSearchByEmail3, seq uint16) error {
	b, hasEmail := inBody.Bytes(wire.ICQTLVTagsEmail)
	if !hasEmail {
		return errors.New("unable to get email from request")
	}

	email := wire.ICQEmail{}
	if err := wire.UnmarshalLE(&email, bytes.NewReader(b)); err != nil {
		return fmt.Errorf("unmarshal email: %w", err)
	}
	res, err := s.userFinder.FindByICQEmail(ctx, email.Email)

	switch {
	case errors.Is(err, state.ErrNoUser):
		return s.reportNoSearchResults(ctx, instance, seq, inFrame.RequestID)
	case err != nil:
		s.logger.Error("FindByICQEmail failed", "err", err.Error())
		return s.reportSearchFailure(ctx, instance, seq, inFrame.RequestID)
	default:
		return s.replySearchHit(ctx, instance, s.createResult(res), inFrame.RequestID, true, seq)
	}
}

func (s *ICQService) FindByICQInterests(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0533_DBQueryMetaReqSearchWhitePages, seq uint16) error {

	interests := strings.Split(inBody.InterestsKeyword, ",")
	res, err := s.userFinder.FindByICQInterests(ctx, inBody.InterestsCode, interests)

	if err != nil {
		return s.reportSearchFailure(ctx, instance, seq, inFrame.RequestID)
	}
	if len(res) == 0 {
		return s.reportNoSearchResults(ctx, instance, seq, inFrame.RequestID)
	}

	for i := 0; i < len(res); i++ {
		last := i == len(res)-1
		resp := s.createResult(res[i])
		if err := s.replySearchHit(ctx, instance, resp, inFrame.RequestID, last, seq); err != nil {
			return err
		}
	}

	return nil
}

func (s *ICQService) FindByWhitePages2(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2, seq uint16) error {
	var criteria state.ICQUserSearchCriteria

	if uin, ok := inBody.Uint32LE(wire.ICQTLVTagsUIN); ok {
		criteria.UIN = &uin
	}
	if sNick, ok := inBody.ICQString(wire.ICQTLVTagsNickname); ok {
		criteria.NickName = &sNick
	}
	if sFirst, ok := inBody.ICQString(wire.ICQTLVTagsFirstName); ok {
		criteria.FirstName = &sFirst
	}
	if sLast, ok := inBody.ICQString(wire.ICQTLVTagsLastName); ok {
		criteria.LastName = &sLast
	}
	if sEmail, ok := inBody.ICQString(wire.ICQTLVTagsEmail); ok {
		criteria.Email = &sEmail
	}
	if b, ok := inBody.Bytes(wire.ICQTLVTagsAgeRangeSearch); ok {
		var ar struct {
			MinAge uint16
			MaxAge uint16
		}
		if err := wire.UnmarshalLE(&ar, bytes.NewReader(b)); err != nil {
			return fmt.Errorf("unmarshaling age range: %w", err)
		}
		criteria.MinAge = &ar.MinAge
		criteria.MaxAge = &ar.MaxAge
	}
	if gender, ok := inBody.Uint8(wire.ICQTLVTagsGender); ok {
		criteria.Gender = &gender
	}
	if lang, ok := inBody.Uint8(wire.ICQTLVTagsSpokenLanguage); ok {
		criteria.SpokenLanguage = &lang
	}
	if city, ok := inBody.ICQString(wire.ICQTLVTagsHomeCityName); ok {
		criteria.City = &city
	}
	if st, ok := inBody.ICQString(wire.ICQTLVTagsHomeStateAbbr); ok {
		criteria.State = &st
	}
	if cc, ok := inBody.Uint16LE(wire.ICQTLVTagsHomeCountryCode); ok {
		criteria.CountryCode = &cc
	}
	if company, ok := inBody.ICQString(wire.ICQTLVTagsWorkCompanyName); ok {
		criteria.Company = &company
	}
	if departmentName, ok := inBody.ICQString(wire.ICQTLVTagsWorkDepartmentName); ok {
		criteria.DepartmentName = &departmentName
	}
	if position, ok := inBody.ICQString(wire.ICQTLVTagsWorkPositionTitle); ok {
		criteria.Position = &position
	}
	if occ, ok := inBody.Uint16LE(wire.ICQTLVTagsWorkOccupationCode); ok {
		criteria.OccupationCode = &occ
	}
	if b, ok := inBody.Bytes(wire.ICQTLVTagsInterestsNode); ok {
		var n struct {
			Code    uint16
			Keyword string `oscar:"len_prefix=uint16,nullterm"`
		}
		if err := wire.UnmarshalLE(&n, bytes.NewReader(b)); err != nil {
			return fmt.Errorf("unmarshaling interests node: %w", err)
		}
		if n.Keyword != "" {
			criteria.InterestsKeywords = strings.Split(n.Keyword, ",")
			criteria.InterestsCode = &n.Code
		}
	}
	if b, ok := inBody.Bytes(wire.ICQTLVTagsAffiliationsNode); ok {
		var n struct {
			Code    uint16
			Keyword string `oscar:"len_prefix=uint16,nullterm"`
		}
		if err := wire.UnmarshalLE(&n, bytes.NewReader(b)); err != nil {
			return fmt.Errorf("unmarshaling affiliations node: %w", err)
		}
		if n.Keyword != "" {
			criteria.AffiliationsKeywords = strings.Split(n.Keyword, ",")
			for i := range criteria.AffiliationsKeywords {
				criteria.AffiliationsKeywords[i] = strings.TrimSpace(criteria.AffiliationsKeywords[i])
			}
			criteria.AffiliationsCode = &n.Code
		}
	}
	if b, ok := inBody.Bytes(wire.ICQTLVTagsPastInfoNode); ok {
		var n struct {
			Code    uint16
			Keyword string `oscar:"len_prefix=uint16,nullterm"`
		}
		if err := wire.UnmarshalLE(&n, bytes.NewReader(b)); err != nil {
			return fmt.Errorf("unmarshaling past info node: %w", err)
		}
		if n.Keyword != "" {
			criteria.PastAffiliationsKeywords = strings.Split(n.Keyword, ",")
			for i := range criteria.PastAffiliationsKeywords {
				criteria.PastAffiliationsKeywords[i] = strings.TrimSpace(criteria.PastAffiliationsKeywords[i])
			}
			criteria.PastAffiliationsCode = &n.Code
		}
	}
	if b, ok := inBody.Bytes(wire.ICQTLVTagsHomepageCategoryKeywords); ok {
		var p struct {
			Index    uint16
			Keywords string `oscar:"len_prefix=uint16,nullterm"`
		}
		if err := wire.UnmarshalLE(&p, bytes.NewReader(b)); err != nil {
			return fmt.Errorf("unmarshaling homepage category keywords: %w", err)
		}
		criteria.HomePageCategoryIndex = new(p.Index)
		if p.Keywords != "" {
			criteria.HomePageKeywords = strings.Split(p.Keywords, ",")
			for i := range criteria.HomePageKeywords {
				criteria.HomePageKeywords[i] = strings.TrimSpace(criteria.HomePageKeywords[i])
			}
		}
	}
	if kw, ok := inBody.ICQString(wire.ICQTLVTagsWhitepagesSearchKeywords); ok {
		criteria.AnyKeyword = &kw
	}

	onlineOnly := false
	if f, ok := inBody.Uint8(wire.ICQTLVTagsSearchOnlineUsersFlag); ok && f != 0 {
		onlineOnly = true
	}

	users, err := s.userFinder.SearchICQUsers(ctx, criteria)
	if err != nil {
		if errors.Is(err, state.ErrICQSearchEmptyCriteria) {
			return s.reportNoSearchResults(ctx, instance, seq, inFrame.RequestID)
		}
		s.logger.Error("FindByWhitePages2 failed", "err", err.Error())
		return s.reportSearchFailure(ctx, instance, seq, inFrame.RequestID)
	}

	if onlineOnly {
		var filtered []state.User
		for _, u := range users {
			if s.sessionRetriever.RetrieveSession(u.IdentScreenName) != nil {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}

	if len(users) == 0 {
		return s.reportNoSearchResults(ctx, instance, seq, inFrame.RequestID)
	}

	for i := 0; i < len(users); i++ {
		isLast := i == len(users)-1
		details := s.createResult(users[i])
		if err := s.replySearchHit(ctx, instance, details, inFrame.RequestID, isLast, seq); err != nil {
			return err
		}
	}

	return nil
}

func (s *ICQService) FindByUIN(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN, seq uint16) error {
	res, err := s.userFinder.FindByUIN(ctx, inBody.UIN)

	switch {
	case errors.Is(err, state.ErrNoUser):
		return s.reportNoSearchResults(ctx, instance, seq, inFrame.RequestID)
	case err != nil:
		s.logger.Error("FindByUIN failed", "err", err.Error())
		return s.reportSearchFailure(ctx, instance, seq, inFrame.RequestID)
	default:
		return s.replySearchHit(ctx, instance, s.createResult(res), inFrame.RequestID, true, seq)
	}
}

func (s *ICQService) FindByUIN2(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2, seq uint16) error {
	UIN, hasUIN := inBody.Uint32LE(wire.ICQTLVTagsUIN)
	if !hasUIN {
		return errors.New("unable to get UIN from request")
	}

	res, err := s.userFinder.FindByUIN(ctx, UIN)

	switch {
	case errors.Is(err, state.ErrNoUser):
		return s.reportNoSearchResults(ctx, instance, seq, inFrame.RequestID)
	case err != nil:
		s.logger.Error("FindByUIN failed", "err", err.Error())
		return s.reportSearchFailure(ctx, instance, seq, inFrame.RequestID)
	default:
		return s.replySearchHit(ctx, instance, s.createResult(res), inFrame.RequestID, true, seq)
	}
}

func (s *ICQService) FullUserInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN, seq uint16) error {

	user, err := s.userFinder.FindByUIN(ctx, inBody.UIN)
	if err != nil {
		return err
	}

	if err := s.userInfo(ctx, instance, user, inFrame.RequestID, seq, wire.SNACFlagsMoreToCome); err != nil {
		return err
	}

	if err := s.moreUserInfo(ctx, instance, user, inFrame.RequestID, seq, wire.SNACFlagsMoreToCome); err != nil {
		return err
	}

	if err := s.extraEmails(ctx, instance, inFrame.RequestID, seq, wire.SNACFlagsMoreToCome); err != nil {
		return err
	}

	if err := s.homepageCat(ctx, instance, inFrame.RequestID, seq, wire.SNACFlagsMoreToCome); err != nil {
		return err
	}

	if err := s.workInfo(ctx, instance, user, inFrame.RequestID, seq, wire.SNACFlagsMoreToCome); err != nil {
		return err
	}

	if err := s.notes(ctx, instance, user, inFrame.RequestID, seq, wire.SNACFlagsMoreToCome); err != nil {
		return err
	}

	if err := s.interests(ctx, instance, user, inFrame.RequestID, seq, wire.SNACFlagsMoreToCome); err != nil {
		return err
	}

	if err := s.affiliations(ctx, instance, user, inFrame.RequestID, seq, 0); err != nil {
		return err
	}
	return nil
}

func (s *ICQService) OfflineMsgReq(ctx context.Context, inFrame wire.SNACFrame, instance *state.SessionInstance, seq uint16) error {
	messages, err := s.offlineMessageManager.RetrieveMessages(ctx, instance.IdentScreenName())
	if err != nil {
		return fmt.Errorf("retrieving messages: %w", err)
	}

	for _, msgIn := range messages {
		if msgIn.Sender.UIN() != 0 {
			reply := wire.ICQ_0x0041_DBQueryOfflineMsgReply{
				ICQMetadata: wire.ICQMetadata{
					UIN:     instance.UIN(),
					ReqType: wire.ICQDBQueryOfflineMsgReply,
					Seq:     seq,
				},
				SenderUIN: msgIn.Sender.UIN(),
				Year:      uint16(msgIn.Sent.Year()),
				Month:     uint8(msgIn.Sent.Month()),
				Day:       uint8(msgIn.Sent.Day()),
				Hour:      uint8(msgIn.Sent.Hour()),
				Minute:    uint8(msgIn.Sent.Minute()),
			}

			switch msgIn.Message.ChannelID {
			case wire.ICBMChannelIM:
				if payload, hasIM := msgIn.Message.Bytes(wire.ICBMTLVAOLIMData); hasIM {
					// send regular IM
					// The sender's capabilities are unknown at retrieval time, so
					// the message charset alone decides the conversion. A message
					// that fails to transcode is delivered as stored.
					tlv := wire.TLV{Tag: wire.ICBMTLVAOLIMData, Value: payload}
					// ICQ doesn't appear to support Unicode offline messages, so
					// force a conversion to fallback character set
					if transcoded, err := transcodeICQMessage(s.legacyCharset, false, tlv); err != nil {
						s.logger.WarnContext(ctx, "unable to transcode offline message", "sender", msgIn.Sender, "err", err)
					} else {
						tlv = transcoded
					}
					msgText, err := wire.UnmarshalICBMMessageText(tlv.Value)
					if err != nil {
						return fmt.Errorf("unmarshalling offline message: %w", err)
					}
					reply.MsgType = wire.ICBMExtendedMsgTypePlain
					reply.Message = msgText
				}
			case wire.ICBMChannelICQ:
				if b, hasAuthReq := msgIn.Message.Bytes(wire.ICBMTLVData); hasAuthReq {
					msg := wire.ICBMCh4Message{}
					buf := bytes.NewBuffer(b)
					if err := wire.UnmarshalLE(&msg, buf); err != nil {
						return err
					}
					if msg.MessageType == wire.ICBMMsgTypeAuthReq ||
						msg.MessageType == wire.ICBMMsgTypeAuthDeny ||
						msg.MessageType == wire.ICBMMsgTypeAuthOK ||
						msg.MessageType == wire.ICBMMsgTypeAdded {
						if instance.Session().UsesFeedbag() {
							// send auth grant/deny/request SNACs instead of the legacy MSG_TYPE_*
							// ICQ messages.
							if err := s.forwardICQAuthEvents(ctx, msgIn.Sender, msgIn.Recipient, msg); err != nil {
								return fmt.Errorf("s.forwardICQAuthEvents: %w", err)
							}
							continue // do not send these messages in response
						}
					}
					reply.MsgType = msg.MessageType
					reply.Flags = msg.Flags
					reply.Message = msg.Message
				}
			}

			if reply.MsgType == 0 {
				s.logger.Info("no offline message payload for channel, skipping message",
					"channel", msgIn.Message.ChannelID,
					"sender", msgIn.Sender.UIN(),
					"recipient", msgIn.Recipient)
				continue
			}

			msgOut := wire.ICQMessageReplyEnvelope{
				Message: reply,
			}
			if err := s.replyToSelf(ctx, instance, msgOut, inFrame.RequestID, wire.SNACFlagsMoreToCome); err != nil {
				return fmt.Errorf("sending offline message: %w", err)
			}
		} else {
			// offline message sent by AIM client. this SNAC supports string
			// screen names, whereas ICQ_0x0041_DBQueryOfflineMsgReply does not.
			clientIM := wire.SNAC_0x04_0x07_ICBMChannelMsgToClient{
				Cookie:    msgIn.Message.Cookie,
				ChannelID: msgIn.Message.ChannelID,
				TLVUserInfo: wire.TLVUserInfo{
					ScreenName: msgIn.Sender.String(),
				},
				TLVRestBlock: wire.TLVRestBlock{},
			}

			for _, tlv := range msgIn.Message.TLVList {
				// The stored SNAC is whatever the sender sent. A send time it
				// carries is not ours, and TLVList lookups return the first match,
				// so it would shadow the stamp appended below.
				if tlv.Tag == wire.ICBMTLVSendTime {
					continue
				}
				// The sender's capabilities are unknown at retrieval time, so the
				// message charset alone decides the conversion. A TLV that fails
				// to transcode is delivered as stored.
				if (clientIM.ChannelID == wire.ICBMChannelIM || clientIM.ChannelID == wire.ICBMChannelMIME) &&
					tlv.Tag == wire.ICBMTLVAOLIMData {
					// ICQ doesn't appear to support Unicode offline messages, so
					// force a conversion to fallback character set
					if transcoded, err := transcodeICQMessage(s.legacyCharset, false, tlv); err != nil {
						s.logger.WarnContext(ctx, "unable to transcode offline message", "sender", msgIn.Sender, "err", err)
					} else {
						tlv = transcoded
					}
				}
				clientIM.Append(tlv)
			}
			clientIM.Append(wire.NewTLVBE(wire.ICBMTLVSendTime, uint32(msgIn.Sent.Unix())))

			// Retrieval answers the instance that asked for it, not every instance
			// of the account.
			s.messageRelayer.RelayToSelf(ctx, instance, wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMChannelMsgToClient,
					RequestID: wire.ReqIDFromServer,
				},
				Body: clientIM,
			})
		}
	}

	eofMsg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x0042_DBQueryOfflineMsgReplyLast{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryOfflineMsgReplyLast,
				Seq:     seq,
			},
			DroppedMessages: 0,
		},
	}

	if err := s.replyToSelf(ctx, instance, eofMsg, inFrame.RequestID, 0); err != nil {
		return fmt.Errorf("sending end of offline messages: %w", err)
	}

	return nil
}

func (s *ICQService) SetAffiliations(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations, seq uint16) error {
	if len(inBody.PastAffiliations) != 3 || len(inBody.Affiliations) != 3 {
		return fmt.Errorf("%w: expected 3 past affiliations and 3 affiliations", errICQBadRequest)
	}
	u := state.ICQAffiliations{
		PastCode1:       inBody.PastAffiliations[0].Code,
		PastKeyword1:    inBody.PastAffiliations[0].Keyword,
		PastCode2:       inBody.PastAffiliations[1].Code,
		PastKeyword2:    inBody.PastAffiliations[1].Keyword,
		PastCode3:       inBody.PastAffiliations[2].Code,
		PastKeyword3:    inBody.PastAffiliations[2].Keyword,
		CurrentCode1:    inBody.Affiliations[0].Code,
		CurrentKeyword1: inBody.Affiliations[0].Keyword,
		CurrentCode2:    inBody.Affiliations[1].Code,
		CurrentKeyword2: inBody.Affiliations[1].Keyword,
		CurrentCode3:    inBody.Affiliations[2].Code,
		CurrentKeyword3: inBody.Affiliations[2].Keyword,
	}

	if err := s.userUpdater.SetAffiliations(ctx, instance.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetAffiliations, inFrame.RequestID)
}

func (s *ICQService) SetBasicInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo, seq uint16) error {
	u := state.ICQBasicInfo{
		CellPhone:    inBody.CellPhone,
		CountryCode:  inBody.CountryCode,
		EmailAddress: inBody.EmailAddress,
		FirstName:    inBody.FirstName,
		GMTOffset:    inBody.GMTOffset,
		Address:      inBody.HomeAddress,
		City:         inBody.City,
		Fax:          inBody.Fax,
		Phone:        inBody.Phone,
		State:        inBody.State,
		LastName:     inBody.LastName,
		Nickname:     inBody.Nickname,
		PublishEmail: inBody.PublishEmail == wire.ICQUserFlagPublishEmailYes,
		ZIPCode:      inBody.ZIP,
	}

	if err := s.userUpdater.SetBasicInfo(ctx, instance.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetBasicInfo, inFrame.RequestID)
}

func (s *ICQService) SetEmails(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x040B_DBQueryMetaReqSetEmails, seq uint16) error {
	if len(inBody.Emails) > 0 {
		s.logger.Debug("adding additional emails is not yet supported")
	}
	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetEmails, inFrame.RequestID)
}

// SetICQInfo handles the TLV-based CLI_SET_FULLINFO (0x0C3A) request used to
// update all profile information in a single packet. The TLV chain may
// contain any subset of fields; omitted fields are preserved by loading the
// current user record and overlaying only the values that were sent. Within a
// multi-valued group (languages, interests, affiliations) any unspecified
// slots are reset when at least one TLV in that group is present, matching
// the way ICQLite tabs replace their entire group on save.
func (s *ICQService) SetICQInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0C3A_DBQueryMetaReqSetFullInfo, seq uint16) error {
	user, err := s.userFinder.FindByUIN(ctx, instance.UIN())
	if err != nil {
		return fmt.Errorf("FindByUIN: %w", err)
	}

	// Multi-valued tags are collected in encounter order and applied to
	// their target struct after the loop.
	var langTLVs []uint8
	var interestTLVs, currentAffTLVs, pastAffTLVs [][]byte

	for _, tlv := range inBody.TLVList {
		switch tlv.Tag {

		// ----- ICQBasicInfo -----
		case wire.ICQTLVTagsFirstName:
			user.ICQInfo.Basic.FirstName = tlv.ICQString()
		case wire.ICQTLVTagsLastName:
			user.ICQInfo.Basic.LastName = tlv.ICQString()
		case wire.ICQTLVTagsNickname:
			user.ICQInfo.Basic.Nickname = tlv.ICQString()
		case wire.ICQTLVTagsEmail:
			var n struct {
				Email   string `oscar:"len_prefix=uint16,nullterm"`
				Publish uint8
			}
			if err := wire.UnmarshalLE(&n, bytes.NewReader(tlv.Value)); err != nil {
				return fmt.Errorf("wire.UnmarshalLE: %w", err)
			}
			user.ICQInfo.Basic.EmailAddress = n.Email
			// publish=0 means "publish my email", matching the
			// existing ICQUserFlagPublishEmailYes (0) convention.
			user.ICQInfo.Basic.PublishEmail = n.Publish == wire.ICQUserFlagPublishEmailYes
		case wire.ICQTLVTagsHomeCityName:
			user.ICQInfo.Basic.City = tlv.ICQString()
		case wire.ICQTLVTagsHomeStateAbbr:
			user.ICQInfo.Basic.State = tlv.ICQString()
		case wire.ICQTLVTagsHomeCountryCode:
			user.ICQInfo.Basic.CountryCode = tlv.Uint16LE()
		case wire.ICQTLVTagsHomeStreetAddress:
			user.ICQInfo.Basic.Address = tlv.ICQString()
		case wire.ICQTLVTagsHomeZipCode:
			user.ICQInfo.Basic.ZIPCode = strconv.FormatUint(uint64(tlv.Uint32LE()), 10)
		case wire.ICQTLVTagsHomePhoneNumber:
			user.ICQInfo.Basic.Phone = tlv.ICQString()
		case wire.ICQTLVTagsHomeFaxNumber:
			user.ICQInfo.Basic.Fax = tlv.ICQString()
		case wire.ICQTLVTagsHomeCellularPhoneNumber:
			user.ICQInfo.Basic.CellPhone = tlv.ICQString()
		case wire.ICQTLVTagsGMTOffset:
			user.ICQInfo.Basic.GMTOffset = tlv.Uint8()
		case wire.ICQTLVTagsOriginallyFromCity:
			user.ICQInfo.Basic.OriginallyFromCity = tlv.ICQString()
		case wire.ICQTLVTagsOriginallyFromState:
			user.ICQInfo.Basic.OriginallyFromState = tlv.ICQString()
		case wire.ICQTLVTagsOriginallyFromCountryCode:
			user.ICQInfo.Basic.OriginallyFromCountryCode = tlv.Uint16LE()

		// ----- ICQMoreInfo -----
		case wire.ICQTLVTagsGender:
			user.ICQInfo.More.Gender = uint16(tlv.Uint8())
		case wire.ICQTLVTagsSpokenLanguage:
			langTLVs = append(langTLVs, tlv.Uint8())
		case wire.ICQTLVTagsBirthdayInfo:
			var n struct {
				Year  uint16
				Month uint16
				Day   uint16
			}
			if err := wire.UnmarshalLE(&n, bytes.NewReader(tlv.Value)); err != nil {
				return fmt.Errorf("wire.UnmarshalLE: %w", err)
			}
			user.ICQInfo.More.BirthYear = n.Year
			user.ICQInfo.More.BirthMonth = uint8(n.Month)
			user.ICQInfo.More.BirthDay = uint8(n.Day)
		case wire.ICQTLVTagsHomepageURL:
			user.ICQInfo.More.HomePageAddr = tlv.ICQString()

		// ----- ICQWorkInfo -----
		case wire.ICQTLVTagsWorkCompanyName:
			user.ICQInfo.Work.Company = tlv.ICQString()
		case wire.ICQTLVTagsWorkDepartmentName:
			user.ICQInfo.Work.Department = tlv.ICQString()
		case wire.ICQTLVTagsWorkPositionTitle:
			user.ICQInfo.Work.Position = tlv.ICQString()
		case wire.ICQTLVTagsWorkOccupationCode:
			user.ICQInfo.Work.OccupationCode = tlv.Uint16LE()
		case wire.ICQTLVTagsWorkStreetAddress:
			user.ICQInfo.Work.Address = tlv.ICQString()
		case wire.ICQTLVTagsWorkCityName:
			user.ICQInfo.Work.City = tlv.ICQString()
		case wire.ICQTLVTagsWorkStateName:
			user.ICQInfo.Work.State = tlv.ICQString()
		case wire.ICQTLVTagsWorkCountryCode:
			user.ICQInfo.Work.CountryCode = tlv.Uint16LE()
		case wire.ICQTLVTagsWorkZipCode:
			user.ICQInfo.Work.ZIPCode = strconv.FormatUint(uint64(tlv.Uint32LE()), 10)
		case wire.ICQTLVTagsWorkPhoneNumber:
			user.ICQInfo.Work.Phone = tlv.ICQString()
		case wire.ICQTLVTagsWorkFaxNumber:
			user.ICQInfo.Work.Fax = tlv.ICQString()
		case wire.ICQTLVTagsWorkWebpageURL:
			user.ICQInfo.Work.WebPage = tlv.ICQString()

		// ----- ICQPermissions -----
		case wire.ICQTLVTagsAuthorizationPermissions:
			// Matches the wire-struct convention used by SetPermissions:
			// authorization == 0 means "authorization required".
			user.ICQInfo.Permissions.AuthRequired = tlv.Uint8() == 0
		case wire.ICQTLVTagsShowWebStatusPermissions:
			user.ICQInfo.Permissions.WebAware = tlv.Uint8() == 1

		// ----- ICQUserNotes -----
		case wire.ICQTLVTagsNotesText:
			user.ICQInfo.Notes.Notes = tlv.ICQString()

		// ----- ICQInterests -----
		case wire.ICQTLVTagsInterestsNode: // may appear multiple times
			interestTLVs = append(interestTLVs, tlv.Value)

		// ----- ICQAffiliations -----
		case wire.ICQTLVTagsAffiliationsNode: // may appear multiple times
			currentAffTLVs = append(currentAffTLVs, tlv.Value)
		case wire.ICQTLVTagsPastInfoNode: // may appear multiple times
			pastAffTLVs = append(pastAffTLVs, tlv.Value)

		// ----- ICQHomepageCategory -----
		case wire.ICQTLVTagsHomepageCategoryKeywords:
			var n struct {
				Index       uint16
				Description string `oscar:"len_prefix=uint16,nullterm"`
			}
			if err := wire.UnmarshalLE(&n, bytes.NewReader(tlv.Value)); err != nil {
				return fmt.Errorf("wire.UnmarshalLE: %w", err)
			}
			user.ICQInfo.HomepageCategory.Index = n.Index
			user.ICQInfo.HomepageCategory.Description = n.Description
			user.ICQInfo.HomepageCategory.Enabled = true

		default:
			// Search-only or otherwise unmapped tags
			// (UIN, Age, AgeRangeSearch, WhitepagesSearchKeywords,
			// SearchOnlineUsersFlag).
			s.logger.Debug("ICQ SetICQInfo: ignoring unsupported TLV",
				"tag", fmt.Sprintf("0x%04X", tlv.Tag),
				"len", len(tlv.Value))
		}
	}

	if len(langTLVs) > 0 {
		user.ICQInfo.More.Lang1, user.ICQInfo.More.Lang2, user.ICQInfo.More.Lang3 = 0, 0, 0
		for i, v := range langTLVs {
			switch i {
			case 0:
				user.ICQInfo.More.Lang1 = v
			case 1:
				user.ICQInfo.More.Lang2 = v
			case 2:
				user.ICQInfo.More.Lang3 = v
			}
		}
	}

	if len(interestTLVs) > 0 {
		user.ICQInfo.Interests = state.ICQInterests{}
		for i, raw := range interestTLVs {
			var n struct {
				Code    uint16
				Keyword string `oscar:"len_prefix=uint16,nullterm"`
			}
			if err := wire.UnmarshalLE(&n, bytes.NewReader(raw)); err != nil {
				return fmt.Errorf("wire.UnmarshalLE: %w", err)
			}
			switch i {
			case 0:
				user.ICQInfo.Interests.Code1, user.ICQInfo.Interests.Keyword1 = n.Code, n.Keyword
			case 1:
				user.ICQInfo.Interests.Code2, user.ICQInfo.Interests.Keyword2 = n.Code, n.Keyword
			case 2:
				user.ICQInfo.Interests.Code3, user.ICQInfo.Interests.Keyword3 = n.Code, n.Keyword
			case 3:
				user.ICQInfo.Interests.Code4, user.ICQInfo.Interests.Keyword4 = n.Code, n.Keyword
			}
		}
	}

	if len(currentAffTLVs) > 0 {
		user.ICQInfo.Affiliations.CurrentCode1, user.ICQInfo.Affiliations.CurrentKeyword1 = 0, ""
		user.ICQInfo.Affiliations.CurrentCode2, user.ICQInfo.Affiliations.CurrentKeyword2 = 0, ""
		user.ICQInfo.Affiliations.CurrentCode3, user.ICQInfo.Affiliations.CurrentKeyword3 = 0, ""
		for i, raw := range currentAffTLVs {
			var n struct {
				Code    uint16
				Keyword string `oscar:"len_prefix=uint16,nullterm"`
			}
			if err := wire.UnmarshalLE(&n, bytes.NewReader(raw)); err != nil {
				return fmt.Errorf("wire.UnmarshalLE: %w", err)
			}
			switch i {
			case 0:
				user.ICQInfo.Affiliations.CurrentCode1, user.ICQInfo.Affiliations.CurrentKeyword1 = n.Code, n.Keyword
			case 1:
				user.ICQInfo.Affiliations.CurrentCode2, user.ICQInfo.Affiliations.CurrentKeyword2 = n.Code, n.Keyword
			case 2:
				user.ICQInfo.Affiliations.CurrentCode3, user.ICQInfo.Affiliations.CurrentKeyword3 = n.Code, n.Keyword
			}
		}
	}

	if len(pastAffTLVs) > 0 {
		user.ICQInfo.Affiliations.PastCode1, user.ICQInfo.Affiliations.PastKeyword1 = 0, ""
		user.ICQInfo.Affiliations.PastCode2, user.ICQInfo.Affiliations.PastKeyword2 = 0, ""
		user.ICQInfo.Affiliations.PastCode3, user.ICQInfo.Affiliations.PastKeyword3 = 0, ""
		for i, raw := range pastAffTLVs {
			var n struct {
				Code    uint16
				Keyword string `oscar:"len_prefix=uint16,nullterm"`
			}
			if err := wire.UnmarshalLE(&n, bytes.NewReader(raw)); err != nil {
				return fmt.Errorf("wire.UnmarshalLE: %w", err)
			}
			switch i {
			case 0:
				user.ICQInfo.Affiliations.PastCode1, user.ICQInfo.Affiliations.PastKeyword1 = n.Code, n.Keyword
			case 1:
				user.ICQInfo.Affiliations.PastCode2, user.ICQInfo.Affiliations.PastKeyword2 = n.Code, n.Keyword
			case 2:
				user.ICQInfo.Affiliations.PastCode3, user.ICQInfo.Affiliations.PastKeyword3 = n.Code, n.Keyword
			}
		}
	}

	name := instance.IdentScreenName()
	if err := s.userUpdater.SetICQInfo(ctx, name, user.ICQInfo); err != nil {
		return err
	}

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetFullInfo, inFrame.RequestID)
}

func (s *ICQService) SetICQPhone(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0654_DBQueryMetaReqSetICQPhone, seq uint16) error {
	s.logger.Debug("received SetICQPhone request")
	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetICQPhone, inFrame.RequestID)
}

func (s *ICQService) SetInterests(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests, seq uint16) error {
	if len(inBody.Interests) != 4 {
		return fmt.Errorf("%w: expected 4 interests", errICQBadRequest)
	}
	u := state.ICQInterests{
		Code1:    inBody.Interests[0].Code,
		Keyword1: inBody.Interests[0].Keyword,
		Code2:    inBody.Interests[1].Code,
		Keyword2: inBody.Interests[1].Keyword,
		Code3:    inBody.Interests[2].Code,
		Keyword3: inBody.Interests[2].Keyword,
		Code4:    inBody.Interests[3].Code,
		Keyword4: inBody.Interests[3].Keyword,
	}

	if err := s.userUpdater.SetInterests(ctx, instance.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetInterests, inFrame.RequestID)
}

func (s *ICQService) SetMoreInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo, seq uint16) error {
	u := state.ICQMoreInfo{
		Gender:       inBody.Gender,
		HomePageAddr: inBody.HomePageAddr,
		BirthYear:    inBody.BirthYear,
		BirthMonth:   inBody.BirthMonth,
		BirthDay:     inBody.BirthDay,
		Lang1:        inBody.Lang1,
		Lang2:        inBody.Lang2,
		Lang3:        inBody.Lang3,
	}

	if err := s.userUpdater.SetMoreInfo(ctx, instance.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetMoreInfo, inFrame.RequestID)
}

// SetPermissions persists ICQ privacy flags. AuthRequired controls whether other
// users need authorization to add this user; when true, contact pre-authorization
// can allow specific users to add without a new prompt.
func (s *ICQService) SetPermissions(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions, seq uint16) error {
	u := state.ICQPermissions{
		AuthRequired: inBody.Authorization == 0,
		WebAware:     inBody.WebAware == 1,
	}

	if err := s.userUpdater.SetPermissions(ctx, instance.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetPermissions, inFrame.RequestID)
}

func (s *ICQService) SetUserNotes(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes, seq uint16) error {
	u := state.ICQUserNotes{
		Notes: inBody.Notes,
	}

	if err := s.userUpdater.SetUserNotes(ctx, instance.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetNotes, inFrame.RequestID)
}

func (s *ICQService) SetWorkInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo, seq uint16) error {
	icqWorkInfo := state.ICQWorkInfo{
		Company:        inBody.Company,
		Department:     inBody.Department,
		OccupationCode: inBody.OccupationCode,
		Position:       inBody.Position,
		Address:        inBody.Address,
		City:           inBody.City,
		CountryCode:    inBody.CountryCode,
		Fax:            inBody.Fax,
		Phone:          inBody.Phone,
		State:          inBody.State,
		WebPage:        inBody.WebPage,
		ZIPCode:        inBody.ZIP,
	}

	if err := s.userUpdater.SetWorkInfo(ctx, instance.IdentScreenName(), icqWorkInfo); err != nil {
		return err
	}

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetWorkInfo, inFrame.RequestID)
}

func (s *ICQService) ShortUserInfo(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x04BA_DBQueryMetaReqShortInfo, seq uint16) error {
	user, err := s.userFinder.FindByUIN(ctx, inBody.UIN)
	if err != nil {
		if errors.Is(err, state.ErrNoUser) {
			msg := wire.ICQMessageReplyEnvelope{
				Message: wire.ICQ_0x07DA_0x0104_DBQueryMetaReplyShortInfo{
					ICQMetadata: wire.ICQMetadata{
						UIN:     instance.UIN(),
						ReqType: wire.ICQDBQueryMetaReply,
						Seq:     seq,
					},
					ReqSubType: wire.ICQDBQueryMetaReplyShortInfo,
					Success:    wire.ICQStatusCodeErr,
				},
			}
			return s.reply(ctx, instance, msg, inFrame.RequestID, 0)
		}
		return err
	}

	info := wire.ICQ_0x07DA_0x0104_DBQueryMetaReplyShortInfo{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyShortInfo,
		Success:    wire.ICQStatusCodeOK,
		Nickname:   user.ICQInfo.Basic.Nickname,
		FirstName:  user.ICQInfo.Basic.FirstName,
		LastName:   user.ICQInfo.Basic.LastName,
		Email:      user.ICQInfo.Basic.EmailAddress,
		Gender:     uint8(user.ICQInfo.More.Gender),
	}
	if !user.ICQInfo.Permissions.AuthRequired {
		info.Authorization = 1
	}

	msg := wire.ICQMessageReplyEnvelope{
		Message: info,
	}

	return s.reply(ctx, instance, msg, inFrame.RequestID, 0)
}

func (s *ICQService) XMLReqData(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0898_DBQueryMetaReqXMLReq, seq uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x08A2_DBQueryMetaReplyXMLData{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyXMLData,
			Success:    wire.ICQStatusCodeErr,
		},
	}
	return s.reply(ctx, instance, msg, inFrame.RequestID, 0)
}

func (s *ICQService) userInfo(ctx context.Context, instance *state.SessionInstance, user state.User, requestID uint32, seq uint16, flags uint16) error {
	userInfo := wire.ICQ_0x07DA_0x00C8_DBQueryMetaReplyBasicInfo{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType:  wire.ICQDBQueryMetaReplyBasicInfo,
		Success:     wire.ICQStatusCodeOK,
		Nickname:    user.ICQInfo.Basic.Nickname,
		FirstName:   user.ICQInfo.Basic.FirstName,
		LastName:    user.ICQInfo.Basic.LastName,
		Email:       user.ICQInfo.Basic.EmailAddress,
		City:        user.ICQInfo.Basic.City,
		State:       user.ICQInfo.Basic.State,
		Phone:       user.ICQInfo.Basic.Phone,
		Fax:         user.ICQInfo.Basic.Fax,
		Address:     user.ICQInfo.Basic.Address,
		CellPhone:   user.ICQInfo.Basic.CellPhone,
		ZIP:         user.ICQInfo.Basic.ZIPCode,
		CountryCode: user.ICQInfo.Basic.CountryCode,
		GMTOffset:   user.ICQInfo.Basic.GMTOffset,
		AuthFlag:    0, // required by default
		WebAware:    1,
		DCPerms:     0,
	}

	if !user.ICQInfo.Permissions.AuthRequired {
		userInfo.AuthFlag = 1
	}
	if user.ICQInfo.Permissions.WebAware {
		userInfo.WebAware = 1
	} else {
		userInfo.WebAware = 0
	}

	if user.ICQInfo.Basic.PublishEmail {
		userInfo.PublishEmail = wire.ICQUserFlagPublishEmailYes
	} else {
		userInfo.PublishEmail = wire.ICQUserFlagPublishEmailNo
	}

	msg := wire.ICQMessageReplyEnvelope{
		Message: userInfo,
	}
	return s.reply(ctx, instance, msg, requestID, flags)

}

func (s *ICQService) moreUserInfo(ctx context.Context, instance *state.SessionInstance, user state.User, requestID uint32, seq uint16, flags uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType:   wire.ICQDBQueryMetaReplyMoreInfo,
			Success:      wire.ICQStatusCodeOK,
			Age:          uint16(user.Age(s.timeNow)),
			Gender:       uint8(user.ICQInfo.More.Gender),
			HomePageAddr: user.ICQInfo.More.HomePageAddr,
			BirthYear:    user.ICQInfo.More.BirthYear,
			BirthMonth:   user.ICQInfo.More.BirthMonth,
			BirthDay:     user.ICQInfo.More.BirthDay,
			Lang1:        user.ICQInfo.More.Lang1,
			Lang2:        user.ICQInfo.More.Lang2,
			Lang3:        user.ICQInfo.More.Lang3,
			City:         user.ICQInfo.Basic.City,
			State:        user.ICQInfo.Basic.State,
			CountryCode:  user.ICQInfo.Basic.CountryCode,
			TimeZone:     user.ICQInfo.Basic.GMTOffset,
		},
	}

	return s.reply(ctx, instance, msg, requestID, flags)
}

func (s *ICQService) extraEmails(ctx context.Context, instance *state.SessionInstance, requestID uint32, seq uint16, flags uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00EB_DBQueryMetaReplyExtEmailInfo{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyExtEmailInfo,
			Success:    wire.ICQStatusCodeOK,
		},
	}

	return s.reply(ctx, instance, msg, requestID, flags)
}

func (s *ICQService) homepageCat(ctx context.Context, instance *state.SessionInstance, requestID uint32, seq uint16, flags uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x010E_DBQueryMetaReplyHomePageCat{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyHomePageCat,
			Success:    wire.ICQStatusCodeOK,
		},
	}

	return s.reply(ctx, instance, msg, requestID, flags)
}

func (s *ICQService) workInfo(ctx context.Context, instance *state.SessionInstance, user state.User, requestID uint32, seq uint16, flags uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00D2_DBQueryMetaReplyWorkInfo{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyWorkInfo,
			Success:    wire.ICQStatusCodeOK,
			ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo: wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo{
				City:           user.ICQInfo.Work.City,
				State:          user.ICQInfo.Work.State,
				Phone:          user.ICQInfo.Work.Phone,
				Fax:            user.ICQInfo.Work.Fax,
				Address:        user.ICQInfo.Work.Address,
				ZIP:            user.ICQInfo.Work.ZIPCode,
				CountryCode:    user.ICQInfo.Work.CountryCode,
				Company:        user.ICQInfo.Work.Company,
				Department:     user.ICQInfo.Work.Department,
				Position:       user.ICQInfo.Work.Position,
				OccupationCode: user.ICQInfo.Work.OccupationCode,
				WebPage:        user.ICQInfo.Work.WebPage,
			},
		},
	}
	return s.reply(ctx, instance, msg, requestID, flags)
}

func (s *ICQService) notes(ctx context.Context, instance *state.SessionInstance, user state.User, requestID uint32, seq uint16, flags uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00E6_DBQueryMetaReplyNotes{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyNotes,
			Success:    wire.ICQStatusCodeOK,
			ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes: wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes{
				Notes: user.ICQInfo.Notes.Notes,
			},
		},
	}

	return s.reply(ctx, instance, msg, requestID, flags)
}

func (s *ICQService) interests(ctx context.Context, instance *state.SessionInstance, user state.User, requestID uint32, seq uint16, flags uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00F0_DBQueryMetaReplyInterests{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyInterests,
			Success:    wire.ICQStatusCodeOK,
			Interests: []struct {
				Code    uint16
				Keyword string `oscar:"len_prefix=uint16,nullterm"`
			}{
				{
					Code:    user.ICQInfo.Interests.Code1,
					Keyword: user.ICQInfo.Interests.Keyword1,
				},
				{
					Code:    user.ICQInfo.Interests.Code2,
					Keyword: user.ICQInfo.Interests.Keyword2,
				},
				{
					Code:    user.ICQInfo.Interests.Code3,
					Keyword: user.ICQInfo.Interests.Keyword3,
				},
				{
					Code:    user.ICQInfo.Interests.Code4,
					Keyword: user.ICQInfo.Interests.Keyword4,
				},
			},
		},
	}

	return s.reply(ctx, instance, msg, requestID, flags)
}

func (s *ICQService) affiliations(ctx context.Context, instance *state.SessionInstance, user state.User, requestID uint32, seq uint16, flags uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00FA_DBQueryMetaReplyAffiliations{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyAffiliations,
			Success:    wire.ICQStatusCodeOK,
			ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations: wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations{
				PastAffiliations: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{
					{
						Code:    user.ICQInfo.Affiliations.PastCode1,
						Keyword: user.ICQInfo.Affiliations.PastKeyword1,
					},
					{
						Code:    user.ICQInfo.Affiliations.PastCode2,
						Keyword: user.ICQInfo.Affiliations.PastKeyword2,
					},
					{
						Code:    user.ICQInfo.Affiliations.PastCode3,
						Keyword: user.ICQInfo.Affiliations.PastKeyword3,
					},
				},
				Affiliations: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{
					{
						Code:    user.ICQInfo.Affiliations.CurrentCode1,
						Keyword: user.ICQInfo.Affiliations.CurrentKeyword1,
					},
					{
						Code:    user.ICQInfo.Affiliations.CurrentCode2,
						Keyword: user.ICQInfo.Affiliations.CurrentKeyword2,
					},
					{
						Code:    user.ICQInfo.Affiliations.CurrentCode3,
						Keyword: user.ICQInfo.Affiliations.CurrentKeyword3,
					},
				},
			},
		},
	}

	return s.reply(ctx, instance, msg, requestID, flags)
}

func (s *ICQService) reply(ctx context.Context, instance *state.SessionInstance, message wire.ICQMessageReplyEnvelope, requestID uint32, snacFlags uint16) error {
	s.messageRelayer.RelayToScreenName(ctx, instance.IdentScreenName(), replySNAC(message, requestID, snacFlags))
	return nil
}

// replyToSelf answers the instance that made the request rather than every
// instance of the account.
func (s *ICQService) replyToSelf(ctx context.Context, instance *state.SessionInstance, message wire.ICQMessageReplyEnvelope, requestID uint32, snacFlags uint16) error {
	s.messageRelayer.RelayToSelf(ctx, instance, replySNAC(message, requestID, snacFlags))
	return nil
}

// replySNAC wraps an ICQ metadata payload in a DB reply SNAC.
func replySNAC(message wire.ICQMessageReplyEnvelope, requestID uint32, snacFlags uint16) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICQ,
			SubGroup:  wire.ICQDBReply,
			RequestID: requestID,
			Flags:     snacFlags,
		},
		Body: wire.SNAC_0x15_0x02_DBReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICQTLVTagsMetadata, message),
				},
			},
		},
	}
}

func (s *ICQService) replySearchHit(ctx context.Context, instance *state.SessionInstance, record wire.ICQUserSearchRecord, requestID uint32, last bool, seq uint16) error {
	var resp any
	var more uint16
	if last {
		resp = wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
			Success:    wire.ICQStatusCodeOK,
			Details:    record,
			UsersLeft:  0,
		}
	} else {
		resp = wire.ICQ_0x07DA_0x01A4_DBQueryMetaReplyUserFound{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyUserFound,
			Success:    wire.ICQStatusCodeOK,
			Details:    record,
		}
		more = wire.SNACFlagsMoreToCome
	}
	return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{Message: resp}, requestID, more)
}

func (s *ICQService) reportSearchFailure(ctx context.Context, instance *state.SessionInstance, seq uint16, requestID uint32) error {
	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
		Success:    wire.ICQStatusCodeErr,
	}
	return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
		Message: resp,
	}, requestID, 0)
}

func (s *ICQService) reportNoSearchResults(ctx context.Context, instance *state.SessionInstance, seq uint16, requestID uint32) error {
	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
		Success:    wire.ICQStatusCodeFail,
	}
	return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
		Message: resp,
	}, requestID, 0)
}

func (s *ICQService) reqAck(ctx context.Context, instance *state.SessionInstance, seq uint16, subType uint16, requestID uint32) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: subType,
			Success:    wire.ICQStatusCodeOK,
		},
	}

	return s.reply(ctx, instance, msg, requestID, 0)
}

func (s *ICQService) createResult(res state.User) wire.ICQUserSearchRecord {
	uin, _ := strconv.Atoi(res.IdentScreenName.String())

	searchRecord := wire.ICQUserSearchRecord{
		UIN:       uint32(uin),
		Nickname:  res.ICQInfo.Basic.Nickname,
		FirstName: res.ICQInfo.Basic.FirstName,
		LastName:  res.ICQInfo.Basic.LastName,
		Email:     res.ICQInfo.Basic.EmailAddress,
		Gender:    uint8(res.ICQInfo.More.Gender),
		Age:       res.Age(s.timeNow),
	}
	if !res.ICQInfo.Permissions.AuthRequired {
		searchRecord.Authorization = 1
	}

	userSess := s.sessionRetriever.RetrieveSession(res.IdentScreenName)
	if userSess != nil {
		searchRecord.OnlineStatus = 1
	}
	return searchRecord
}

func (s *ICQService) DirQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x5B9_ICQDirQuery, seq uint16, ver *wire.TLVLBlock) error {
	var criteria state.ICQUserSearchCriteria
	onlineOnly := false

	for _, tlv := range inBody.TLVList {
		switch tlv.Tag {
		case wire.ICQDirTLVTagsUID:
			if state.DisplayScreenName(string(tlv.Value)).IsUIN() {
				uinFromSn, _ := strconv.Atoi(string(tlv.Value))
				uin := uint32(uinFromSn)
				criteria.UIN = &uin
			}
		case wire.ICQDirTLVTagsVerifiedEmail:
			email := string(tlv.Value)
			criteria.Email = &email
		case wire.ICQDirTLVTagsFirstName:
			firstName := string(tlv.Value)
			criteria.FirstName = &firstName
		case wire.ICQDirTLVTagsLastName:
			lastName := string(tlv.Value)
			criteria.LastName = &lastName
		case wire.ICQDirTLVTagsNickname:
			nickName := string(tlv.Value)
			criteria.NickName = &nickName
		case wire.ICQDirGenderSearchTag:
			gender := tlv.Uint8()
			criteria.Gender = &gender
		case wire.ICQDirCitySearchTag:
			city := string(tlv.Value)
			criteria.City = &city
		case wire.ICQDirCountrySearchTag:
			countryCode := uint16(tlv.Uint32BE())
			criteria.CountryCode = &countryCode
		case wire.ICQDirLanguageSearchTag:
			lang := uint8(tlv.Uint16BE())
			criteria.SpokenLanguage = &lang
		case wire.ICQDirOnlineUsersSearchTag:
			if tlv.Uint16BE() > 0 {
				onlineOnly = true
			}
		case wire.ICQDirAgeRangeSearchTag:
			var ageRange struct {
				MaxAge uint16
				MinAge uint16
			}
			if err := wire.UnmarshalBE(&ageRange, bytes.NewReader(tlv.Value)); err != nil {
				return fmt.Errorf("unmarshaling age range: %w", err)
			}
			criteria.MinAge = &ageRange.MinAge
			criteria.MaxAge = &ageRange.MaxAge
		case wire.ICQDirBasicSearchTag:
			nickOrName := string(tlv.Value)
			criteria.FirstLastNickName = &nickOrName
		}
	}

	users, err := s.userFinder.SearchICQUsers(ctx, criteria)
	if err != nil {
		return fmt.Errorf("FindByICQName failed: %w", err)
	}

	if onlineOnly {
		var filtered []state.User
		for _, u := range users {
			if s.sessionRetriever.RetrieveSession(u.IdentScreenName) != nil {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}

	if len(users) == 0 {
		if err := s.icqDirQueryReply(ctx, instance, 0, inFrame.RequestID, seq, inBody.RequestType, true, ver, nil); err != nil {
			return err
		}
	}
	for i, user := range users {
		if i == len(users)-1 {
			if err := s.icqDirQueryReply(ctx, instance, uint32(len(users)), inFrame.RequestID, seq, inBody.RequestType, true, ver, &user); err != nil {
				return err
			}
		} else {
			if err := s.icqDirQueryReply(ctx, instance, uint32(len(users)), inFrame.RequestID, seq, inBody.RequestType, false, ver, &user); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ICQService) DirUpdate(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x5B9_0x03_ICQDirUpdate, seq uint16) error {
	user, err := s.userFinder.FindByUIN(ctx, instance.UIN())
	if err != nil {
		s.logger.Error("FindByUIN failed", "err", err.Error())
		return err
	}

	for _, tlv := range inBody.TLVList {
		switch tlv.Tag {
		case wire.ICQDirTLVTagsStatusNote:
			user.ICQInfo.MDirData.StatusNote = string(tlv.Value)
		case wire.ICQDirTLVTagsAbout:
			user.ICQInfo.Notes.Notes = string(tlv.Value)
		case wire.ICQDirTLVTagsAuth:
			user.ICQInfo.Permissions.AuthRequired = tlv.Uint16BE() == 0
		case wire.ICQDirTLVTagsWebAware:
			user.ICQInfo.Permissions.WebAware = tlv.Uint8() == 1
		case wire.ICQDirTLVTagsGender:
			user.ICQInfo.More.Gender = uint16(tlv.Uint8())
		case wire.ICQDirTLVTagsHomepage:
			user.ICQInfo.More.HomePageAddr = string(tlv.Value)
		case wire.ICQDirTLVTagsBirthDate:
			if len(tlv.Value) != 8 {
				return fmt.Errorf("invalid birthdate length: need 8 bytes")
			}
			ConvertBirthDate := func(birthDate float64) (uint16, uint8, uint8) {
				if birthDate > 0 {
					birthTime := mdirTimeToTime(birthDate)
					return uint16(birthTime.Year()), uint8(birthTime.Month()), uint8(birthTime.Day())
				}
				return 0, 0, 0
			}
			user.ICQInfo.More.BirthYear, user.ICQInfo.More.BirthMonth, user.ICQInfo.More.BirthDay = ConvertBirthDate(math.Float64frombits(tlv.Uint64BE()))
		case wire.ICQDirTLVTagsLanguage1:
			user.ICQInfo.More.Lang1 = uint8(tlv.Uint16BE())
		case wire.ICQDirTLVTagsLanguage2:
			user.ICQInfo.More.Lang2 = uint8(tlv.Uint16BE())
		case wire.ICQDirTLVTagsLanguage3:
			user.ICQInfo.More.Lang3 = uint8(tlv.Uint16BE())
		case wire.ICQDirTLVTagsFirstName:
			user.ICQInfo.Basic.FirstName = string(tlv.Value)
		case wire.ICQDirTLVTagsLastName:
			user.ICQInfo.Basic.LastName = string(tlv.Value)
		case wire.ICQDirTLVTagsNickname:
			user.ICQInfo.Basic.Nickname = string(tlv.Value)
		case wire.ICQDirTLVTagsHome:
			ICQTLVMetadata := wire.TLVList{}
			if err := wire.UnmarshalBE(&ICQTLVMetadata, bytes.NewReader(tlv.Value)); err != nil {
				return fmt.Errorf("unmarshal homes record: %w", err)
			}

			for _, tlv := range ICQTLVMetadata {
				if tlv.Tag == wire.ICQTLVTagsMetadata {
					homesTLVs := wire.TLVList{}
					if err := wire.UnmarshalBE(&homesTLVs, bytes.NewReader(tlv.Value)); err != nil {
						return fmt.Errorf("unmarshal homes record: %w", err)
					}

					for _, tlv := range homesTLVs {
						switch tlv.Tag {
						case wire.ICQDirTLVTagsHomeAddress:
							user.ICQInfo.Basic.Address = string(tlv.Value)
						case wire.ICQDirTLVTagsHomeCity:
							user.ICQInfo.Basic.City = string(tlv.Value)
						case wire.ICQDirTLVTagsHomeState:
							user.ICQInfo.Basic.State = string(tlv.Value)
						case wire.ICQDirTLVTagsHomeZIP:
							user.ICQInfo.Basic.ZIPCode = string(tlv.Value)
						case wire.ICQDirTLVTagsHomeCountry:
							user.ICQInfo.Basic.CountryCode = uint16(tlv.Uint32BE())
						}
					}
				}
			}
		case wire.ICQDirTLVTagsOrigin:
			ICQTLVMetadata := wire.TLVList{}
			if err := wire.UnmarshalBE(&ICQTLVMetadata, bytes.NewReader(tlv.Value)); err != nil {
				return fmt.Errorf("unmarshal homes record: %w", err)
			}

			for _, tlv := range ICQTLVMetadata {
				if tlv.Tag == wire.ICQTLVTagsMetadata {
					homesTLVs := wire.TLVList{}
					if err := wire.UnmarshalBE(&homesTLVs, bytes.NewReader(tlv.Value)); err != nil {
						return fmt.Errorf("unmarshal homes record: %w", err)
					}

					for _, tlv := range homesTLVs {
						switch tlv.Tag {
						case wire.ICQDirTLVTagsOriginCity:
							user.ICQInfo.Basic.OriginallyFromCity = string(tlv.Value)
						case wire.ICQDirTLVTagsOriginState:
							user.ICQInfo.Basic.OriginallyFromState = string(tlv.Value)
						case wire.ICQDirTLVTagsHomeCountry:
							user.ICQInfo.Basic.OriginallyFromCountryCode = uint16(tlv.Uint32BE())
						}
					}
				}
			}
		case wire.ICQDirTLVTagsWork:
			ICQTLVMetadata := wire.TLVList{}
			if err := wire.UnmarshalBE(&ICQTLVMetadata, bytes.NewReader(tlv.Value)); err != nil {
				return fmt.Errorf("unmarshal homes record: %w", err)
			}

			for _, tlv := range ICQTLVMetadata {
				if tlv.Tag == wire.ICQTLVTagsMetadata {
					workTLVs := wire.TLVList{}
					if err := wire.UnmarshalBE(&workTLVs, bytes.NewReader(tlv.Value)); err != nil {
						return fmt.Errorf("unmarshal work info record: %w", err)
					}

					for _, tlv := range workTLVs {
						switch tlv.Tag {
						case wire.ICQDirTLVTagsWorkPosition:
							user.ICQInfo.Work.Position = string(tlv.Value)
						case wire.ICQDirTLVTagsWorkCompany:
							user.ICQInfo.Work.Company = string(tlv.Value)
						case wire.ICQDirTLVTagsWorkWebPage:
							user.ICQInfo.Work.WebPage = string(tlv.Value)
						case wire.ICQDirTLVTagsWorkDepartment:
							user.ICQInfo.Work.Department = string(tlv.Value)
						case wire.ICQDirTLVTagsWorkOccupationCode:
							user.ICQInfo.Work.OccupationCode = tlv.Uint16BE()
						case wire.ICQDirTLVTagsWorkAddress:
							user.ICQInfo.Work.Address = string(tlv.Value)
						case wire.ICQDirTLVTagsWorkCity:
							user.ICQInfo.Work.City = string(tlv.Value)
						case wire.ICQDirTLVTagsWorkState:
							user.ICQInfo.Work.State = string(tlv.Value)
						case wire.ICQDirTLVTagsWorkZIP:
							user.ICQInfo.Work.ZIPCode = string(tlv.Value)
						case wire.ICQDirTLVTagsWorkCountry:
							user.ICQInfo.Work.CountryCode = uint16(tlv.Uint32BE())
						}
					}
				}
			}
		case wire.ICQDirTLVTagsInterests:
			user.ICQInfo.Interests = state.ICQInterests{}

			var interestsTLVs struct {
				Interests []wire.TLVLBlock `oscar:"count_prefix=uint16"`
			}
			if err := wire.UnmarshalBE(&interestsTLVs, bytes.NewReader(tlv.Value)); err != nil {
				return fmt.Errorf("unmarshal interests record: %w", err)
			}

			for i := range interestsTLVs.Interests {
				switch i {
				case 0:
					for _, tlv := range interestsTLVs.Interests[0].TLVList {
						switch tlv.Tag {
						case wire.ICQDirTLVTagsInterestCode:
							user.ICQInfo.Interests.Code1 = tlv.Uint16BE()
						case wire.ICQDirTLVTagsInterestKeyword:
							user.ICQInfo.Interests.Keyword1 = string(tlv.Value)
						}
					}
				case 1:
					for _, tlv := range interestsTLVs.Interests[1].TLVList {
						switch tlv.Tag {
						case wire.ICQDirTLVTagsInterestCode:
							user.ICQInfo.Interests.Code2 = tlv.Uint16BE()
						case wire.ICQDirTLVTagsInterestKeyword:
							user.ICQInfo.Interests.Keyword2 = string(tlv.Value)
						}
					}
				case 2:
					for _, tlv := range interestsTLVs.Interests[2].TLVList {
						switch tlv.Tag {
						case wire.ICQDirTLVTagsInterestCode:
							user.ICQInfo.Interests.Code3 = tlv.Uint16BE()
						case wire.ICQDirTLVTagsInterestKeyword:
							user.ICQInfo.Interests.Keyword3 = string(tlv.Value)
						}
					}
				case 3:
					for _, tlv := range interestsTLVs.Interests[3].TLVList {
						switch tlv.Tag {
						case wire.ICQDirTLVTagsInterestCode:
							user.ICQInfo.Interests.Code4 = tlv.Uint16BE()
						case wire.ICQDirTLVTagsInterestKeyword:
							user.ICQInfo.Interests.Keyword4 = string(tlv.Value)
						}
					}
				}
			}
			//case wire.ICQDirTLVTagsPhoneNumbers:
			/*var phonesTLVs struct {
				Phones []wire.TLVLBlock `oscar:"count_prefix=uint16"`
			}
			if err := wire.UnmarshalBE(&phonesTLVs, bytes.NewReader(tlv.Value)); err != nil {
				return fmt.Errorf("unmarshal interests record: %w", err)
			}*/
			//0000   2a 02 16 85 00 a7 00 15 00 02 00 00 03 13 00 02   *...............
			//0010   00 01 00 99 97 00 84 7b 03 00 d0 07 25 ac d2 0f   .......{....%...
			//0020   8b 00 05 b9 00 03 80 00 00 00 00 00 00 06 00 01   ................
			//0030   00 02 00 02 00 00 04 e4 00 00 00 02 00 03 00 6d   ...............m

			//0040   01 22 00 29 00 02 00 0f 00 6e 00 02 00 80 00 64   .".).....n.....d <- interests
			//0050   00 05 61 73 74 72 6f 00 14 00 6e 00 02 00 93 00   ..astro...n.....
			//0060   64 00 0a 61 75 64 69 6f 77 6f 72 6c 64 .. .. ..   d..audioworld

			//0060   .. .. .. .. .. .. .. .. .. .. .. .. .. 00 c8 00                ...<- phones
			//0070   3c 00 02 00 1d 00 6e 00 02 00 03 00 64 00 13 2b   <.....n.....d..+
			//0080   31 20 39 39 20 39 39 39 39 39 39 39 39 39 20 53   1 99 999999999 S
			//0090   4d 53 00 19 00 6e 00 02 00 01 00 64 00 0f 2b 31   MS...n.....d..+1
			//00a0   20 31 31 20 31 31 31 31 31 31 31 31 31             11 111111111
		}
	}

	var ownersPrivateKey string
	if user.ICQInfo.MDirData.PrivateKey != "" {
		ownersPrivateKey = user.ICQInfo.MDirData.PrivateKey
	} else {
		ownersPrivateKey = uuid.New().String()
	}
	user.ICQInfo.MDirData.PrivateKey = ownersPrivateKey

	newLastUpdateTime := math.Float64bits(timeToMdirTime(s.timeNow()))
	user.ICQInfo.MDirData.LastUpdate = newLastUpdateTime

	if err := s.userUpdater.SetICQInfo(ctx, instance.IdentScreenName(), user.ICQInfo); err != nil {
		return err
	}

	resp := wire.ICQ_0x07DA_0x0FB4_DBQueryMetaReplyDirectoryResponse{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyDirectoryUpdate,
		Success:    wire.ICQStatusCodeOK,
		SNACMessage: wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICQDir,
				SubGroup:  wire.ICQDirUpdateAck,
				Flags:     wire.SNACFlagsExtendedInfo,
			},
			Body: wire.SNAC_0x5B9_0x0A_ICQDirUpdateAck{
				Version:       inBody.Version,
				RequestStatus: 1,
				Timestamp:     newLastUpdateTime,
				PrivateKey:    uuid.MustParse(user.ICQInfo.MDirData.PrivateKey),
			},
		},
	}

	return s.replyToSelf(ctx, instance, wire.ICQMessageReplyEnvelope{Message: resp}, inFrame.RequestID, 0)
}

func (s *ICQService) DirMultiQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x5B9_0x06_ICQDirMultiQuery, seq uint16) error {
	foundUsers := []*state.User{}
	for _, userInfo := range inBody.QueriedUserInfo {
		if uid, hasUID := userInfo.String(wire.ICQDirTLVTagsUID); hasUID {
			if state.DisplayScreenName(uid).IsUIN() { // AIM users aren't usually queried in this request, but let's check for safety, I guess
				uin, _ := strconv.Atoi(uid)
				user, err := s.userFinder.FindByUIN(ctx, uint32(uin))
				switch {
				default:
					foundUsers = append(foundUsers, &user)
				case errors.Is(err, state.ErrNoUser): // non-existent user in the contact list???
					continue
				case err != nil:
					s.logger.Error("FindByUIN failed", "err", err.Error())
					return err
				}
			}
		}
	}
	for i, user := range foundUsers {
		if i == len(foundUsers)-1 {
			if err := s.icqDirQueryReply(ctx, instance, uint32(len(foundUsers)), inFrame.RequestID, seq, 0x0002, true, &inBody.Version, user); err != nil {
				return err
			}
		} else {
			if err := s.icqDirQueryReply(ctx, instance, uint32(len(foundUsers)), inFrame.RequestID, seq, 0x0002, false, &inBody.Version, user); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *ICQService) icqDirQueryReply(ctx context.Context, instance *state.SessionInstance, totalMatches, reqID uint32, seq, reqType uint16, last bool, ver *wire.TLVLBlock, u *state.User) error {
	var reqSubType, flag, more, subGroup uint16
	if last {
		reqSubType = wire.ICQDBQueryMetaReplyDirectoryResponse
	} else {
		reqSubType = wire.ICQDBQueryMetaReplyDirectoryData
		more = wire.SNACFlagsMoreToCome
	}

	var pagesFound, tlvLBlockCount uint16
	if totalMatches > 0 {
		pagesFound = 1
		tlvLBlockCount = 1
	}

	body := wire.SNAC_0x5B9_ICQDirQueryReply{
		RequestStatus:  1,
		TotalMatches:   totalMatches,
		TotalPages:     pagesFound, // TODO: support multiple pages if there are too many results
		TLVLBlockCount: tlvLBlockCount,
		TLVLBlock:      s.dirTLVInfo(u, reqType),
	}
	if ver == nil {
		subGroup = wire.ICQDirQueryReplyLegacy
		body.ServerDataLegacy = &struct{ Reserved [8]byte }{}
	} else {
		subGroup = wire.ICQDirQueryReply
		flag = wire.SNACFlagsExtendedInfo
		body.Version = ver
		body.ServerData = &struct{ Data [16]byte }{
			Data: GetUsersPrivateKeyFromMDir(u),
		}
	}

	resp := wire.ICQ_0x07DA_0x0FB4_DBQueryMetaReplyDirectoryResponse{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: reqSubType,
		Success:    wire.ICQStatusCodeOK,
		SNACMessage: wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.ICQDir,
				SubGroup:  subGroup,
				Flags:     flag + more,
			},
			Body: body,
		},
	}

	return s.replyToSelf(ctx, instance, wire.ICQMessageReplyEnvelope{Message: resp}, reqID, more)
}

func (s *ICQService) EmailToUIN(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x1090_DBQueryMetaReqEmailToUIN, seq uint16) error {
	user, err := s.userFinder.FindByICQEmail(ctx, inBody.Email)

	resp := wire.ICQ_0x07DA_0x109A_DBQueryMetaReplyEmailToUIN{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyEmailToUIN,
		Success:    wire.ICQStatusCodeOK,
	}

	switch {
	case errors.Is(err, state.ErrNoUser):
		// do nothing
	case err != nil:
		s.logger.Error("FindByICQEmail failed", "err", err.Error())
	default:
		resp.UIN = user.IdentScreenName.UIN()
	}

	return s.replyToSelf(ctx, instance, wire.ICQMessageReplyEnvelope{Message: resp}, inFrame.RequestID, 0)
}

//
// Tools
//

func (s *ICQService) dirTLVInfo(user *state.User, reqType uint16) wire.TLVLBlock {
	tlvs := wire.TLVLBlock{}
	if user == nil {
		return tlvs
	}

	GetUsersPhoneNumbers := func() struct {
		Phones []wire.TLVLBlock `oscar:"count_prefix=uint16"`
	} {
		var tlvs struct {
			Phones []wire.TLVLBlock `oscar:"count_prefix=uint16"`
		}
		if user.ICQInfo.Basic.Phone != "" {
			tlvs.Phones = append(tlvs.Phones, wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICQDirTLVTagsPhoneNumber, user.ICQInfo.Basic.Phone),
					wire.NewTLVBE(wire.ICQDirTLVTagsPhoneType, uint16(0x0001)),
				}})
		}
		if user.ICQInfo.Work.Phone != "" {
			tlvs.Phones = append(tlvs.Phones, wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICQDirTLVTagsPhoneNumber, user.ICQInfo.Work.Phone),
					wire.NewTLVBE(wire.ICQDirTLVTagsPhoneType, uint16(0x0002)),
				}})
		}
		if user.ICQInfo.Basic.CellPhone != "" {
			tlvs.Phones = append(tlvs.Phones, wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICQDirTLVTagsPhoneNumber, user.ICQInfo.Basic.CellPhone),
					wire.NewTLVBE(wire.ICQDirTLVTagsPhoneType, uint16(0x0003)),
				}})
		}
		if user.ICQInfo.Basic.Fax != "" {
			tlvs.Phones = append(tlvs.Phones, wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICQDirTLVTagsPhoneNumber, user.ICQInfo.Basic.Fax),
					wire.NewTLVBE(wire.ICQDirTLVTagsPhoneType, uint16(0x0004)),
				}})
		}
		if user.ICQInfo.Work.Fax != "" {
			tlvs.Phones = append(tlvs.Phones, wire.TLVLBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICQDirTLVTagsPhoneNumber, user.ICQInfo.Work.Fax),
					wire.NewTLVBE(wire.ICQDirTLVTagsPhoneType, uint16(0x0005)),
				}})
		}
		return tlvs
	}
	GetUsersAuthFlag := func() uint16 {
		if user.ICQInfo.Permissions.AuthRequired {
			return 0
		}
		return 1
	}
	GetUsersBirthDate := func() float64 {
		switch {
		case user.ICQInfo.More.BirthYear > 0 && user.ICQInfo.More.BirthMonth == 0 && user.ICQInfo.More.BirthDay == 0:
			bday := time.Date(int(user.ICQInfo.More.BirthYear), time.January, 1, 0, 0, 0, 0, time.UTC)
			return timeToMdirTime(bday)
		case user.ICQInfo.More.BirthYear > 0 && user.ICQInfo.More.BirthMonth > 0 && user.ICQInfo.More.BirthDay > 0:
			bday := time.Date(int(user.ICQInfo.More.BirthYear), time.Month(user.ICQInfo.More.BirthMonth), int(user.ICQInfo.More.BirthDay), 0, 0, 0, 0, time.UTC)
			return timeToMdirTime(bday)
		default: // invalid date
			return 0.0
		}
	}
	GetUsersWebStatus := func() uint16 {
		if user.ICQInfo.Permissions.WebAware {
			if s.sessionRetriever.RetrieveSession(user.IdentScreenName) == nil {
				return 0
			} else {
				return 1
			}
		}
		return 2
	}
	GetUsersAllowSpam := func() uint8 {
		if user.ICQInfo.Permissions.AllowSpam {
			return 1
		}
		return 0
	}
	GetUsersWebAware := func() uint8 {
		if user.ICQInfo.Permissions.WebAware {
			return 1
		}
		return 0
	}
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsUID, user.IdentScreenName.String()))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsNickname2, user.ICQInfo.Basic.Nickname))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsVerifiedEmail, user.ICQInfo.Basic.EmailAddress))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsPendingEmail, "")) // Non-verified email
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsFirstName, user.ICQInfo.Basic.FirstName))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsLastName, user.ICQInfo.Basic.LastName))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsNickname, user.ICQInfo.Basic.Nickname))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsGender, uint8(user.ICQInfo.More.Gender)))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsEmailAddresses, "")) // Additional mails aren't supported yet, should be packed as TLVList inside of the TLV with the ICQTLVTagsMetadata tag
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsHome,
		wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.TLVList{
			wire.NewTLVBE(wire.ICQDirTLVTagsHomeAddress, user.ICQInfo.Basic.Address),
			wire.NewTLVBE(wire.ICQDirTLVTagsHomeCity, user.ICQInfo.Basic.City),
			wire.NewTLVBE(wire.ICQDirTLVTagsHomeState, user.ICQInfo.Basic.State),
			wire.NewTLVBE(wire.ICQDirTLVTagsHomeZIP, user.ICQInfo.Basic.ZIPCode),
			wire.NewTLVBE(wire.ICQDirTLVTagsHomeCountry, uint32(user.ICQInfo.Basic.CountryCode)),
		})))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsOrigin,
		wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.TLVList{
			wire.NewTLVBE(wire.ICQDirTLVTagsOriginAddress, ""),
			wire.NewTLVBE(wire.ICQDirTLVTagsOriginCity, user.ICQInfo.Basic.OriginallyFromCity),
			wire.NewTLVBE(wire.ICQDirTLVTagsOriginState, user.ICQInfo.Basic.OriginallyFromState),
			wire.NewTLVBE(wire.ICQDirTLVTagsOriginZIP, ""),
			wire.NewTLVBE(wire.ICQDirTLVTagsOriginCountry, uint32(user.ICQInfo.Basic.OriginallyFromCountryCode)),
		})))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsLanguage1, uint16(user.ICQInfo.More.Lang1)))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsLanguage2, uint16(user.ICQInfo.More.Lang2)))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsLanguage3, uint16(user.ICQInfo.More.Lang3)))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsPhoneNumbers, GetUsersPhoneNumbers()))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsHomepage, user.ICQInfo.More.HomePageAddr))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsWork,
		wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.TLVList{
			wire.NewTLVBE(wire.ICQDirTLVTagsWorkPosition, user.ICQInfo.Work.Position),
			wire.NewTLVBE(wire.ICQDirTLVTagsWorkCompany, user.ICQInfo.Work.Company),
			wire.NewTLVBE(wire.ICQDirTLVTagsWorkWebPage, user.ICQInfo.Work.WebPage),
			wire.NewTLVBE(wire.ICQDirTLVTagsWorkDepartment, user.ICQInfo.Work.Department),
			wire.NewTLVBE(wire.ICQDirTLVTagsWorkOccupationCode, user.ICQInfo.Work.OccupationCode),
			wire.NewTLVBE(wire.ICQDirTLVTagsWorkAddress, user.ICQInfo.Work.Address),
			wire.NewTLVBE(wire.ICQDirTLVTagsWorkCity, user.ICQInfo.Work.City),
			wire.NewTLVBE(wire.ICQDirTLVTagsWorkState, user.ICQInfo.Work.State),
			wire.NewTLVBE(wire.ICQDirTLVTagsWorkZIP, user.ICQInfo.Work.ZIPCode),
			wire.NewTLVBE(wire.ICQDirTLVTagsWorkCountry, uint32(user.ICQInfo.Work.CountryCode)),
		})))
	if reqType == 0x0003 { // full info (with interests)
		GetUsersInterests := func() struct {
			Interests []wire.TLVLBlock `oscar:"count_prefix=uint16"`
		} {
			var tlvs struct {
				Interests []wire.TLVLBlock `oscar:"count_prefix=uint16"`
			}
			if user.ICQInfo.Interests.Code1 > 0 && user.ICQInfo.Interests.Keyword1 != "" {
				tlvs.Interests = append(tlvs.Interests, wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.ICQDirTLVTagsInterestKeyword, user.ICQInfo.Interests.Keyword1),
						wire.NewTLVBE(wire.ICQDirTLVTagsInterestCode, user.ICQInfo.Interests.Code1),
					}})
			}
			if user.ICQInfo.Interests.Code2 > 0 && user.ICQInfo.Interests.Keyword2 != "" {
				tlvs.Interests = append(tlvs.Interests, wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.ICQDirTLVTagsInterestKeyword, user.ICQInfo.Interests.Keyword2),
						wire.NewTLVBE(wire.ICQDirTLVTagsInterestCode, user.ICQInfo.Interests.Code2),
					}})
			}
			if user.ICQInfo.Interests.Code3 > 0 && user.ICQInfo.Interests.Keyword3 != "" {
				tlvs.Interests = append(tlvs.Interests, wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.ICQDirTLVTagsInterestKeyword, user.ICQInfo.Interests.Keyword3),
						wire.NewTLVBE(wire.ICQDirTLVTagsInterestCode, user.ICQInfo.Interests.Code3),
					}})
			}
			if user.ICQInfo.Interests.Code4 > 0 && user.ICQInfo.Interests.Keyword4 != "" {
				tlvs.Interests = append(tlvs.Interests, wire.TLVLBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.ICQDirTLVTagsInterestKeyword, user.ICQInfo.Interests.Keyword4),
						wire.NewTLVBE(wire.ICQDirTLVTagsInterestCode, user.ICQInfo.Interests.Code4),
					}})
			}
			return tlvs
		}
		tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsInterests, GetUsersInterests()))
	}
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsAbout, user.ICQInfo.Notes.Notes))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsWebStatus, GetUsersWebStatus()))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsAuth, GetUsersAuthFlag()))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsBirthDate, math.Float64bits(GetUsersBirthDate())))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsLastUpdate, user.ICQInfo.MDirData.LastUpdate))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsAllowSpam, GetUsersAllowSpam()))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsPrivacyLevel, uint16(0)))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsWebAware, GetUsersWebAware()))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsBetaFlag, uint8(0x3C)))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsStatusNote, user.ICQInfo.MDirData.StatusNote))
	tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsPrivateKey, GetUsersPrivateKeyFromMDir(user)))

	return tlvs
}

func GetUsersPrivateKeyFromMDir(user *state.User) [16]byte {
	if user != nil {
		if user.ICQInfo.MDirData.PrivateKey != "" {
			return uuid.MustParse(user.ICQInfo.MDirData.PrivateKey)
		}
	}
	return uuid.Nil
}

func mdirTimeToTime(mdir float64) time.Time {
	mdirToOle := func() float64 {
		if mdir != 0 {
			return mdir + 2.0
		}
		return 0.0
	}
	return time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC).Add(time.Duration(mdirToOle() * 24 * float64(time.Hour)))
}

func timeToMdirTime(t time.Time) float64 {
	oleToMdir := func(ole float64) float64 {
		if ole != 0 {
			return ole - 2.0
		}
		return 0.0
	}
	return oleToMdir(float64((t.Truncate(time.Second)).Sub(time.Date(1899, 12, 30, 0, 0, 0, 0, time.UTC))) / float64(24*time.Hour))
	// The original ICQ servers had never had anything after seconds, so truncate
}
