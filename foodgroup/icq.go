package foodgroup

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
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
) *ICQService {
	return &ICQService{
		messageRelayer:        messageRelayer,
		userFinder:            finder,
		userUpdater:           userUpdater,
		logger:                logger,
		sessionRetriever:      sessionRetriever,
		offlineMessageManager: offlineMessageManager,
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

func (s *ICQService) FindByICQName(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0515_DBQueryMetaReqSearchByDetails, seq uint16) error {
	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		Success:    wire.ICQStatusCodeOK,
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
	}

	res, err := s.userFinder.FindByICQName(ctx, inBody.FirstName, inBody.LastName, inBody.NickName)

	if err != nil {
		s.logger.Error("FindByICQName failed", "err", err.Error())
		resp.Success = wire.ICQStatusCodeErr
		return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: resp,
		})
	}
	if len(res) == 0 {
		resp.Success = wire.ICQStatusCodeFail
		return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: resp,
		})
	}

	for i := 0; i < len(res); i++ {
		if i == len(res)-1 {
			resp.LastResult()
		} else {
			resp.ReqSubType = wire.ICQDBQueryMetaReplyUserFound
		}
		resp.Details = s.createResult(res[i])
		if err := s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: resp,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *ICQService) FindByICQEmail(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0529_DBQueryMetaReqSearchByEmail, seq uint16) error {
	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
		Success:    wire.ICQStatusCodeOK,
	}
	resp.LastResult()

	res, err := s.userFinder.FindByICQEmail(ctx, inBody.Email)

	switch {
	case errors.Is(err, state.ErrNoUser):
		resp.Success = wire.ICQStatusCodeFail
	case err != nil:
		s.logger.Error("FindByICQEmail failed", "err", err.Error())
		resp.Success = wire.ICQStatusCodeErr
	default:
		resp.Success = wire.ICQStatusCodeOK
		resp.Details = s.createResult(res)
	}

	return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
		Message: resp,
	})
}

func (s *ICQService) FindByEmail3(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0573_DBQueryMetaReqSearchByEmail3, seq uint16) error {
	b, hasEmail := inBody.Bytes(wire.ICQTLVTagsEmail)
	if !hasEmail {
		return errors.New("unable to get email from request")
	}

	email := wire.ICQEmail{}
	if err := wire.UnmarshalLE(&email, bytes.NewReader(b)); err != nil {
		return fmt.Errorf("unmarshal email: %w", err)
	}

	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
		Success:    wire.ICQStatusCodeOK,
	}
	resp.LastResult()

	res, err := s.userFinder.FindByICQEmail(ctx, email.Email)

	switch {
	case errors.Is(err, state.ErrNoUser):
		resp.Success = wire.ICQStatusCodeFail
	case err != nil:
		s.logger.Error("FindByICQEmail failed", "err", err.Error())
		resp.Success = wire.ICQStatusCodeErr
	default:
		resp.Success = wire.ICQStatusCodeOK
		resp.Details = s.createResult(res)
	}

	return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
		Message: resp,
	})
}

func (s *ICQService) FindByICQInterests(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0533_DBQueryMetaReqSearchWhitePages, seq uint16) error {
	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		Success:    wire.ICQStatusCodeOK,
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
	}

	interests := strings.Split(inBody.InterestsKeyword, ",")
	res, err := s.userFinder.FindByICQInterests(ctx, inBody.InterestsCode, interests)

	if err != nil {
		s.logger.Error("FindByICQInterests failed", "err", err.Error())
		resp.Success = wire.ICQStatusCodeErr
		return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: resp,
		})
	}
	if len(res) == 0 {
		resp.Success = wire.ICQStatusCodeFail
		return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: resp,
		})
	}

	for i := 0; i < len(res); i++ {
		if i == len(res)-1 {
			resp.LastResult()
		} else {
			resp.ReqSubType = wire.ICQDBQueryMetaReplyUserFound
		}
		resp.Details = s.createResult(res[i])
		if err := s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: resp,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *ICQService) FindByWhitePages2(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2, seq uint16) error {
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

	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		Success:    wire.ICQStatusCodeOK,
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
	}

	if err != nil {
		if errors.Is(err, state.ErrICQSearchEmptyCriteria) {
			resp.Success = wire.ICQStatusCodeFail
		} else {
			s.logger.Error("FindByWhitePages2 failed", "err", err.Error())
			resp.Success = wire.ICQStatusCodeErr
		}
		return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: resp,
		})
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
		resp.Success = wire.ICQStatusCodeFail
		return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: resp,
		})
	}

	for i := 0; i < len(users); i++ {
		if i == len(users)-1 {
			resp.LastResult()
		} else {
			resp.ReqSubType = wire.ICQDBQueryMetaReplyUserFound
		}
		resp.Details = s.createResult(users[i])
		if err := s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: resp,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s *ICQService) FindByUIN(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN, seq uint16) error {
	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
		Success:    wire.ICQStatusCodeOK,
	}
	resp.LastResult()

	res, err := s.userFinder.FindByUIN(ctx, inBody.UIN)

	switch {
	case errors.Is(err, state.ErrNoUser):
		resp.Success = wire.ICQStatusCodeFail
	case err != nil:
		s.logger.Error("FindByUIN failed", "err", err.Error())
		resp.Success = wire.ICQStatusCodeErr
	default:
		resp.Success = wire.ICQStatusCodeOK
		resp.Details = s.createResult(res)
	}

	return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
		Message: resp,
	})
}

func (s *ICQService) FindByUIN2(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2, seq uint16) error {
	UIN, hasUIN := inBody.Uint32LE(wire.ICQTLVTagsUIN)
	if !hasUIN {
		return errors.New("unable to get UIN from request")
	}

	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     instance.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
		Success:    wire.ICQStatusCodeOK,
	}
	resp.LastResult()

	res, err := s.userFinder.FindByUIN(ctx, UIN)

	switch {
	case errors.Is(err, state.ErrNoUser):
		resp.Success = wire.ICQStatusCodeFail
	case err != nil:
		s.logger.Error("FindByUIN failed", "err", err.Error())
		resp.Success = wire.ICQStatusCodeErr
	default:
		resp.Success = wire.ICQStatusCodeOK
		resp.Details = s.createResult(res)
	}

	return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
		Message: resp,
	})
}

func (s *ICQService) FullUserInfo(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN, seq uint16) error {

	user, err := s.userFinder.FindByUIN(ctx, inBody.UIN)
	if err != nil {
		return err
	}

	if err := s.userInfo(ctx, instance, user, seq); err != nil {
		return err
	}

	if err := s.moreUserInfo(ctx, instance, user, seq); err != nil {
		return err
	}

	if err := s.extraEmails(ctx, instance, user, seq); err != nil {
		return err
	}

	if err := s.homepageCat(ctx, instance, user, seq); err != nil {
		return err
	}

	if err := s.workInfo(ctx, instance, user, seq); err != nil {
		return err
	}

	if err := s.notes(ctx, instance, user, seq); err != nil {
		return err
	}

	if err := s.interests(ctx, instance, user, seq); err != nil {
		return err
	}

	if err := s.affiliations(ctx, instance, user, seq); err != nil {
		return err
	}
	return nil
}

func (s *ICQService) OfflineMsgReq(ctx context.Context, instance *state.SessionInstance, seq uint16) error {
	messages, err := s.offlineMessageManager.RetrieveMessages(ctx, instance.IdentScreenName())
	if err != nil {
		return fmt.Errorf("retrieving messages: %w", err)
	}

	for _, msgIn := range messages {
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
				msgText, err := wire.UnmarshalICBMMessageText(payload)
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
			return fmt.Errorf("did not find an appropriate saved message payload. channel: %d",
				msgIn.Message.ChannelID)
		}

		msgOut := wire.ICQMessageReplyEnvelope{
			Message: reply,
		}
		if err := s.reply(ctx, instance, msgOut); err != nil {
			return fmt.Errorf("sending offline message: %w", err)
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

	if err := s.reply(ctx, instance, eofMsg); err != nil {
		return fmt.Errorf("sending end of offline messages: %w", err)
	}

	return nil
}

func (s *ICQService) SetAffiliations(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations, seq uint16) error {
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

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetAffiliations)
}

func (s *ICQService) SetBasicInfo(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo, seq uint16) error {
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

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetBasicInfo)
}

func (s *ICQService) SetEmails(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x040B_DBQueryMetaReqSetEmails, seq uint16) error {
	if len(inBody.Emails) > 0 {
		s.logger.Debug("adding additional emails is not yet supported")
	}
	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetEmails)
}

// SetICQInfo handles the TLV-based CLI_SET_FULLINFO (0x0C3A) request used to
// update all profile information in a single packet. The TLV chain may
// contain any subset of fields; omitted fields are preserved by loading the
// current user record and overlaying only the values that were sent. Within a
// multi-valued group (languages, interests, affiliations) any unspecified
// slots are reset when at least one TLV in that group is present, matching
// the way ICQLite tabs replace their entire group on save.
func (s *ICQService) SetICQInfo(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0C3A_DBQueryMetaReqSetFullInfo, seq uint16) error {
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

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetFullInfo)
}

func (s *ICQService) SetICQPhone(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0654_DBQueryMetaReqSetICQPhone, seq uint16) error {
	s.logger.Debug("received SetICQPhone request")
	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetICQPhone)
}

func (s *ICQService) SetInterests(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests, seq uint16) error {
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

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetInterests)
}

func (s *ICQService) SetMoreInfo(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo, seq uint16) error {
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

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetMoreInfo)
}

// SetPermissions persists ICQ privacy flags. AuthRequired controls whether other
// users need authorization to add this user; when true, contact pre-authorization
// can allow specific users to add without a new prompt.
func (s *ICQService) SetPermissions(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions, seq uint16) error {
	u := state.ICQPermissions{
		AuthRequired: inBody.Authorization == 0,
		WebAware:     inBody.WebAware == 1,
	}

	if err := s.userUpdater.SetPermissions(ctx, instance.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetPermissions)
}

func (s *ICQService) SetUserNotes(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes, seq uint16) error {
	u := state.ICQUserNotes{
		Notes: inBody.Notes,
	}

	if err := s.userUpdater.SetUserNotes(ctx, instance.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetNotes)
}

func (s *ICQService) SetWorkInfo(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo, seq uint16) error {
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

	return s.reqAck(ctx, instance, seq, wire.ICQDBQueryMetaReplySetWorkInfo)
}

func (s *ICQService) ShortUserInfo(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x04BA_DBQueryMetaReqShortInfo, seq uint16) error {
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
			return s.reply(ctx, instance, msg)
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

	return s.reply(ctx, instance, msg)
}

func (s *ICQService) XMLReqData(ctx context.Context, instance *state.SessionInstance, inBody wire.ICQ_0x07D0_0x0898_DBQueryMetaReqXMLReq, seq uint16) error {
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
	return s.reply(ctx, instance, msg)
}

func (s *ICQService) affiliations(ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
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

	return s.reply(ctx, instance, msg)
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

func (s *ICQService) extraEmails(ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
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

	return s.reply(ctx, instance, msg)
}

func (s *ICQService) homepageCat(ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
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

	return s.reply(ctx, instance, msg)
}

func (s *ICQService) interests(ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
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

	return s.reply(ctx, instance, msg)
}

func (s *ICQService) moreUserInfo(ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
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

	return s.reply(ctx, instance, msg)
}

func (s *ICQService) notes(ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
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

	return s.reply(ctx, instance, msg)
}

func (s *ICQService) reply(ctx context.Context, instance *state.SessionInstance, message wire.ICQMessageReplyEnvelope) error {
	msg := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ICQ,
			SubGroup:  wire.ICQDBReply,
		},
		Body: wire.SNAC_0x15_0x02_DBReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.ICQTLVTagsMetadata, message),
				},
			},
		},
	}

	s.messageRelayer.RelayToScreenName(ctx, instance.IdentScreenName(), msg)
	return nil
}

func (s *ICQService) reqAck(ctx context.Context, instance *state.SessionInstance, seq uint16, subType uint16) error {
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

	return s.reply(ctx, instance, msg)
}

func (s *ICQService) userInfo(ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
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
	return s.reply(ctx, instance, msg)

}

func (s *ICQService) workInfo(ctx context.Context, instance *state.SessionInstance, user state.User, seq uint16) error {
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
	return s.reply(ctx, instance, msg)
}
