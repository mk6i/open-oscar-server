package foodgroup

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

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

func (s *ICQService) DirectoryQuery(ctx context.Context, instance *state.SessionInstance, frame wire.SNACFrame, inBody wire.ICQ_0x07D0_0x0FA0_DBQueryMetaReqDirectoryQuery, seq uint16) error {
	req := wire.ICQ_0x07D0_0x0FA0_DBQueryMetaReqDirectoryBody{}
	if err := wire.UnmarshalBE(&req, bytes.NewReader(inBody.Body)); err != nil {
		return err
	}

	// QIP 2012 repeats the meta request subtype where the nested SNAC subtype
	// belongs, so map it to the query info command.
	if req.SubType == wire.ICQDBQueryMetaReqDirectoryQuery {
		req.SubType = wire.ICQDirCmdQuery
	}

	switch req.SubType {
	case wire.ICQDirCmdQuery:
		return s.directoryQueryInfo(ctx, instance, frame, req, seq)
	case wire.ICQDirCmdQueryMulti:
		return s.directoryMultiInfo(ctx, instance, frame, req, seq)
	default:
		return s.directoryError(ctx, instance, frame.RequestID, seq, req.SubType, req.Versioned())
	}
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
			if s.searchStatus(u) == wire.ICQDirStatusOnline {
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

	searchRecord.OnlineStatus = s.searchStatus(res)
	return searchRecord
}

// searchStatus is the presence a search result reports for u. A user who does
// not publish their web status shows as hidden, connected or not.
func (s *ICQService) searchStatus(u state.User) uint16 {
	switch {
	case !u.ICQInfo.Permissions.WebAware:
		return wire.ICQDirStatusHidden
	case s.sessionRetriever.RetrieveSession(u.IdentScreenName) == nil:
		return wire.ICQDirStatusOffline
	default:
		return wire.ICQDirStatusOnline
	}
}

// directoryQueryInfo handles a directory search or a single profile lookup. Both
// share a layout up to the block tag, which tells them apart; each block then
// carries its own body.
func (s *ICQService) directoryQueryInfo(ctx context.Context, instance *state.SessionInstance, frame wire.SNACFrame, req wire.ICQ_0x07D0_0x0FA0_DBQueryMetaReqDirectoryBody, seq uint16) error {
	header := wire.ICQDirectoryQueryHeader{}
	if req.Versioned() {
		header.SetVersioned()
	}
	r := bytes.NewReader(req.Body)
	if err := wire.UnmarshalBE(&header, r); err != nil {
		return err
	}

	switch header.Block {
	case wire.ICQDirBlockSearch:
		return s.directorySearch(ctx, instance, frame, req, r, seq)
	case wire.ICQDirBlockLookup:
		return s.directoryInfo(ctx, instance, frame, req, r, seq)
	default:
		return s.directoryError(ctx, instance, frame.RequestID, seq, req.SubType, req.Versioned())
	}
}

// directoryInfo handles a single profile lookup. Profiles are not served yet, so
// the request is refused.
func (s *ICQService) directoryInfo(ctx context.Context, instance *state.SessionInstance, frame wire.SNACFrame, req wire.ICQ_0x07D0_0x0FA0_DBQueryMetaReqDirectoryBody, r io.Reader, seq uint16) error {
	query := wire.ICQDirectoryInfoQuery{}
	if err := wire.UnmarshalBE(&query, r); err != nil {
		return err
	}

	s.logger.DebugContext(ctx, "directory profile lookup refused", "requester", instance.UIN())
	return s.directoryError(ctx, instance, frame.RequestID, seq, req.SubType, req.Versioned())
}

// directorySearch applies the conditions of a directory search and replies with
// the matching users.
func (s *ICQService) directorySearch(ctx context.Context, instance *state.SessionInstance, frame wire.SNACFrame, req wire.ICQ_0x07D0_0x0FA0_DBQueryMetaReqDirectoryBody, r io.Reader, seq uint16) error {
	versioned := req.Versioned()

	query := wire.ICQDirectorySearchQuery{}
	if err := wire.UnmarshalBE(&query, r); err != nil {
		return err
	}

	var c state.ICQUserSearchCriteria
	var onlineOnly bool
	for _, tlv := range query.TLVList {
		if len(tlv.Value) == 0 {
			continue
		}
		val := string(tlv.Value)
		switch tlv.Tag {
		case wire.ICQDirTLVTagsUID:
			if uin, err := strconv.ParseUint(val, 10, 32); err == nil {
				c.UIN = new(uint32(uin))
			}
		case wire.ICQDirTLVTagsFirstName:
			c.FirstName = new(val)
		case wire.ICQDirTLVTagsLastName:
			c.LastName = new(val)
		case wire.ICQDirTLVTagsNickname:
			c.NickName = new(val)
		case wire.ICQDirTLVTagsVerifiedEmail:
			c.Email = new(val)
		case wire.ICQDirTLVTagsOnlineOnly:
			onlineOnly = tlv.Value[len(tlv.Value)-1] != 0
		case wire.ICQDirTLVTagsGender:
			if len(tlv.Value) == 1 && (tlv.Value[0] == 1 || tlv.Value[0] == 2) {
				c.Gender = new(tlv.Value[0])
			}
		case wire.ICQDirTLVTagsSearchLanguage:
			if len(tlv.Value) == 2 {
				if v := binary.BigEndian.Uint16(tlv.Value); v > 0 && v < 256 {
					c.SpokenLanguage = new(uint8(v))
				}
			}
		case wire.ICQDirTLVTagsSearchCountry:
			if len(tlv.Value) == 4 {
				if v := binary.BigEndian.Uint32(tlv.Value); v > 0 && v < 20000 {
					c.CountryCode = new(uint16(v))
				}
			}
		case wire.ICQDirTLVTagsSearchAge:
			if len(tlv.Value) == 4 {
				lo := binary.BigEndian.Uint16(tlv.Value[0:2])
				hi := binary.BigEndian.Uint16(tlv.Value[2:4])
				if lo > hi {
					lo, hi = hi, lo
				}
				if lo != 0 && hi != 0 {
					c.MinAge, c.MaxAge = &lo, &hi
				}
			}
		}
	}

	users, err := s.userFinder.SearchICQUsers(ctx, c)
	if errors.Is(err, state.ErrICQSearchEmptyCriteria) {
		// Nothing searchable was sent, so nothing matches.
		users, err = nil, nil
	}
	if err != nil {
		s.logger.ErrorContext(ctx, "directory search failed", "requester", instance.UIN(), "err", err.Error())
		return s.directoryError(ctx, instance, frame.RequestID, seq, req.SubType, versioned)
	}

	type hit struct {
		user   state.User
		status uint16
	}
	hits := make([]hit, 0, len(users))
	for _, u := range users {
		status := s.searchStatus(u)
		if onlineOnly && status != wire.ICQDirStatusOnline {
			continue
		}
		hits = append(hits, hit{user: u, status: status})
	}

	if len(hits) == 0 {
		// The client finishes its search when it receives a reply with no blocks.
		return s.directoryReply(ctx, instance, frame.RequestID, seq, wire.ICQDirectoryReplyBody{
			SubType:   wire.ICQDirCmdQueryAck,
			Result:    wire.ICQDirResultOK,
			Pages:     1,
			Versioned: versioned,
		})
	}

	total := uint32(len(hits))
	for i, h := range hits {
		u := h.user
		last := i == len(hits)-1

		tlvs := wire.TLVList{}
		tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsUID, u.IdentScreenName.String()))

		if u.ICQInfo.Basic.FirstName != "" {
			tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsFirstName, u.ICQInfo.Basic.FirstName))
		}
		if u.ICQInfo.Basic.LastName != "" {
			tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsLastName, u.ICQInfo.Basic.LastName))
		}
		if u.ICQInfo.Basic.Nickname != "" {
			tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsNickname, u.ICQInfo.Basic.Nickname))
		}
		if u.ICQInfo.Basic.EmailAddress != "" {
			tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsVerifiedEmail, u.ICQInfo.Basic.EmailAddress))
		}
		if u.ICQInfo.More.Gender != 0 {
			tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsGender, uint8(u.ICQInfo.More.Gender)))
		}
		if days, ok := wire.ICQDirDate(u.ICQInfo.More.BirthYear, u.ICQInfo.More.BirthMonth, u.ICQInfo.More.BirthDay); ok {
			// a birth date goes out as the day count in an 8-byte big-endian float
			var date [8]byte
			binary.BigEndian.PutUint64(date[:], math.Float64bits(days))
			tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsBirthDate, date[:]))
		}

		authOptional := uint8(0)
		if !u.ICQInfo.Permissions.AuthRequired {
			authOptional = 1
		}
		tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsAuthRequired, authOptional))

		if u.ICQInfo.Basic.CountryCode != 0 {
			addr := wire.TLVList{}
			addr.Append(wire.NewTLVBE(wire.ICQDirTLVTagsAddressCountry, uint32(u.ICQInfo.Basic.CountryCode)))
			blob := &bytes.Buffer{}
			if err := wire.MarshalBE(wire.TLVRestBlock{TLVList: addr}, blob); err != nil {
				return err
			}
			tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsHomeAddress, blob.Bytes()))
		}

		tlvs.Append(wire.NewTLVBE(wire.ICQDirTLVTagsOnlineStatus, h.status))

		err := s.directoryReply(ctx, instance, frame.RequestID, seq, wire.ICQDirectoryReplyBody{
			SubType:   wire.ICQDirCmdQueryAck,
			Result:    wire.ICQDirResultOK,
			Item:      tlvs,
			Total:     total,
			Pages:     1,
			More:      !last,
			Versioned: versioned,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// directoryMultiInfo handles a request for the profiles of several users at
// once. Each item is a length-prefixed TLV list naming one user: the UID, the
// time the client last saw the profile and optionally a privacy token. The
// profiles are not served yet, so the request is refused.
func (s *ICQService) directoryMultiInfo(ctx context.Context, instance *state.SessionInstance, frame wire.SNACFrame, req wire.ICQ_0x07D0_0x0FA0_DBQueryMetaReqDirectoryBody, seq uint16) error {
	query := struct {
		Extras *struct {
			Body []byte `oscar:"len_prefix=uint16"`
		} `oscar:"variant"`
		Filler [8]byte
		Items  []wire.TLVLBlock `oscar:"count_prefix=uint16"`
	}{}
	versioned := req.Versioned()
	if versioned {
		query.Extras = &struct {
			Body []byte `oscar:"len_prefix=uint16"`
		}{}
	}
	if err := wire.UnmarshalBE(&query, bytes.NewReader(req.Body)); err != nil {
		return err
	}

	s.logger.DebugContext(ctx, "directory multi lookup refused", "requester", instance.UIN(), "items", len(query.Items))
	return s.directoryError(ctx, instance, frame.RequestID, seq, wire.ICQDirCmdQueryMulti, versioned)
}

// directoryReply builds one directory packet from r and sends it. The client
// reads a single result from each packet, so a result set goes out as several
// packets. All but the last are flagged as more to come and use the "data" meta
// subtype; the last uses "response", which ends the search.
func (s *ICQService) directoryReply(ctx context.Context, instance *state.SessionInstance, requestID uint32, seq uint16, r wire.ICQDirectoryReplyBody) error {
	// A hit is a single block; no hit means no block at all, not an empty one.
	var items []wire.TLVLBlock
	if len(r.Item) > 0 {
		items = []wire.TLVLBlock{{TLVList: r.Item}}
	}

	header := wire.ICQDirectoryReply{
		SNACFamily: wire.ICQDirNestedFamily,
		SubType:    r.SubType,
		Result:     r.Result,
		Total:      r.Total,
		BlockCount: uint16(len(items)),
		Items:      items,
	}
	if r.More {
		header.Flags |= 0x0001
	}
	if r.Versioned {
		header.SetVersion1(r.Pages)
	}

	body := &bytes.Buffer{}
	if err := wire.MarshalBE(header, body); err != nil {
		return err
	}

	if body.Len() > math.MaxUint16 {
		return errors.New("directory payload too long")
	}

	snacFlags := uint16(0)
	replySubType := wire.ICQDBQueryMetaReplyDirectoryResponse
	if r.More {
		snacFlags = wire.SNACFlagsMoreToCome
		replySubType = wire.ICQDBQueryMetaReplyDirectoryData
	}

	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x0FAA_DBQueryMetaReplyDirectory{
			ICQMetadata: wire.ICQMetadata{
				UIN:     instance.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: replySubType,
			Success:    wire.ICQStatusCodeOK,
			Payload:    body.Bytes(),
		},
	}
	return s.reply(ctx, instance, msg, requestID, snacFlags)
}

// directoryError replies to a request with its subtype, result 0 and no data.
func (s *ICQService) directoryError(ctx context.Context, instance *state.SessionInstance, requestID uint32, seq uint16, subType uint16, versioned bool) error {
	return s.directoryReply(ctx, instance, requestID, seq, wire.ICQDirectoryReplyBody{
		SubType:   subType,
		Versioned: versioned,
	})
}
