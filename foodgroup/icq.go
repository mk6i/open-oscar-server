package foodgroup

import (
	"bytes"
	"context"
	"encoding/binary"
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

	users, err := func() ([]state.User, error) {
		if keyword, hasKeyword := inBody.ICQString(wire.ICQTLVTagsWhitepagesSearchKeywords); hasKeyword {
			res, err := s.userFinder.FindByICQKeyword(ctx, keyword)
			if err != nil {
				return nil, fmt.Errorf("FindByICQKeyword failed: %w", err)
			}
			return res, nil
		}

		bNick, hasNick := inBody.ICQString(wire.ICQTLVTagsNickname)
		bFirst, hasFirst := inBody.ICQString(wire.ICQTLVTagsFirstName)
		bLast, hastLast := inBody.ICQString(wire.ICQTLVTagsLastName)

		if hasNick || hasFirst || hastLast {
			res, err := s.userFinder.FindByICQName(ctx, bFirst, bLast, bNick)
			if err != nil {
				return nil, fmt.Errorf("FindByICQName failed: %w", err)
			}
			return res, nil
		}

		return nil, nil
	}()

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
		s.logger.Error("FindByWhitePages2 failed", "err", err.Error())
		resp.Success = wire.ICQStatusCodeErr
		return s.reply(ctx, instance, wire.ICQMessageReplyEnvelope{
			Message: resp,
		})
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
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.FirstName = v
			}
		case wire.ICQTLVTagsLastName:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.LastName = v
			}
		case wire.ICQTLVTagsNickname:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.Nickname = v
			}
		case wire.ICQTLVTagsEmail:
			if email, publish, ok := decodeICQECombo(tlv.Value); ok {
				user.ICQInfo.Basic.EmailAddress = email
				// publish=0 means "publish my email", matching the
				// existing ICQUserFlagPublishEmailYes (0) convention.
				user.ICQInfo.Basic.PublishEmail = publish == wire.ICQUserFlagPublishEmailYes
			}
		case wire.ICQTLVTagsHomeCityName:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.City = v
			}
		case wire.ICQTLVTagsHomeStateAbbr:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.State = v
			}
		case wire.ICQTLVTagsHomeCountryCode:
			if v, ok := readUint16LE(tlv.Value); ok {
				user.ICQInfo.Basic.CountryCode = v
			}
		case wire.ICQTLVTagsHomeStreetAddress:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.Address = v
			}
		case wire.ICQTLVTagsHomeZipCode:
			if v, ok := readUint32LE(tlv.Value); ok {
				user.ICQInfo.Basic.ZIPCode = strconv.FormatUint(uint64(v), 10)
			}
		case wire.ICQTLVTagsHomePhoneNumber:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.Phone = v
			}
		case wire.ICQTLVTagsHomeFaxNumber:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.Fax = v
			}
		case wire.ICQTLVTagsHomeCellularPhoneNumber:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.CellPhone = v
			}
		case wire.ICQTLVTagsGMTOffset:
			if v, ok := readUint8(tlv.Value); ok {
				user.ICQInfo.Basic.GMTOffset = v
			}
		case wire.ICQTLVTagsOriginallyFromCity:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.OriginallyFromCity = v
			}
		case wire.ICQTLVTagsOriginallyFromState:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Basic.OriginallyFromState = v
			}
		case wire.ICQTLVTagsOriginallyFromCountryCode:
			if v, ok := readUint16LE(tlv.Value); ok {
				user.ICQInfo.Basic.OriginallyFromCountryCode = v
			}

		// ----- ICQMoreInfo -----
		case wire.ICQTLVTagsGender:
			if v, ok := readUint8(tlv.Value); ok {
				user.ICQInfo.More.Gender = uint16(v)
			}
		case wire.ICQTLVTagsSpokenLanguage:
			if v, ok := readUint8(tlv.Value); ok {
				langTLVs = append(langTLVs, v)
			}
		case wire.ICQTLVTagsBirthdayInfo:
			if year, month, day, ok := decodeICQBCombo(tlv.Value); ok {
				user.ICQInfo.More.BirthYear = year
				user.ICQInfo.More.BirthMonth = uint8(month)
				user.ICQInfo.More.BirthDay = uint8(day)
			}
		case wire.ICQTLVTagsHomepageURL:
			if _, url, ok := decodeICQICombo(tlv.Value); ok {
				user.ICQInfo.More.HomePageAddr = url
			}

		// ----- ICQWorkInfo -----
		case wire.ICQTLVTagsWorkCompanyName:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Work.Company = v
			}
		case wire.ICQTLVTagsWorkDepartmentName:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Work.Department = v
			}
		case wire.ICQTLVTagsWorkPositionTitle:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Work.Position = v
			}
		case wire.ICQTLVTagsWorkOccupationCode:
			if v, ok := readUint16LE(tlv.Value); ok {
				user.ICQInfo.Work.OccupationCode = v
			}
		case wire.ICQTLVTagsWorkStreetAddress:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Work.Address = v
			}
		case wire.ICQTLVTagsWorkCityName:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Work.City = v
			}
		case wire.ICQTLVTagsWorkStateName:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Work.State = v
			}
		case wire.ICQTLVTagsWorkCountryCode:
			if v, ok := readUint16LE(tlv.Value); ok {
				user.ICQInfo.Work.CountryCode = v
			}
		case wire.ICQTLVTagsWorkZipCode:
			if v, ok := readUint32LE(tlv.Value); ok {
				user.ICQInfo.Work.ZIPCode = strconv.FormatUint(uint64(v), 10)
			}
		case wire.ICQTLVTagsWorkPhoneNumber:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Work.Phone = v
			}
		case wire.ICQTLVTagsWorkFaxNumber:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Work.Fax = v
			}
		case wire.ICQTLVTagsWorkWebpageURL:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Work.WebPage = v
			}

		// ----- ICQPermissions -----
		case wire.ICQTLVTagsAuthorizationPermissions:
			if v, ok := readUint8(tlv.Value); ok {
				// Matches the wire-struct convention used by SetPermissions:
				// authorization == 0 means "authorization required".
				user.ICQInfo.Permissions.AuthRequired = v == 0
			}
		case wire.ICQTLVTagsShowWebStatusPermissions:
			if v, ok := readUint8(tlv.Value); ok {
				user.ICQInfo.Permissions.WebAware = v == 1
			}

		// ----- ICQUserNotes -----
		case wire.ICQTLVTagsNotesText:
			if v, ok := decodeICQSString(tlv.Value); ok {
				user.ICQInfo.Notes.Notes = v
			}

		// ----- ICQInterests -----
		case wire.ICQTLVTagsInterestsNode:
			interestTLVs = append(interestTLVs, tlv.Value)

		// ----- ICQAffiliations -----
		case wire.ICQTLVTagsAffiliationsNode:
			currentAffTLVs = append(currentAffTLVs, tlv.Value)
		case wire.ICQTLVTagsPastInfoNode:
			pastAffTLVs = append(pastAffTLVs, tlv.Value)

		// ----- ICQHomepageCategory -----
		case wire.ICQTLVTagsHomepageCategoryKeywords:
			if code, kw, ok := decodeICQICombo(tlv.Value); ok {
				user.ICQInfo.HomepageCategory.Index = code
				user.ICQInfo.HomepageCategory.Description = kw
				user.ICQInfo.HomepageCategory.Enabled = true
			}

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
			code, kw, ok := decodeICQICombo(raw)
			if !ok {
				continue
			}
			switch i {
			case 0:
				user.ICQInfo.Interests.Code1, user.ICQInfo.Interests.Keyword1 = code, kw
			case 1:
				user.ICQInfo.Interests.Code2, user.ICQInfo.Interests.Keyword2 = code, kw
			case 2:
				user.ICQInfo.Interests.Code3, user.ICQInfo.Interests.Keyword3 = code, kw
			case 3:
				user.ICQInfo.Interests.Code4, user.ICQInfo.Interests.Keyword4 = code, kw
			}
		}
	}

	if len(currentAffTLVs) > 0 {
		user.ICQInfo.Affiliations.CurrentCode1, user.ICQInfo.Affiliations.CurrentKeyword1 = 0, ""
		user.ICQInfo.Affiliations.CurrentCode2, user.ICQInfo.Affiliations.CurrentKeyword2 = 0, ""
		user.ICQInfo.Affiliations.CurrentCode3, user.ICQInfo.Affiliations.CurrentKeyword3 = 0, ""
		for i, raw := range currentAffTLVs {
			code, kw, ok := decodeICQICombo(raw)
			if !ok {
				continue
			}
			switch i {
			case 0:
				user.ICQInfo.Affiliations.CurrentCode1, user.ICQInfo.Affiliations.CurrentKeyword1 = code, kw
			case 1:
				user.ICQInfo.Affiliations.CurrentCode2, user.ICQInfo.Affiliations.CurrentKeyword2 = code, kw
			case 2:
				user.ICQInfo.Affiliations.CurrentCode3, user.ICQInfo.Affiliations.CurrentKeyword3 = code, kw
			}
		}
	}

	if len(pastAffTLVs) > 0 {
		user.ICQInfo.Affiliations.PastCode1, user.ICQInfo.Affiliations.PastKeyword1 = 0, ""
		user.ICQInfo.Affiliations.PastCode2, user.ICQInfo.Affiliations.PastKeyword2 = 0, ""
		user.ICQInfo.Affiliations.PastCode3, user.ICQInfo.Affiliations.PastKeyword3 = 0, ""
		for i, raw := range pastAffTLVs {
			code, kw, ok := decodeICQICombo(raw)
			if !ok {
				continue
			}
			switch i {
			case 0:
				user.ICQInfo.Affiliations.PastCode1, user.ICQInfo.Affiliations.PastKeyword1 = code, kw
			case 1:
				user.ICQInfo.Affiliations.PastCode2, user.ICQInfo.Affiliations.PastKeyword2 = code, kw
			case 2:
				user.ICQInfo.Affiliations.PastCode3, user.ICQInfo.Affiliations.PastKeyword3 = code, kw
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
			ReqSubType: wire.ICQDBQueryMetaReplyMoreInfo,
			Success:    wire.ICQStatusCodeOK,
			ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo: wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo{
				Age:          uint8(user.Age(s.timeNow)),
				Gender:       user.ICQInfo.More.Gender,
				HomePageAddr: user.ICQInfo.More.HomePageAddr,
				BirthYear:    user.ICQInfo.More.BirthYear,
				BirthMonth:   user.ICQInfo.More.BirthMonth,
				BirthDay:     user.ICQInfo.More.BirthDay,
				Lang1:        user.ICQInfo.More.Lang1,
				Lang2:        user.ICQInfo.More.Lang2,
				Lang3:        user.ICQInfo.More.Lang3,
			},
			City:        user.ICQInfo.Basic.City,
			State:       user.ICQInfo.Basic.State,
			CountryCode: user.ICQInfo.Basic.CountryCode,
			TimeZone:    user.ICQInfo.Basic.GMTOffset,
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

// decodeICQSString decodes an ICQ "sstring" value: a uint16 (LE) length
// prefix followed by an ASCIIZ string. The length includes the trailing
// null terminator. Returns the string (without the terminator) and true
// when the value is well-formed; otherwise returns "" and false.
func decodeICQSString(b []byte) (string, bool) {
	if len(b) < 3 {
		return "", false
	}
	expected := binary.LittleEndian.Uint16(b[0:2])
	value := b[2:]
	if int(expected) != len(value) {
		return "", false
	}
	return string(value[:len(value)-1]), true
}

// decodeICQECombo decodes an ICQ "ecombo" value: an sstring (email) followed
// by a uint8 publish flag.
func decodeICQECombo(b []byte) (email string, publish uint8, ok bool) {
	if len(b) < 4 {
		return "", 0, false
	}
	expected := binary.LittleEndian.Uint16(b[0:2])
	if int(expected)+2+1 != len(b) {
		return "", 0, false
	}
	value := b[2 : 2+int(expected)]
	return string(value[:len(value)-1]), b[2+int(expected)], true
}

// decodeICQICombo decodes an ICQ "icombo"/"hcombo" value: a uint16 (LE)
// category code followed by an sstring keyword.
func decodeICQICombo(b []byte) (code uint16, keyword string, ok bool) {
	if len(b) < 2 {
		return 0, "", false
	}
	code = binary.LittleEndian.Uint16(b[0:2])
	keyword, ok = decodeICQSString(b[2:])
	return code, keyword, ok
}

// decodeICQBCombo decodes an ICQ "bcombo" birthday value: three uint16 (LE)
// values for year, month, and day.
func decodeICQBCombo(b []byte) (year, month, day uint16, ok bool) {
	if len(b) < 6 {
		return 0, 0, 0, false
	}
	return binary.LittleEndian.Uint16(b[0:2]),
		binary.LittleEndian.Uint16(b[2:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		true
}

func readUint8(b []byte) (uint8, bool) {
	if len(b) < 1 {
		return 0, false
	}
	return b[0], true
}

func readUint16LE(b []byte) (uint16, bool) {
	if len(b) < 2 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b), true
}

func readUint32LE(b []byte) (uint32, bool) {
	if len(b) < 4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b), true
}
