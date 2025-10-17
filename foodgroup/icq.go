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

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
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
) ICQService {
	return ICQService{
		messageRelayer:        messageRelayer,
		userFinder:            finder,
		userUpdater:           userUpdater,
		logger:                logger,
		sessionRetriever:      sessionRetriever,
		offlineMessageManager: offlineMessageManager,
		timeNow:               time.Now,
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
}

func (s ICQService) DeleteMsgReq(ctx context.Context, sess *state.Session, seq uint16) error {
	if err := s.offlineMessageManager.DeleteMessages(ctx, sess.IdentScreenName()); err != nil {
		return fmt.Errorf("deleting messages: %w", err)
	}
	return nil
}

func (s ICQService) FindByICQName(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0515_DBQueryMetaReqSearchByDetails, seq uint16) error {
	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     sess.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		Success:    wire.ICQStatusCodeOK,
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
	}

	res, err := s.userFinder.FindByICQName(ctx, req.FirstName, req.LastName, req.NickName)

	if err != nil {
		s.logger.Error("FindByICQName failed", "err", err.Error())
		resp.Success = wire.ICQStatusCodeErr
		return s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
			Message: resp,
		})
	}
	if len(res) == 0 {
		resp.Success = wire.ICQStatusCodeFail
		return s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
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
		if err := s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
			Message: resp,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s ICQService) FindByICQEmail(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0529_DBQueryMetaReqSearchByEmail, seq uint16) error {
	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     sess.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
		Success:    wire.ICQStatusCodeOK,
	}
	resp.LastResult()

	res, err := s.userFinder.FindByICQEmail(ctx, req.Email)

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

	return s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
		Message: resp,
	})
}

func (s ICQService) FindByEmail3(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0573_DBQueryMetaReqSearchByEmail3, seq uint16) error {
	b, hasEmail := req.Bytes(wire.ICQTLVTagsEmail)
	if !hasEmail {
		return errors.New("unable to get email from request")
	}

	email := wire.ICQEmail{}
	if err := wire.UnmarshalLE(&email, bytes.NewReader(b)); err != nil {
		return fmt.Errorf("unmarshal email: %w", err)
	}

	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     sess.UIN(),
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

	return s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
		Message: resp,
	})
}

func (s ICQService) FindByICQInterests(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0533_DBQueryMetaReqSearchWhitePages, seq uint16) error {
	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     sess.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		Success:    wire.ICQStatusCodeOK,
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
	}

	interests := strings.Split(req.InterestsKeyword, ",")
	res, err := s.userFinder.FindByICQInterests(ctx, req.InterestsCode, interests)

	if err != nil {
		s.logger.Error("FindByICQInterests failed", "err", err.Error())
		resp.Success = wire.ICQStatusCodeErr
		return s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
			Message: resp,
		})
	}
	if len(res) == 0 {
		resp.Success = wire.ICQStatusCodeFail
		return s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
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
		if err := s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
			Message: resp,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s ICQService) FindByWhitePages2(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2, seq uint16) error {

	users, err := func() ([]state.User, error) {
		if keyword, hasKeyword := req.ICQString(wire.ICQTLVTagsWhitepagesSearchKeywords); hasKeyword {
			res, err := s.userFinder.FindByICQKeyword(ctx, keyword)
			if err != nil {
				return nil, fmt.Errorf("FindByICQKeyword failed: %w", err)
			}
			return res, nil
		}

		bNick, hasNick := req.ICQString(wire.ICQTLVTagsNickname)
		bFirst, hasFirst := req.ICQString(wire.ICQTLVTagsFirstName)
		bLast, hastLast := req.ICQString(wire.ICQTLVTagsLastName)

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
			UIN:     sess.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		Success:    wire.ICQStatusCodeOK,
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
	}

	if err != nil {
		s.logger.Error("FindByWhitePages2 failed", "err", err.Error())
		resp.Success = wire.ICQStatusCodeErr
		return s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
			Message: resp,
		})
	}

	if len(users) == 0 {
		resp.Success = wire.ICQStatusCodeFail
		return s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
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
		if err := s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
			Message: resp,
		}); err != nil {
			return err
		}
	}

	return nil
}

func (s ICQService) FindByUIN(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN, seq uint16) error {
	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     sess.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
		Success:    wire.ICQStatusCodeOK,
	}
	resp.LastResult()

	res, err := s.userFinder.FindByUIN(ctx, req.UIN)

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

	return s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
		Message: resp,
	})
}

func (s ICQService) FindByUIN2(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2, seq uint16) error {
	UIN, hasUIN := req.Uint32LE(wire.ICQTLVTagsUIN)
	if !hasUIN {
		return errors.New("unable to get UIN from request")
	}

	resp := wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
		ICQMetadata: wire.ICQMetadata{
			UIN:     sess.UIN(),
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

	return s.reply(ctx, sess, wire.ICQMessageReplyEnvelope{
		Message: resp,
	})
}

func (s ICQService) FullUserInfo(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN, seq uint16) error {

	user, err := s.userFinder.FindByUIN(ctx, req.UIN)
	if err != nil {
		return err
	}

	if err := s.userInfo(ctx, sess, user, seq); err != nil {
		return err
	}

	if err := s.moreUserInfo(ctx, sess, user, seq); err != nil {
		return err
	}

	if err := s.extraEmails(ctx, sess, user, seq); err != nil {
		return err
	}

	if err := s.homepageCat(ctx, sess, user, seq); err != nil {
		return err
	}

	if err := s.workInfo(ctx, sess, user, seq); err != nil {
		return err
	}

	if err := s.notes(ctx, sess, user, seq); err != nil {
		return err
	}

	if err := s.interests(ctx, sess, user, seq); err != nil {
		return err
	}

	if err := s.affiliations(ctx, sess, user, seq); err != nil {
		return err
	}
	return nil
}

func (s ICQService) OfflineMsgReq(ctx context.Context, sess *state.Session, seq uint16) error {
	messages, err := s.offlineMessageManager.RetrieveMessages(ctx, sess.IdentScreenName())
	if err != nil {
		return fmt.Errorf("retrieving messages: %w", err)
	}

	for _, msgIn := range messages {
		reply := wire.ICQ_0x0041_DBQueryOfflineMsgReply{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
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
				// send authorization request
				msg := wire.ICBMCh4Message{}
				buf := bytes.NewBuffer(b)
				if err := wire.UnmarshalLE(&msg, buf); err != nil {
					return err
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
		if err := s.reply(ctx, sess, msgOut); err != nil {
			return fmt.Errorf("sending offline message: %w", err)
		}
	}

	eofMsg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x0042_DBQueryOfflineMsgReplyLast{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
				ReqType: wire.ICQDBQueryOfflineMsgReplyLast,
				Seq:     seq,
			},
			DroppedMessages: 0,
		},
	}

	return s.reply(ctx, sess, eofMsg)
}

func (s ICQService) SetAffiliations(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations, seq uint16) error {
	if len(req.PastAffiliations) != 3 || len(req.Affiliations) != 3 {
		return fmt.Errorf("%w: expected 3 past affiliations and 3 affiliations", errICQBadRequest)
	}
	u := state.ICQAffiliations{
		PastCode1:       req.PastAffiliations[0].Code,
		PastKeyword1:    req.PastAffiliations[0].Keyword,
		PastCode2:       req.PastAffiliations[1].Code,
		PastKeyword2:    req.PastAffiliations[1].Keyword,
		PastCode3:       req.PastAffiliations[2].Code,
		PastKeyword3:    req.PastAffiliations[2].Keyword,
		CurrentCode1:    req.Affiliations[0].Code,
		CurrentKeyword1: req.Affiliations[0].Keyword,
		CurrentCode2:    req.Affiliations[1].Code,
		CurrentKeyword2: req.Affiliations[1].Keyword,
		CurrentCode3:    req.Affiliations[2].Code,
		CurrentKeyword3: req.Affiliations[2].Keyword,
	}

	if err := s.userUpdater.SetAffiliations(ctx, sess.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, sess, seq, wire.ICQDBQueryMetaReplySetAffiliations)
}

func (s ICQService) SetBasicInfo(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo, seq uint16) error {
	u := state.ICQBasicInfo{
		CellPhone:    req.CellPhone,
		CountryCode:  req.CountryCode,
		EmailAddress: req.EmailAddress,
		FirstName:    req.FirstName,
		GMTOffset:    req.GMTOffset,
		Address:      req.HomeAddress,
		City:         req.City,
		Fax:          req.Fax,
		Phone:        req.Phone,
		State:        req.State,
		LastName:     req.LastName,
		Nickname:     req.Nickname,
		PublishEmail: req.PublishEmail == wire.ICQUserFlagPublishEmailYes,
		ZIPCode:      req.ZIP,
	}

	if err := s.userUpdater.SetBasicInfo(ctx, sess.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, sess, seq, wire.ICQDBQueryMetaReplySetBasicInfo)
}

func (s ICQService) SetEmails(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x040B_DBQueryMetaReqSetEmails, seq uint16) error {
	if len(req.Emails) > 0 {
		s.logger.Debug("adding additional emails is not yet supported")
	}
	return s.reqAck(ctx, sess, seq, wire.ICQDBQueryMetaReplySetEmails)
}

func (s ICQService) SetInterests(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests, seq uint16) error {
	if len(req.Interests) != 4 {
		return fmt.Errorf("%w: expected 4 interests", errICQBadRequest)
	}
	u := state.ICQInterests{
		Code1:    req.Interests[0].Code,
		Keyword1: req.Interests[0].Keyword,
		Code2:    req.Interests[1].Code,
		Keyword2: req.Interests[1].Keyword,
		Code3:    req.Interests[2].Code,
		Keyword3: req.Interests[2].Keyword,
		Code4:    req.Interests[3].Code,
		Keyword4: req.Interests[3].Keyword,
	}

	if err := s.userUpdater.SetInterests(ctx, sess.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, sess, seq, wire.ICQDBQueryMetaReplySetInterests)
}

func (s ICQService) SetMoreInfo(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo, seq uint16) error {
	u := state.ICQMoreInfo{
		Gender:       req.Gender,
		HomePageAddr: req.HomePageAddr,
		BirthYear:    req.BirthYear,
		BirthMonth:   req.BirthMonth,
		BirthDay:     req.BirthDay,
		Lang1:        req.Lang1,
		Lang2:        req.Lang2,
		Lang3:        req.Lang3,
	}

	if err := s.userUpdater.SetMoreInfo(ctx, sess.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, sess, seq, wire.ICQDBQueryMetaReplySetMoreInfo)
}

func (s ICQService) SetPermissions(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions, seq uint16) error {
	s.logger.Debug("setting permissions is not yet supported")
	return s.reqAck(ctx, sess, seq, wire.ICQDBQueryMetaReplySetPermissions)
}

func (s ICQService) SetUserNotes(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes, seq uint16) error {
	u := state.ICQUserNotes{
		Notes: req.Notes,
	}

	if err := s.userUpdater.SetUserNotes(ctx, sess.IdentScreenName(), u); err != nil {
		return err
	}

	return s.reqAck(ctx, sess, seq, wire.ICQDBQueryMetaReplySetNotes)
}

func (s ICQService) SetWorkInfo(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo, seq uint16) error {
	icqWorkInfo := state.ICQWorkInfo{
		Company:        req.Company,
		Department:     req.Department,
		OccupationCode: req.OccupationCode,
		Position:       req.Position,
		Address:        req.Address,
		City:           req.City,
		CountryCode:    req.CountryCode,
		Fax:            req.Fax,
		Phone:          req.Phone,
		State:          req.State,
		WebPage:        req.WebPage,
		ZIPCode:        req.ZIP,
	}

	if err := s.userUpdater.SetWorkInfo(ctx, sess.IdentScreenName(), icqWorkInfo); err != nil {
		return err
	}

	return s.reqAck(ctx, sess, seq, wire.ICQDBQueryMetaReplySetWorkInfo)
}

func (s ICQService) ShortUserInfo(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x04BA_DBQueryMetaReqShortInfo, seq uint16) error {
	user, err := s.userFinder.FindByUIN(ctx, req.UIN)
	if err != nil {
		return err
	}

	info := wire.ICQ_0x07DA_0x0104_DBQueryMetaReplyShortInfo{
		ICQMetadata: wire.ICQMetadata{
			UIN:     sess.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType: wire.ICQDBQueryMetaReplyShortInfo,
		Success:    wire.ICQStatusCodeOK,
		Nickname:   user.ICQBasicInfo.Nickname,
		FirstName:  user.ICQBasicInfo.FirstName,
		LastName:   user.ICQBasicInfo.LastName,
		Email:      user.ICQBasicInfo.EmailAddress,
		Gender:     uint8(user.ICQMoreInfo.Gender),
	}
	if user.ICQPermissions.AuthRequired {
		info.Authorization = 1
	}

	msg := wire.ICQMessageReplyEnvelope{
		Message: info,
	}

	return s.reply(ctx, sess, msg)
}

func (s ICQService) XMLReqData(ctx context.Context, sess *state.Session, req wire.ICQ_0x07D0_0x0898_DBQueryMetaReqXMLReq, seq uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x08A2_DBQueryMetaReplyXMLData{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyXMLData,
			Success:    wire.ICQStatusCodeFail,
		},
	}
	return s.reply(ctx, sess, msg)
}

func (s ICQService) affiliations(ctx context.Context, sess *state.Session, user state.User, seq uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00FA_DBQueryMetaReplyAffiliations{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
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
						Code:    user.ICQAffiliations.PastCode1,
						Keyword: user.ICQAffiliations.PastKeyword1,
					},
					{
						Code:    user.ICQAffiliations.PastCode2,
						Keyword: user.ICQAffiliations.PastKeyword2,
					},
					{
						Code:    user.ICQAffiliations.PastCode3,
						Keyword: user.ICQAffiliations.PastKeyword3,
					},
				},
				Affiliations: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{
					{
						Code:    user.ICQAffiliations.CurrentCode1,
						Keyword: user.ICQAffiliations.CurrentKeyword1,
					},
					{
						Code:    user.ICQAffiliations.CurrentCode2,
						Keyword: user.ICQAffiliations.CurrentKeyword2,
					},
					{
						Code:    user.ICQAffiliations.CurrentCode3,
						Keyword: user.ICQAffiliations.CurrentKeyword3,
					},
				},
			},
		},
	}

	return s.reply(ctx, sess, msg)
}

func (s ICQService) createResult(res state.User) wire.ICQUserSearchRecord {
	uin, _ := strconv.Atoi(res.IdentScreenName.String())

	searchRecord := wire.ICQUserSearchRecord{
		UIN:       uint32(uin),
		Nickname:  res.ICQBasicInfo.Nickname,
		FirstName: res.ICQBasicInfo.FirstName,
		LastName:  res.ICQBasicInfo.LastName,
		Email:     res.ICQBasicInfo.EmailAddress,
		Gender:    uint8(res.ICQMoreInfo.Gender),
		Age:       res.Age(s.timeNow),
	}
	if res.ICQPermissions.AuthRequired {
		searchRecord.Authorization = 1
	}

	userSess := s.sessionRetriever.RetrieveSession(res.IdentScreenName, 0)
	if userSess != nil {
		searchRecord.OnlineStatus = 1
	}
	return searchRecord
}

func (s ICQService) extraEmails(ctx context.Context, sess *state.Session, user state.User, seq uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00EB_DBQueryMetaReplyExtEmailInfo{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyExtEmailInfo,
			Success:    wire.ICQStatusCodeOK,
		},
	}

	return s.reply(ctx, sess, msg)
}

func (s ICQService) homepageCat(ctx context.Context, sess *state.Session, user state.User, seq uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x010E_DBQueryMetaReplyHomePageCat{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyHomePageCat,
			Success:    wire.ICQStatusCodeOK,
		},
	}

	return s.reply(ctx, sess, msg)
}

func (s ICQService) interests(ctx context.Context, sess *state.Session, user state.User, seq uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00F0_DBQueryMetaReplyInterests{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
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
					Code:    user.ICQInterests.Code1,
					Keyword: user.ICQInterests.Keyword1,
				},
				{
					Code:    user.ICQInterests.Code2,
					Keyword: user.ICQInterests.Keyword2,
				},
				{
					Code:    user.ICQInterests.Code3,
					Keyword: user.ICQInterests.Keyword3,
				},
				{
					Code:    user.ICQInterests.Code4,
					Keyword: user.ICQInterests.Keyword4,
				},
			},
		},
	}

	return s.reply(ctx, sess, msg)
}

func (s ICQService) moreUserInfo(ctx context.Context, sess *state.Session, user state.User, seq uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyMoreInfo,
			Success:    wire.ICQStatusCodeOK,
			ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo: wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo{
				Age:          uint8(user.Age(s.timeNow)),
				Gender:       user.ICQMoreInfo.Gender,
				HomePageAddr: user.ICQMoreInfo.HomePageAddr,
				BirthYear:    user.ICQMoreInfo.BirthYear,
				BirthMonth:   user.ICQMoreInfo.BirthMonth,
				BirthDay:     user.ICQMoreInfo.BirthDay,
				Lang1:        user.ICQMoreInfo.Lang1,
				Lang2:        user.ICQMoreInfo.Lang2,
				Lang3:        user.ICQMoreInfo.Lang3,
			},
			City:        user.ICQBasicInfo.City,
			State:       user.ICQBasicInfo.State,
			CountryCode: user.ICQBasicInfo.CountryCode,
			TimeZone:    user.ICQBasicInfo.GMTOffset,
		},
	}

	return s.reply(ctx, sess, msg)
}

func (s ICQService) notes(ctx context.Context, sess *state.Session, user state.User, seq uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00E6_DBQueryMetaReplyNotes{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyNotes,
			Success:    wire.ICQStatusCodeOK,
			ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes: wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes{
				Notes: user.ICQNotes.Notes,
			},
		},
	}

	return s.reply(ctx, sess, msg)
}

func (s ICQService) reply(ctx context.Context, sess *state.Session, message wire.ICQMessageReplyEnvelope) error {
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

	s.messageRelayer.RelayToScreenName(ctx, sess.IdentScreenName(), msg)
	return nil
}

func (s ICQService) reqAck(ctx context.Context, sess *state.Session, seq uint16, subType uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: subType,
			Success:    wire.ICQStatusCodeOK,
		},
	}

	return s.reply(ctx, sess, msg)
}

func (s ICQService) userInfo(ctx context.Context, sess *state.Session, user state.User, seq uint16) error {
	userInfo := wire.ICQ_0x07DA_0x00C8_DBQueryMetaReplyBasicInfo{
		ICQMetadata: wire.ICQMetadata{
			UIN:     sess.UIN(),
			ReqType: wire.ICQDBQueryMetaReply,
			Seq:     seq,
		},
		ReqSubType:  wire.ICQDBQueryMetaReplyBasicInfo,
		Success:     wire.ICQStatusCodeOK,
		Nickname:    user.ICQBasicInfo.Nickname,
		FirstName:   user.ICQBasicInfo.FirstName,
		LastName:    user.ICQBasicInfo.LastName,
		Email:       user.ICQBasicInfo.EmailAddress,
		City:        user.ICQBasicInfo.City,
		State:       user.ICQBasicInfo.State,
		Phone:       user.ICQBasicInfo.Phone,
		Fax:         user.ICQBasicInfo.Fax,
		Address:     user.ICQBasicInfo.Address,
		CellPhone:   user.ICQBasicInfo.CellPhone,
		ZIP:         user.ICQBasicInfo.ZIPCode,
		CountryCode: user.ICQBasicInfo.CountryCode,
		GMTOffset:   user.ICQBasicInfo.GMTOffset,
		AuthFlag:    0, // todo figure these out
		WebAware:    1, // todo figure these out
		DCPerms:     0, // todo figure these out
	}

	if user.ICQBasicInfo.PublishEmail {
		userInfo.PublishEmail = wire.ICQUserFlagPublishEmailYes
	} else {
		userInfo.PublishEmail = wire.ICQUserFlagPublishEmailNo
	}

	msg := wire.ICQMessageReplyEnvelope{
		Message: userInfo,
	}
	return s.reply(ctx, sess, msg)

}

func (s ICQService) workInfo(ctx context.Context, sess *state.Session, user state.User, seq uint16) error {
	msg := wire.ICQMessageReplyEnvelope{
		Message: wire.ICQ_0x07DA_0x00D2_DBQueryMetaReplyWorkInfo{
			ICQMetadata: wire.ICQMetadata{
				UIN:     sess.UIN(),
				ReqType: wire.ICQDBQueryMetaReply,
				Seq:     seq,
			},
			ReqSubType: wire.ICQDBQueryMetaReplyWorkInfo,
			Success:    wire.ICQStatusCodeOK,
			ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo: wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo{
				City:           user.ICQWorkInfo.City,
				State:          user.ICQWorkInfo.State,
				Phone:          user.ICQWorkInfo.Phone,
				Fax:            user.ICQWorkInfo.Fax,
				Address:        user.ICQWorkInfo.Address,
				ZIP:            user.ICQWorkInfo.ZIPCode,
				CountryCode:    user.ICQWorkInfo.CountryCode,
				Company:        user.ICQWorkInfo.Company,
				Department:     user.ICQWorkInfo.Department,
				Position:       user.ICQWorkInfo.Position,
				OccupationCode: user.ICQWorkInfo.OccupationCode,
				WebPage:        user.ICQWorkInfo.WebPage,
			},
		},
	}
	return s.reply(ctx, sess, msg)
}
