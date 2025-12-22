package foodgroup

import (
	"context"
	"errors"
	"log/slog"
	"net/mail"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// NewAdminService creates an instance of AdminService.
func NewAdminService(
	accountManager AccountManager,
	bartItemManager BARTItemManager,
	relationshipFetcher RelationshipFetcher,
	messageRelayer MessageRelayer,
	sessionRetriever SessionRetriever,
	logger *slog.Logger,
) *AdminService {
	return &AdminService{
		accountManager:   accountManager,
		buddyBroadcaster: newBuddyNotifier(bartItemManager, relationshipFetcher, messageRelayer, sessionRetriever),
		messageRelayer:   messageRelayer,
		logger:           logger,
	}
}

// AdminService provides functionality for the Admin food group.
// The Admin food group is used for client control of passwords, screen name formatting,
// email address, and account confirmation.
type AdminService struct {
	accountManager   AccountManager
	buddyBroadcaster buddyBroadcaster
	messageRelayer   MessageRelayer
	logger           *slog.Logger
}

// ConfirmRequest will mark the user account as confirmed if the user has an email address set
func (s AdminService) ConfirmRequest(ctx context.Context, sess *state.Session, frame wire.SNACFrame) (wire.SNACMessage, error) {
	// getAdminInfoReply returns an AdminAcctConfirmReply SNAC
	var getAdminConfirmReply = func(status uint16) wire.SNACMessage {
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Admin,
				SubGroup:  wire.AdminAcctConfirmReply,
				RequestID: frame.RequestID,
			},
			Body: wire.SNAC_0x07_0x07_AdminConfirmReply{
				Status: status,
			},
		}
	}

	_, err := s.accountManager.EmailAddress(ctx, sess.IdentScreenName())
	if errors.Is(err, state.ErrNoEmailAddress) {
		return getAdminConfirmReply(wire.AdminAcctConfirmStatusServerError), nil
	} else if err != nil {
		return wire.SNACMessage{}, err
	}

	accountConfirmed, err := s.accountManager.ConfirmStatus(ctx, sess.IdentScreenName())
	if err != nil {
		return wire.SNACMessage{}, err
	}
	if accountConfirmed {
		return getAdminConfirmReply(wire.AdminAcctConfirmStatusAlreadyConfirmed), nil
	}
	if err := s.accountManager.UpdateConfirmStatus(ctx, sess.IdentScreenName(), true); err != nil {
		return wire.SNACMessage{}, err
	}
	sess.ClearUserInfoFlag(wire.OServiceUserFlagUnconfirmed)
	if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, sess.IdentScreenName(), sess.TLVUserInfo()); err != nil {
		return wire.SNACMessage{}, err
	}
	return getAdminConfirmReply(wire.AdminAcctConfirmStatusEmailSent), nil
}

// InfoQuery returns the requested information about the account
func (s AdminService) InfoQuery(ctx context.Context, sess *state.Session, frame wire.SNACFrame, body wire.SNAC_0x07_0x02_AdminInfoQuery) (wire.SNACMessage, error) {
	// getAdminInfoReply returns an AdminInfoReply SNAC
	var getAdminInfoReply = func(tlvList wire.TLVList) wire.SNACMessage {
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Admin,
				SubGroup:  wire.AdminInfoReply,
				RequestID: frame.RequestID,
			},
			Body: wire.SNAC_0x07_0x03_AdminInfoReply{
				Permissions: wire.AdminInfoPermissionsReadWrite, // todo: what does this actually control?
				TLVBlock: wire.TLVBlock{
					TLVList: tlvList,
				},
			},
		}
	}

	tlvList := wire.TLVList{}

	if _, hasRegStatus := body.TLVRestBlock.Bytes(wire.AdminTLVRegistrationStatus); hasRegStatus {
		regStatus, err := s.accountManager.RegStatus(ctx, sess.IdentScreenName())
		if err != nil {
			return wire.SNACMessage{}, err
		}
		tlvList.Append(wire.NewTLVBE(wire.AdminTLVRegistrationStatus, regStatus))
		return getAdminInfoReply(tlvList), nil
	}

	if _, hasEmail := body.TLVRestBlock.Bytes(wire.AdminTLVEmailAddress); hasEmail {
		e, err := s.accountManager.EmailAddress(ctx, sess.IdentScreenName())
		if errors.Is(err, state.ErrNoEmailAddress) {
			tlvList.Append(wire.NewTLVBE(wire.AdminTLVEmailAddress, ""))
		} else if err != nil {
			return wire.SNACMessage{}, err
		} else {
			tlvList.Append(wire.NewTLVBE(wire.AdminTLVEmailAddress, e.Address))
		}
		return getAdminInfoReply(tlvList), nil
	}

	if _, hasNickName := body.TLVRestBlock.Bytes(wire.AdminTLVScreenNameFormatted); hasNickName {
		tlvList.Append(wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, sess.DisplayScreenName().String()))
		return getAdminInfoReply(tlvList), nil
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Admin,
			SubGroup:  wire.AdminErr,
			RequestID: frame.RequestID,
		},
		Body: wire.SNACError{
			Code: wire.ErrorCodeNotSupportedByHost,
		},
	}, nil
}

// InfoChangeRequest handles the user changing account information
func (s AdminService) InfoChangeRequest(ctx context.Context, sess *state.Session, frame wire.SNACFrame, body wire.SNAC_0x07_0x04_AdminInfoChangeRequest) (wire.SNACMessage, error) {
	// replyMessage builds and returns an AdminChangeReply SNAC
	var getAdminChangeReply = func(tlvList wire.TLVList) wire.SNACMessage {
		return wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.Admin,
				SubGroup:  wire.AdminInfoChangeReply,
				RequestID: frame.RequestID,
			},
			Body: wire.SNAC_0x07_0x05_AdminChangeReply{
				Permissions: wire.AdminInfoPermissionsReadWrite,
				TLVBlock: wire.TLVBlock{
					TLVList: tlvList,
				},
			},
		}
	}

	// validateProposedName ensures that the name is valid
	var validateProposedName = func(name state.DisplayScreenName) (ok bool, errorCode uint16) {
		err := name.ValidateAIMHandle()
		switch {
		case errors.Is(err, state.ErrAIMHandleLength):
			// proposed name is too long
			return false, wire.AdminInfoErrorInvalidNickNameLength
		case errors.Is(err, state.ErrAIMHandleInvalidFormat):
			// character or spacing issues
			return false, wire.AdminInfoErrorInvalidNickName
		}

		// proposed name does not match session name (e.g. malicious client)
		if name.IdentScreenName() != sess.IdentScreenName() {
			return false, wire.AdminInfoErrorValidateNickName
		}

		return true, 0
	}

	// validateProposedEmailAddress ensures that the email address is valid
	var validateProposedEmailAddress = func(emailAddress []byte) (e *mail.Address, errorCode uint16) {
		/*
			todo: pidgin/libpurple will show 'unknown error: 0xNNNN' for these error codes.
			We could do a client check here and send wire.AdminInfoErrorDNSFail so pidgin
			will show "given email address is invalid" instead.
		*/

		e, err := mail.ParseAddress(string(emailAddress))

		// rfc 5322 basic validation
		if err != nil {
			return nil, wire.AdminInfoErrorInvalidEmail
		}
		// rfc 5521 length - local-part (64) + @ (1) + domain (255)
		if len(e.Address) > 320 {
			return nil, wire.AdminInfoErrorInvalidEmailLength
		}
		// todo: wire.AdminInfoErrorDNSFail could be sent here for an invalid domain name
		return e, 0
	}

	tlvList := wire.TLVList{}

	if sn, hasScreenNameFormatted := body.TLVRestBlock.Bytes(wire.AdminTLVScreenNameFormatted); hasScreenNameFormatted {
		proposedName := state.DisplayScreenName(sn)
		if ok, errorCode := validateProposedName(proposedName); !ok {
			tlvList.Append(wire.NewTLVBE(wire.AdminTLVErrorCode, errorCode))
			tlvList.Append(wire.NewTLVBE(wire.AdminTLVUrl, ""))
			return getAdminChangeReply(tlvList), nil
		}
		if err := s.accountManager.UpdateDisplayScreenName(ctx, proposedName); err != nil {
			return wire.SNACMessage{}, err
		}
		sess.SetDisplayScreenName(proposedName)
		if err := s.buddyBroadcaster.BroadcastBuddyArrived(ctx, sess.IdentScreenName(), sess.TLVUserInfo()); err != nil {
			return wire.SNACMessage{}, err
		}
		s.messageRelayer.RelayToScreenName(ctx, sess.IdentScreenName(), wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceUserInfoUpdate,
			},
			Body: newOServiceUserInfoUpdate(sess),
		})
		tlvList.Append(wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, proposedName.String()))
		return getAdminChangeReply(tlvList), nil
	}

	if emailAddress, hasEmailAddress := body.TLVRestBlock.Bytes(wire.AdminTLVEmailAddress); hasEmailAddress {
		e, errorCode := validateProposedEmailAddress(emailAddress)
		if errorCode != 0 {
			tlvList.Append(wire.NewTLVBE(wire.AdminTLVErrorCode, errorCode))
			tlvList.Append(wire.NewTLVBE(wire.AdminTLVUrl, ""))
			return getAdminChangeReply(tlvList), nil

		}
		if err := s.accountManager.UpdateEmailAddress(ctx, sess.IdentScreenName(), e); err != nil {
			return wire.SNACMessage{}, err
		}
		tlvList.Append(wire.NewTLVBE(wire.AdminTLVEmailAddress, e.Address))
		return getAdminChangeReply(tlvList), nil
	}

	if regStatus, hasRegStatus := body.TLVRestBlock.Uint16BE(wire.AdminTLVRegistrationStatus); hasRegStatus {
		switch regStatus {
		case
			wire.AdminInfoRegStatusFullDisclosure,
			wire.AdminInfoRegStatusLimitDisclosure,
			wire.AdminInfoRegStatusNoDisclosure:
			if err := s.accountManager.UpdateRegStatus(ctx, sess.IdentScreenName(), regStatus); err != nil {
				return wire.SNACMessage{}, err
			}
			tlvList.Append(wire.NewTLVBE(wire.AdminTLVRegistrationStatus, regStatus))
			return getAdminChangeReply(tlvList), nil
		}
		tlvList.Append(wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorInvalidRegistrationPreference))
		tlvList.Append(wire.NewTLVBE(wire.AdminTLVUrl, ""))
		return getAdminChangeReply(tlvList), nil
	}

	// change password
	if newPass, hasPassStatus := body.TLVRestBlock.String(wire.AdminTLVNewPassword); hasPassStatus {
		tlvList.Append(wire.NewTLVBE(wire.AdminTLVNewPassword, []byte{}))

		oldPass, ok := body.TLVRestBlock.String(wire.AdminTLVOldPassword)
		if !ok {
			tlvList.Append(wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorNeedOldPassword))
			return getAdminChangeReply(tlvList), nil
		}

		u, err := s.accountManager.User(ctx, sess.IdentScreenName())
		if err != nil || u == nil {
			if err != nil {
				s.logger.ErrorContext(ctx, "accountManager.User: runtime error", "err", err)
			} else {
				s.logger.ErrorContext(ctx, "accountManager.User: can't find user", "err", err)
			}
			tlvList.Append(wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorAllOtherErrors))
			return getAdminChangeReply(tlvList), nil
		}

		if !u.ValidateHash(wire.StrongMD5PasswordHash(oldPass, u.AuthKey)) {
			tlvList.Append(wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorValidatePassword))
			return getAdminChangeReply(tlvList), nil
		}

		if err := s.accountManager.SetUserPassword(ctx, sess.IdentScreenName(), newPass); err != nil {
			if errors.Is(err, state.ErrPasswordInvalid) {
				tlvList.Append(wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorInvalidPasswordLength))
			} else {
				s.logger.ErrorContext(ctx, "accountManager.SetUserPassword: runtime error", "err", err)
				tlvList.Append(wire.NewTLVBE(wire.AdminTLVErrorCode, wire.AdminInfoErrorAllOtherErrors))
			}
			return getAdminChangeReply(tlvList), nil
		}

		return getAdminChangeReply(tlvList), nil
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Admin,
			SubGroup:  wire.AdminErr,
			RequestID: frame.RequestID,
		},
		Body: wire.SNACError{
			Code: wire.ErrorCodeNotSupportedByHost,
		},
	}, nil
}
