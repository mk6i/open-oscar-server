package foodgroup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

var defaultExchangeCfg = wire.TLVBlock{
	TLVList: wire.TLVList{
		wire.NewTLV(wire.ChatRoomTLVMaxConcurrentRooms, uint8(10)),
		wire.NewTLV(wire.ChatRoomTLVClassPerms, uint16(0x0010)),
		wire.NewTLV(wire.ChatRoomTLVMaxNameLen, uint16(100)),
		wire.NewTLV(wire.ChatRoomTLVFlags, uint16(15)),
		wire.NewTLV(wire.ChatRoomTLVNavCreatePerms, uint8(2)),
		wire.NewTLV(wire.ChatRoomTLVCharSet1, "us-ascii"),
		wire.NewTLV(wire.ChatRoomTLVLang1, "en"),
		wire.NewTLV(wire.ChatRoomTLVCharSet2, "us-ascii"),
		wire.NewTLV(wire.ChatRoomTLVLang2, "en"),
	},
}

var (
	errChatNavRoomNameMissing    = errors.New("unable to find chat name in TLV payload")
	errChatNavRoomCreateFailed   = errors.New("unable to create chat room")
	errChatNavRetrieveFailed     = errors.New("unable to retrieve chat room chat room")
	errChatNavMismatchedExchange = errors.New("chat room exchange does not match requested exchange")
)

// detailLevel is the detail level of the chat room (whatever that means).
// Pidgin 2.13.0 expects value 0x02.
const detailLevel uint8 = 2

// NewChatNavService creates a new instance of NewChatNavService.
func NewChatNavService(logger *slog.Logger, chatRoomManager ChatRoomRegistry, fnNewChatRoom func() state.ChatRoom) *ChatNavService {
	return &ChatNavService{
		logger:          logger,
		chatRoomManager: chatRoomManager,
		fnNewChatRoom:   fnNewChatRoom,
	}
}

// ChatNavService provides functionality for the ChatNav food group, which
// handles chat room creation and serving chat room metadata.
type ChatNavService struct {
	logger          *slog.Logger
	chatRoomManager ChatRoomRegistry
	fnNewChatRoom   func() state.ChatRoom
}

// RequestChatRights returns SNAC wire.ChatNavNavInfo, which contains chat
// navigation service parameters and limits.
func (s ChatNavService) RequestChatRights(_ context.Context, inFrame wire.SNACFrame) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ChatNav,
			SubGroup:  wire.ChatNavNavInfo,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLV(wire.ChatNavTLVMaxConcurrentRooms, uint8(10)),
					wire.NewTLV(wire.ChatNavTLVExchangeInfo, wire.SNAC_0x0D_0x09_TLVExchangeInfo{
						Identifier: state.PrivateExchange,
						TLVBlock:   defaultExchangeCfg,
					}),
					wire.NewTLV(wire.ChatNavTLVExchangeInfo, wire.SNAC_0x0D_0x09_TLVExchangeInfo{
						Identifier: state.PublicExchange,
						TLVBlock:   defaultExchangeCfg,
					}),
				},
			},
		},
	}
}

// CreateRoom creates and returns a chat room or returns an existing chat
// room. It returns SNAC wire.ChatNavNavInfo, which contains metadata for the
// chat room.
func (s ChatNavService) CreateRoom(_ context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate) (wire.SNACMessage, error) {
	if err := validateExchange(inBody.Exchange); err != nil {
		s.logger.Debug("error validating exchange: " + err.Error())
		return sendChatNavErrorSNAC(inFrame, wire.ErrorCodeNotSupportedByHost)
	}
	if inBody.Cookie != "create" {
		s.logger.Info("got a non-create cookie", "value", inBody.Cookie)
	}

	name, hasName := inBody.String(wire.ChatRoomTLVRoomName)
	if !hasName {
		return wire.SNACMessage{}, errChatNavRoomNameMissing
	}

	// todo call ChatRoomByName and CreateChatRoom in a txn
	room, err := s.chatRoomManager.ChatRoomByName(inBody.Exchange, name)

	switch {
	case errors.Is(err, state.ErrChatRoomNotFound):
		if inBody.Exchange == state.PublicExchange {
			s.logger.Debug(fmt.Sprintf("public chat room not found: %s:%d", name, inBody.Exchange))
			return sendChatNavErrorSNAC(inFrame, wire.ErrorCodeNoMatch)
		}

		room = s.fnNewChatRoom()
		room.Creator = sess.IdentScreenName()
		room.Exchange = inBody.Exchange
		room.InstanceNumber = inBody.InstanceNumber
		room.Name = name
		// According to Pidgin, the chat cookie is a 3-part identifier. The
		// third segment is the chat name, which is shown explicitly in the
		// Pidgin code. We can assume that the first two parts were the
		// exchange and instance number. As of now, Pidgin is the only client
		// that cares about the cookie format, and it only cares about the chat
		// name segment.
		room.Cookie = fmt.Sprintf("%d-%d-%s", inBody.Exchange, inBody.InstanceNumber, name)

		if err := s.chatRoomManager.CreateChatRoom(room); err != nil {
			return wire.SNACMessage{}, fmt.Errorf("%w: %w", errChatNavRoomCreateFailed, err)
		}
		break
	case err != nil:
		return wire.SNACMessage{}, fmt.Errorf("%w: %w", errChatNavRetrieveFailed, err)
	}
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ChatNav,
			SubGroup:  wire.ChatNavNavInfo,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLV(wire.ChatNavTLVRoomInfo, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
						Exchange:       room.Exchange,
						Cookie:         room.Cookie,
						InstanceNumber: room.InstanceNumber,
						DetailLevel:    detailLevel,
						TLVBlock: wire.TLVBlock{
							TLVList: room.TLVList(),
						},
					}),
				},
			},
		},
	}, nil
}

// RequestRoomInfo returns wire.ChatNavNavInfo, which contains metadata for
// the chat room specified in the inFrame.hmacCookie.
func (s ChatNavService) RequestRoomInfo(_ context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo) (wire.SNACMessage, error) {
	if err := validateExchange(inBody.Exchange); err != nil {
		s.logger.Debug("error validating exchange: " + err.Error())
		return sendChatNavErrorSNAC(inFrame, wire.ErrorCodeNotSupportedByHost)
	}

	room, err := s.chatRoomManager.ChatRoomByCookie(inBody.Cookie)
	if err != nil {
		return wire.SNACMessage{}, fmt.Errorf("%w: %w", state.ErrChatRoomNotFound, err)
	}

	if room.Exchange != inBody.Exchange {
		return wire.SNACMessage{}, errChatNavMismatchedExchange
	}

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ChatNav,
			SubGroup:  wire.ChatNavNavInfo,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLV(wire.ChatNavTLVRoomInfo, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
						Exchange:       room.Exchange,
						Cookie:         room.Cookie,
						InstanceNumber: room.InstanceNumber,
						DetailLevel:    detailLevel,
						TLVBlock: wire.TLVBlock{
							TLVList: room.TLVList(),
						},
					}),
				},
			},
		},
	}, nil
}

func (s ChatNavService) ExchangeInfo(_ context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0D_0x03_ChatNavRequestExchangeInfo) (wire.SNACMessage, error) {
	if err := validateExchange(inBody.Exchange); err != nil {
		s.logger.Debug("error validating exchange: " + err.Error())
		return sendChatNavErrorSNAC(inFrame, wire.ErrorCodeNotSupportedByHost)
	}
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ChatNav,
			SubGroup:  wire.ChatNavNavInfo,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLV(wire.ChatNavTLVMaxConcurrentRooms, uint8(10)),
					wire.NewTLV(wire.ChatNavTLVExchangeInfo, wire.SNAC_0x0D_0x09_TLVExchangeInfo{
						Identifier: inBody.Exchange,
						TLVBlock:   defaultExchangeCfg,
					}),
				},
			},
		},
	}, nil
}

// sendChatNavErrorSNAC returns a ChatNavErr SNAC and logs an error for the operator
func sendChatNavErrorSNAC(inFrame wire.SNACFrame, errorCode uint16) (wire.SNACMessage, error) {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ChatNav,
			SubGroup:  wire.ChatNavErr,
			RequestID: inFrame.RequestID,
		},
		Body: wire.SNACError{
			Code: errorCode,
		},
	}, nil
}

func validateExchange(exchange uint16) error {
	if !(exchange == state.PrivateExchange || exchange == state.PublicExchange) {
		return fmt.Errorf("only exchanges %d and %d are supported", state.PrivateExchange, state.PublicExchange)
	}
	return nil
}
