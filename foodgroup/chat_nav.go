package foodgroup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

var defaultExchangeCfg = wire.TLVList{
	wire.NewTLVBE(wire.ChatRoomTLVMaxConcurrentRooms, uint8(10)),
	wire.NewTLVBE(wire.ChatRoomTLVClassPerms, uint16(0x0010)),
	wire.NewTLVBE(wire.ChatRoomTLVMaxNameLen, uint16(100)),
	wire.NewTLVBE(wire.ChatRoomTLVFlags, uint16(15)),
	wire.NewTLVBE(wire.ChatRoomTLVNavCreatePerms, uint8(2)),
	wire.NewTLVBE(wire.ChatRoomTLVCharSet1, "us-ascii"),
	wire.NewTLVBE(wire.ChatRoomTLVLang1, "en"),
	wire.NewTLVBE(wire.ChatRoomTLVCharSet2, "us-ascii"),
	wire.NewTLVBE(wire.ChatRoomTLVLang2, "en"),
}

var (
	errChatNavRoomNameMissing    = errors.New("unable to find chat name in TLV payload")
	errChatNavRoomCreateFailed   = errors.New("unable to create chat room")
	errChatNavRetrieveFailed     = errors.New("unable to retrieve chat room chat room")
	errChatNavMismatchedExchange = errors.New("chat room exchange does not match requested exchange")
)

// NewChatNavService creates a new instance of NewChatNavService.
func NewChatNavService(logger *slog.Logger, chatRoomManager ChatRoomRegistry) *ChatNavService {
	return &ChatNavService{
		logger:          logger,
		chatRoomManager: chatRoomManager,
	}
}

// ChatNavService provides functionality for the ChatNav food group, which
// handles chat room creation and serving chat room metadata.
type ChatNavService struct {
	logger          *slog.Logger
	chatRoomManager ChatRoomRegistry
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
					wire.NewTLVBE(wire.ChatNavTLVMaxConcurrentRooms, uint8(10)),
					wire.NewTLVBE(wire.ChatNavTLVExchangeInfo, wire.SNAC_0x0D_0x09_TLVExchangeInfo{
						Identifier: state.PrivateExchange,
						TLVPaddedRestBlock: wire.TLVPaddedRestBlock{
							Reserved: 0,
							TLVList:  defaultExchangeCfg,
						},
					}),
					wire.NewTLVBE(wire.ChatNavTLVExchangeInfo, wire.SNAC_0x0D_0x09_TLVExchangeInfo{
						Identifier: state.PublicExchange,
						TLVPaddedRestBlock: wire.TLVPaddedRestBlock{
							Reserved: 0,
							TLVList:  defaultExchangeCfg,
						},
					}),
				},
			},
		},
	}
}

// CreateRoom creates and returns a chat room or returns an existing chat
// room. It returns SNAC wire.ChatNavNavInfo, which contains metadata for the
// chat room.
func (s ChatNavService) CreateRoom(ctx context.Context, sess *state.Session, inFrame wire.SNACFrame, inBody wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate) (wire.SNACMessage, error) {
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
	room, err := s.chatRoomManager.ChatRoomByName(ctx, inBody.Exchange, name)

	switch {
	case errors.Is(err, state.ErrChatRoomNotFound):
		if inBody.Exchange == state.PublicExchange {
			s.logger.Debug(fmt.Sprintf("public chat room not found: %s:%d", name, inBody.Exchange))
			return sendChatNavErrorSNAC(inFrame, wire.ErrorCodeNoMatch)
		}

		room = state.NewChatRoom(name, sess.IdentScreenName(), inBody.Exchange)

		if err := s.chatRoomManager.CreateChatRoom(ctx, &room); err != nil {
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
					wire.NewTLVBE(wire.ChatNavTLVRoomInfo, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
						Cookie:         room.Cookie(),
						Exchange:       room.Exchange(),
						DetailLevel:    room.DetailLevel(),
						InstanceNumber: room.InstanceNumber(),
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
func (s ChatNavService) RequestRoomInfo(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo) (wire.SNACMessage, error) {
	if err := validateExchange(inBody.Exchange); err != nil {
		s.logger.Debug("error validating exchange: " + err.Error())
		return sendChatNavErrorSNAC(inFrame, wire.ErrorCodeNotSupportedByHost)
	}

	room, err := s.chatRoomManager.ChatRoomByCookie(ctx, inBody.Cookie)
	if err != nil {
		return wire.SNACMessage{}, fmt.Errorf("%w: %w", state.ErrChatRoomNotFound, err)
	}

	if room.Exchange() != inBody.Exchange {
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
					wire.NewTLVBE(wire.ChatNavTLVRoomInfo, wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
						Cookie:         room.Cookie(),
						Exchange:       room.Exchange(),
						DetailLevel:    room.DetailLevel(),
						InstanceNumber: room.InstanceNumber(),
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
					wire.NewTLVBE(wire.ChatNavTLVMaxConcurrentRooms, uint8(10)),
					wire.NewTLVBE(wire.ChatNavTLVExchangeInfo, wire.SNAC_0x0D_0x09_TLVExchangeInfo{
						Identifier: inBody.Exchange,
						TLVPaddedRestBlock: wire.TLVPaddedRestBlock{
							Reserved: 0,
							TLVList:  defaultExchangeCfg,
						},
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
