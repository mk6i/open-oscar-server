package foodgroup

import (
	"context"
	"fmt"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"

	"golang.org/x/text/encoding"
)

const (
	defaultPopupWidth  uint16 = 320
	defaultPopupHeight uint16 = 200
)

// NewPopupService returns a new instance of PopupService.
func NewPopupService(messageRelayer MessageRelayer, legacyCharset encoding.Encoding) PopupService {
	return PopupService{
		legacyCharset:  legacyCharset,
		messageRelayer: messageRelayer,
	}
}

// PopupService implements the Popup food group.
type PopupService struct {
	legacyCharset  encoding.Encoding
	messageRelayer MessageRelayer
}

// Display shows a popup to the given screen names.
func (s PopupService) Display(ctx context.Context, screenNames []state.IdentScreenName, message string, url string, width uint16, height uint16) error {
	msg, err := s.popupDisplay(message, url, width, height)
	if err != nil {
		return err
	}
	s.messageRelayer.RelayToScreenNames(ctx, screenNames, msg)
	return nil
}

// DisplayAll shows a popup to all connected users.
func (s PopupService) DisplayAll(ctx context.Context, message string, url string, width uint16, height uint16) error {
	msg, err := s.popupDisplay(message, url, width, height)
	if err != nil {
		return err
	}
	s.messageRelayer.RelayToAll(ctx, msg)
	return nil
}

func (s PopupService) popupDisplay(message string, url string, width uint16, height uint16) (wire.SNACMessage, error) {
	text, err := encodeLegacy(s.legacyCharset, message)
	if err != nil {
		return wire.SNACMessage{}, fmt.Errorf("encodeLegacy: %w", err)
	}

	// AIM opens a minimal window without dimensions.
	if width == 0 {
		width = defaultPopupWidth
	}
	if height == 0 {
		height = defaultPopupHeight
	}

	body := wire.SNAC_0x08_0x02_PopupDisplay{}
	body.Append(wire.NewTLVBE(wire.PopupTLVMessage, text))
	if url != "" {
		body.Append(wire.NewTLVBE(wire.PopupTLVURL, url))
	}
	body.Append(wire.NewTLVBE(wire.PopupTLVWidth, width))
	body.Append(wire.NewTLVBE(wire.PopupTLVHeight, height))

	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Popup,
			SubGroup:  wire.PopupDisplay,
			RequestID: wire.ReqIDFromServer,
		},
		Body: body,
	}, nil
}
