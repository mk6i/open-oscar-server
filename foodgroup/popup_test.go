package foodgroup

import (
	"context"
	"testing"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"

	"github.com/stretchr/testify/assert"
	"golang.org/x/text/encoding/charmap"
)

func popupMessage(tlvs ...wire.TLV) wire.SNACMessage {
	return wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Popup,
			SubGroup:  wire.PopupDisplay,
			RequestID: wire.ReqIDFromServer,
		},
		Body: wire.SNAC_0x08_0x02_PopupDisplay{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: tlvs,
			},
		},
	}
}

func TestPopupService_Display(t *testing.T) {
	screenNames := []state.IdentScreenName{
		state.NewIdentScreenName("them"),
		state.NewIdentScreenName("them2"),
	}

	cases := []struct {
		name       string
		message    string
		url        string
		width      uint16
		height     uint16
		mockParams mockParams
	}{
		{
			name:    "all fields set",
			message: "hello",
			url:     "http://example.com",
			width:   400,
			height:  300,
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNamesParams: relayToScreenNamesParams{
						{
							screenNames: screenNames,
							message: popupMessage(
								wire.NewTLVBE(wire.PopupTLVMessage, []byte("hello")),
								wire.NewTLVBE(wire.PopupTLVURL, "http://example.com"),
								wire.NewTLVBE(wire.PopupTLVWidth, uint16(400)),
								wire.NewTLVBE(wire.PopupTLVHeight, uint16(300)),
							),
						},
					},
				},
			},
		},
		{
			name:    "no url",
			message: "hello",
			width:   400,
			height:  300,
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNamesParams: relayToScreenNamesParams{
						{
							screenNames: screenNames,
							message: popupMessage(
								wire.NewTLVBE(wire.PopupTLVMessage, []byte("hello")),
								wire.NewTLVBE(wire.PopupTLVWidth, uint16(400)),
								wire.NewTLVBE(wire.PopupTLVHeight, uint16(300)),
							),
						},
					},
				},
			},
		},
		{
			name:    "non-ascii text",
			message: "caf\u00e9 \u2122 \u65e5",
			width:   400,
			height:  300,
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNamesParams: relayToScreenNamesParams{
						{
							screenNames: screenNames,
							message: popupMessage(
								wire.NewTLVBE(wire.PopupTLVMessage, []byte("caf\xe9 \x99 ?")),
								wire.NewTLVBE(wire.PopupTLVWidth, uint16(400)),
								wire.NewTLVBE(wire.PopupTLVHeight, uint16(300)),
							),
						},
					},
				},
			},
		},
		{
			name:    "default dimensions",
			message: "hello",
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNamesParams: relayToScreenNamesParams{
						{
							screenNames: screenNames,
							message: popupMessage(
								wire.NewTLVBE(wire.PopupTLVMessage, []byte("hello")),
								wire.NewTLVBE(wire.PopupTLVWidth, defaultPopupWidth),
								wire.NewTLVBE(wire.PopupTLVHeight, defaultPopupHeight),
							),
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tc.mockParams.relayToScreenNamesParams {
				messageRelayer.EXPECT().
					RelayToScreenNames(matchContext(), params.screenNames, params.message)
			}

			svc := NewPopupService(messageRelayer, charmap.Windows1252)
			err := svc.Display(context.Background(), screenNames, tc.message, tc.url, tc.width, tc.height)
			assert.NoError(t, err)
		})
	}
}

func TestPopupService_DisplayAll(t *testing.T) {
	want := popupMessage(
		wire.NewTLVBE(wire.PopupTLVMessage, []byte("hello")),
		wire.NewTLVBE(wire.PopupTLVURL, "http://example.com"),
		wire.NewTLVBE(wire.PopupTLVWidth, uint16(400)),
		wire.NewTLVBE(wire.PopupTLVHeight, uint16(300)),
	)

	messageRelayer := newMockMessageRelayer(t)
	messageRelayer.EXPECT().RelayToAll(matchContext(), want)

	svc := NewPopupService(messageRelayer, charmap.Windows1252)
	err := svc.DisplayAll(context.Background(), "hello", "http://example.com", 400, 300)
	assert.NoError(t, err)
}
