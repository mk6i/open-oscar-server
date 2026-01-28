package foodgroup

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestOServiceService_ServiceRequest(t *testing.T) {
	chatRoom := state.NewChatRoom("the-chat-room", state.NewIdentScreenName(""), state.PrivateExchange)

	cases := []struct {
		// name is the unit test name
		name string
		// service is the OSCAR service type
		service uint16
		// listener is the connection listener
		listener config.Listener
		// instance is the session of the user requesting the chat service
		// info
		instance *state.SessionInstance
		// inputSNAC is the SNAC sent by the sender client
		inputSNAC wire.SNACMessage
		// expectSNACFrame is the SNAC frame sent from the server to the recipient
		// client
		expectOutput wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectErr is the expected error returned by the router
		expectErr error
	}{
		{
			name:     "request info for connecting to admin svc, return admin svc connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234"},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.Admin,
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.Admin),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1234"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: []byte{
								0x00, 0x07, // admin service
								0x02, 'm', 'e',
								0x0,  // no client ID
								0x0,  // no chat cookie
								0x0,  // multi conn flag
								0x0,  // kerberos flag
								0x01, // session num
							},
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
		},
		{
			name:     "request info for connecting to alert svc, return alert svc connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234"},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.Alert,
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.Alert),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1234"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: []byte{
								0x00, 0x18, // alert service
								0x02, 'm', 'e',
								0x0,  // no client ID
								0x0,  // no chat cookie
								0x0,  // multi conn flag
								0x0,  // kerberos flag
								0x01, // session num
							},
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
		},
		{
			name:     "request info for connecting to BART service, return BART connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234"},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.BART,
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.BART),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1234"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: []byte{
								0x00, 0x10, // chatnav service
								0x02, 'm', 'e',
								0x0,  // no client ID
								0x0,  // no chat cookie
								0x0,  // multi conn flag
								0x0,  // kerberos flag
								0x01, // session num
							},
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
		},
		{
			name:     "request info for connecting to chat nav, return chat nav connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234"},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.ChatNav,
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.ChatNav),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1234"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: []byte{
								0x00, 0x0d, // chatnav service
								0x02, 'm', 'e',
								0x0,  // no client ID
								0x0,  // no chat cookie
								0x0,  // multi conn flag
								0x0,  // kerberos flag
								0x01, // session num
							},
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
		},
		{
			name:     "request info for connecting to chat room, return chat service and chat room metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234"},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.Chat,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{
								Exchange:       chatRoom.Exchange(),
								Cookie:         chatRoom.Cookie(),
								InstanceNumber: chatRoom.InstanceNumber(),
							}),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.Chat),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1234"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-auth-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
			mockParams: func() mockParams {
				return mockParams{
					chatRoomRegistryParams: chatRoomRegistryParams{
						chatRoomByCookieParams: chatRoomByCookieParams{
							{
								cookie: chatRoom.Cookie(),
								room:   chatRoom,
							},
						},
					},
					cookieBakerParams: cookieBakerParams{
						cookieIssueParams: cookieIssueParams{
							{
								dataIn: []byte{
									0x00, 0x0e, // chat service,
									0x02, 'm', 'e', // screen name
									0x00, // no client ID
									0x11, '4', '-', '0', '-', 't', 'h', 'e', '-', 'c', 'h', 'a', 't', '-', 'r', 'o', 'o', 'm',
									0x0,  // multi conn flag
									0x0,  // kerberos flag
									0x01, // session num
								},
								cookieOut: []byte("the-auth-cookie"),
							},
						},
					},
				}
			}(),
		},
		{
			name:     "request info for connecting to BART service, return BART connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234"},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.ODir,
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.ODir),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1234"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x00)),
						},
					},
				},
			},
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: []byte{
								0x00, 0x0F, // chatnav service
								0x02, 'm', 'e',
								0x0,  // no client ID
								0x0,  // no chat cookie
								0x0,  // multi conn flag
								0x0,  // kerberos flag
								0x01, // session num
							},
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
		},
		{
			name:     "request info for connecting to non-existent chat room, return ErrChatRoomNotFound",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234"},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.Chat,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{
								Exchange:       8,
								Cookie:         "the-chat-cookie",
								InstanceNumber: 16,
							}),
						},
					},
				},
			},
			mockParams: mockParams{
				chatRoomRegistryParams: chatRoomRegistryParams{
					chatRoomByCookieParams: chatRoomByCookieParams{
						{
							cookie: "the-chat-cookie",
							err:    state.ErrChatRoomNotFound,
						},
					},
				},
			},
			expectErr: state.ErrChatRoomNotFound,
		},
		{
			name:     "request info from a non-BOS service",
			service:  wire.Chat,
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.ICBM,
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotSupportedByHost,
				},
			},
		},
		{
			name:     "request info for ICBM service, return invalid SNAC err",
			service:  wire.BOS,
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.ICBM,
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeServiceUnavailable,
				},
			},
		},
		{
			name:     "request info for connecting to admin svc with SSL, return admin svc SSL connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234", BOSAdvertisedHostSSL: "127.0.0.1:1235", HasSSL: true},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.Admin,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OserviceTLVTagsSSLUseSSL, []byte{}),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.Admin),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1235"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x02)),
						},
					},
				},
			},
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: []byte{
								0x00, 0x07, // admin service
								0x02, 'm', 'e',
								0x0,  // no client ID
								0x0,  // no chat cookie
								0x0,  // multi conn flag
								0x0,  // kerberos flag
								0x01, // session num
							},
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
		},
		{
			name:     "request info for connecting to alert svc with SSL, return alert svc SSL connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234", BOSAdvertisedHostSSL: "127.0.0.1:1235", HasSSL: true},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.Alert,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OserviceTLVTagsSSLUseSSL, []byte{}),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.Alert),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1235"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x02)),
						},
					},
				},
			},
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: []byte{
								0x00, 0x18, // alert service
								0x02, 'm', 'e',
								0x0,  // no client ID
								0x0,  // no chat cookie
								0x0,  // multi conn flag
								0x0,  // kerberos flag
								0x01, // session num
							},
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
		},
		{
			name:     "request info for connecting to BART service with SSL, return BART SSL connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234", BOSAdvertisedHostSSL: "127.0.0.1:1235", HasSSL: true},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.BART,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OserviceTLVTagsSSLUseSSL, []byte{}),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.BART),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1235"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x02)),
						},
					},
				},
			},
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: []byte{
								0x00, 0x10, // BART service
								0x02, 'm', 'e',
								0x0,  // no client ID
								0x0,  // no chat cookie
								0x0,  // multi conn flag
								0x0,  // kerberos flag
								0x01, // session num
							},
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
		},
		{
			name:     "request info for connecting to chat nav with SSL, return chat nav SSL connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234", BOSAdvertisedHostSSL: "127.0.0.1:1235", HasSSL: true},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.ChatNav,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OserviceTLVTagsSSLUseSSL, []byte{}),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.ChatNav),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1235"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x02)),
						},
					},
				},
			},
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: []byte{
								0x00, 0x0d, // chatnav service
								0x02, 'm', 'e',
								0x0,  // no client ID
								0x0,  // no chat cookie
								0x0,  // multi conn flag
								0x0,  // kerberos flag
								0x01, // session num
							},
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
		},
		{
			name:     "request info for connecting to chat room with SSL, return chat service SSL connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234", BOSAdvertisedHostSSL: "127.0.0.1:1235", HasSSL: true},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.Chat,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(0x01, wire.SNAC_0x01_0x04_TLVRoomInfo{
								Exchange:       chatRoom.Exchange(),
								Cookie:         chatRoom.Cookie(),
								InstanceNumber: chatRoom.InstanceNumber(),
							}),
							wire.NewTLVBE(wire.OserviceTLVTagsSSLUseSSL, []byte{}),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.Chat),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1235"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-auth-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x02)),
						},
					},
				},
			},
			mockParams: func() mockParams {
				return mockParams{
					chatRoomRegistryParams: chatRoomRegistryParams{
						chatRoomByCookieParams: chatRoomByCookieParams{
							{
								cookie: chatRoom.Cookie(),
								room:   chatRoom,
							},
						},
					},
					cookieBakerParams: cookieBakerParams{
						cookieIssueParams: cookieIssueParams{
							{
								dataIn: []byte{
									0x00, 0x0e, // chat service,
									0x02, 'm', 'e', // screen name
									0x00, // no client ID
									0x11, '4', '-', '0', '-', 't', 'h', 'e', '-', 'c', 'h', 'a', 't', '-', 'r', 'o', 'o', 'm',
									0x0,  // multi conn flag
									0x0,  // kerberos flag
									0x01, // session num
								},
								cookieOut: []byte("the-auth-cookie"),
							},
						},
					},
				}
			}(),
		},
		{
			name:     "request info for connecting to ODir service with SSL, return ODir SSL connection metadata",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234", BOSAdvertisedHostSSL: "127.0.0.1:1235", HasSSL: true},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.ODir,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OserviceTLVTagsSSLUseSSL, []byte{}),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceTLVTagsGroupID, wire.ODir),
							wire.NewTLVBE(wire.OServiceTLVTagsReconnectHere, "127.0.0.1:1235"),
							wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("the-cookie")),
							wire.NewTLVBE(wire.OServiceTLVTagsSSLState, uint8(0x02)),
						},
					},
				},
			},
			mockParams: mockParams{
				cookieBakerParams: cookieBakerParams{
					cookieIssueParams: cookieIssueParams{
						{
							dataIn: []byte{
								0x00, 0x0F, // ODir service
								0x02, 'm', 'e',
								0x0,  // no client ID
								0x0,  // no chat cookie
								0x0,  // multi conn flag
								0x0,  // kerberos flag
								0x01, // session num
							},
							cookieOut: []byte("the-cookie"),
						},
					},
				},
			},
		},
		{
			name:     "request SSL service but listener doesn't support SSL, return error",
			service:  wire.BOS,
			listener: config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234", HasSSL: false},
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x04_OServiceServiceRequest{
					FoodGroup: wire.Admin,
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OserviceTLVTagsSSLUseSSL, []byte{}),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeGeneralFailure,
				},
			},
			mockParams: mockParams{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			//
			// initialize dependencies
			//
			chatRoomManager := newMockChatRoomRegistry(t)
			for _, params := range tc.mockParams.chatRoomByCookieParams {
				chatRoomManager.EXPECT().
					ChatRoomByCookie(context.Background(), params.cookie).
					Return(params.room, params.err)
			}
			cookieIssuer := newMockCookieBaker(t)
			for _, params := range tc.mockParams.cookieIssueParams {
				cookieIssuer.EXPECT().
					Issue(params.dataIn).
					Return(params.cookieOut, params.err)
			}
			chatMessageRelayer := newMockChatMessageRelayer(t)

			//
			// send input SNAC
			//
			svc := NewOServiceService(config.Config{}, nil, slog.Default(), cookieIssuer, chatRoomManager, nil, nil, nil, wire.DefaultSNACRateLimits(), chatMessageRelayer, nil, nil)

			outputSNAC, err := svc.ServiceRequest(context.Background(), tc.service, tc.instance, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x01_0x04_OServiceServiceRequest), tc.listener)
			assert.ErrorIs(t, err, tc.expectErr)
			if tc.expectErr != nil {
				return
			}
			//
			// verify output
			//
			assert.Equal(t, tc.expectOutput, outputSNAC)
		})
	}
}

func TestOServiceService_SetUserInfoFields(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user whose info is being set
		instance *state.SessionInstance
		// inputSNAC is the SNAC sent from the client to the server
		inputSNAC wire.SNACMessage
		// expectOutput is the SNAC reply sent from the server back to the
		// client
		expectOutput wire.SNACMessage
		// broadcastMessage is the arrival/departure message sent to buddies
		broadcastMessage []struct {
			recipients []string
			msg        wire.SNACMessage
		}
		// interestedUserLookups contains all the users who have this user on
		// their buddy list
		interestedUserLookups map[string][]string
		// expectErr is the expected error returned
		expectErr error
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:     "set user status to visible aim < 6",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceUserInfoUpdate,
					RequestID: 1234,
				},
				Body: func(val any) bool {
					snac, ok := val.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate)
					if !ok {
						return false
					}
					if len(snac.UserInfo) == 0 {
						return false
					}
					status, hasStatus := snac.UserInfo[0].Uint32BE(wire.OServiceUserInfoStatus)
					return hasStatus && status == uint32(0x0000)
				},
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyArrivedParams: broadcastBuddyArrivedParams{
						{
							screenName: state.DisplayScreenName("me"),
						},
					},
				},
			},
		},
		{
			name:     "set user status to invisible aim < 6",
			instance: newTestInstance("me"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0100)),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceUserInfoUpdate,
					RequestID: 1234,
				},
				Body: func(val any) bool {
					snac, ok := val.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate)
					if !ok {
						return false
					}
					if len(snac.UserInfo) == 0 {
						return false
					}
					status, hasStatus := snac.UserInfo[0].Uint32BE(wire.OServiceUserInfoStatus)
					return hasStatus && status == uint32(0x0100)
				},
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyDepartedParams: broadcastBuddyDepartedParams{
						{
							screenName: state.NewIdentScreenName("me"),
						},
					},
				},
			},
		},
		{
			name:     "set user status to visible aim >= 6",
			instance: newTestInstance("me", sessOptSetFoodGroupVersion(wire.OService, 4)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0000)),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceUserInfoUpdate,
					RequestID: 1234,
				},
				Body: func(val any) bool {
					snac, ok := val.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate)
					if !ok {
						return false
					}
					if len(snac.UserInfo) == 0 {
						return false
					}
					status, hasStatus := snac.UserInfo[0].Uint32BE(wire.OServiceUserInfoStatus)
					return hasStatus && status == uint32(0x0000)
				},
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyArrivedParams: broadcastBuddyArrivedParams{
						{
							screenName: state.DisplayScreenName("me"),
						},
					},
				},
			},
		},
		{
			name:     "set user status to invisible aim >= 6",
			instance: newTestInstance("me", sessOptSetFoodGroupVersion(wire.OService, 4)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.OServiceUserInfoStatus, uint32(0x0100)),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceUserInfoUpdate,
					RequestID: 1234,
				},
				Body: func(val any) bool {
					snac, ok := val.(wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate)
					if !ok {
						return false
					}
					if len(snac.UserInfo) == 0 {
						return false
					}
					status, hasStatus := snac.UserInfo[0].Uint32BE(wire.OServiceUserInfoStatus)
					return hasStatus && status == uint32(0x0100)
				},
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyDepartedParams: broadcastBuddyDepartedParams{
						{
							screenName: state.NewIdentScreenName("me"),
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buddyUpdateBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tc.mockParams.broadcastBuddyArrivedParams {
				buddyUpdateBroadcaster.EXPECT().
					BroadcastBuddyArrived(mock.Anything, state.NewIdentScreenName(params.screenName.String()), mock.MatchedBy(func(userInfo wire.TLVUserInfo) bool {
						return userInfo.ScreenName == params.screenName.String()
					})).
					Return(params.err)
			}
			for _, params := range tc.mockParams.broadcastBuddyDepartedParams {
				buddyUpdateBroadcaster.EXPECT().
					BroadcastBuddyDeparted(mock.Anything, matchSession(params.screenName)).
					Return(params.err)
			}
			svc := OServiceService{
				cfg:              config.Config{},
				logger:           slog.Default(),
				buddyBroadcaster: buddyUpdateBroadcaster,
			}
			outputSNAC, err := svc.SetUserInfoFields(nil, tc.instance, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields))
			assert.ErrorIs(t, err, tc.expectErr)
			if tc.expectErr != nil {
				return
			}
			assert.Equal(t, tc.expectOutput.Frame, outputSNAC.Frame)
			if matcherFn, ok := tc.expectOutput.Body.(func(val any) bool); ok {
				assert.True(t, matcherFn(outputSNAC.Body), "Body matcher function failed")
			} else {
				assert.Equal(t, tc.expectOutput.Body, outputSNAC.Body)
			}
		})
	}
}

func TestOServiceService_RateParamsQuery(t *testing.T) {
	rateClasses := wire.NewRateLimitClasses([5]wire.RateClass{
		{
			ID:              1,
			WindowSize:      80,
			ClearLevel:      2500,
			AlertLevel:      2000,
			LimitLevel:      1500,
			DisconnectLevel: 800,
			MaxLevel:        6000,
		},
		{
			ID:              2,
			WindowSize:      80,
			ClearLevel:      3000,
			AlertLevel:      2000,
			LimitLevel:      1500,
			DisconnectLevel: 1000,
			MaxLevel:        6000,
		},
		{
			ID:              3,
			WindowSize:      20,
			ClearLevel:      5100,
			AlertLevel:      5000,
			LimitLevel:      4000,
			DisconnectLevel: 3000,
			MaxLevel:        6000,
		},
		{
			ID:              4,
			WindowSize:      20,
			ClearLevel:      5500,
			AlertLevel:      5300,
			LimitLevel:      4200,
			DisconnectLevel: 3000,
			MaxLevel:        8000,
		},
		{
			ID:              5,
			WindowSize:      10,
			ClearLevel:      5500,
			AlertLevel:      5300,
			LimitLevel:      4200,
			DisconnectLevel: 3000,
			MaxLevel:        8000,
		},
	})

	expectRateGroups := []struct {
		ID    uint16
		Pairs []struct {
			FoodGroup uint16
			SubGroup  uint16
		} `oscar:"count_prefix=uint16"`
	}{
		{
			ID: 1,
			Pairs: []struct {
				FoodGroup uint16
				SubGroup  uint16
			}{
				{FoodGroup: wire.OService, SubGroup: wire.OServiceErr},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceClientOnline},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceHostOnline},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceServiceRequest},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceServiceResponse},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceRateParamsQuery},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceRateParamsReply},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceRateParamsSubAdd},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceRateDelParamSub},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceRateParamChange},
				{FoodGroup: wire.OService, SubGroup: wire.OServicePauseReq},
				{FoodGroup: wire.OService, SubGroup: wire.OServicePauseAck},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceResume},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceUserInfoQuery},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceUserInfoUpdate},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceEvilNotification},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceIdleNotification},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceMigrateGroups},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceMotd},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceSetPrivacyFlags},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceWellKnownUrls},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceNoop},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceClientVersions},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceHostVersions},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceMaxConfigQuery},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceMaxConfigReply},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceStoreConfig},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceConfigQuery},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceConfigReply},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceSetUserInfoFields},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceProbeReq},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceProbeAck},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceBartReply},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceBartQuery2},
				{FoodGroup: wire.OService, SubGroup: wire.OServiceBartReply2},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateErr},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateRightsQuery},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateRightsReply},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateSetInfo},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoReply},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateWatcherSubRequest},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateWatcherNotification},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateSetDirReply},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateGetDirReply},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateGroupCapabilityQuery},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateGroupCapabilityReply},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateSetKeywordInfo},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateSetKeywordReply},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateGetKeywordInfo},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateGetKeywordReply},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateFindListByEmail},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateFindListReply},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery2},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyErr},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyRightsQuery},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyRightsReply},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyWatcherListQuery},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyWatcherListResponse},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyWatcherSubRequest},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyWatcherNotification},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyRejectNotification},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyArrived},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyDeparted},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyAddTempBuddies},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyDelTempBuddies},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMErr},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMAddParameters},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMDelParameters},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMParameterQuery},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMParameterReply},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToClient},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMEvilRequest},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMEvilReply},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMMissedCalls},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMClientErr},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMHostAck},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMSinStored},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMSinListQuery},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMSinListReply},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMOfflineRetrieve},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMSinDelete},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMNotifyRequest},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMNotifyReply},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMClientEvent},
				{FoodGroup: wire.Advert, SubGroup: wire.AdvertErr},
				{FoodGroup: wire.Advert, SubGroup: wire.AdvertAdsQuery},
				{FoodGroup: wire.Advert, SubGroup: wire.AdvertAdsReply},
				{FoodGroup: wire.Invite, SubGroup: wire.InviteErr},
				{FoodGroup: wire.Invite, SubGroup: wire.InviteRequestQuery},
				{FoodGroup: wire.Invite, SubGroup: wire.InviteRequestReply},
				{FoodGroup: wire.Admin, SubGroup: wire.AdminErr},
				{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoQuery},
				{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoReply},
				{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoChangeRequest},
				{FoodGroup: wire.Admin, SubGroup: wire.AdminInfoChangeReply},
				{FoodGroup: wire.Admin, SubGroup: wire.AdminAcctConfirmRequest},
				{FoodGroup: wire.Admin, SubGroup: wire.AdminAcctConfirmReply},
				{FoodGroup: wire.Admin, SubGroup: wire.AdminAcctDeleteRequest},
				{FoodGroup: wire.Admin, SubGroup: wire.AdminAcctDeleteReply},
				{FoodGroup: wire.Popup, SubGroup: wire.PopupErr},
				{FoodGroup: wire.Popup, SubGroup: wire.PopupDisplay},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenyErr},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenyRightsQuery},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenyRightsReply},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenySetGroupPermitMask},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenyBosErr},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenyAddTempPermitListEntries},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenyDelTempPermitListEntries},
				{FoodGroup: wire.UserLookup, SubGroup: wire.UserLookupErr},
				{FoodGroup: wire.UserLookup, SubGroup: wire.UserLookupFindByEmail},
				{FoodGroup: wire.UserLookup, SubGroup: wire.UserLookupFindReply},
				{FoodGroup: wire.Stats, SubGroup: wire.StatsErr},
				{FoodGroup: wire.Stats, SubGroup: wire.StatsSetMinReportInterval},
				{FoodGroup: wire.Stats, SubGroup: wire.StatsReportEvents},
				{FoodGroup: wire.Stats, SubGroup: wire.StatsReportAck},
				{FoodGroup: wire.Translate, SubGroup: wire.TranslateErr},
				{FoodGroup: wire.Translate, SubGroup: wire.TranslateRequest},
				{FoodGroup: wire.Translate, SubGroup: wire.TranslateReply},
				{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavErr},
				{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavRequestChatRights},
				{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavRequestExchangeInfo},
				{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavRequestRoomInfo},
				{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavRequestMoreRoomInfo},
				{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavRequestOccupantList},
				{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavSearchForRoom},
				{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavCreateRoom},
				{FoodGroup: wire.ChatNav, SubGroup: wire.ChatNavNavInfo},
				{FoodGroup: wire.Chat, SubGroup: wire.ChatErr},
				{FoodGroup: wire.Chat, SubGroup: wire.ChatRoomInfoUpdate},
				{FoodGroup: wire.Chat, SubGroup: wire.ChatUsersJoined},
				{FoodGroup: wire.Chat, SubGroup: wire.ChatUsersLeft},
				{FoodGroup: wire.Chat, SubGroup: wire.ChatChannelMsgToClient},
				{FoodGroup: wire.Chat, SubGroup: wire.ChatEvilRequest},
				{FoodGroup: wire.Chat, SubGroup: wire.ChatEvilReply},
				{FoodGroup: wire.Chat, SubGroup: wire.ChatClientErr},
				{FoodGroup: wire.ODir, SubGroup: wire.ODirErr},
				{FoodGroup: wire.ODir, SubGroup: wire.ODirInfoQuery},
				{FoodGroup: wire.ODir, SubGroup: wire.ODirInfoReply},
				{FoodGroup: wire.ODir, SubGroup: wire.ODirKeywordListQuery},
				{FoodGroup: wire.BART, SubGroup: wire.BARTErr},
				{FoodGroup: wire.BART, SubGroup: wire.BARTUploadQuery},
				{FoodGroup: wire.BART, SubGroup: wire.BARTDownloadQuery},
				{FoodGroup: wire.BART, SubGroup: wire.BARTDownload2Query},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagErr},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRightsQuery},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRightsReply},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQuery},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagQueryIfModified},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagReply},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUse},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertItem},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateItem},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteItem},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagInsertClass},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagUpdateClass},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteClass},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagStatus},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagReplyNotModified},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagDeleteUser},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagStartCluster},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagEndCluster},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagAuthorizeBuddy},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagPreAuthorizeBuddy},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagPreAuthorizedBuddy},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRemoveMe},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRemoveMe2},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRequestAuthorizeToHost},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRequestAuthorizeToClient},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRespondAuthorizeToHost},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRespondAuthorizeToClient},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagBuddyAdded},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRequestAuthorizeToBadog},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRespondAuthorizeToBadog},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagBuddyAddedToBadog},
				{FoodGroup: wire.Feedbag, SubGroup: 0x0020},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagTestSnac},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagForwardMsg},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagIsAuthRequiredQuery},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagIsAuthRequiredReply},
				{FoodGroup: wire.Feedbag, SubGroup: wire.FeedbagRecentBuddyUpdate},
				{FoodGroup: wire.Feedbag, SubGroup: 0x0026},
				{FoodGroup: wire.Feedbag, SubGroup: 0x0027},
				{FoodGroup: wire.Feedbag, SubGroup: 0x0028},
				{FoodGroup: wire.ICQ, SubGroup: wire.ICQErr},
				{FoodGroup: wire.ICQ, SubGroup: wire.ICQDBQuery},
				{FoodGroup: wire.ICQ, SubGroup: wire.ICQDBReply},
				{FoodGroup: wire.BUCP, SubGroup: wire.BUCPErr},
				{FoodGroup: wire.BUCP, SubGroup: wire.BUCPLoginRequest},
				{FoodGroup: wire.BUCP, SubGroup: wire.BUCPRegisterRequest},
				{FoodGroup: wire.BUCP, SubGroup: wire.BUCPChallengeRequest},
				{FoodGroup: wire.BUCP, SubGroup: wire.BUCPAsasnRequest},
				{FoodGroup: wire.BUCP, SubGroup: wire.BUCPSecuridRequest},
				{FoodGroup: wire.BUCP, SubGroup: wire.BUCPRegistrationImageRequest},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertErr},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertSetAlertRequest},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertGetSubsRequest},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertNotifyCapabilities},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertNotify},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertGetRuleRequest},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertGetFeedRequest},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertRefreshFeed},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertEvent},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertQogSnac},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertRefreshFeedStock},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertNotifyTransport},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertSetAlertRequestV2},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertNotifyAck},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertNotifyDisplayCapabilities},
				{FoodGroup: wire.Alert, SubGroup: wire.AlertUserOnline},
			},
		},
		{
			ID: 2,
			Pairs: []struct {
				FoodGroup uint16
				SubGroup  uint16
			}{
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyAddBuddies},
				{FoodGroup: wire.Buddy, SubGroup: wire.BuddyDelBuddies},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenyAddPermListEntries},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenyDelPermListEntries},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenyAddDenyListEntries},
				{FoodGroup: wire.PermitDeny, SubGroup: wire.PermitDenyDelDenyListEntries},
				{FoodGroup: wire.Chat, SubGroup: wire.ChatChannelMsgToHost},
			},
		},
		{
			ID: 3,
			Pairs: []struct {
				FoodGroup uint16
				SubGroup  uint16
			}{
				{FoodGroup: wire.Locate, SubGroup: wire.LocateUserInfoQuery},
				{FoodGroup: wire.ICBM, SubGroup: wire.ICBMChannelMsgToHost},
			},
		},
		{
			ID: 4,
			Pairs: []struct {
				FoodGroup uint16
				SubGroup  uint16
			}{
				{FoodGroup: wire.Locate, SubGroup: wire.LocateSetDirInfo},
				{FoodGroup: wire.Locate, SubGroup: wire.LocateGetDirInfo},
			},
		},
		{
			ID: 5,
			Pairs: []struct {
				FoodGroup uint16
				SubGroup  uint16
			}{},
		},
	}

	cases := []struct {
		// name is the unit test name
		name string
		// instance is the session of the user requesting the chat service
		// info
		instance *state.SessionInstance
		// inputSNAC is the SNAC sent by the sender client
		inputSNAC wire.SNACMessage
		// expectSNACFrame is the SNAC frame sent from the server to the recipient
		// client
		expectOutput wire.SNACMessage
		// expectErr is the expected error returned by the router
		expectErr error
		// timeNow returns the current time
		timeNow func() time.Time
	}{
		{
			name:     "get rate limits for AIM > 1.x clients",
			instance: newTestInstance("me", sessOptSetFoodGroupVersion(wire.OService, 3), sessOptSetRateClasses(rateClasses)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{RequestID: 1234},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceRateParamsReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x07_OServiceRateParamsReply{
					RateClasses: []wire.RateParamsSNAC{
						{
							ID:              1,
							WindowSize:      80,
							ClearLevel:      2500,
							AlertLevel:      2000,
							LimitLevel:      1500,
							DisconnectLevel: 800,
							MaxLevel:        6000,
							CurrentLevel:    6000,
							V2Params: &struct {
								LastTime      uint32
								DroppingSNACs uint8
							}{
								LastTime:      999,
								DroppingSNACs: 0x00,
							},
						},
						{
							ID:              2,
							WindowSize:      80,
							ClearLevel:      3000,
							AlertLevel:      2000,
							LimitLevel:      1500,
							DisconnectLevel: 1000,
							MaxLevel:        6000,
							CurrentLevel:    6000,
							V2Params: &struct {
								LastTime      uint32
								DroppingSNACs uint8
							}{
								LastTime:      999,
								DroppingSNACs: 0x00,
							},
						},
						{
							ID:              3,
							WindowSize:      20,
							ClearLevel:      5100,
							AlertLevel:      5000,
							LimitLevel:      4000,
							DisconnectLevel: 3000,
							MaxLevel:        6000,
							CurrentLevel:    6000,
							V2Params: &struct {
								LastTime      uint32
								DroppingSNACs uint8
							}{
								LastTime:      999,
								DroppingSNACs: 0x00,
							},
						},
						{
							ID:              4,
							WindowSize:      20,
							ClearLevel:      5500,
							AlertLevel:      5300,
							LimitLevel:      4200,
							DisconnectLevel: 3000,
							MaxLevel:        8000,
							CurrentLevel:    8000,
							V2Params: &struct {
								LastTime      uint32
								DroppingSNACs uint8
							}{
								LastTime:      999,
								DroppingSNACs: 0x00,
							},
						},
						{
							ID:              5,
							WindowSize:      10,
							ClearLevel:      5500,
							AlertLevel:      5300,
							LimitLevel:      4200,
							DisconnectLevel: 3000,
							MaxLevel:        8000,
							CurrentLevel:    8000,
							V2Params: &struct {
								LastTime      uint32
								DroppingSNACs uint8
							}{
								LastTime:      999,
								DroppingSNACs: 0x00,
							},
						},
					},
					RateGroups: expectRateGroups,
				},
			},
			timeNow: func() time.Time {
				return time.Unix(1000, 0)
			},
		},
		{
			name:     "get rate limits for AIM 1.x client",
			instance: newTestInstance("me", sessClientID("AOL Instant Messenger (TM), version 1."), sessOptSetRateClasses(rateClasses)),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{RequestID: 1234},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceRateParamsReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x01_0x07_OServiceRateParamsReply{
					RateClasses: []wire.RateParamsSNAC{
						{
							ID:              1,
							WindowSize:      80,
							ClearLevel:      2500,
							AlertLevel:      2000,
							LimitLevel:      1500,
							DisconnectLevel: 800,
							MaxLevel:        6000,
						},
						{
							ID:              2,
							WindowSize:      80,
							ClearLevel:      3000,
							AlertLevel:      2000,
							LimitLevel:      1500,
							DisconnectLevel: 1000,
							MaxLevel:        6000,
						},
						{
							ID:              3,
							WindowSize:      20,
							ClearLevel:      5100,
							AlertLevel:      5000,
							LimitLevel:      4000,
							DisconnectLevel: 3000,
							MaxLevel:        6000,
						},
						{
							ID:              4,
							WindowSize:      20,
							ClearLevel:      5500,
							AlertLevel:      5300,
							LimitLevel:      4200,
							DisconnectLevel: 3000,
							MaxLevel:        8000,
						},
						{
							ID:              5,
							WindowSize:      10,
							ClearLevel:      5500,
							AlertLevel:      5300,
							LimitLevel:      4200,
							DisconnectLevel: 3000,
							MaxLevel:        8000,
						},
					},
					RateGroups: expectRateGroups,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := OServiceService{
				cfg:            config.Config{},
				logger:         slog.Default(),
				snacRateLimits: wire.DefaultSNACRateLimits(),
				timeNow:        tc.timeNow,
			}
			have := svc.RateParamsQuery(context.Background(), tc.instance, tc.inputSNAC.Frame)
			assert.ElementsMatch(t, tc.expectOutput.Body.(wire.SNAC_0x01_0x07_OServiceRateParamsReply).RateGroups[0].Pairs,
				have.Body.(wire.SNAC_0x01_0x07_OServiceRateParamsReply).RateGroups[0].Pairs)
			assert.ElementsMatch(t, tc.expectOutput.Body.(wire.SNAC_0x01_0x07_OServiceRateParamsReply).RateGroups[1].Pairs,
				have.Body.(wire.SNAC_0x01_0x07_OServiceRateParamsReply).RateGroups[1].Pairs)
			assert.ElementsMatch(t, tc.expectOutput.Body.(wire.SNAC_0x01_0x07_OServiceRateParamsReply).RateGroups[2].Pairs,
				have.Body.(wire.SNAC_0x01_0x07_OServiceRateParamsReply).RateGroups[2].Pairs)
			assert.ElementsMatch(t, tc.expectOutput.Body.(wire.SNAC_0x01_0x07_OServiceRateParamsReply).RateGroups[3].Pairs,
				have.Body.(wire.SNAC_0x01_0x07_OServiceRateParamsReply).RateGroups[3].Pairs)
			assert.ElementsMatch(t, tc.expectOutput.Body.(wire.SNAC_0x01_0x07_OServiceRateParamsReply).RateGroups[4].Pairs,
				have.Body.(wire.SNAC_0x01_0x07_OServiceRateParamsReply).RateGroups[4].Pairs)
		})
	}
}

func TestOServiceService_HostOnline(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// service is the OSCAR service type
		service uint16
		// expectSNACFrame is the SNAC frame sent from the server to the recipient
		// client
		expectOutput wire.SNACMessage
	}{
		{
			name:    "Admin service",
			service: wire.Admin,
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceHostOnline,
					RequestID: wire.ReqIDFromServer,
				},
				Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
					FoodGroups: []uint16{
						wire.OService,
						wire.Admin,
					},
				},
			},
		},
		{
			name:    "Alert service",
			service: wire.Alert,
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceHostOnline,
					RequestID: wire.ReqIDFromServer,
				},
				Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
					FoodGroups: []uint16{
						wire.Alert,
						wire.OService,
					},
				},
			},
		},
		{
			name:    "BART service",
			service: wire.BART,
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceHostOnline,
					RequestID: wire.ReqIDFromServer,
				},
				Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
					FoodGroups: []uint16{
						wire.BART,
						wire.OService,
					},
				},
			},
		},
		{
			name:    "BOS service",
			service: wire.BOS,
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceHostOnline,
					RequestID: wire.ReqIDFromServer,
				},
				Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
					FoodGroups: []uint16{
						wire.Alert,
						wire.BART,
						wire.Buddy,
						wire.Feedbag,
						wire.ICBM,
						wire.ICQ,
						wire.Locate,
						wire.OService,
						wire.PermitDeny,
						wire.UserLookup,
						wire.Invite,
						wire.Popup,
						wire.Stats,
					},
				},
			},
		},
		{
			name:    "Chat service",
			service: wire.Chat,
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceHostOnline,
					RequestID: wire.ReqIDFromServer,
				},
				Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
					FoodGroups: []uint16{
						wire.OService,
						wire.Chat,
					},
				},
			},
		},
		{
			name:    "ChatNav service",
			service: wire.ChatNav,
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceHostOnline,
					RequestID: wire.ReqIDFromServer,
				},
				Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
					FoodGroups: []uint16{
						wire.ChatNav,
						wire.OService,
					},
				},
			},
		},
		{
			name:    "ODir service",
			service: wire.ODir,
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceHostOnline,
					RequestID: wire.ReqIDFromServer,
				},
				Body: wire.SNAC_0x01_0x03_OServiceHostOnline{
					FoodGroups: []uint16{
						wire.ODir,
						wire.OService,
					},
				},
			},
		},
		{
			name:    "Oops, unsupported service",
			service: wire.Kerberos,
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceErr,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewOServiceService(config.Config{}, nil, slog.Default(), nil, nil, nil, nil, nil, wire.DefaultSNACRateLimits(), nil, nil, nil)
			have := svc.HostOnline(tc.service)
			assert.Equal(t, tc.expectOutput, have)
		})
	}
}

func TestOServiceService_ClientVersions(t *testing.T) {
	svc := OServiceService{
		cfg:    config.Config{},
		logger: slog.Default(),
	}

	want := []wire.SNACMessage{
		{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceHostVersions,
				RequestID: 1234,
			},
			Body: wire.SNAC_0x01_0x18_OServiceHostVersions{
				Versions: []uint16{5, 6, 7, 8},
			},
		},
		{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceMotd,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x13_OServiceMOTD{
				MessageType: 0x0004,
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.OServiceTLVTagsMOTDMessage, "Welcome to Open OSCAR Server"),
					},
				},
			},
		},
	}

	instance := newTestInstance("me")
	have := svc.ClientVersions(context.Background(), instance, wire.SNACFrame{
		RequestID: 1234,
	}, wire.SNAC_0x01_0x17_OServiceClientVersions{
		Versions: []uint16{5, 6, 7, 8},
	})

	assert.Equal(t, want, have)
}

func TestNewOServiceUserInfoUpdate(t *testing.T) {
	memberSince := time.Unix(1_700_000_000, 0)
	profileUpdated := time.Unix(1_700_100_000, 0)
	signonTime := time.Now().Add(-3 * time.Second)

	t.Run("OService version < 4 without profile", func(t *testing.T) {
		session := newTestInstance("me",
			sessOptMemberSince(memberSince),
			sessOptSignonTime(signonTime))
		signon := session.SignonTime()
		onlineLowerBound := uint32(time.Since(signon).Seconds())

		got := newOServiceUserInfoUpdate(session)

		require.Len(t, got.UserInfo, 1)

		memberVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoMemberSince)
		require.True(t, ok)
		require.Equal(t, uint32(memberSince.Unix()), memberVal)

		signonVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoSignonTOD)
		require.True(t, ok)
		require.Equal(t, uint32(signon.Unix()), signonVal)

		onlineVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoOnlineTime)
		require.True(t, ok)
		require.GreaterOrEqual(t, onlineVal, onlineLowerBound)
		require.LessOrEqual(t, onlineVal-onlineLowerBound, uint32(2))

		hasSigTime := got.UserInfo[0].HasTag(wire.OServiceUserInfoSigTime)
		require.False(t, hasSigTime)

		require.False(t, got.UserInfo[0].HasTag(wire.OServiceUserInfoPrimaryInstance))
	})

	t.Run("includes profile update time when set", func(t *testing.T) {
		session := newTestInstance("me",
			sessOptMemberSince(memberSince),
			sessOptSignonTime(signonTime),
			sessOptProfile(state.UserProfile{UpdateTime: profileUpdated}),
			sessOptSetFoodGroupVersion(wire.OService, 4))
		signon := session.SignonTime()
		onlineLowerBound := uint32(time.Since(signon).Seconds())

		got := newOServiceUserInfoUpdate(session)

		require.Len(t, got.UserInfo, 2)

		memberVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoMemberSince)
		require.True(t, ok)
		require.Equal(t, uint32(memberSince.Unix()), memberVal)

		signonVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoSignonTOD)
		require.True(t, ok)
		require.Equal(t, uint32(signon.Unix()), signonVal)

		onlineVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoOnlineTime)
		require.True(t, ok)
		require.GreaterOrEqual(t, onlineVal, onlineLowerBound)
		require.LessOrEqual(t, onlineVal-onlineLowerBound, uint32(2))

		hasSigTime := got.UserInfo[0].HasTag(wire.OServiceUserInfoSigTime)
		require.False(t, hasSigTime)

		// Signature time is in the instance block, not UserInfo[0]
		hasSigTimeInstance := got.UserInfo[1].HasTag(wire.OServiceUserInfoSigTime)
		require.True(t, hasSigTimeInstance)
		sigVal, ok := got.UserInfo[1].Uint32BE(wire.OServiceUserInfoSigTime)
		require.True(t, ok)
		require.Equal(t, uint32(profileUpdated.Unix()), sigVal)

		require.False(t, got.UserInfo[0].HasTag(wire.OServiceUserInfoPrimaryInstance))
	})

	t.Run("appends additional instance info when food group version >= 4", func(t *testing.T) {
		session := newTestInstance("me",
			sessOptMemberSince(memberSince),
			sessOptSignonTime(signonTime),
			sessOptSetFoodGroupVersion(wire.OService, 4))
		signon := session.SignonTime()
		onlineLowerBound := uint32(time.Since(signon).Seconds())

		got := newOServiceUserInfoUpdate(session)

		require.Len(t, got.UserInfo, 2)

		memberVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoMemberSince)
		require.True(t, ok)
		require.Equal(t, uint32(memberSince.Unix()), memberVal)

		signonVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoSignonTOD)
		require.True(t, ok)
		require.Equal(t, uint32(signon.Unix()), signonVal)

		onlineVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoOnlineTime)
		require.True(t, ok)
		require.GreaterOrEqual(t, onlineVal, onlineLowerBound)
		require.LessOrEqual(t, onlineVal-onlineLowerBound, uint32(2))

		hasSigTime := got.UserInfo[0].HasTag(wire.OServiceUserInfoSigTime)
		require.False(t, hasSigTime)

		instanceBytes, ok := got.UserInfo[0].Bytes(wire.OServiceUserInfoMyInstanceNum)
		require.True(t, ok)
		require.Equal(t, []byte{0x01}, instanceBytes)

		primaryBytes, ok := got.UserInfo[1].Bytes(wire.OServiceUserInfoPrimaryInstance)
		require.True(t, ok)
		require.Equal(t, []byte{0x01}, primaryBytes)

		require.Equal(t, got.UserInfo[0].ScreenName, got.UserInfo[1].ScreenName)
	})

	t.Run("includes info for all instances when session has 2 instances", func(t *testing.T) {
		session := newTestInstance("me",
			sessOptMemberSince(memberSince),
			sessOptSignonTime(signonTime),
			sessOptSetFoodGroupVersion(wire.OService, 4))
		// Add a second instance to the session
		session.Session().AddInstance()
		signon := session.SignonTime()
		onlineLowerBound := uint32(time.Since(signon).Seconds())

		got := newOServiceUserInfoUpdate(session)

		require.Len(t, got.UserInfo, 3)

		memberVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoMemberSince)
		require.True(t, ok)
		require.Equal(t, uint32(memberSince.Unix()), memberVal)

		signonVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoSignonTOD)
		require.True(t, ok)
		require.Equal(t, uint32(signon.Unix()), signonVal)

		onlineVal, ok := got.UserInfo[0].Uint32BE(wire.OServiceUserInfoOnlineTime)
		require.True(t, ok)
		require.GreaterOrEqual(t, onlineVal, onlineLowerBound)
		require.LessOrEqual(t, onlineVal-onlineLowerBound, uint32(2))

		hasSigTime := got.UserInfo[0].HasTag(wire.OServiceUserInfoSigTime)
		require.False(t, hasSigTime)

		instanceBytes, ok := got.UserInfo[0].Bytes(wire.OServiceUserInfoMyInstanceNum)
		require.True(t, ok)
		require.Equal(t, []byte{0x01}, instanceBytes)

		// First instance block
		primary1Bytes, ok := got.UserInfo[1].Bytes(wire.OServiceUserInfoPrimaryInstance)
		require.True(t, ok)
		require.Equal(t, []byte{0x01}, primary1Bytes)
		require.Equal(t, got.UserInfo[0].ScreenName, got.UserInfo[1].ScreenName)

		// Second instance block
		primary2Bytes, ok := got.UserInfo[2].Bytes(wire.OServiceUserInfoPrimaryInstance)
		require.True(t, ok)
		require.Equal(t, []byte{0x02}, primary2Bytes)
		require.Equal(t, got.UserInfo[0].ScreenName, got.UserInfo[2].ScreenName)
	})
}

func TestOServiceService_UserInfoQuery(t *testing.T) {
	tests := []struct {
		name     string
		instance *state.SessionInstance
		given    wire.SNACMessage
		want     wire.SNACMessage
		wantErr  error
	}{
		{
			name:     "happy path windows aim < 6",
			instance: newTestInstance("me"),
			given: wire.SNACMessage{
				Frame: wire.SNACFrame{RequestID: 1234},
			},
			want: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceUserInfoUpdate,
					RequestID: 1234,
				},
				Body: newOServiceUserInfoUpdate(newTestInstance("me")),
			},
		},
		{
			name:     "happy path windows aim >= 6",
			instance: newTestInstance("me", sessOptSetFoodGroupVersion(wire.OService, 4)),
			given: wire.SNACMessage{
				Frame: wire.SNACFrame{RequestID: 1234},
			},
			want: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceUserInfoUpdate,
					RequestID: 1234,
				},
				Body: newOServiceUserInfoUpdate(newTestInstance("me", sessOptSetFoodGroupVersion(wire.OService, 4))),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := OServiceService{
				cfg:    config.Config{},
				logger: slog.Default(),
			}
			have := svc.UserInfoQuery(context.Background(), tt.instance, tt.given.Frame)
			assert.Equal(t, tt.want, have)
		})
	}
}

func TestOServiceService_ProbeReq(t *testing.T) {
	svc := NewOServiceService(config.Config{}, nil, slog.Default(), nil, nil, nil, nil, nil, wire.DefaultSNACRateLimits(), nil, nil, nil)

	inFrame := wire.SNACFrame{
		FoodGroup: wire.OService,
		SubGroup:  wire.OServiceProbeReq,
		RequestID: 12345,
	}

	want := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.OService,
			SubGroup:  wire.OServiceProbeAck,
			RequestID: 12345,
		},
	}

	have := svc.ProbeReq(context.Background(), inFrame)
	assert.Equal(t, want, have)
}

func TestOServiceService_IdleNotification(t *testing.T) {
	tests := []struct {
		name     string
		instance *state.SessionInstance
		bodyIn   wire.SNAC_0x01_0x11_OServiceIdleNotification
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		wantErr    error
	}{
		{
			name:     "set idle from active",
			instance: newTestInstance("me"),
			bodyIn: wire.SNAC_0x01_0x11_OServiceIdleNotification{
				IdleTime: 90,
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyArrivedParams: broadcastBuddyArrivedParams{
						{
							screenName: state.DisplayScreenName("me"),
						},
					},
				},
			},
		},
		{
			name:     "set active from idle",
			instance: newTestInstance("me", sessOptIdle(90*time.Second)),
			bodyIn: wire.SNAC_0x01_0x11_OServiceIdleNotification{
				IdleTime: 0,
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyArrivedParams: broadcastBuddyArrivedParams{
						{
							screenName: state.DisplayScreenName("me"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buddyUpdateBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tt.mockParams.broadcastBuddyArrivedParams {
				buddyUpdateBroadcaster.EXPECT().
					BroadcastBuddyArrived(mock.Anything, state.NewIdentScreenName(params.screenName.String()), mock.MatchedBy(func(userInfo wire.TLVUserInfo) bool {
						return userInfo.ScreenName == params.screenName.String()
					})).
					Return(params.err)
			}
			svc := OServiceService{
				cfg:              config.Config{},
				logger:           slog.Default(),
				buddyBroadcaster: buddyUpdateBroadcaster,
			}
			haveErr := svc.IdleNotification(nil, tt.instance, tt.bodyIn)
			assert.ErrorIs(t, tt.wantErr, haveErr)
		})
	}
}

func TestOServiceService_ClientOnline(t *testing.T) {
	chatRoom := state.NewChatRoom("the-chat-room", state.NewIdentScreenName("creator"), state.PrivateExchange)
	chatter1 := newTestInstance("chatter-1", sessOptChatRoomCookie(chatRoom.Cookie()))
	chatter2 := newTestInstance("chatter-2", sessOptChatRoomCookie(chatRoom.Cookie()))

	tests := []struct {
		// name is the name of the test
		name string
		// joiningChatter is the session of the arriving user
		instance *state.SessionInstance
		// bodyIn is the SNAC body sent from the arriving user's client to the
		// server
		bodyIn wire.SNAC_0x01_0x02_OServiceClientOnline
		// service is the OSCAR service type
		service uint16
		// wantErr is the expected error from the handler
		wantErr error
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// validateSess verifies the session state after the handler has run
		validateSess func(t *testing.T, instance *state.SessionInstance)
		// cfg is the config to use for this test. Zero value uses default config.Config{}
		cfg config.Config
	}{
		{
			name:     "notify that BOS user is online",
			instance: newTestInstance("me", sessOptCannedSignonTime),
			bodyIn:   wire.SNAC_0x01_0x02_OServiceClientOnline{},
			service:  wire.BOS,
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from:             state.NewIdentScreenName("me"),
							filter:           nil,
							doSendDepartures: false,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Stats,
									SubGroup:  wire.StatsSetMinReportInterval,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{
									MinReportInterval: 1,
								},
							},
						},
					},
				},
			},
			validateSess: func(t *testing.T, instance *state.SessionInstance) {
				assert.True(t, instance.SignonComplete())
			},
		},
		{
			name:     "notify that BOS user is online via Kerberos auth, does not have stored profile",
			instance: newTestInstance("me", sessOptCannedSignonTime, sessOptKerberosAuth),
			bodyIn:   wire.SNAC_0x01_0x02_OServiceClientOnline{},
			service:  wire.BOS,
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from:             state.NewIdentScreenName("me"),
							filter:           nil,
							doSendDepartures: false,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Stats,
									SubGroup:  wire.StatsSetMinReportInterval,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{
									MinReportInterval: 1,
								},
							},
						},
					},
				},
				profileManagerParams: profileManagerParams{
					retrieveProfileParams: retrieveProfileParams{
						{
							screenName: state.NewIdentScreenName("me"),
							result:     state.UserProfile{},
						},
					},
				},
			},
			validateSess: func(t *testing.T, instance *state.SessionInstance) {
				assert.True(t, instance.SignonComplete())
				assert.True(t, instance.Session().Profile().IsZero())
			},
		},
		{
			name:     "notify that BOS user is online via Kerberos auth, has stored profile",
			instance: newTestInstance("me", sessOptCannedSignonTime, sessOptKerberosAuth),
			bodyIn:   wire.SNAC_0x01_0x02_OServiceClientOnline{},
			service:  wire.BOS,
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from:             state.NewIdentScreenName("me"),
							filter:           nil,
							doSendDepartures: false,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Stats,
									SubGroup:  wire.StatsSetMinReportInterval,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{
									MinReportInterval: 1,
								},
							},
						},
					},
					relayToSelfParams: relayToSelfParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.OService,
									SubGroup:  wire.OServiceUserInfoUpdate,
								},
								Body: newOServiceUserInfoUpdate(newTestInstance("me", sessOptCannedSignonTime, sessOptProfile(
									state.UserProfile{
										ProfileText: "profile-result",
										MIMEType:    `text/aolrtf; charset="us-ascii"`,
										UpdateTime:  time.Unix(100000, 0),
									},
								))),
							},
						},
					},
				},
				profileManagerParams: profileManagerParams{
					retrieveProfileParams: retrieveProfileParams{
						{
							screenName: state.NewIdentScreenName("me"),
							result: state.UserProfile{
								ProfileText: "profile-result",
								MIMEType:    `text/aolrtf; charset="us-ascii"`,
								UpdateTime:  time.Unix(100000, 0),
							},
						},
					},
				},
			},
			validateSess: func(t *testing.T, instance *state.SessionInstance) {
				assert.True(t, instance.SignonComplete())
				assert.False(t, instance.Session().Profile().IsZero(), "profile update  time is non-zero")
				assert.Equal(t, "profile-result", instance.Session().Profile().ProfileText, "profile text matches")
				assert.Equal(t, `text/aolrtf; charset="us-ascii"`, instance.Session().Profile().MIMEType, "profile mimetype matches")
			},
		},
		{
			name:     "notify that BOS user is online with 0 offline messages, no notification sent",
			instance: newTestInstance("me", sessOptCannedSignonTime, sessOptOfflineMsgCount(0)),
			bodyIn:   wire.SNAC_0x01_0x02_OServiceClientOnline{},
			service:  wire.BOS,
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from:             state.NewIdentScreenName("me"),
							filter:           nil,
							doSendDepartures: false,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Stats,
									SubGroup:  wire.StatsSetMinReportInterval,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{
									MinReportInterval: 1,
								},
							},
						},
					},
				},
			},
			validateSess: func(t *testing.T, instance *state.SessionInstance) {
				assert.True(t, instance.SignonComplete())
				assert.Equal(t, 0, instance.OfflineMsgCount())
			},
		},
		{
			name:     "notify that BOS user is online with offline messages, send notification and reset count",
			instance: newTestInstance("me", sessOptCannedSignonTime, sessOptOfflineMsgCount(3)),
			bodyIn:   wire.SNAC_0x01_0x02_OServiceClientOnline{},
			service:  wire.BOS,
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from:             state.NewIdentScreenName("me"),
							filter:           nil,
							doSendDepartures: false,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Stats,
									SubGroup:  wire.StatsSetMinReportInterval,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{
									MinReportInterval: 1,
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("me"),
							message: func() wire.SNACMessage {
								msg, err := systemMessage("You just received 3 IM(s) while you were offline. If you " +
									"do not wish to receive offline messages, please go to " +
									"<a href=\"https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=RDdQw4w9WgXcQ&start_radio=1&pp=ygUJcmljayByb2xsoAcB\">IM Settings</a>.")
								require.NoError(t, err)
								return msg
							}(),
						},
					},
				},
				offlineMessageManagerParams: offlineMessageManagerParams{
					setOfflineMsgCountParams: setOfflineMsgCountParams{
						{
							screenName: state.NewIdentScreenName("me"),
							count:      0,
							err:        nil,
						},
					},
				},
			},
			validateSess: func(t *testing.T, instance *state.SessionInstance) {
				assert.True(t, instance.SignonComplete())
				assert.Equal(t, 0, instance.OfflineMsgCount())
			},
		},
		{
			name: "notify that BOS user is logged in to multiple locations",
			instance: func() *state.SessionInstance {
				instance1 := newTestInstance("me")
				instance1.SetSignonComplete()
				instance2 := instance1.Session().AddInstance()
				instance2.SetSignonComplete()
				instance3 := instance1.Session().AddInstance()
				// instance 3 is not yet signed on
				return instance3
			}(),
			bodyIn:  wire.SNAC_0x01_0x02_OServiceClientOnline{},
			service: wire.BOS,
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from:             state.NewIdentScreenName("me"),
							filter:           nil,
							doSendDepartures: false,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Stats,
									SubGroup:  wire.StatsSetMinReportInterval,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{
									MinReportInterval: 1,
								},
							},
						},
					},
					relayToOtherInstancesParams: relayToOtherInstancesParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: func() wire.SNACMessage {
								msg, err := systemMessage("Your screen name (me) is now signed into Open OSCAR Server in 3 locations. Click " +
									"<a href=\"https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=RDdQw4w9WgXcQ&start_radio=1&pp=ygUJcmljayByb2xsoAcB\">here</a> " +
									"for more information.")
								require.NoError(t, err)
								return msg
							}(),
						},
					},
				},
			},
			validateSess: func(t *testing.T, instance *state.SessionInstance) {
				assert.True(t, instance.Session().Instance(3).SignonComplete())
			},
		},
		{
			name: "BOS user is logged in to multiple locations, DisableMultiLoginNotif is true, no notification sent",
			instance: func() *state.SessionInstance {
				instance1 := newTestInstance("me")
				instance1.SetSignonComplete()
				instance2 := instance1.Session().AddInstance()
				instance2.SetSignonComplete()
				instance3 := instance1.Session().AddInstance()
				// instance 3 is not yet signed on
				return instance3
			}(),
			bodyIn:  wire.SNAC_0x01_0x02_OServiceClientOnline{},
			service: wire.BOS,
			cfg: config.Config{
				DisableMultiLoginNotif: true,
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from:             state.NewIdentScreenName("me"),
							filter:           nil,
							doSendDepartures: false,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Stats,
									SubGroup:  wire.StatsSetMinReportInterval,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{
									MinReportInterval: 1,
								},
							},
						},
					},
					// relayToOtherInstancesParams is intentionally omitted - notification should not be sent
				},
			},
			validateSess: func(t *testing.T, instance *state.SessionInstance) {
				assert.True(t, instance.Session().Instance(3).SignonComplete())
			},
		},
		{
			name:     "notify that BOS user is online with offline messages, SetOfflineMsgCount fails",
			instance: newTestInstance("me", sessOptCannedSignonTime, sessOptOfflineMsgCount(2)),
			bodyIn:   wire.SNAC_0x01_0x02_OServiceClientOnline{},
			service:  wire.BOS,
			wantErr:  assert.AnError,
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastVisibilityParams: broadcastVisibilityParams{
						{
							from:             state.NewIdentScreenName("me"),
							filter:           nil,
							doSendDepartures: false,
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("me"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Stats,
									SubGroup:  wire.StatsSetMinReportInterval,
									RequestID: wire.ReqIDFromServer,
								},
								Body: wire.SNAC_0x0B_0x02_StatsSetMinReportInterval{
									MinReportInterval: 1,
								},
							},
						},
					},
				},
				offlineMessageManagerParams: offlineMessageManagerParams{
					setOfflineMsgCountParams: setOfflineMsgCountParams{
						{
							screenName: state.NewIdentScreenName("me"),
							count:      0,
							err:        assert.AnError,
						},
					},
				},
			},
			validateSess: func(t *testing.T, instance *state.SessionInstance) {
				assert.True(t, instance.SignonComplete())
				assert.Equal(t, 2, instance.OfflineMsgCount())
			},
		},
		{
			name:     "upon joining, send chat room metadata and participant list to joining user; alert arrival to existing participants",
			instance: chatter1,
			bodyIn:   wire.SNAC_0x01_0x02_OServiceClientOnline{},
			service:  wire.Chat,
			mockParams: mockParams{
				chatMessageRelayerParams: chatMessageRelayerParams{
					chatRelayToAllExceptParams: chatRelayToAllExceptParams{
						{
							screenName: state.NewIdentScreenName("chatter-1"),
							cookie:     chatRoom.Cookie(),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatUsersJoined,
								},
								Body: wire.SNAC_0x0E_0x03_ChatUsersJoined{
									Users: []wire.TLVUserInfo{
										chatter1.Session().TLVUserInfo(),
									},
								},
							},
						},
					},
					chatAllSessionsParams: chatAllSessionsParams{
						{
							cookie: chatRoom.Cookie(),
							sessions: []*state.Session{
								chatter1.Session(),
								chatter2.Session(),
							},
						},
					},
					chatRelayToScreenNameParams: chatRelayToScreenNameParams{
						{
							cookie:     chatRoom.Cookie(),
							screenName: chatter1.IdentScreenName(),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatRoomInfoUpdate,
								},
								Body: wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
									Exchange:       chatRoom.Exchange(),
									Cookie:         chatRoom.Cookie(),
									InstanceNumber: chatRoom.InstanceNumber(),
									DetailLevel:    chatRoom.DetailLevel(),
									TLVBlock: wire.TLVBlock{
										TLVList: chatRoom.TLVList(),
									},
								},
							},
						},
						{
							cookie:     chatRoom.Cookie(),
							screenName: chatter1.IdentScreenName(),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Chat,
									SubGroup:  wire.ChatUsersJoined,
								},
								Body: wire.SNAC_0x0E_0x03_ChatUsersJoined{
									Users: []wire.TLVUserInfo{
										chatter1.Session().TLVUserInfo(),
										chatter2.Session().TLVUserInfo(),
									},
								},
							},
						},
					},
				},
				chatRoomRegistryParams: chatRoomRegistryParams{
					chatRoomByCookieParams: chatRoomByCookieParams{
						{
							cookie: chatRoom.Cookie(),
							room:   chatRoom,
						},
					},
				},
			},
			validateSess: func(t *testing.T, instance *state.SessionInstance) {
				assert.True(t, instance.SignonComplete())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buddyUpdateBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tt.mockParams.broadcastVisibilityParams {
				buddyUpdateBroadcaster.EXPECT().
					BroadcastVisibility(matchContext(), matchSession(params.from), params.filter, params.doSendDepartures).
					Return(params.err)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().
					RelayToScreenName(matchContext(), params.screenName, params.message)
			}
			for _, params := range tt.mockParams.relayToSelfParams {
				messageRelayer.EXPECT().
					RelayToSelf(matchContext(), mock.Anything, mock.MatchedBy(func(msg wire.SNACMessage) bool {
						return msg.Frame.FoodGroup == params.message.Frame.FoodGroup &&
							msg.Frame.SubGroup == params.message.Frame.SubGroup
					}))
			}
			for _, params := range tt.mockParams.relayToOtherInstancesParams {
				messageRelayer.EXPECT().
					RelayToOtherInstances(matchContext(), matchSession(params.screenName), params.message)
			}
			chatRoomManager := newMockChatRoomRegistry(t)
			for _, params := range tt.mockParams.chatRoomByCookieParams {
				chatRoomManager.EXPECT().
					ChatRoomByCookie(context.Background(), params.cookie).
					Return(params.room, params.err)
			}
			chatMessageRelayer := newMockChatMessageRelayer(t)
			for _, params := range tt.mockParams.chatRelayToAllExceptParams {
				chatMessageRelayer.EXPECT().
					RelayToAllExcept(matchContext(), params.cookie, params.screenName, params.message)
			}
			for _, params := range tt.mockParams.chatAllSessionsParams {
				chatMessageRelayer.EXPECT().
					AllSessions(params.cookie).
					Return(params.sessions)
			}
			for _, params := range tt.mockParams.chatRelayToScreenNameParams {
				chatMessageRelayer.EXPECT().
					RelayToScreenName(matchContext(), params.cookie, params.screenName, params.message)
			}
			profileManager := newMockProfileManager(t)
			for _, params := range tt.mockParams.profileManagerParams.retrieveProfileParams {
				profileManager.EXPECT().
					Profile(matchContext(), params.screenName).
					Return(params.result, params.err)
			}
			offlineMessageManager := newMockOfflineMessageManager(t)
			for _, params := range tt.mockParams.offlineMessageManagerParams.setOfflineMsgCountParams {
				offlineMessageManager.EXPECT().
					SetOfflineMsgCount(matchContext(), params.screenName, params.count).
					Return(params.err)
			}

			svc := NewOServiceService(tt.cfg, messageRelayer, slog.Default(), nil, chatRoomManager, nil, nil, nil, wire.DefaultSNACRateLimits(), chatMessageRelayer, profileManager, offlineMessageManager)
			svc.buddyBroadcaster = buddyUpdateBroadcaster
			haveErr := svc.ClientOnline(context.Background(), tt.service, tt.bodyIn, tt.instance)
			assert.ErrorIs(t, haveErr, tt.wantErr)

			tt.validateSess(t, tt.instance)
		})
	}
}

func TestOServiceService_SetPrivacyFlags(t *testing.T) {
	svc := OServiceService{
		cfg:    config.Config{},
		logger: slog.Default(),
	}
	body := wire.SNAC_0x01_0x14_OServiceSetPrivacyFlags{
		PrivacyFlags: wire.OServicePrivacyFlagMember | wire.OServicePrivacyFlagIdle,
	}
	svc.SetPrivacyFlags(context.Background(), body)
}

func TestOServiceService_RateLimitUpdates(t *testing.T) {
	rateClasses := [5]wire.RateClass{
		{
			ID:              1,
			WindowSize:      80,
			ClearLevel:      2500,
			AlertLevel:      2000,
			LimitLevel:      1500,
			DisconnectLevel: 800,
			MaxLevel:        6000,
		},
		{
			ID:              2,
			WindowSize:      80,
			ClearLevel:      3000,
			AlertLevel:      2000,
			LimitLevel:      1500,
			DisconnectLevel: 1000,
			MaxLevel:        6000,
		},
		{
			ID:              3,
			WindowSize:      20,
			ClearLevel:      5100,
			AlertLevel:      5000,
			LimitLevel:      4000,
			DisconnectLevel: 3000,
			MaxLevel:        6000,
		},
		{
			ID:              4,
			WindowSize:      20,
			ClearLevel:      5500,
			AlertLevel:      5300,
			LimitLevel:      4200,
			DisconnectLevel: 3000,
			MaxLevel:        8000,
		},
		{
			ID:              5,
			WindowSize:      10,
			ClearLevel:      5500,
			AlertLevel:      5300,
			LimitLevel:      4200,
			DisconnectLevel: 3000,
			MaxLevel:        8000,
		},
	}

	svc := OServiceService{
		cfg:    config.Config{},
		logger: slog.Default(),
	}

	t.Run("(win aim 1.x) transition state from clear > alert > limited > clear, then change rate limit param", func(t *testing.T) {
		now := time.Now()
		instance := newTestInstance("me")
		instance.Session().SetRateClasses(now, wire.NewRateLimitClasses(rateClasses))

		classId := wire.RateLimitClassID(3)
		instance.Session().SubscribeRateLimits([]wire.RateLimitClassID{classId})

		// get into an alert state
		maxTries := 4
		for i := 1; i <= maxTries; i++ {
			now = now.Add(time.Millisecond)
			if s := instance.Session().EvaluateRateLimit(now, classId); s == wire.RateLimitStatusAlert {
				break
			}
			if i == maxTries {
				t.Fail()
				return
			}
		}

		outputSNACs := svc.RateLimitUpdates(context.Background(), instance, now)
		expect := wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceRateParamChange,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x0A_OServiceRateParamsChange{
				Code: 2,
				Rate: wire.RateParamsSNAC{
					ID:              3,
					WindowSize:      20,
					ClearLevel:      5100,
					AlertLevel:      5000,
					LimitLevel:      4000,
					DisconnectLevel: 3000,
					CurrentLevel:    4886,
					MaxLevel:        6000,
				},
			},
		}
		assert.Equal(t, expect, outputSNACs[0])

		// get into a rate-limited state
		maxTries = 4
		for i := 1; i <= maxTries; i++ {
			now = now.Add(time.Millisecond)
			if s := instance.Session().EvaluateRateLimit(now, classId); s == wire.RateLimitStatusLimited {
				break
			}
			if i == maxTries {
				t.Fail()
				return
			}
		}

		outputSNACs = svc.RateLimitUpdates(context.Background(), instance, now)
		expect = wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceRateParamChange,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x0A_OServiceRateParamsChange{
				Code: 3,
				Rate: wire.RateParamsSNAC{
					ID:              3,
					WindowSize:      20,
					ClearLevel:      5100,
					AlertLevel:      5000,
					LimitLevel:      4000,
					DisconnectLevel: 3000,
					CurrentLevel:    3978,
					MaxLevel:        6000,
				},
			},
		}
		assert.Equal(t, expect, outputSNACs[0])

		// simulate waiting a minute for the clear threshold
		now = now.Add(time.Minute)

		// verify that the clear threshold has been reached
		outputSNACs = svc.RateLimitUpdates(context.Background(), instance, now)
		expect = wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceRateParamChange,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x0A_OServiceRateParamsChange{
				Code: 4,
				Rate: wire.RateParamsSNAC{
					ID:              3,
					WindowSize:      20,
					ClearLevel:      5100,
					AlertLevel:      5000,
					LimitLevel:      4000,
					DisconnectLevel: 3000,
					CurrentLevel:    6000,
					MaxLevel:        6000,
				},
			},
		}
		assert.Equal(t, expect, outputSNACs[0])

		// verify rate class param changes are detected
		classesCopy := rateClasses
		classesCopy[2].DisconnectLevel--
		instance.Session().SetRateClasses(now, wire.NewRateLimitClasses(classesCopy))

		outputSNACs = svc.RateLimitUpdates(context.Background(), instance, now)
		expect = wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceRateParamChange,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x0A_OServiceRateParamsChange{
				Code: 1,
				Rate: wire.RateParamsSNAC{
					ID:              3,
					WindowSize:      20,
					ClearLevel:      5100,
					AlertLevel:      5000,
					LimitLevel:      4000,
					DisconnectLevel: 2999,
					CurrentLevel:    6000,
					MaxLevel:        6000,
				},
			},
		}
		assert.Equal(t, expect, outputSNACs[0])
	})

	t.Run("(win aim > 1.x) transition state from clear > alert > limited > clear", func(t *testing.T) {
		now := time.Now()
		instance := newTestInstance("me")
		instance.Session().SetRateClasses(now, wire.NewRateLimitClasses(rateClasses))

		var versions [wire.MDir + 1]uint16
		versions[wire.OService] = 3
		instance.SetFoodGroupVersions(versions)

		classId := wire.RateLimitClassID(3)
		instance.Session().SubscribeRateLimits([]wire.RateLimitClassID{classId})

		// get into an alert state
		maxTries := 4
		for i := 1; i <= maxTries; i++ {
			now = now.Add(time.Millisecond)
			if s := instance.Session().EvaluateRateLimit(now, classId); s == wire.RateLimitStatusAlert {
				break
			}
			if i == maxTries {
				t.Fail()
				return
			}
		}

		outputSNACs := svc.RateLimitUpdates(context.Background(), instance, now)
		expect := wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceRateParamChange,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x0A_OServiceRateParamsChange{
				Code: 2,
				Rate: wire.RateParamsSNAC{
					ID:              3,
					WindowSize:      20,
					ClearLevel:      5100,
					AlertLevel:      5000,
					LimitLevel:      4000,
					DisconnectLevel: 3000,
					CurrentLevel:    4886,
					MaxLevel:        6000,
					V2Params: &struct {
						LastTime      uint32
						DroppingSNACs uint8
					}{
						DroppingSNACs: 0,
					},
				},
			},
		}
		assert.Equal(t, expect, outputSNACs[0])

		// get into a rate-limited state
		maxTries = 4
		for i := 1; i <= maxTries; i++ {
			now = now.Add(time.Millisecond)
			if s := instance.Session().EvaluateRateLimit(now, classId); s == wire.RateLimitStatusLimited {
				break
			}
			if i == maxTries {
				t.Fail()
				return
			}
		}

		outputSNACs = svc.RateLimitUpdates(context.Background(), instance, now)
		expect = wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceRateParamChange,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x0A_OServiceRateParamsChange{
				Code: 3,
				Rate: wire.RateParamsSNAC{
					ID:              3,
					WindowSize:      20,
					ClearLevel:      5100,
					AlertLevel:      5000,
					LimitLevel:      4000,
					DisconnectLevel: 3000,
					CurrentLevel:    3978,
					MaxLevel:        6000,
					V2Params: &struct {
						LastTime      uint32
						DroppingSNACs uint8
					}{
						DroppingSNACs: 1,
					},
				},
			},
		}
		assert.Equal(t, expect, outputSNACs[0])

		// simulate waiting a minute for the clear threshold
		now = now.Add(time.Minute)

		// verify that the clear threshold has been reached
		outputSNACs = svc.RateLimitUpdates(context.Background(), instance, now)
		expect = wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceRateParamChange,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x0A_OServiceRateParamsChange{
				Code: 4,
				Rate: wire.RateParamsSNAC{
					ID:              3,
					WindowSize:      20,
					ClearLevel:      5100,
					AlertLevel:      5000,
					LimitLevel:      4000,
					DisconnectLevel: 3000,
					CurrentLevel:    6000,
					MaxLevel:        6000,
					V2Params: &struct {
						LastTime      uint32
						DroppingSNACs uint8
					}{
						DroppingSNACs: 0,
						LastTime:      60,
					},
				},
			},
		}
		assert.Equal(t, expect, outputSNACs[0])

		// verify rate class param changes are detected
		classesCopy := rateClasses
		classesCopy[2].DisconnectLevel--
		instance.Session().SetRateClasses(now, wire.NewRateLimitClasses(classesCopy))

		outputSNACs = svc.RateLimitUpdates(context.Background(), instance, now)
		expect = wire.SNACMessage{
			Frame: wire.SNACFrame{
				FoodGroup: wire.OService,
				SubGroup:  wire.OServiceRateParamChange,
				RequestID: wire.ReqIDFromServer,
			},
			Body: wire.SNAC_0x01_0x0A_OServiceRateParamsChange{
				Code: 1,
				Rate: wire.RateParamsSNAC{
					ID:              3,
					WindowSize:      20,
					ClearLevel:      5100,
					AlertLevel:      5000,
					LimitLevel:      4000,
					DisconnectLevel: 2999,
					CurrentLevel:    6000,
					MaxLevel:        6000,
					V2Params: &struct {
						LastTime      uint32
						DroppingSNACs uint8
					}{
						DroppingSNACs: 0,
						LastTime:      0,
					},
				},
			},
		}
		assert.Equal(t, expect, outputSNACs[0])
	})
}

func TestOServiceService_RateParamsSubAdd(t *testing.T) {
	svc := OServiceService{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)), // silence logs
	}

	classes := [5]wire.RateClass{
		{
			ID:              1,
			WindowSize:      80,
			ClearLevel:      2500,
			AlertLevel:      2000,
			LimitLevel:      1500,
			DisconnectLevel: 800,
			MaxLevel:        6000,
		},
		{
			ID:              2,
			WindowSize:      80,
			ClearLevel:      3000,
			AlertLevel:      2000,
			LimitLevel:      1500,
			DisconnectLevel: 1000,
			MaxLevel:        6000,
		},
		{
			ID:              3,
			WindowSize:      20,
			ClearLevel:      5100,
			AlertLevel:      5000,
			LimitLevel:      4000,
			DisconnectLevel: 3000,
			MaxLevel:        6000,
		},
		{
			ID:              4,
			WindowSize:      20,
			ClearLevel:      5500,
			AlertLevel:      5300,
			LimitLevel:      4200,
			DisconnectLevel: 3000,
			MaxLevel:        8000,
		},
		{
			ID:              5,
			WindowSize:      10,
			ClearLevel:      5500,
			AlertLevel:      5300,
			LimitLevel:      4200,
			DisconnectLevel: 3000,
			MaxLevel:        8000,
		},
	}

	t.Run("happy path", func(t *testing.T) {
		classes := classes

		instance := newTestInstance("me")
		instance.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses(classes))

		deltas, _ := instance.Session().ObserveRateChanges(time.Now())
		assert.Len(t, deltas, 0)

		// expect 3 rate limit class changes
		classes[0].MaxLevel = 8888
		classes[1].MaxLevel = 8888
		classes[2].MaxLevel = 8888
		classes[3].MaxLevel = 8888
		classes[4].MaxLevel = 8888
		instance.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses(classes))

		snac := wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{
			ClassIDs: []uint16{2, 5},
		}
		svc.RateParamsSubAdd(context.Background(), instance, snac)

		deltas, _ = instance.Session().ObserveRateChanges(time.Now())
		assert.Len(t, deltas, 2)

		// expect 5 rate limit class changes
		classes[0].MaxLevel = 9999
		classes[1].MaxLevel = 9999
		classes[2].MaxLevel = 9999
		classes[3].MaxLevel = 9999
		classes[4].MaxLevel = 9999
		instance.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses(classes))

		snac = wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{
			ClassIDs: []uint16{1, 3, 4},
		}
		svc.RateParamsSubAdd(context.Background(), instance, snac)

		deltas, _ = instance.Session().ObserveRateChanges(time.Now())
		assert.Len(t, deltas, 5)
	})

	t.Run("empty subscribe list", func(t *testing.T) {
		classes := classes

		instance := newTestInstance("me")
		instance.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses(classes))

		deltas, _ := instance.Session().ObserveRateChanges(time.Now())
		assert.Len(t, deltas, 0)

		// expect 3 rate limit class changes
		classes[0].MaxLevel = 8888
		classes[1].MaxLevel = 8888
		classes[2].MaxLevel = 8888
		classes[3].MaxLevel = 8888
		classes[4].MaxLevel = 8888
		instance.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses(classes))

		snac := wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{
			ClassIDs: []uint16{},
		}
		svc.RateParamsSubAdd(context.Background(), instance, snac)

		deltas, _ = instance.Session().ObserveRateChanges(time.Now())
		assert.Empty(t, deltas)
	})

	t.Run("class IDs out of range", func(t *testing.T) {
		classes := classes

		instance := newTestInstance("me")
		instance.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses(classes))

		deltas, _ := instance.Session().ObserveRateChanges(time.Now())
		assert.Len(t, deltas, 0)

		// expect 3 rate limit class changes
		classes[0].MaxLevel = 8888
		classes[1].MaxLevel = 8888
		classes[2].MaxLevel = 8888
		classes[3].MaxLevel = 8888
		classes[4].MaxLevel = 8888
		instance.Session().SetRateClasses(time.Now(), wire.NewRateLimitClasses(classes))

		snac := wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{
			ClassIDs: []uint16{0, 6},
		}
		svc.RateParamsSubAdd(context.Background(), instance, snac)

		deltas, _ = instance.Session().ObserveRateChanges(time.Now())
		assert.Empty(t, deltas)
	})
}
