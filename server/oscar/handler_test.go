package oscar

import (
	"bytes"
	"context"
	"log/slog"
	"math"
	"testing"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/server/oscar/middleware"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandler_AdminConfirmRequest(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x07_0x06_AdminConfirmRequest
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name:      "success",
			inputBody: wire.SNAC_0x07_0x06_AdminConfirmRequest{},
		},
		{
			name:          "service error",
			inputBody:     wire.SNAC_0x07_0x06_AdminConfirmRequest{},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name:          "response writer error",
			inputBody:     wire.SNAC_0x07_0x06_AdminConfirmRequest{},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Admin,
					SubGroup:  wire.AdminAcctConfirmRequest,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Admin,
					SubGroup:  wire.AdminAcctConfirmReply,
				},
				Body: wire.SNAC_0x07_0x07_AdminConfirmReply{
					Status: wire.AdminAcctConfirmStatusEmailSent,
				},
			}

			svc := newMockAdminService(t)
			svc.EXPECT().
				ConfirmRequest(mock.Anything, mock.Anything, input.Frame).
				Return(output, tt.serviceError)

			h := Handler{
				AdminService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_AdminInfoQuery_RegistrationStatus(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x07_0x02_AdminInfoQuery
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x07_0x02_AdminInfoQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.AdminTLVRegistrationStatus, uint16(0x00)),
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x07_0x02_AdminInfoQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.AdminTLVRegistrationStatus, uint16(0x00)),
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x07_0x02_AdminInfoQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.AdminTLVRegistrationStatus, uint16(0x00)),
					},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Admin,
					SubGroup:  wire.AdminInfoQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Admin,
					SubGroup:  wire.AdminInfoReply,
				},
				Body: wire.SNAC_0x07_0x03_AdminInfoReply{
					Permissions: wire.AdminInfoPermissionsReadWrite,
					TLVBlock: wire.TLVBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.AdminTLVRegistrationStatus, wire.AdminInfoRegStatusFullDisclosure),
						},
					},
				},
			}

			svc := newMockAdminService(t)
			svc.EXPECT().
				InfoQuery(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				AdminService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_AdminInfoChangeRequest_ScreenNameFormatted(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x07_0x04_AdminInfoChangeRequest
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "Chatting Chuck"),
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "Chatting Chuck"),
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x07_0x04_AdminInfoChangeRequest{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "Chatting Chuck"),
					},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Admin,
					SubGroup:  wire.AdminInfoChangeRequest,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Admin,
					SubGroup:  wire.AdminInfoChangeReply,
				},
				Body: wire.SNAC_0x07_0x05_AdminChangeReply{
					Permissions: wire.AdminInfoPermissionsReadWrite,
					TLVBlock: wire.TLVBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.AdminTLVScreenNameFormatted, "Chatting Chuck"),
						},
					},
				},
			}

			svc := newMockAdminService(t)
			svc.EXPECT().
				InfoChangeRequest(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				AdminService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_AlertNotifyCapabilities(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNACFrame
		expectedError error
	}{
		{
			name:      "success",
			inputBody: wire.SNACFrame{},
		},
		{
			name:      "empty body",
			inputBody: wire.SNACFrame{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Alert,
					SubGroup:  wire.AlertNotifyCapabilities,
				},
				Body: tt.inputBody,
			}

			h := Handler{
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, nil, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_AlertNotifyDisplayCapabilities(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNACFrame
		expectedError error
	}{
		{
			name:      "success",
			inputBody: wire.SNACFrame{},
		},
		{
			name:      "empty body",
			inputBody: wire.SNACFrame{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Alert,
					SubGroup:  wire.AlertNotifyDisplayCapabilities,
				},
				Body: tt.inputBody,
			}

			h := Handler{
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, nil, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_BARTDownloadQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x10_0x04_BARTDownloadQuery
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name:      "success",
			inputBody: wire.SNAC_0x10_0x04_BARTDownloadQuery{},
		},
		{
			name:          "service error",
			inputBody:     wire.SNAC_0x10_0x04_BARTDownloadQuery{},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name:          "response writer error",
			inputBody:     wire.SNAC_0x10_0x04_BARTDownloadQuery{},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BART,
					SubGroup:  wire.BARTDownloadQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BART,
					SubGroup:  wire.BARTDownloadReply,
				},
				Body: wire.SNAC_0x10_0x05_BARTDownloadReply{
					ScreenName: "the-screen-name",
				},
			}

			svc := newMockBARTService(t)
			svc.EXPECT().
				RetrieveItem(mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				BARTService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_BARTDownload2Query(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x10_0x06_BARTDownload2Query
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name:      "success",
			inputBody: wire.SNAC_0x10_0x06_BARTDownload2Query{},
		},
		{
			name:          "service error",
			inputBody:     wire.SNAC_0x10_0x06_BARTDownload2Query{},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name:          "response writer error",
			inputBody:     wire.SNAC_0x10_0x06_BARTDownload2Query{},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BART,
					SubGroup:  wire.BARTDownload2Query,
				},
				Body: tt.inputBody,
			}
			output := []wire.SNACMessage{
				{
					Frame: wire.SNACFrame{
						FoodGroup: wire.BART,
						SubGroup:  wire.BARTDownload2Reply,
					},
					Body: wire.SNAC_0x10_0x07_BARTDownload2Reply{
						ScreenName: "the-screen-name",
					},
				},
			}

			svc := newMockBARTService(t)
			svc.EXPECT().
				RetrieveItemV2(mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				BARTService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				for _, msg := range output {
					responseWriter.EXPECT().
						SendSNAC(msg.Frame, msg.Body).
						Return(tt.responseError)
				}
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_BARTUploadQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x10_0x02_BARTUploadQuery
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x10_0x02_BARTUploadQuery{
				Type: 1,
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x10_0x02_BARTUploadQuery{
				Type: 1,
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x10_0x02_BARTUploadQuery{
				Type: 1,
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BART,
					SubGroup:  wire.BARTUploadQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.BART,
					SubGroup:  wire.BARTUploadReply,
				},
				Body: wire.SNAC_0x10_0x03_BARTUploadReply{
					Code: wire.BARTReplyCodesSuccess,
				},
			}

			svc := newMockBARTService(t)
			svc.EXPECT().
				UpsertItem(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				BARTService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_BuddyRightsQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x03_0x02_BuddyRightsQuery
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x03_0x02_BuddyRightsQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(0x01, uint16(1000)),
					},
				},
			},
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x03_0x02_BuddyRightsQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(0x01, uint16(1000)),
					},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Buddy,
					SubGroup:  wire.BuddyRightsQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Buddy,
					SubGroup:  wire.BuddyRightsReply,
				},
				Body: wire.SNAC_0x03_0x03_BuddyRightsReply{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(0x01, uint16(1000)),
						},
					},
				},
			}

			svc := newMockBuddyService(t)
			svc.EXPECT().
				RightsQuery(mock.Anything, input.Frame).
				Return(output)

			h := Handler{
				BuddyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			responseWriter.EXPECT().
				SendSNAC(output.Frame, output.Body).
				Return(tt.responseError)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_BuddyAddBuddies(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x03_0x04_BuddyAddBuddies
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x03_0x04_BuddyAddBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "user1",
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x03_0x04_BuddyAddBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "user1",
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Buddy,
					SubGroup:  wire.BuddyAddBuddies,
				},
				Body: tt.inputBody,
			}

			svc := newMockBuddyService(t)
			svc.EXPECT().
				AddBuddies(mock.Anything, mock.Anything, input.Body).
				Return(tt.serviceError)

			h := Handler{
				BuddyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_BuddyDelBuddies(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x03_0x05_BuddyDelBuddies
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x03_0x05_BuddyDelBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "user1",
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x03_0x05_BuddyDelBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "user1",
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Buddy,
					SubGroup:  wire.BuddyDelBuddies,
				},
				Body: tt.inputBody,
			}

			svc := newMockBuddyService(t)
			svc.EXPECT().
				DelBuddies(mock.Anything, mock.Anything, input.Body).
				Return(tt.serviceError)

			h := Handler{
				BuddyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_BuddyAddTempBuddies(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x03_0x0F_BuddyAddTempBuddies
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x03_0x0F_BuddyAddTempBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "user1",
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x03_0x0F_BuddyAddTempBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "user1",
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Buddy,
					SubGroup:  wire.BuddyAddTempBuddies,
				},
				Body: tt.inputBody,
			}

			svc := newMockBuddyService(t)
			svc.EXPECT().
				AddTempBuddies(mock.Anything, mock.Anything, input.Body).
				Return(tt.serviceError)

			h := Handler{
				BuddyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_BuddyDelTempBuddies(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x03_0x10_BuddyDelTempBuddies
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x03_0x10_BuddyDelTempBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "user1",
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x03_0x10_BuddyDelTempBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "user1",
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Buddy,
					SubGroup:  wire.BuddyDelTempBuddies,
				},
				Body: tt.inputBody,
			}

			svc := newMockBuddyService(t)
			svc.EXPECT().
				DelTempBuddies(mock.Anything, mock.Anything, input.Body).
				Return(tt.serviceError)

			h := Handler{
				BuddyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ChatNavCreateRoom(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
				Exchange: 1,
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
				Exchange: 1,
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
				Exchange: 1,
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ChatNav,
					SubGroup:  wire.ChatNavCreateRoom,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ChatNav,
					SubGroup:  wire.ChatNavNavInfo,
				},
				Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{},
			}

			instance := state.NewSession().AddInstance()

			svc := newMockChatNavService(t)
			svc.EXPECT().
				CreateRoom(mock.Anything, instance, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				ChatNavService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, instance, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ChatNavCreateRoom_ReadErr(t *testing.T) {
	input := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ChatNav,
			SubGroup:  wire.ChatNavCreateRoom,
		},
		Body: wire.SNAC_0x0E_0x02_ChatRoomInfoUpdate{
			Exchange: 1,
		},
	}
	output := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.ChatNav,
			SubGroup:  wire.ChatNavNavInfo,
		},
		Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{},
	}

	instance := state.NewSession().AddInstance()

	svc := newMockChatNavService(t)
	svc.EXPECT().
		CreateRoom(mock.Anything, instance, input.Frame, input.Body).
		Return(output, nil)

	h := Handler{
		ChatNavService: svc,
		RouteLogger: middleware.RouteLogger{
			Logger: slog.Default(),
		},
	}

	ss := newMockResponseWriter(t)
	ss.EXPECT().
		SendSNAC(output.Frame, output.Body).
		Return(nil)

	buf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(input.Body, buf))

	assert.NoError(t, h.Handle(context.TODO(), wire.BOS, instance, input.Frame, buf, ss, config.Listener{}))
}

func TestHandler_ChatNavRequestChatRights(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     struct{}
		responseError error
		expectedError error
	}{
		{
			name:      "success",
			inputBody: struct{}{},
		},
		{
			name:          "response writer error",
			inputBody:     struct{}{},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ChatNav,
					SubGroup:  wire.ChatNavRequestChatRights,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ChatNav,
					SubGroup:  wire.ChatNavNavInfo,
				},
				Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{},
			}

			svc := newMockChatNavService(t)
			svc.EXPECT().
				RequestChatRights(mock.Anything, input.Frame).
				Return(output)

			h := Handler{
				ChatNavService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			responseWriter.EXPECT().
				SendSNAC(output.Frame, output.Body).
				Return(tt.responseError)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ChatNavRequestRoomInfo(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
				Exchange: 1,
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
				Exchange: 1,
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x0D_0x04_ChatNavRequestRoomInfo{
				Exchange: 1,
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ChatNav,
					SubGroup:  wire.ChatNavRequestRoomInfo,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ChatNav,
					SubGroup:  wire.ChatNavNavInfo,
				},
				Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{},
			}

			svc := newMockChatNavService(t)
			svc.EXPECT().
				RequestRoomInfo(mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				ChatNavService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ChatNavRequestExchangeInfo(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x0D_0x03_ChatNavRequestExchangeInfo
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x0D_0x03_ChatNavRequestExchangeInfo{
				Exchange: 4,
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x0D_0x03_ChatNavRequestExchangeInfo{
				Exchange: 4,
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x0D_0x03_ChatNavRequestExchangeInfo{
				Exchange: 4,
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ChatNav,
					SubGroup:  wire.ChatNavRequestExchangeInfo,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ChatNav,
					SubGroup:  wire.ChatNavNavInfo,
				},
				Body: wire.SNAC_0x0D_0x09_ChatNavNavInfo{},
			}

			svc := newMockChatNavService(t)
			svc.EXPECT().
				ExchangeInfo(mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				ChatNavService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ChatChannelMsgToHost(t *testing.T) {
	tests := []struct {
		name            string
		inputBody       wire.SNAC_0x0E_0x05_ChatChannelMsgToHost
		serviceResponse *wire.SNACMessage
		serviceError    error
		responseError   error
		expectedError   error
	}{
		{
			name: "success with reflected response",
			inputBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
				Channel: 4,
			},
			serviceResponse: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Chat,
					SubGroup:  wire.ChatChannelMsgToClient,
				},
				Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
					Channel: 4,
				},
			},
		},
		{
			name: "service error with reflected response",
			inputBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
				Channel: 4,
			},
			serviceResponse: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Chat,
					SubGroup:  wire.ChatChannelMsgToClient,
				},
				Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
					Channel: 4,
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error with reflected response",
			inputBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
				Channel: 4,
			},
			serviceResponse: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Chat,
					SubGroup:  wire.ChatChannelMsgToClient,
				},
				Body: wire.SNAC_0x0E_0x06_ChatChannelMsgToClient{
					Channel: 4,
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "success without reflected response",
			inputBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
				Channel: 4,
			},
			serviceResponse: nil, // nil response means no reflection back to caller
		},
		{
			name: "service error without reflected response",
			inputBody: wire.SNAC_0x0E_0x05_ChatChannelMsgToHost{
				Channel: 4,
			},
			serviceResponse: nil,
			serviceError:    assert.AnError,
			expectedError:   assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Chat,
					SubGroup:  wire.ChatChannelMsgToHost,
				},
				Body: tt.inputBody,
			}

			svc := newMockChatService(t)
			svc.EXPECT().
				ChannelMsgToHost(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(tt.serviceResponse, tt.serviceError)

			h := Handler{
				ChatService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil && tt.serviceResponse != nil {
				responseWriter.EXPECT().
					SendSNAC(tt.serviceResponse.Frame, tt.serviceResponse.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_FeedbagDeleteItem(t *testing.T) {
	tests := []struct {
		name           string
		inputBody      wire.SNAC_0x13_0x0A_FeedbagDeleteItem
		expectedOutput *wire.SNACMessage
		serviceError   error
		responseError  error
		expectedError  error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagStatus,
				},
				Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
					Results: []uint16{1234},
				},
			},
		},
		{
			name: "success (nil output)",
			inputBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: nil,
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagStatus,
				},
				Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
					Results: []uint16{1234},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x13_0x0A_FeedbagDeleteItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagStatus,
				},
				Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
					Results: []uint16{1234},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagDeleteItem,
				},
				Body: tt.inputBody,
			}

			svc := newMockFeedbagService(t)
			svc.EXPECT().
				DeleteItem(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(tt.expectedOutput, tt.serviceError)

			h := Handler{
				FeedbagService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil && tt.expectedOutput != nil {
				responseWriter.EXPECT().
					SendSNAC(tt.expectedOutput.Frame, tt.expectedOutput.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_FeedbagEndCluster(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     struct{}
		expectedError error
	}{
		{
			name:      "success",
			inputBody: struct{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagEndCluster,
				},
				Body: tt.inputBody,
			}

			svc := newMockFeedbagService(t)
			h := Handler{
				FeedbagService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}
			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_FeedbagInsertItem(t *testing.T) {
	tests := []struct {
		name           string
		inputBody      wire.SNAC_0x13_0x08_FeedbagInsertItem
		expectedOutput *wire.SNACMessage
		serviceError   error
		responseError  error
		expectedError  error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x13_0x08_FeedbagInsertItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: nil,
		},
		{
			name: "success (non-nil output)",
			inputBody: wire.SNAC_0x13_0x08_FeedbagInsertItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagStatus,
				},
				Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
					Results: []uint16{1234},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x13_0x08_FeedbagInsertItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagStatus,
				},
				Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
					Results: []uint16{1234},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x13_0x08_FeedbagInsertItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagStatus,
				},
				Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
					Results: []uint16{1234},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagInsertItem,
				},
				Body: tt.inputBody,
			}

			svc := newMockFeedbagService(t)
			svc.EXPECT().
				UpsertItem(mock.Anything, mock.Anything, input.Frame, tt.inputBody.Items).
				Return(tt.expectedOutput, tt.serviceError)

			h := Handler{
				FeedbagService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil && tt.expectedOutput != nil {
				responseWriter.EXPECT().
					SendSNAC(tt.expectedOutput.Frame, tt.expectedOutput.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_FeedbagQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x13_0x02_FeedbagRightsQuery
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x13_0x02_FeedbagRightsQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						{
							Tag:   0x01,
							Value: []byte{1, 2, 3, 4},
						},
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x13_0x02_FeedbagRightsQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						{
							Tag:   0x01,
							Value: []byte{1, 2, 3, 4},
						},
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x13_0x02_FeedbagRightsQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						{
							Tag:   0x01,
							Value: []byte{1, 2, 3, 4},
						},
					},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagReply,
				},
				Body: wire.SNAC_0x13_0x06_FeedbagReply{
					Version: 4,
				},
			}

			svc := newMockFeedbagService(t)
			svc.EXPECT().
				Query(mock.Anything, mock.Anything, input.Frame).
				Return(output, tt.serviceError)

			h := Handler{
				FeedbagService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_FeedbagQueryIfModified(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x13_0x05_FeedbagQueryIfModified
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x13_0x05_FeedbagQueryIfModified{
				LastUpdate: 1234,
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x13_0x05_FeedbagQueryIfModified{
				LastUpdate: 1234,
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x13_0x05_FeedbagQueryIfModified{
				LastUpdate: 1234,
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagQueryIfModified,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagReply,
				},
				Body: wire.SNAC_0x13_0x06_FeedbagReply{
					LastUpdate: 1234,
				},
			}

			svc := newMockFeedbagService(t)
			svc.EXPECT().
				QueryIfModified(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				FeedbagService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_FeedbagRightsQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x13_0x02_FeedbagRightsQuery
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x13_0x02_FeedbagRightsQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						{
							Tag:   0x01,
							Value: []byte{1, 2, 3, 4},
						},
					},
				},
			},
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x13_0x02_FeedbagRightsQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						{
							Tag:   0x01,
							Value: []byte{1, 2, 3, 4},
						},
					},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagRightsQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagRightsReply,
				},
				Body: wire.SNAC_0x13_0x03_FeedbagRightsReply{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							{
								Tag:   0x01,
								Value: []byte{1, 2, 3, 4},
							},
						},
					},
				},
			}

			svc := newMockFeedbagService(t)
			svc.EXPECT().
				RightsQuery(mock.Anything, input.Frame).
				Return(output)

			h := Handler{
				FeedbagService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			responseWriter.EXPECT().
				SendSNAC(output.Frame, output.Body).
				Return(tt.responseError)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_FeedbagStartCluster(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x13_0x11_FeedbagStartCluster
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x13_0x11_FeedbagStartCluster{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						{
							Tag:   0x01,
							Value: []byte{1, 2, 3, 4},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagStartCluster,
				},
				Body: tt.inputBody,
			}

			svc := newMockFeedbagService(t)
			svc.EXPECT().
				StartCluster(mock.Anything, input.Frame, input.Body)

			h := Handler{
				FeedbagService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_FeedbagUpdateItem(t *testing.T) {
	tests := []struct {
		name           string
		inputBody      wire.SNAC_0x13_0x09_FeedbagUpdateItem
		expectedOutput *wire.SNACMessage
		serviceError   error
		responseError  error
		expectedError  error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: nil,
		},
		{
			name: "success (non-nil output)",
			inputBody: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagStatus,
				},
				Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
					Results: []uint16{1234},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagStatus,
				},
				Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
					Results: []uint16{1234},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x13_0x09_FeedbagUpdateItem{
				Items: []wire.FeedbagItem{
					{
						Name: "my-item",
					},
				},
			},
			expectedOutput: &wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagStatus,
				},
				Body: wire.SNAC_0x13_0x0E_FeedbagStatus{
					Results: []uint16{1234},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagUpdateItem,
				},
				Body: tt.inputBody,
			}

			svc := newMockFeedbagService(t)
			svc.EXPECT().
				UpsertItem(mock.Anything, mock.Anything, input.Frame, tt.inputBody.Items).
				Return(tt.expectedOutput, tt.serviceError)

			h := Handler{
				FeedbagService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil && tt.expectedOutput != nil {
				responseWriter.EXPECT().
					SendSNAC(tt.expectedOutput.Frame, tt.expectedOutput.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_FeedbagUse(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     struct{}
		serviceError  error
		expectedError error
	}{
		{
			name:      "success",
			inputBody: struct{}{},
		},
		{
			name:          "service error",
			inputBody:     struct{}{},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Feedbag,
					SubGroup:  wire.FeedbagUse,
				},
				Body: tt.inputBody,
			}

			svc := newMockFeedbagService(t)
			svc.EXPECT().
				Use(mock.Anything, mock.Anything).
				Return(tt.serviceError)

			h := Handler{
				FeedbagService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}
			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_FeedbagRespondAuthorizeToHost(t *testing.T) {
	input := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Feedbag,
			SubGroup:  wire.FeedbagRespondAuthorizeToHost,
		},
		Body: wire.SNAC_0x13_0x1A_FeedbagRespondAuthorizeToHost{
			ScreenName: "theScreenName",
		},
	}

	svc := newMockFeedbagService(t)
	svc.EXPECT().
		RespondAuthorizeToHost(mock.Anything, mock.Anything, input.Frame, input.Body).
		Return(nil)

	h := Handler{
		FeedbagService: svc,
		RouteLogger: middleware.RouteLogger{
			Logger: slog.Default(),
		},
	}
	responseWriter := newMockResponseWriter(t)

	buf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(input.Body, buf))

	assert.NoError(t, h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{}))
}

func TestHandler_ICBMAddParameters(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x04_0x02_ICBMAddParameters
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x04_0x02_ICBMAddParameters{
				Channel: 1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMAddParameters,
				},
				Body: tt.inputBody,
			}

			svc := newMockICBMService(t)
			h := Handler{
				ICBMService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}
			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ICBMChannelMsgToHost(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x04_0x06_ICBMChannelMsgToHost
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ScreenName: "recipient-screen-name",
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ScreenName: "recipient-screen-name",
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
				ScreenName: "recipient-screen-name",
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMChannelMsgToHost,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMHostAck,
				},
				Body: wire.SNAC_0x04_0x0C_ICBMHostAck{
					ChannelID: 4,
				},
			}

			svc := newMockICBMService(t)
			svc.EXPECT().
				ChannelMsgToHost(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(&output, tt.serviceError)

			h := Handler{
				ICBMService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ICBMClientErr(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x04_0x0B_ICBMClientErr
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x04_0x0B_ICBMClientErr{
				Code: 4,
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x04_0x0B_ICBMClientErr{
				Code: 4,
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMClientErr,
				},
				Body: tt.inputBody,
			}

			svc := newMockICBMService(t)
			svc.EXPECT().
				ClientErr(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(tt.serviceError)

			h := Handler{
				ICBMService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ICBMClientEvent(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x04_0x14_ICBMClientEvent
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x04_0x14_ICBMClientEvent{
				ScreenName: "recipient-screen-name",
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x04_0x14_ICBMClientEvent{
				ScreenName: "recipient-screen-name",
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMClientEvent,
				},
				Body: tt.inputBody,
			}

			svc := newMockICBMService(t)
			svc.EXPECT().
				ClientEvent(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(tt.serviceError)

			h := Handler{
				ICBMService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ICBMEvilRequest(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x04_0x08_ICBMEvilRequest
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x04_0x08_ICBMEvilRequest{
				ScreenName: "recipient-screen-name",
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x04_0x08_ICBMEvilRequest{
				ScreenName: "recipient-screen-name",
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x04_0x08_ICBMEvilRequest{
				ScreenName: "recipient-screen-name",
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMEvilRequest,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMEvilReply,
				},
				Body: wire.SNAC_0x04_0x09_ICBMEvilReply{
					EvilDeltaApplied: 100,
				},
			}

			svc := newMockICBMService(t)
			svc.EXPECT().
				EvilRequest(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				ICBMService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ICBMOfflineRetrieve(t *testing.T) {
	tests := []struct {
		name          string
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
		},
		{
			name:          "service error",
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name:          "response writer error",
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMOfflineRetrieve,
				},
				Body: wire.SNAC_0x04_0x0A_ICBMOfflineRetrieve{},
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMOfflineRetrieveReply,
				},
				Body: wire.SNAC_0x04_0x17_ICBMOfflineRetrieveReply{},
			}

			svc := newMockICBMService(t)
			svc.EXPECT().
				OfflineRetrieve(mock.Anything, mock.Anything, input.Frame).
				Return(output, tt.serviceError)

			h := Handler{
				ICBMService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ICBMParameterQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     struct{}
		responseError error
		expectedError error
	}{
		{
			name:      "success",
			inputBody: struct{}{},
		},
		{
			name:          "response writer error",
			inputBody:     struct{}{},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMParameterQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ICBM,
					SubGroup:  wire.ICBMParameterReply,
				},
				Body: wire.SNAC_0x04_0x05_ICBMParameterReply{
					MaxSlots: 100,
				},
			}

			svc := newMockICBMService(t)
			svc.EXPECT().
				ParameterQuery(mock.Anything, input.Frame).
				Return(output)

			h := Handler{
				ICBMService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			responseWriter.EXPECT().
				SendSNAC(output.Frame, output.Body).
				Return(tt.responseError)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ICQDBQuery(t *testing.T) {
	type ICQMetaRequest struct {
		wire.ICQMetadata
		ReqSubType  uint16
		MetaRequest any
	}
	type reqParams struct {
		ctx      context.Context
		instance *state.SessionInstance
		inFrame  wire.SNACFrame
		inBody   wire.SNAC_0x15_0x02_BQuery
		rw       ResponseWriter
		seq      uint16
		wantErr  error
	}
	type mockParam struct {
		req     any
		wantErr error
	}
	type allMockParams struct {
		deleteMsgReq      *mockParam
		findByDetails     *mockParam
		findByEmail       *mockParam
		findByEmail3      *mockParam
		findByInterests   *mockParam
		findByUIN         *mockParam
		findByUIN2        *mockParam
		findByWhitePages2 *mockParam
		fullUserInfo      *mockParam
		offlineMsgReq     *mockParam
		setAffiliations   *mockParam
		setBasicInfo      *mockParam
		setEmails         *mockParam
		setInterests      *mockParam
		setMoreInfo       *mockParam
		setPermissions    *mockParam
		setUserNotes      *mockParam
		setWorkInfo       *mockParam
		shortUserInfo     *mockParam
		xmlReqData        *mockParam
	}
	tests := []struct {
		name          string
		reqParams     reqParams
		allMockParams allMockParams
	}{
		{
			name: "MetaReqFullInfo - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqFullInfo,
									MetaRequest: wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN{
										UIN: 123456789,
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				fullUserInfo: &mockParam{
					req: wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN{
						UIN: 123456789,
					},
				},
			},
		},
		{
			name: "MetaReqShortInfo - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqShortInfo,
									MetaRequest: wire.ICQ_0x07D0_0x04BA_DBQueryMetaReqShortInfo{
										UIN: 123456789,
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				shortUserInfo: &mockParam{
					req: wire.ICQ_0x07D0_0x04BA_DBQueryMetaReqShortInfo{
						UIN: 123456789,
					},
				},
			},
		},
		{
			name: "MetaReqFullInfo2 - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqFullInfo2,
									MetaRequest: wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN{
										UIN: 123456789,
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				fullUserInfo: &mockParam{
					req: wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN{
						UIN: 123456789,
					},
				},
			},
		},
		{
			name: "MetaReqXMLReq - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqXMLReq,
									MetaRequest: wire.ICQ_0x07D0_0x0898_DBQueryMetaReqXMLReq{
										XMLRequest: "<xml></xml>",
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				xmlReqData: &mockParam{
					req: wire.ICQ_0x07D0_0x0898_DBQueryMetaReqXMLReq{
						XMLRequest: "<xml></xml>",
					},
				},
			},
		},
		{
			name: "MetaReqSetPermissions - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSetPermissions,
									MetaRequest: wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions{
										Authorization: 1,
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				setPermissions: &mockParam{
					req: wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions{
						Authorization: 1,
					},
				},
			},
		},
		{
			name: "MetaReqSearchByUIN - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSearchByUIN,
									MetaRequest: wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN{
										UIN: 123456789,
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				findByUIN: &mockParam{
					req: wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN{
						UIN: 123456789,
					},
				},
			},
		},
		{
			name: "MetaReqSearchByUIN2 - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSearchByUIN2,
									MetaRequest: wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2{
										TLVRestBlock: wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(1, uint16(1)),
											},
										},
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				findByUIN2: &mockParam{
					req: wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2{
						TLVRestBlock: wire.TLVRestBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(1, uint16(1)),
							},
						},
					},
				},
			},
		},
		{
			name: "MetaReqSearchByEmail - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSearchByEmail,
									MetaRequest: wire.ICQ_0x07D0_0x0529_DBQueryMetaReqSearchByEmail{
										Email: "test@aol.com",
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				findByEmail: &mockParam{
					req: wire.ICQ_0x07D0_0x0529_DBQueryMetaReqSearchByEmail{
						Email: "test@aol.com",
					},
				},
			},
		},
		{
			name: "MetaReqSearchByEmail3 - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSearchByEmail3,
									MetaRequest: wire.ICQ_0x07D0_0x0573_DBQueryMetaReqSearchByEmail3{
										TLVRestBlock: wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(1, uint16(1)),
											},
										},
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				findByEmail3: &mockParam{
					req: wire.ICQ_0x07D0_0x0573_DBQueryMetaReqSearchByEmail3{
						TLVRestBlock: wire.TLVRestBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(1, uint16(1)),
							},
						},
					},
				},
			},
		},
		{
			name: "MetaReqSearchByDetails - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSearchByDetails,
									MetaRequest: wire.ICQ_0x07D0_0x0515_DBQueryMetaReqSearchByDetails{
										FirstName: "john",
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				findByDetails: &mockParam{
					req: wire.ICQ_0x07D0_0x0515_DBQueryMetaReqSearchByDetails{
						FirstName: "john",
					},
				},
			},
		},
		{
			name: "MetaReqSearchWhitePages - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSearchWhitePages,
									MetaRequest: wire.ICQ_0x07D0_0x0533_DBQueryMetaReqSearchWhitePages{
										InterestsCode: 1,
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				findByInterests: &mockParam{
					req: wire.ICQ_0x07D0_0x0533_DBQueryMetaReqSearchWhitePages{
						InterestsCode: 1,
					},
				},
			},
		},
		{
			name: "MetaReqSearchWhitePages2 - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSearchWhitePages2,
									MetaRequest: wire.ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2{
										TLVRestBlock: wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(1, uint16(1)),
											},
										},
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				findByWhitePages2: &mockParam{
					req: wire.ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2{
						TLVRestBlock: wire.TLVRestBlock{
							TLVList: wire.TLVList{
								wire.NewTLVBE(1, uint16(1)),
							},
						},
					},
				},
			},
		},
		{
			name: "MetaReqSetBasicInfo - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSetBasicInfo,
									MetaRequest: wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo{
										FirstName: "john",
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				setBasicInfo: &mockParam{
					req: wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo{
						FirstName: "john",
					},
				},
			},
		},
		{
			name: "MetaReqSetWorkInfo - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSetWorkInfo,
									MetaRequest: wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo{
										ZIP: "11111",
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				setWorkInfo: &mockParam{
					req: wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo{
						ZIP: "11111",
					},
				},
			},
		},
		{
			name: "MetaReqSetMoreInfo - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSetMoreInfo,
									MetaRequest: wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo{
										Age: 100,
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				setMoreInfo: &mockParam{
					req: wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo{
						Age: 100,
					},
				},
			},
		},
		{
			name: "MetaReqSetNotes - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSetNotes,
									MetaRequest: wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes{
										Notes: "my note",
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				setUserNotes: &mockParam{
					req: wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes{
						Notes: "my note",
					},
				},
			},
		},
		{
			name: "MetaReqSetEmails - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSetEmails,
									MetaRequest: wire.ICQ_0x07D0_0x040B_DBQueryMetaReqSetEmails{
										Emails: []struct {
											Publish uint8
											Email   string `oscar:"len_prefix=uint16,nullterm"`
										}{
											{
												Email: "test@aol.com",
											},
										},
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				setEmails: &mockParam{
					req: wire.ICQ_0x07D0_0x040B_DBQueryMetaReqSetEmails{
						Emails: []struct {
							Publish uint8
							Email   string `oscar:"len_prefix=uint16,nullterm"`
						}{
							{
								Email: "test@aol.com",
							},
						},
					},
				},
			},
		},
		{
			name: "MetaReqSetInterests - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSetInterests,
									MetaRequest: wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests{
										Interests: []struct {
											Code    uint16
											Keyword string `oscar:"len_prefix=uint16,nullterm"`
										}{
											{
												Keyword: "an_interest",
											},
										},
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				setInterests: &mockParam{
					req: wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests{
						Interests: []struct {
							Code    uint16
							Keyword string `oscar:"len_prefix=uint16,nullterm"`
						}{
							{
								Keyword: "an_interest",
							},
						},
					},
				},
			},
		},
		{
			name: "MetaReqSetAffiliations - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType: wire.ICQDBQueryMetaReqSetAffiliations,
									MetaRequest: wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations{
										PastAffiliations: []struct {
											Code    uint16
											Keyword string `oscar:"len_prefix=uint16,nullterm"`
										}{
											{
												Keyword: "a_past_affiliation",
											},
										},
										Affiliations: []struct {
											Code    uint16
											Keyword string `oscar:"len_prefix=uint16,nullterm"`
										}{
											{
												Keyword: "an_affiliation",
											},
										},
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				setAffiliations: &mockParam{
					req: wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations{
						PastAffiliations: []struct {
							Code    uint16
							Keyword string `oscar:"len_prefix=uint16,nullterm"`
						}{
							{
								Keyword: "a_past_affiliation",
							},
						},
						Affiliations: []struct {
							Code    uint16
							Keyword string `oscar:"len_prefix=uint16,nullterm"`
						}{
							{
								Keyword: "an_affiliation",
							},
						},
					},
				},
			},
		},
		{
			name: "MetaReqStat - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType:  wire.ICQDBQueryMetaReqStat0a8c,
									MetaRequest: struct{}{},
								},
							}),
						},
					},
				},
				seq: 1,
			},
		},
		{
			name: "unknown metadata request subtype",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryMetaReq,
										Seq:     1,
									},
									ReqSubType:  0xCA8E,
									MetaRequest: struct{}{},
								},
							}),
						},
					},
				},
				seq:     1,
				wantErr: errUnknownICQMetaReqSubType,
			},
		},
		{
			name: "OfflineMsgReq - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: wire.ICQMetadataWithSubType{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryOfflineMsgReq,
										Seq:     1,
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				offlineMsgReq: &mockParam{},
			},
		},
		{
			name: "DeleteMsgReq - happy path",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: wire.ICQMetadataWithSubType{
									ICQMetadata: wire.ICQMetadata{
										ReqType: wire.ICQDBQueryDeleteMsgReq,
										Seq:     1,
									},
								},
							}),
						},
					},
				},
				seq: 1,
			},
			allMockParams: allMockParams{
				deleteMsgReq: &mockParam{},
			},
		},
		{
			name: "unknown request type",
			reqParams: reqParams{
				instance: state.NewSession().AddInstance(),
				inBody: wire.SNAC_0x15_0x02_BQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
								Message: ICQMetaRequest{
									ICQMetadata: wire.ICQMetadata{
										ReqType: 0x13B4,
										Seq:     1,
									},
									ReqSubType:  0xCA8E,
									MetaRequest: struct{}{},
								},
							}),
						},
					},
				},
				seq:     1,
				wantErr: errUnknownICQMetaReqType,
			},
		}, // todo: add to a separate test
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			icqService := newMockICQService(t)
			switch {
			case tt.allMockParams.fullUserInfo != nil:
				icqService.EXPECT().
					FullUserInfo(mock.Anything, tt.reqParams.instance, tt.allMockParams.fullUserInfo.req, tt.reqParams.seq).
					Return(tt.allMockParams.fullUserInfo.wantErr)
			case tt.allMockParams.shortUserInfo != nil:
				icqService.EXPECT().
					ShortUserInfo(mock.Anything, tt.reqParams.instance, tt.allMockParams.shortUserInfo.req, tt.reqParams.seq).
					Return(tt.allMockParams.shortUserInfo.wantErr)
			case tt.allMockParams.xmlReqData != nil:
				icqService.EXPECT().
					XMLReqData(mock.Anything, tt.reqParams.instance, tt.allMockParams.xmlReqData.req, tt.reqParams.seq).
					Return(tt.allMockParams.xmlReqData.wantErr)
			case tt.allMockParams.setPermissions != nil:
				icqService.EXPECT().
					SetPermissions(mock.Anything, tt.reqParams.instance, tt.allMockParams.setPermissions.req, tt.reqParams.seq).
					Return(tt.allMockParams.setPermissions.wantErr)
			case tt.allMockParams.findByUIN != nil:
				icqService.EXPECT().
					FindByUIN(mock.Anything, tt.reqParams.instance, tt.allMockParams.findByUIN.req, tt.reqParams.seq).
					Return(tt.allMockParams.findByUIN.wantErr)
			case tt.allMockParams.findByUIN2 != nil:
				icqService.EXPECT().
					FindByUIN2(mock.Anything, tt.reqParams.instance, tt.allMockParams.findByUIN2.req, tt.reqParams.seq).
					Return(tt.allMockParams.findByUIN2.wantErr)
			case tt.allMockParams.findByEmail != nil:
				icqService.EXPECT().
					FindByICQEmail(mock.Anything, tt.reqParams.instance, tt.allMockParams.findByEmail.req, tt.reqParams.seq).
					Return(tt.allMockParams.findByEmail.wantErr)
			case tt.allMockParams.findByEmail3 != nil:
				icqService.EXPECT().
					FindByEmail3(mock.Anything, tt.reqParams.instance, tt.allMockParams.findByEmail3.req, tt.reqParams.seq).
					Return(tt.allMockParams.findByEmail3.wantErr)
			case tt.allMockParams.findByDetails != nil:
				icqService.EXPECT().
					FindByICQName(mock.Anything, tt.reqParams.instance, tt.allMockParams.findByDetails.req, tt.reqParams.seq).
					Return(tt.allMockParams.findByDetails.wantErr)
			case tt.allMockParams.findByInterests != nil:
				icqService.EXPECT().
					FindByICQInterests(mock.Anything, tt.reqParams.instance, tt.allMockParams.findByInterests.req, tt.reqParams.seq).
					Return(tt.allMockParams.findByInterests.wantErr)
			case tt.allMockParams.findByWhitePages2 != nil:
				icqService.EXPECT().
					FindByWhitePages2(mock.Anything, tt.reqParams.instance, tt.allMockParams.findByWhitePages2.req, tt.reqParams.seq).
					Return(tt.allMockParams.findByWhitePages2.wantErr)
			case tt.allMockParams.setBasicInfo != nil:
				icqService.EXPECT().
					SetBasicInfo(mock.Anything, tt.reqParams.instance, tt.allMockParams.setBasicInfo.req, tt.reqParams.seq).
					Return(tt.allMockParams.setBasicInfo.wantErr)
			case tt.allMockParams.setWorkInfo != nil:
				icqService.EXPECT().
					SetWorkInfo(mock.Anything, tt.reqParams.instance, tt.allMockParams.setWorkInfo.req, tt.reqParams.seq).
					Return(tt.allMockParams.setWorkInfo.wantErr)
			case tt.allMockParams.setMoreInfo != nil:
				icqService.EXPECT().
					SetMoreInfo(mock.Anything, tt.reqParams.instance, tt.allMockParams.setMoreInfo.req, tt.reqParams.seq).
					Return(tt.allMockParams.setMoreInfo.wantErr)
			case tt.allMockParams.setUserNotes != nil:
				icqService.EXPECT().
					SetUserNotes(mock.Anything, tt.reqParams.instance, tt.allMockParams.setUserNotes.req, tt.reqParams.seq).
					Return(tt.allMockParams.setUserNotes.wantErr)
			case tt.allMockParams.setEmails != nil:
				icqService.EXPECT().
					SetEmails(mock.Anything, tt.reqParams.instance, tt.allMockParams.setEmails.req, tt.reqParams.seq).
					Return(tt.allMockParams.setEmails.wantErr)
			case tt.allMockParams.setInterests != nil:
				icqService.EXPECT().
					SetInterests(mock.Anything, tt.reqParams.instance, tt.allMockParams.setInterests.req, tt.reqParams.seq).
					Return(tt.allMockParams.setInterests.wantErr)
			case tt.allMockParams.setAffiliations != nil:
				icqService.EXPECT().
					SetAffiliations(mock.Anything, tt.reqParams.instance, tt.allMockParams.setAffiliations.req, tt.reqParams.seq).
					Return(tt.allMockParams.setAffiliations.wantErr)
			case tt.allMockParams.offlineMsgReq != nil:
				icqService.EXPECT().
					OfflineMsgReq(mock.Anything, tt.reqParams.instance, tt.reqParams.seq).
					Return(tt.allMockParams.offlineMsgReq.wantErr)
			case tt.allMockParams.deleteMsgReq != nil:
				icqService.EXPECT().
					DeleteMsgReq(mock.Anything, tt.reqParams.instance, tt.reqParams.seq).
					Return(tt.allMockParams.deleteMsgReq.wantErr)
			}

			h := Handler{
				ICQService: icqService,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(tt.reqParams.inBody, buf))

			frame := wire.SNACFrame{
				FoodGroup: wire.ICQ,
				SubGroup:  wire.ICQDBQuery,
			}
			err := h.Handle(context.TODO(), wire.BOS, tt.reqParams.instance, frame, buf, nil, config.Listener{})
			assert.ErrorIs(t, err, tt.reqParams.wantErr)
		})
	}
}

// Test workaround for QIP 2005 bug where TLV length is incorrect.
func TestHandler_ICQDBQuery_QIP2005UINSearchBug(t *testing.T) {
	icqService := newMockICQService(t)

	type ICQMetaRequest struct {
		wire.ICQMetadata
		ReqSubType  uint16
		MetaRequest any
	}

	expect := wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ICQTLVTagsUIN, uint32(100009)),
			},
		},
	}

	instance := state.NewSession().AddInstance()
	icqService.EXPECT().
		FindByUIN2(mock.Anything, instance, expect, uint16(1)).
		Return(nil)

	h := Handler{
		ICQService: icqService,
		RouteLogger: middleware.RouteLogger{
			Logger: slog.Default(),
		},
	}

	inBody := wire.SNAC_0x15_0x02_BQuery{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
					Message: ICQMetaRequest{
						ICQMetadata: wire.ICQMetadata{
							ReqType: wire.ICQDBQueryMetaReq,
							Seq:     1,
						},
						ReqSubType: wire.ICQDBQueryMetaReqSearchByUIN2,
						MetaRequest: wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2{
							TLVRestBlock: wire.TLVRestBlock{
								TLVList: wire.TLVList{
									wire.NewTLVBE(wire.ICQTLVTagsUIN, uint32(100009)),
								},
							},
						},
					},
				}),
			},
		},
	}

	buf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(inBody, buf))

	b := buf.Bytes()
	b[18] = 6 // incorrectly set TLV length to 6 (should be 4)

	err := h.ICQDBQuery(nil, instance, wire.SNACFrame{}, buf, nil)
	assert.NoError(t, err)
}

func TestHandler_ODirInfoQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x0F_0x02_InfoQuery
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x0F_0x02_InfoQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(1, uint16(2)),
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x0F_0x02_InfoQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(1, uint16(2)),
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x0F_0x02_InfoQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(1, uint16(2)),
					},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirInfoQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirInfoReply,
				},
				Body: wire.SNAC_0x0F_0x03_InfoReply{
					Status: 5, // OK has results/not found
				},
			}

			svc := newMockODirService(t)
			svc.EXPECT().
				InfoQuery(mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				ODirService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			ss := newMockResponseWriter(t)
			if tt.serviceError == nil {
				ss.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, ss, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_ODirKeywordListQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x0F_0x02_InfoQuery
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x0F_0x02_InfoQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(1, uint16(2)),
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x0F_0x02_InfoQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(1, uint16(2)),
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x0F_0x02_InfoQuery{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(1, uint16(2)),
					},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirKeywordListQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirKeywordListReply,
				},
				Body: wire.SNAC_0x0F_0x04_KeywordListReply{
					Status: 0x01,
				},
			}

			svc := newMockODirService(t)
			svc.EXPECT().
				KeywordListQuery(mock.Anything, input.Frame).
				Return(output, tt.serviceError)

			h := Handler{
				ODirService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			ss := newMockResponseWriter(t)
			if tt.serviceError == nil {
				ss.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, ss, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_OServiceServiceClientOnline(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x01_0x02_OServiceClientOnline
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x01_0x02_OServiceClientOnline{
				GroupVersions: []struct {
					FoodGroup   uint16
					Version     uint16
					ToolID      uint16
					ToolVersion uint16
				}{
					{
						FoodGroup: 10,
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x01_0x02_OServiceClientOnline{
				GroupVersions: []struct {
					FoodGroup   uint16
					Version     uint16
					ToolID      uint16
					ToolVersion uint16
				}{
					{
						FoodGroup: 10,
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceClientOnline,
				},
				Body: tt.inputBody,
			}

			svc := newMockOServiceService(t)
			svc.EXPECT().
				ClientOnline(mock.Anything, wire.BOS, input.Body, mock.Anything).
				Return(tt.serviceError)

			h := Handler{
				OServiceService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, nil, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_OServiceServiceServiceRequest(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x01_0x04_OServiceServiceRequest
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x01_0x04_OServiceServiceRequest{
				FoodGroup: wire.Chat,
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x01_0x04_OServiceServiceRequest{
				FoodGroup: wire.Chat,
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x01_0x04_OServiceServiceRequest{
				FoodGroup: wire.Chat,
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceRequest,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceServiceResponse,
				},
				Body: wire.SNAC_0x01_0x05_OServiceServiceResponse{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(0x01, uint16(1000)),
						},
					},
				},
			}

			svc := newMockOServiceService(t)
			svc.EXPECT().
				ServiceRequest(mock.Anything, wire.BOS, mock.Anything, input.Frame, input.Body, config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234"}).
				Return(output, tt.serviceError)

			h := Handler{
				OServiceService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{BOSAdvertisedHostPlain: "127.0.0.1:1234"})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_OServiceServiceIdleNotification(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x01_0x11_OServiceIdleNotification
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x01_0x11_OServiceIdleNotification{
				IdleTime: 10,
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x01_0x11_OServiceIdleNotification{
				IdleTime: 10,
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceIdleNotification,
				},
				Body: tt.inputBody,
			}

			svc := newMockOServiceService(t)
			svc.EXPECT().
				IdleNotification(mock.Anything, mock.Anything, input.Body).
				Return(tt.serviceError)

			h := Handler{
				OServiceService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_OServiceServiceClientVersions(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x01_0x17_OServiceClientVersions
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x01_0x17_OServiceClientVersions{
				Versions: []uint16{
					10,
				},
			},
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x01_0x17_OServiceClientVersions{
				Versions: []uint16{
					10,
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceClientVersions,
				},
				Body: tt.inputBody,
			}
			output := []wire.SNACMessage{
				{
					Frame: wire.SNACFrame{
						FoodGroup: wire.OService,
						SubGroup:  wire.OServiceHostVersions,
					},
					Body: wire.SNAC_0x01_0x18_OServiceHostVersions{
						Versions: []uint16{
							10,
						},
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

			instance := state.NewSession().AddInstance()
			svc := newMockOServiceService(t)
			svc.EXPECT().
				ClientVersions(mock.Anything, instance, input.Frame, input.Body).
				Return(output)

			h := Handler{
				OServiceService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.responseError == nil {
				for _, snac := range output {
					responseWriter.EXPECT().
						SendSNAC(snac.Frame, snac.Body).
						Return(nil)
				}
			} else {
				responseWriter.EXPECT().
					SendSNAC(output[0].Frame, output[0].Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.Background(), wire.BOS, instance, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_OServiceServiceRateParamsQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     struct{}
		responseError error
		expectedError error
	}{
		{
			name:      "success",
			inputBody: struct{}{},
		},
		{
			name:          "response writer error",
			inputBody:     struct{}{},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceRateParamsQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceRateParamsReply,
				},
				Body: wire.SNAC_0x01_0x07_OServiceRateParamsReply{
					RateGroups: []struct {
						ID    uint16
						Pairs []struct {
							FoodGroup uint16
							SubGroup  uint16
						} `oscar:"count_prefix=uint16"`
					}{
						{
							ID: 1,
						},
					},
				},
			}

			svc := newMockOServiceService(t)
			svc.EXPECT().
				RateParamsQuery(mock.Anything, mock.Anything, input.Frame).
				Return(output)

			h := Handler{
				OServiceService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			responseWriter.EXPECT().
				SendSNAC(output.Frame, output.Body).
				Return(tt.responseError)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_OServiceServiceRateParamsSubAdd(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x01_0x08_OServiceRateParamsSubAdd{
				ClassIDs: []uint16{1, 2, 3, 4},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceRateParamsSubAdd,
				},
				Body: tt.inputBody,
			}

			instance := state.NewSession().AddInstance()

			svc := newMockOServiceService(t)
			svc.EXPECT().
				RateParamsSubAdd(mock.Anything, instance, input.Body)

			h := Handler{
				OServiceService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.Background(), wire.BOS, instance, input.Frame, buf, nil, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_OServiceServiceSetUserInfoFields(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(0x01, []byte{1, 2, 3, 4}),
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(0x01, []byte{1, 2, 3, 4}),
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x01_0x1E_OServiceSetUserInfoFields{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(0x01, []byte{1, 2, 3, 4}),
					},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceSetUserInfoFields,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceUserInfoUpdate,
				},
				Body: wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{
					UserInfo: []wire.TLVUserInfo{
						{ScreenName: "screen-name"},
						{ScreenName: "screen-name"},
					},
				},
			}

			svc := newMockOServiceService(t)
			svc.EXPECT().
				SetUserInfoFields(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				OServiceService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_OServiceServiceUserInfoQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     struct{}
		responseError error
		expectedError error
	}{
		{
			name:      "success",
			inputBody: struct{}{},
		},
		{
			name:          "response writer error",
			inputBody:     struct{}{},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceUserInfoQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceUserInfoUpdate,
				},
				Body: wire.SNAC_0x01_0x0F_OServiceUserInfoUpdate{
					UserInfo: []wire.TLVUserInfo{
						{ScreenName: "screen-name"},
						{ScreenName: "screen-name"},
					},
				},
			}

			svc := newMockOServiceService(t)
			svc.EXPECT().
				UserInfoQuery(mock.Anything, mock.Anything, input.Frame).
				Return(output)

			h := Handler{
				OServiceService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			responseWriter.EXPECT().
				SendSNAC(output.Frame, output.Body).
				Return(tt.responseError)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_OServiceServiceNoop(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     struct{}
		expectedError error
	}{
		{
			name:      "success",
			inputBody: struct{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceNoop,
				},
				Body: tt.inputBody,
			}

			h := Handler{
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_OServiceServiceSetPrivacyFlags(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x01_0x14_OServiceSetPrivacyFlags
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x01_0x14_OServiceSetPrivacyFlags{
				PrivacyFlags: wire.OServicePrivacyFlagMember,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.OService,
					SubGroup:  wire.OServiceSetPrivacyFlags,
				},
				Body: tt.inputBody,
			}

			svc := newMockOServiceService(t)
			svc.EXPECT().
				SetPrivacyFlags(mock.Anything, input.Body)

			h := Handler{
				OServiceService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_PermitDenyRightsQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     struct{}
		responseError error
		expectedError error
	}{
		{
			name:      "success",
			inputBody: struct{}{},
		},
		{
			name:          "response writer error",
			inputBody:     struct{}{},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.PermitDeny,
					SubGroup:  wire.PermitDenyRightsQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.PermitDeny,
					SubGroup:  wire.PermitDenyRightsReply,
				},
				Body: wire.SNAC_0x09_0x03_PermitDenyRightsReply{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(0x01, uint16(1000)),
						},
					},
				},
			}

			svc := newMockPermitDenyService(t)
			svc.EXPECT().
				RightsQuery(mock.Anything, input.Frame).
				Return(output)

			h := Handler{
				PermitDenyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			responseWriter.EXPECT().
				SendSNAC(output.Frame, output.Body).
				Return(tt.responseError)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_PermitDenyAddDenyListEntries(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "friend1",
					},
					{
						ScreenName: "friend2",
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x09_0x07_PermitDenyAddDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "friend1",
					},
					{
						ScreenName: "friend2",
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := state.NewSession().AddInstance()
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.PermitDeny,
					SubGroup:  wire.PermitDenyAddDenyListEntries,
				},
				Body: tt.inputBody,
			}

			svc := newMockPermitDenyService(t)
			svc.EXPECT().
				AddDenyListEntries(mock.Anything, instance, input.Body).
				Return(tt.serviceError)

			h := Handler{
				PermitDenyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, instance, input.Frame, buf, nil, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_PermitDenyDelDenyListEntries(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x09_0x08_PermitDenyDelDenyListEntries
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x09_0x08_PermitDenyDelDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "friend1",
					},
					{
						ScreenName: "friend2",
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x09_0x08_PermitDenyDelDenyListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "friend1",
					},
					{
						ScreenName: "friend2",
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := state.NewSession().AddInstance()
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.PermitDeny,
					SubGroup:  wire.PermitDenyDelDenyListEntries,
				},
				Body: tt.inputBody,
			}

			svc := newMockPermitDenyService(t)
			svc.EXPECT().
				DelDenyListEntries(mock.Anything, instance, input.Body).
				Return(tt.serviceError)

			h := Handler{
				PermitDenyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, instance, input.Frame, buf, nil, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_PermitDenyAddPermListEntries(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "friend1",
					},
					{
						ScreenName: "friend2",
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x09_0x05_PermitDenyAddPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "friend1",
					},
					{
						ScreenName: "friend2",
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := state.NewSession().AddInstance()
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.PermitDeny,
					SubGroup:  wire.PermitDenyAddPermListEntries,
				},
				Body: tt.inputBody,
			}

			svc := newMockPermitDenyService(t)
			svc.EXPECT().
				AddPermListEntries(mock.Anything, instance, input.Body).
				Return(tt.serviceError)

			h := Handler{
				PermitDenyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, instance, input.Frame, buf, nil, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_PermitDenyDelPermListEntries(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries
		serviceError  error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "friend1",
					},
					{
						ScreenName: "friend2",
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "friend1",
					},
					{
						ScreenName: "friend2",
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := state.NewSession().AddInstance()
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.PermitDeny,
					SubGroup:  wire.PermitDenyDelPermListEntries,
				},
				Body: tt.inputBody,
			}

			svc := newMockPermitDenyService(t)
			svc.EXPECT().
				DelPermListEntries(mock.Anything, instance, input.Body).
				Return(tt.serviceError)

			h := Handler{
				PermitDenyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, instance, input.Frame, buf, nil, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_PermitDenySetGroupPermitMask(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x09_0x06_PermitDenyDelPermListEntries{
				Users: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{
						ScreenName: "friend1",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			instance := state.NewSession().AddInstance()
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.PermitDeny,
					SubGroup:  wire.PermitDenySetGroupPermitMask,
				},
				Body: tt.inputBody,
			}

			svc := newMockPermitDenyService(t)

			h := Handler{
				PermitDenyService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, instance, input.Frame, buf, nil, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUserLookupHandler_FindByEmail(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x0A_0x02_UserLookupFindByEmail
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x0A_0x02_UserLookupFindByEmail{
				Email: []byte("haha@aol.com"),
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x0A_0x02_UserLookupFindByEmail{
				Email: []byte("haha@aol.com"),
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x0A_0x02_UserLookupFindByEmail{
				Email: []byte("haha@aol.com"),
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.UserLookup,
					SubGroup:  wire.UserLookupFindByEmail,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.UserLookup,
					SubGroup:  wire.UserLookupFindReply,
				},
				Body: wire.SNAC_0x0A_0x03_UserLookupFindReply{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(0x01, uint16(0x02)),
						},
					},
				},
			}

			svc := newMockUserLookupService(t)
			svc.EXPECT().
				FindByEmail(mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				UserLookupService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			ss := newMockResponseWriter(t)
			if tt.serviceError == nil {
				ss.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, ss, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_LocateGetDirInfo(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x02_0x0B_LocateGetDirInfo
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x02_0x0B_LocateGetDirInfo{
				ScreenName: "screen-name",
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x02_0x0B_LocateGetDirInfo{
				ScreenName: "screen-name",
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x02_0x0B_LocateGetDirInfo{
				ScreenName: "screen-name",
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateGetDirInfo,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateGetDirReply,
				},
				Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{
					Status: 1,
				},
			}

			svc := newMockLocateService(t)
			svc.EXPECT().
				DirInfo(mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				LocateService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_LocateRightsQuery(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     struct{}
		responseError error
		expectedError error
	}{
		{
			name:      "success",
			inputBody: struct{}{},
		},
		{
			name:          "response writer error",
			inputBody:     struct{}{},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateRightsQuery,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateRightsReply,
				},
				Body: wire.SNAC_0x02_0x03_LocateRightsReply{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(0x01, uint16(1000)),
						},
					},
				},
			}

			svc := newMockLocateService(t)
			svc.EXPECT().
				RightsQuery(mock.Anything, input.Frame).
				Return(output)

			h := Handler{
				LocateService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			responseWriter.EXPECT().
				SendSNAC(output.Frame, output.Body).
				Return(tt.responseError)

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_LocateSetDirInfo(t *testing.T) {
	tests := []struct {
		name          string
		inputBody     wire.SNAC_0x02_0x09_LocateSetDirInfo
		serviceError  error
		responseError error
		expectedError error
	}{
		{
			name: "success",
			inputBody: wire.SNAC_0x02_0x09_LocateSetDirInfo{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						{
							Tag:   0x01,
							Value: []byte{1, 2, 3, 4},
						},
					},
				},
			},
		},
		{
			name: "service error",
			inputBody: wire.SNAC_0x02_0x09_LocateSetDirInfo{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						{
							Tag:   0x01,
							Value: []byte{1, 2, 3, 4},
						},
					},
				},
			},
			serviceError:  assert.AnError,
			expectedError: assert.AnError,
		},
		{
			name: "response writer error",
			inputBody: wire.SNAC_0x02_0x09_LocateSetDirInfo{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						{
							Tag:   0x01,
							Value: []byte{1, 2, 3, 4},
						},
					},
				},
			},
			responseError: assert.AnError,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateSetDirInfo,
				},
				Body: tt.inputBody,
			}
			output := wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateSetDirReply,
				},
				Body: wire.SNAC_0x02_0x0A_LocateSetDirReply{
					Result: 1,
				},
			}

			svc := newMockLocateService(t)
			svc.EXPECT().
				SetDirInfo(mock.Anything, mock.Anything, input.Frame, input.Body).
				Return(output, tt.serviceError)

			h := Handler{
				LocateService: svc,
				RouteLogger: middleware.RouteLogger{
					Logger: slog.Default(),
				},
			}

			responseWriter := newMockResponseWriter(t)
			if tt.serviceError == nil {
				responseWriter.EXPECT().
					SendSNAC(output.Frame, output.Body).
					Return(tt.responseError)
			}

			buf := &bytes.Buffer{}
			assert.NoError(t, wire.MarshalBE(input.Body, buf))

			err := h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{})
			if tt.expectedError != nil {
				assert.ErrorIs(t, err, tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestHandler_LocateSetInfo(t *testing.T) {
	input := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateSetInfo,
		},
		Body: wire.SNAC_0x02_0x04_LocateSetInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					{
						Tag:   0x01,
						Value: []byte{1, 2, 3, 4},
					},
				},
			},
		},
	}

	svc := newMockLocateService(t)
	svc.EXPECT().
		SetInfo(mock.Anything, mock.Anything, input.Body).
		Return(nil)

	h := Handler{
		LocateService: svc,
		RouteLogger: middleware.RouteLogger{
			Logger: slog.Default(),
		},
	}

	responseWriter := newMockResponseWriter(t)

	buf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(input.Body, buf))

	assert.NoError(t, h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{}))
}

func TestHandler_LocateSetKeywordInfo(t *testing.T) {
	input := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateSetKeywordInfo,
		},
		Body: wire.SNAC_0x02_0x0F_LocateSetKeywordInfo{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					{
						Tag:   0x01,
						Value: []byte{1, 2, 3, 4},
					},
				},
			},
		},
	}
	output := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateSetKeywordReply,
		},
		Body: wire.SNAC_0x02_0x10_LocateSetKeywordReply{
			Unknown: 1,
		},
	}

	svc := newMockLocateService(t)
	svc.EXPECT().
		SetKeywordInfo(mock.Anything, mock.Anything, input.Frame, input.Body).
		Return(output, nil)

	h := Handler{
		LocateService: svc,
		RouteLogger: middleware.RouteLogger{
			Logger: slog.Default(),
		},
	}

	responseWriter := newMockResponseWriter(t)
	responseWriter.EXPECT().
		SendSNAC(output.Frame, output.Body).
		Return(nil)

	buf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(input.Body, buf))

	assert.NoError(t, h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{}))
}

func TestHandler_LocateUserInfoQuery(t *testing.T) {
	input := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateUserInfoQuery,
		},
		Body: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
			Type: 1,
		},
	}
	output := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateUserInfoReply,
		},
		Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
			TLVUserInfo: wire.TLVUserInfo{
				ScreenName: "screen-name",
			},
			LocateInfo: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					{
						Tag:   0x01,
						Value: []byte{1, 2, 3, 4},
					},
				},
			},
		},
	}

	svc := newMockLocateService(t)
	svc.EXPECT().
		UserInfoQuery(mock.Anything, mock.Anything, input.Frame, input.Body).
		Return(output, nil)

	h := Handler{
		LocateService: svc,
		RouteLogger: middleware.RouteLogger{
			Logger: slog.Default(),
		},
	}

	responseWriter := newMockResponseWriter(t)
	responseWriter.EXPECT().
		SendSNAC(output.Frame, output.Body).
		Return(nil)

	buf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(input.Body, buf))

	assert.NoError(t, h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{}))
}

func TestHandler_LocateUserInfoQuery2(t *testing.T) {
	input := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateUserInfoQuery2,
		},
		Body: wire.SNAC_0x02_0x15_LocateUserInfoQuery2{
			Type2: 1,
		},
	}
	output := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateUserInfoReply,
		},
		Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
			TLVUserInfo: wire.TLVUserInfo{
				ScreenName: "screen-name",
			},
			LocateInfo: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					{
						Tag:   0x01,
						Value: []byte{1, 2, 3, 4},
					},
				},
			},
		},
	}

	svc := newMockLocateService(t)
	svc.EXPECT().
		UserInfoQuery(mock.Anything, mock.Anything, input.Frame, wire.SNAC_0x02_0x05_LocateUserInfoQuery{Type: 1}).
		Return(output, nil)

	h := Handler{
		LocateService: svc,
		RouteLogger: middleware.RouteLogger{
			Logger: slog.Default(),
		},
	}

	responseWriter := newMockResponseWriter(t)
	responseWriter.EXPECT().
		SendSNAC(output.Frame, output.Body).
		Return(nil)

	buf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(input.Body, buf))

	assert.NoError(t, h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, responseWriter, config.Listener{}))
}

func TestHandler_StatsReportEvents(t *testing.T) {
	input := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Stats,
			SubGroup:  wire.StatsReportEvents,
		},
		Body: wire.SNAC_0x0B_0x03_StatsReportEvents{},
	}
	output := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Stats,
			SubGroup:  wire.StatsReportAck,
		},
		Body: wire.SNAC_0x0B_0x04_StatsReportAck{},
	}

	svc := newMockStatsService(t)
	svc.EXPECT().
		ReportEvents(mock.Anything, input.Frame, input.Body).
		Return(output)

	h := Handler{
		StatsService: svc,
		RouteLogger: middleware.RouteLogger{
			Logger: slog.Default(),
		},
	}

	ss := newMockResponseWriter(t)
	ss.EXPECT().
		SendSNAC(output.Frame, output.Body).
		Return(nil)

	buf := &bytes.Buffer{}
	assert.NoError(t, wire.MarshalBE(input.Body, buf))

	assert.NoError(t, h.Handle(context.TODO(), wire.BOS, nil, input.Frame, buf, ss, config.Listener{}))
}

func TestHandler_RouteNotFound(t *testing.T) {
	input := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Stats,
			SubGroup:  math.MaxUint16,
		},
		Body: wire.SNAC_0x0B_0x03_StatsReportEvents{},
	}

	h := Handler{
		RouteLogger: middleware.RouteLogger{
			Logger: slog.Default(),
		},
	}

	assert.ErrorIs(t, ErrRouteNotFound, h.Handle(context.TODO(), wire.BOS, nil, input.Frame, nil, nil, config.Listener{}))
}
