package foodgroup

import (
	"context"
	"io"
	"testing"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"

	"github.com/stretchr/testify/assert"
)

func TestUserLookupService_FindByEmail(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// inputSNAC is the SNAC sent by the sender client
		inputSNAC wire.SNACMessage
		// expectSNACFrame is the SNAC frame sent from the server to the recipient
		// client
		expectOutput wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// expectErr is the expected error returned by the handler
		expectErr error
	}{
		{
			name: "search by email address - results found",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0A_0x02_UserLookupFindByEmail{
					Email: []byte("user@aol.com"),
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.UserLookup,
					SubGroup:  wire.UserLookupFindReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0A_0x03_UserLookupFindReply{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.UserLookupTLVEmailAddress, "ChattingChuck"),
						},
					},
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					findByAIMEmailParams: findByAIMEmailParams{
						{
							email: "user@aol.com",
							result: state.User{
								DisplayScreenName: "ChattingChuck",
							},
						},
					},
				},
			},
		},
		{
			name: "search by email address - no results found",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0A_0x02_UserLookupFindByEmail{
					Email: []byte("user@aol.com"),
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.UserLookup,
					SubGroup:  wire.UserLookupErr,
					RequestID: 1234,
				},
				Body: wire.UserLookupErrNoUserFound,
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					findByAIMEmailParams: findByAIMEmailParams{
						{
							email: "user@aol.com",
							err:   state.ErrNoUser,
						},
					},
				},
			},
		},
		{
			name: "search by email address - search error",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0A_0x02_UserLookupFindByEmail{
					Email: []byte("user@aol.com"),
				},
			},
			expectOutput: wire.SNACMessage{},
			expectErr:    io.EOF,
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					findByAIMEmailParams: findByAIMEmailParams{
						{
							email: "user@aol.com",
							err:   io.EOF,
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profileManager := newMockProfileManager(t)

			for _, params := range tc.mockParams.findByAIMEmailParams {
				profileManager.EXPECT().
					FindByAIMEmail(matchContext(), params.email).
					Return(params.result, params.err)
			}

			svc := NewUserLookupService(profileManager)
			actual, err := svc.FindByEmail(context.Background(), tc.inputSNAC.Frame, tc.inputSNAC.Body.(wire.SNAC_0x0A_0x02_UserLookupFindByEmail))
			assert.ErrorIs(t, err, tc.expectErr)
			assert.Equal(t, tc.expectOutput, actual)
		})
	}
}
