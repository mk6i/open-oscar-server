package foodgroup

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestLocateService_UserInfoQuery(t *testing.T) {
	cases := []struct {
		// name is the unit test name
		name string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// userSession is the session of the user requesting user info
		userSession *state.Session
		// inputSNAC is the SNAC sent from client to server
		inputSNAC wire.SNACMessage
		// expectOutput is the SNAC sent from the server to client
		expectOutput wire.SNACMessage
	}{
		{
			name: "request user info, expect user info response",
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("requested-user"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("requested-user"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnYourList:  true,
								IsOnTheirList: true,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("requested-user"),
							result: newTestSession("requested-user",
								sessOptCannedSignonTime,
								sessOptCannedAwayMessage),
						},
					},
				},
			},
			userSession: newTestSession("user_screen_name"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
					Type:       0,
					ScreenName: "requested-user",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateUserInfoReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
					TLVUserInfo: newTestSession("requested-user",
						sessOptCannedSignonTime,
						sessOptCannedAwayMessage).
						TLVUserInfo(),
					LocateInfo: wire.TLVRestBlock{},
				},
			},
		},
		{
			name: "request user info + profile, expect user info response + profile",
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("requested-user"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("requested-user"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnYourList:  true,
								IsOnTheirList: true,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("requested-user"),
							result: newTestSession("requested-user",
								sessOptCannedSignonTime,
								sessOptCannedAwayMessage,
								sessOptProfile(state.UserProfile{
									ProfileText: "this is my profile!",
									MIMEType:    "text/aolrtf; charset=\"us-ascii\"",
								})),
						},
					},
				},
			},
			userSession: newTestSession("user_screen_name"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
					// 2048 is a dummy to make sure bitmask check works
					Type:       uint16(wire.LocateTypeSig) | 2048,
					ScreenName: "requested-user",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateUserInfoReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
					TLVUserInfo: newTestSession("requested-user",
						sessOptCannedSignonTime,
						sessOptCannedAwayMessage).TLVUserInfo(),
					LocateInfo: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LocateTLVTagsInfoSigMime, `text/aolrtf; charset="us-ascii"`),
							wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "this is my profile!"),
						},
					},
				},
			},
		},
		{
			name: "request user info + away message, expect user info response + away message",
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("requested-user"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("requested-user"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnYourList:  true,
								IsOnTheirList: true,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("requested-user"),
							result: newTestSession("requested-user",
								sessOptCannedSignonTime,
								sessOptCannedAwayMessage),
						},
					},
				},
			},
			userSession: newTestSession("user_screen_name"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
					// 2048 is a dummy to make sure bitmask check works
					Type:       uint16(wire.LocateTypeUnavailable) | 2048,
					ScreenName: "requested-user",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateUserInfoReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
					TLVUserInfo: newTestSession("requested-user",
						sessOptCannedSignonTime,
						sessOptCannedAwayMessage).
						TLVUserInfo(),
					LocateInfo: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableMime, `text/aolrtf; charset="us-ascii"`),
							wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "this is my away message!"),
						},
					},
				},
			},
		},
		{
			name: "request user info of user who blocked requester, expect not logged in error",
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("requested-user"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("requested-user"),
								BlocksYou:     true,
								YouBlock:      false,
								IsOnYourList:  true,
								IsOnTheirList: true,
							},
						},
					},
				},
			},
			userSession: newTestSession("user_screen_name"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
					ScreenName: "requested-user",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
		},
		{
			name: "request user info of user who does not exist, expect not logged in error",
			mockParams: mockParams{
				relationshipFetcherParams: relationshipFetcherParams{
					relationshipParams: relationshipParams{
						{
							me:   state.NewIdentScreenName("user_screen_name"),
							them: state.NewIdentScreenName("non_existent_requested_user"),
							result: state.Relationship{
								User:          state.NewIdentScreenName("non_existent_requested_user"),
								BlocksYou:     false,
								YouBlock:      false,
								IsOnYourList:  true,
								IsOnTheirList: true,
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("non_existent_requested_user"),
							result:     nil,
						},
					},
				},
			},
			userSession: newTestSession("user_screen_name"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
					ScreenName: "non_existent_requested_user",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateErr,
					RequestID: 1234,
				},
				Body: wire.SNACError{
					Code: wire.ErrorCodeNotLoggedOn,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			relationshipFetcher := newMockRelationshipFetcher(t)
			for _, params := range tc.mockParams.relationshipFetcherParams.relationshipParams {
				relationshipFetcher.EXPECT().
					Relationship(matchContext(), params.me, params.them).
					Return(params.result, params.err)
			}
			sessionRetriever := newMockSessionRetriever(t)
			for _, val := range tc.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(val.screenName).
					Return(val.result)
			}
			svc := LocateService{
				relationshipFetcher: relationshipFetcher,
				sessionRetriever:    sessionRetriever,
			}
			outputSNAC, err := svc.UserInfoQuery(context.Background(), tc.userSession, tc.inputSNAC.Frame,
				tc.inputSNAC.Body.(wire.SNAC_0x02_0x05_LocateUserInfoQuery))
			assert.NoError(t, err)
			assert.Equal(t, tc.expectOutput, outputSNAC)
		})
	}
}

func TestLocateService_SetKeywordInfo(t *testing.T) {
	tests := []struct {
		// name is the unit test name
		name string
		// userSession is the session of the user setting info
		userSession *state.Session
		// inputSNAC is the SNAC sent from client to server
		inputSNAC wire.SNACMessage
		// expectOutput is the SNAC sent from the server to client
		expectOutput wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name:        "set exactly 5 interests",
			userSession: newTestSession("test-user"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x0F_LocateSetKeywordInfo{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVInterest, "interest1"),
							wire.NewTLVBE(wire.ODirTLVFirstName, "first_name"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest2"),
							wire.NewTLVBE(wire.ODirTLVLastName, "last_name"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest3"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest4"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest5"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateSetKeywordReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x10_LocateSetKeywordReply{
					Unknown: 1,
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					setKeywordsParams: setKeywordsParams{
						{
							screenName: state.NewIdentScreenName("test-user"),
							keywords: [5]string{
								"interest1",
								"interest2",
								"interest3",
								"interest4",
								"interest5",
							},
						},
					},
				},
			},
		},
		{
			name:        "set less than 5 interests",
			userSession: newTestSession("test-user"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x0F_LocateSetKeywordInfo{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVInterest, "interest1"),
							wire.NewTLVBE(wire.ODirTLVFirstName, "first_name"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest2"),
							wire.NewTLVBE(wire.ODirTLVLastName, "last_name"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest3"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest4"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateSetKeywordReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x10_LocateSetKeywordReply{
					Unknown: 1,
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					setKeywordsParams: setKeywordsParams{
						{
							screenName: state.NewIdentScreenName("test-user"),
							keywords: [5]string{
								"interest1",
								"interest2",
								"interest3",
								"interest4",
							},
						},
					},
				},
			},
		},
		{
			name:        "set more than 5 interests",
			userSession: newTestSession("test-user"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x0F_LocateSetKeywordInfo{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVInterest, "interest1"),
							wire.NewTLVBE(wire.ODirTLVFirstName, "first_name"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest2"),
							wire.NewTLVBE(wire.ODirTLVLastName, "last_name"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest3"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest4"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest5"),
							wire.NewTLVBE(wire.ODirTLVInterest, "interest6"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateSetKeywordReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x10_LocateSetKeywordReply{
					Unknown: 1,
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					setKeywordsParams: setKeywordsParams{
						{
							screenName: state.NewIdentScreenName("test-user"),
							keywords: [5]string{
								"interest1",
								"interest2",
								"interest3",
								"interest4",
								"interest5",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profileManager := newMockProfileManager(t)
			for _, params := range tt.mockParams.setKeywordsParams {
				profileManager.EXPECT().
					SetKeywords(matchContext(), params.screenName, params.keywords).
					Return(params.err)
			}
			svc := NewLocateService(nil, nil, profileManager, nil, nil, nil)
			outputSNAC, err := svc.SetKeywordInfo(context.Background(), tt.userSession, tt.inputSNAC.Frame, tt.inputSNAC.Body.(wire.SNAC_0x02_0x0F_LocateSetKeywordInfo))
			assert.NoError(t, err)
			assert.Equal(t, tt.expectOutput, outputSNAC)
		})
	}
}

func TestLocateService_SetDirInfo(t *testing.T) {
	tests := []struct {
		// name is the unit test name
		name string
		// userSession is the session of the user setting info
		userSession *state.Session
		// inputSNAC is the SNAC sent from client to server
		inputSNAC wire.SNACMessage
		// expectOutput is the SNAC sent from the server to client
		expectOutput wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name:        "set directory info",
			userSession: newTestSession("test-user"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x09_LocateSetDirInfo{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVFirstName, "first_name"),
							wire.NewTLVBE(wire.ODirTLVLastName, "last_name"),
							wire.NewTLVBE(wire.ODirTLVMiddleName, "middle_name"),
							wire.NewTLVBE(wire.ODirTLVMaidenName, "maiden_name"),
							wire.NewTLVBE(wire.ODirTLVCountry, "country"),
							wire.NewTLVBE(wire.ODirTLVState, "state"),
							wire.NewTLVBE(wire.ODirTLVCity, "city"),
							wire.NewTLVBE(wire.ODirTLVNickName, "nick_name"),
							wire.NewTLVBE(wire.ODirTLVZIP, "zip"),
							wire.NewTLVBE(wire.ODirTLVAddress, "address"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateSetDirReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x0A_LocateSetDirReply{
					Result: 1,
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					setDirectoryInfoParams: setDirectoryInfoParams{
						{
							screenName: state.NewIdentScreenName("test-user"),
							info: state.AIMNameAndAddr{
								FirstName:  "first_name",
								LastName:   "last_name",
								MiddleName: "middle_name",
								MaidenName: "maiden_name",
								Country:    "country",
								State:      "state",
								City:       "city",
								NickName:   "nick_name",
								ZIPCode:    "zip",
								Address:    "address",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profileManager := newMockProfileManager(t)
			for _, params := range tt.mockParams.setDirectoryInfoParams {
				profileManager.EXPECT().
					SetDirectoryInfo(matchContext(), params.screenName, params.info).
					Return(nil)
			}
			svc := NewLocateService(nil, nil, profileManager, nil, nil, nil)
			outputSNAC, err := svc.SetDirInfo(context.Background(), tt.userSession, tt.inputSNAC.Frame, tt.inputSNAC.Body.(wire.SNAC_0x02_0x09_LocateSetDirInfo))
			assert.NoError(t, err)
			assert.Equal(t, tt.expectOutput, outputSNAC)
		})
	}
}

func TestLocateService_SetInfo(t *testing.T) {
	tests := []struct {
		// name is the unit test name
		name string
		// userSession is the session of the user setting info
		userSession *state.Session
		// inBody is the message sent from client to server
		inBody wire.SNAC_0x02_0x04_LocateSetInfo
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantSessionProfile is the expected profile set on the session
		wantSessionProfile state.UserProfile
		// wantErr is the expected error
		wantErr error
	}{
		{
			name:        "set session profile (AIM < 6)",
			userSession: newTestSession("test-user"),
			inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "profile-result"),
						wire.NewTLVBE(wire.LocateTLVTagsInfoSigMime, `text/aolrtf; charset="us-ascii"`),
					},
				},
			},
			wantSessionProfile: state.UserProfile{
				ProfileText: "profile-result",
				MIMEType:    `text/aolrtf; charset="us-ascii"`,
			},
		},
		{
			name:        "set stored profile (AIM 6-7)",
			userSession: newTestSession("test-user", sessOptKerberosAuth),
			inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "profile-result"),
						wire.NewTLVBE(wire.LocateTLVTagsInfoSigMime, `text/aolrtf; charset="us-ascii"`),
					},
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					setProfileParams: setProfileParams{
						{
							screenName: state.NewIdentScreenName("test-user"),
							body: state.UserProfile{
								ProfileText: "profile-result",
								MIMEType:    `text/aolrtf; charset="us-ascii"`,
							},
						},
					},
				},
			},
			wantSessionProfile: state.UserProfile{
				ProfileText: "profile-result",
				MIMEType:    `text/aolrtf; charset="us-ascii"`,
			},
		},
		{
			name:        "set away message during sign on flow",
			userSession: newTestSession("user_screen_name"),
			inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "this is my away message!"),
					},
				},
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyArrivedParams: broadcastBuddyArrivedParams{},
				},
			},
		},
		{
			name:        "set away message after sign on flow",
			userSession: newTestSession("user_screen_name", sessOptSignonComplete),
			inBody: wire.SNAC_0x02_0x04_LocateSetInfo{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVBE(wire.LocateTLVTagsInfoUnavailableData, "this is my away message!"),
					},
				},
			},
			mockParams: mockParams{
				buddyBroadcasterParams: buddyBroadcasterParams{
					broadcastBuddyArrivedParams: broadcastBuddyArrivedParams{
						{
							screenName: state.DisplayScreenName("user_screen_name"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profileManager := newMockProfileManager(t)
			for _, params := range tt.mockParams.setProfileParams {
				profileManager.EXPECT().
					SetProfile(matchContext(), params.screenName, mock.MatchedBy(func(profile state.UserProfile) bool {
						return profile.ProfileText == params.body.ProfileText &&
							profile.MIMEType == params.body.MIMEType &&
							!profile.UpdateTime.IsZero()
					})).
					Return(nil)
			}
			buddyUpdateBroadcaster := newMockbuddyBroadcaster(t)
			for _, params := range tt.mockParams.broadcastBuddyArrivedParams {
				buddyUpdateBroadcaster.EXPECT().
					BroadcastBuddyArrived(mock.Anything, state.NewIdentScreenName(params.screenName.String()), mock.MatchedBy(func(userInfo wire.TLVUserInfo) bool {
						return userInfo.ScreenName == params.screenName.String()
					})).
					Return(params.err)
			}
			svc := NewLocateService(nil, nil, profileManager, nil, nil, nil)
			svc.buddyBroadcaster = buddyUpdateBroadcaster
			assert.Equal(t, tt.wantErr, svc.SetInfo(context.Background(), tt.userSession, tt.inBody))

			if tt.wantSessionProfile.Empty() {
				assert.True(t, tt.userSession.Profile().Empty())
			} else {
				assert.Equal(t, tt.wantSessionProfile.ProfileText, tt.userSession.Profile().ProfileText)
				assert.Equal(t, tt.wantSessionProfile.MIMEType, tt.userSession.Profile().MIMEType)
			}
		})
	}
}

func TestLocateService_SetInfo_SetCaps(t *testing.T) {
	svc := NewLocateService(nil, nil, nil, nil, nil, nil)

	sess := newTestSession("screen-name")
	inBody := wire.SNAC_0x02_0x04_LocateSetInfo{
		TLVRestBlock: wire.TLVRestBlock{
			TLVList: wire.TLVList{
				wire.NewTLVBE(wire.LocateTLVTagsInfoCapabilities, []byte{
					// chat: "748F2420-6287-11D1-8222-444553540000"
					0x74, 0x8f, 0x24, 0x20, 0x62, 0x87, 0x11, 0xd1, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00,
					// avatar: "09461346-4c7f-11d1-8222-444553540000"
					9, 70, 19, 70, 76, 127, 17, 209, 130, 34, 68, 69, 83, 84, 0, 0,
					// 0946134a-4c7f-11d1-8222-444553540000 (games)
					9, 70, 19, 74, 76, 127, 17, 209, 130, 34, 68, 69, 83, 84, 0, 0,
					// 0946134d-4c7f-11d1-8222-444553540000 (ICQ inter-op)
					9, 70, 19, 77, 76, 127, 17, 209, 130, 34, 68, 69, 83, 84, 0, 0,
					// 09461341-4c7f-11d1-8222-444553540000 (voice chat)
					9, 70, 19, 65, 76, 127, 17, 209, 130, 34, 68, 69, 83, 84, 0, 0,
				}),
			},
		},
	}
	assert.NoError(t, svc.SetInfo(context.Background(), sess, inBody))

	expect := [][16]byte{
		// 748F2420-6287-11D1-8222-444553540000 (chat)
		{0x74, 0x8f, 0x24, 0x20, 0x62, 0x87, 0x11, 0xd1, 0x82, 0x22, 0x44, 0x45, 0x53, 0x54, 0x00, 0x00},
		// 09461346-4C7F-11D1-8222-444553540000 (avatar)
		{9, 70, 19, 70, 76, 127, 17, 209, 130, 34, 68, 69, 83, 84, 0, 0},
	}
	assert.Equal(t, expect, sess.Caps())
}

func TestLocateService_RightsQuery(t *testing.T) {
	svc := NewLocateService(nil, nil, nil, nil, nil, nil)

	outputSNAC := svc.RightsQuery(context.Background(), wire.SNACFrame{RequestID: 1234})
	expectSNAC := wire.SNACMessage{
		Frame: wire.SNACFrame{
			FoodGroup: wire.Locate,
			SubGroup:  wire.LocateRightsReply,
			RequestID: 1234,
		},
		Body: wire.SNAC_0x02_0x03_LocateRightsReply{
			TLVRestBlock: wire.TLVRestBlock{
				TLVList: wire.TLVList{
					wire.NewTLVBE(wire.LocateTLVTagsRightsMaxSigLen, uint16(1000)),
					wire.NewTLVBE(wire.LocateTLVTagsRightsMaxCapabilitiesLen, uint16(1000)),
					wire.NewTLVBE(wire.LocateTLVTagsRightsMaxFindByEmailList, uint16(1000)),
					wire.NewTLVBE(wire.LocateTLVTagsRightsMaxCertsLen, uint16(1000)),
					wire.NewTLVBE(wire.LocateTLVTagsRightsMaxMaxShortCapabilities, uint16(1000)),
				},
			},
		},
	}

	assert.Equal(t, expectSNAC, outputSNAC)
}

func TestLocateService_DirInfo(t *testing.T) {
	tests := []struct {
		// name is the unit test name
		name string
		// userSession is the session of the user setting info
		userSession *state.Session
		// inputSNAC is the SNAC sent from client to server
		inputSNAC wire.SNACMessage
		// expectOutput is the SNAC sent from the server to client
		expectOutput wire.SNACMessage
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
		// wantErr is the expected error
		wantErr error
	}{
		{
			name:        "happy path",
			userSession: newTestSession("test-user"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x0B_LocateGetDirInfo{
					ScreenName: "test-user",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateGetDirReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{
					Status: wire.LocateGetDirReplyOK,
					TLVBlock: wire.TLVBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVFirstName, "John"),
							wire.NewTLVBE(wire.ODirTLVLastName, "Doe"),
							wire.NewTLVBE(wire.ODirTLVMiddleName, "A"),
							wire.NewTLVBE(wire.ODirTLVMaidenName, "Smith"),
							wire.NewTLVBE(wire.ODirTLVCountry, "USA"),
							wire.NewTLVBE(wire.ODirTLVState, "CA"),
							wire.NewTLVBE(wire.ODirTLVCity, "San Francisco"),
							wire.NewTLVBE(wire.ODirTLVNickName, "Johnny"),
							wire.NewTLVBE(wire.ODirTLVZIP, "94107"),
							wire.NewTLVBE(wire.ODirTLVAddress, "123 Main St"),
						},
					},
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("test-user"),
							result: &state.User{
								AIMDirectoryInfo: state.AIMNameAndAddr{
									FirstName:  "John",
									LastName:   "Doe",
									MiddleName: "A",
									MaidenName: "Smith",
									Country:    "USA",
									State:      "CA",
									City:       "San Francisco",
									NickName:   "Johnny",
									ZIPCode:    "94107",
									Address:    "123 Main St",
								},
							},
						},
					},
				},
			},
		},
		{
			name:        "user not found",
			userSession: newTestSession("test-user"),
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x0B_LocateGetDirInfo{
					ScreenName: "test-user",
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.Locate,
					SubGroup:  wire.LocateGetDirReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{
					Status: wire.LocateGetDirReplyOK,
					TLVBlock: wire.TLVBlock{
						TLVList: wire.TLVList{},
					},
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					getUserParams: getUserParams{
						{
							screenName: state.NewIdentScreenName("test-user"),
							result:     nil,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profileManager := newMockProfileManager(t)
			for _, params := range tt.mockParams.profileManagerParams.getUserParams {
				profileManager.EXPECT().
					User(matchContext(), params.screenName).
					Return(params.result, params.err)
			}
			svc := NewLocateService(nil, nil, profileManager, nil, nil, nil)
			outputSNAC, err := svc.DirInfo(context.Background(), tt.inputSNAC.Frame, tt.inputSNAC.Body.(wire.SNAC_0x02_0x0B_LocateGetDirInfo))
			assert.NoError(t, err)
			assert.Equal(t, tt.expectOutput, outputSNAC)
		})
	}
}
