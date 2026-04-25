package icq_legacy

import (
	"context"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestICQLegacyService_AuthenticateUser(t *testing.T) {
	authKey := "test-auth-key"
	password := "secret123"
	passHash := wire.StrongMD5PasswordHash(password, authKey)

	tests := []struct {
		name       string
		mockParams mockParams
		req        AuthRequest
		wantResult *AuthResult
		wantErr    error
	}{
		{
			name: "valid credentials",
			req: AuthRequest{
				UIN:      12345,
				Password: password,
				Version:  ICQLegacyVersionV5,
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					userParams: userParams{
						{
							screenName: state.NewIdentScreenName("12345"),
							result: &state.User{
								AuthKey:       authKey,
								StrongMD5Pass: passHash,
							},
						},
					},
				},
			},
			wantResult: &AuthResult{
				Success:   true,
				ErrorCode: 0,
			},
		},
		{
			name: "bad password",
			req: AuthRequest{
				UIN:      12345,
				Password: "wrongpass",
				Version:  ICQLegacyVersionV5,
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					userParams: userParams{
						{
							screenName: state.NewIdentScreenName("12345"),
							result: &state.User{
								AuthKey:       authKey,
								StrongMD5Pass: passHash,
							},
						},
					},
				},
			},
			wantResult: &AuthResult{
				Success:   false,
				ErrorCode: 0x0001,
			},
		},
		{
			name: "user not found",
			req: AuthRequest{
				UIN:      99999,
				Password: password,
				Version:  ICQLegacyVersionV5,
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					userParams: userParams{
						{
							screenName: state.NewIdentScreenName("99999"),
							result:     nil,
							err:        state.ErrNoUser,
						},
					},
				},
			},
			wantResult: &AuthResult{
				Success:   false,
				ErrorCode: 0x0002,
			},
		},
		{
			name: "missing UIN (UIN=0)",
			req: AuthRequest{
				UIN:      0,
				Password: password,
			},
			wantResult: &AuthResult{
				Success:   false,
				ErrorCode: 0x0002,
			},
		},
		{
			name: "no password hash",
			req: AuthRequest{
				UIN:      12345,
				Password: password,
				Version:  ICQLegacyVersionV5,
			},
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					userParams: userParams{
						{
							screenName: state.NewIdentScreenName("12345"),
							result: &state.User{
								AuthKey:       authKey,
								StrongMD5Pass: nil,
							},
						},
					},
				},
			},
			wantResult: &AuthResult{
				Success:   false,
				ErrorCode: 0x0001,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userManager := newMockUserManager(t)
			for _, p := range tc.mockParams.userParams {
				userManager.EXPECT().
					User(matchContext(), p.screenName).
					Return(p.result, p.err)
			}

			svc := NewICQLegacyService(
				userManager,
				newMockAccountManager(t),
				newMockSessionRetriever(t),
				newMockMessageRelayer(t),
				newMockBuddyBroadcaster(t),
				newMockOfflineMessageManager(t),
				newMockICQUserFinder(t),
				newMockICQUserUpdater(t),
				newMockFeedbagManager(t),
				newMockRelationshipFetcher(t),
				newMockBuddyListRegistry(t),
				newMockClientSideBuddyListManager(t),
				newMockICBMService(t),
				slog.Default(),
			)

			got, err := svc.AuthenticateUser(context.Background(), tc.req)

			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantResult.Success, got.Success)
			assert.Equal(t, tc.wantResult.ErrorCode, got.ErrorCode)
			if tc.wantResult.Success {
				assert.NotEmpty(t, got.SessionID)
			}
		})
	}
}

func TestICQLegacyService_ProcessMessage(t *testing.T) {
	tests := []struct {
		name       string
		sess       *LegacySession
		mockParams mockParams
		req        MessageRequest
		wantResult *MessageResult
		wantErr    error
		// legacySessionManager is set to non-nil when we need legacy session lookup
		setupLegacyMgr func(t *testing.T, svc *ICQLegacyService)
	}{
		{
			name: "target online - legacy session exists",
			req: MessageRequest{
				FromUIN: 11111,
				ToUIN:   22222,
				MsgType: ICQLegacyMsgText,
				Message: "hello",
			},
			setupLegacyMgr: func(t *testing.T, svc *ICQLegacyService) {
				mgr := &LegacySessionManager{
					sessions: map[uint32]*LegacySession{
						22222: newTestLegacySession(22222),
					},
				}
				svc.SetLegacySessionManager(mgr)
			},
			wantResult: &MessageResult{
				Delivered:     true,
				StoredOffline: false,
				TargetOnline:  true,
				TargetVersion: ICQLegacyVersionV5,
			},
		},
		{
			name: "target online - OSCAR session",
			sess: newTestLegacySession(11111, legacySessionOptOSCARSess),
			req: MessageRequest{
				FromUIN: 11111,
				ToUIN:   22222,
				MsgType: ICQLegacyMsgText,
				Message: "hello from legacy",
			},
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("22222"),
							result:     &state.Session{},
						},
					},
				},
				icbmFoodgroupParams: icbmFoodgroupParams{
					channelMsgToHostParams: channelMsgToHostParams{
						{
							screenName: state.NewIdentScreenName("11111"),
							inFrame: wire.SNACFrame{
								FoodGroup: wire.ICBM,
								SubGroup:  wire.ICBMChannelMsgToHost,
							},
							inBody: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
								ChannelID:  wire.ICBMChannelICQ,
								ScreenName: "22222",
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVLE(wire.ICBMTLVData, wire.ICBMCh4Message{
											UIN:         11111,
											MessageType: wire.ICBMMsgTypePlain,
											Message:     "hello from legacy",
										}),
										wire.NewTLVBE(wire.ICBMTLVStore, []byte{}),
									},
								},
							},
						},
					},
				},
			},
			wantResult: &MessageResult{
				Delivered:     true,
				StoredOffline: false,
				TargetOnline:  true,
				TargetVersion: 0,
			},
		},
		{
			name: "target offline - stored",
			req: MessageRequest{
				FromUIN: 11111,
				ToUIN:   22222,
				MsgType: ICQLegacyMsgText,
				Message: "offline msg",
			},
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("22222"),
							result:     nil,
						},
					},
				},
				offlineMessageManagerParams: offlineMessageManagerParams{
					saveMessageParams: saveMessageParams{
						{
							count: 1,
						},
					},
				},
			},
			wantResult: &MessageResult{
				Delivered:     false,
				StoredOffline: true,
				TargetOnline:  false,
				TargetVersion: 0,
			},
		},
		{
			name: "invalid sender UIN (0)",
			req: MessageRequest{
				FromUIN: 0,
				ToUIN:   22222,
				MsgType: ICQLegacyMsgText,
				Message: "hello",
			},
			wantResult: &MessageResult{
				Delivered:     false,
				StoredOffline: false,
				TargetOnline:  false,
			},
		},
		{
			name: "invalid target UIN (0)",
			req: MessageRequest{
				FromUIN: 11111,
				ToUIN:   0,
				MsgType: ICQLegacyMsgText,
				Message: "hello",
			},
			wantResult: &MessageResult{
				Delivered:     false,
				StoredOffline: false,
				TargetOnline:  false,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sessionRetriever := newMockSessionRetriever(t)
			for _, p := range tc.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(p.screenName).
					Return(p.result)
			}

			messageRelayer := newMockMessageRelayer(t)
			for range tc.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().
					RelayToScreenName(matchContext(), mock.Anything, mock.Anything).
					Return()
			}

			offlineMsgMgr := newMockOfflineMessageManager(t)
			for _, p := range tc.mockParams.saveMessageParams {
				offlineMsgMgr.EXPECT().
					SaveMessage(matchContext(), mock.Anything).
					Return(p.count, p.err)
			}

			icbmSvc := newMockICBMService(t)
			for _, msg := range tc.mockParams.channelMsgToHostParams {
				icbmSvc.EXPECT().
					ChannelMsgToHost(matchContext(), matchSession(msg.screenName), msg.inFrame, msg.inBody).
					Return(nil, msg.err)
			}

			svc := NewICQLegacyService(
				newMockUserManager(t),
				newMockAccountManager(t),
				sessionRetriever,
				messageRelayer,
				newMockBuddyBroadcaster(t),
				offlineMsgMgr,
				newMockICQUserFinder(t),
				newMockICQUserUpdater(t),
				newMockFeedbagManager(t),
				newMockRelationshipFetcher(t),
				newMockBuddyListRegistry(t),
				newMockClientSideBuddyListManager(t),
				icbmSvc,
				slog.Default(),
			)

			if tc.setupLegacyMgr != nil {
				tc.setupLegacyMgr(t, svc)
			}

			got, err := svc.ProcessMessage(context.Background(), tc.sess, tc.req)

			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantResult.Delivered, got.Delivered)
			assert.Equal(t, tc.wantResult.StoredOffline, got.StoredOffline)
			assert.Equal(t, tc.wantResult.TargetOnline, got.TargetOnline)
			assert.Equal(t, tc.wantResult.TargetVersion, got.TargetVersion)
		})
	}
}

func TestICQLegacyService_ProcessContactList(t *testing.T) {
	tests := []struct {
		name           string
		mockParams     mockParams
		req            ContactListRequest
		setupLegacyMgr func(t *testing.T, svc *ICQLegacyService)
		wantResult     *ContactListResult
	}{
		{
			name: "mixed online/offline contacts",
			req: ContactListRequest{
				UIN:      11111,
				Contacts: []uint32{22222, 33333},
			},
			mockParams: mockParams{
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("22222"),
							result:     nil, // not on OSCAR either
						},
						{
							screenName: state.NewIdentScreenName("33333"),
							result:     &state.Session{}, // online via OSCAR
						},
					},
				},
			},
			setupLegacyMgr: func(t *testing.T, svc *ICQLegacyService) {
				mgr := &LegacySessionManager{
					sessions: make(map[uint32]*LegacySession),
				}
				svc.SetLegacySessionManager(mgr)
			},
			wantResult: &ContactListResult{
				OnlineContacts: []ContactStatus{
					{UIN: 22222, Online: false, Status: 0},
					{UIN: 33333, Online: true, Status: ICQLegacyStatusOnline},
				},
			},
		},
		{
			name: "empty list",
			req: ContactListRequest{
				UIN:      11111,
				Contacts: []uint32{},
			},
			wantResult: &ContactListResult{
				OnlineContacts: []ContactStatus{},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sessionRetriever := newMockSessionRetriever(t)
			for _, p := range tc.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(p.screenName).
					Return(p.result)
			}

			clientSideBuddyListMgr := newMockClientSideBuddyListManager(t)
			userFinder := newMockICQUserFinder(t)
			// ProcessContactList adds both forward and reverse buddy entries
			clientSideBuddyListMgr.EXPECT().
				AddBuddy(mock.Anything, mock.Anything, mock.Anything).
				Return(nil).
				Maybe()
			userFinder.EXPECT().
				FindByUIN(mock.Anything, mock.Anything).
				Return(state.User{}, nil).
				Maybe()

			svc := NewICQLegacyService(
				newMockUserManager(t),
				newMockAccountManager(t),
				sessionRetriever,
				newMockMessageRelayer(t),
				newMockBuddyBroadcaster(t),
				newMockOfflineMessageManager(t),
				userFinder,
				newMockICQUserUpdater(t),
				newMockFeedbagManager(t),
				newMockRelationshipFetcher(t),
				newMockBuddyListRegistry(t),
				clientSideBuddyListMgr,
				newMockICBMService(t),
				slog.Default(),
			)

			if tc.setupLegacyMgr != nil {
				tc.setupLegacyMgr(t, svc)
			}

			got, err := svc.ProcessContactList(context.Background(), tc.req)

			assert.NoError(t, err)
			assert.Equal(t, len(tc.wantResult.OnlineContacts), len(got.OnlineContacts))
			for i, want := range tc.wantResult.OnlineContacts {
				assert.Equal(t, want.UIN, got.OnlineContacts[i].UIN)
				assert.Equal(t, want.Online, got.OnlineContacts[i].Online)
				if want.Online {
					assert.Equal(t, want.Status, got.OnlineContacts[i].Status)
				}
			}
		})
	}
}

func TestICQLegacyService_ProcessStatusChange(t *testing.T) {
	tests := []struct {
		name           string
		mockParams     mockParams
		req            StatusChangeRequest
		setupLegacyMgr func(t *testing.T, svc *ICQLegacyService)
		wantTargets    int
	}{
		{
			name: "status change with notification targets",
			req: StatusChangeRequest{
				UIN:       11111,
				OldStatus: ICQLegacyStatusOnline,
				NewStatus: ICQLegacyStatusAway,
			},
			setupLegacyMgr: func(t *testing.T, svc *ICQLegacyService) {
				sess := newTestLegacySession(11111, legacySessionOptContactList([]uint32{22222}))
				contactSess := newTestLegacySession(22222, legacySessionOptContactList([]uint32{11111}))
				mgr := &LegacySessionManager{
					sessions: map[uint32]*LegacySession{
						11111: sess,
						22222: contactSess,
					},
				}
				svc.SetLegacySessionManager(mgr)
			},
			wantTargets: 1,
		},
		{
			name: "no targets - session not found",
			req: StatusChangeRequest{
				UIN:       99999,
				OldStatus: ICQLegacyStatusOnline,
				NewStatus: ICQLegacyStatusAway,
			},
			wantTargets: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewICQLegacyService(
				newMockUserManager(t),
				newMockAccountManager(t),
				newMockSessionRetriever(t),
				newMockMessageRelayer(t),
				newMockBuddyBroadcaster(t),
				newMockOfflineMessageManager(t),
				newMockICQUserFinder(t),
				newMockICQUserUpdater(t),
				newMockFeedbagManager(t),
				newMockRelationshipFetcher(t),
				newMockBuddyListRegistry(t),
				newMockClientSideBuddyListManager(t),
				newMockICBMService(t),
				slog.Default(),
			)

			if tc.setupLegacyMgr != nil {
				tc.setupLegacyMgr(t, svc)
			}

			got, err := svc.ProcessStatusChange(context.Background(), tc.req)

			assert.NoError(t, err)
			assert.Len(t, got.NotifyTargets, tc.wantTargets)
		})
	}
}

func TestICQLegacyService_SearchByUIN(t *testing.T) {
	tests := []struct {
		name       string
		mockParams mockParams
		uin        uint32
		wantResult *LegacyUserSearchResult
		wantErr    bool
	}{
		{
			name: "found",
			uin:  12345,
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByUINParams: findByUINParams{
						{
							UIN: 12345,
							result: state.User{
								IdentScreenName: state.NewIdentScreenName("12345"),
								ICQBasicInfo: state.ICQBasicInfo{
									Nickname:     "CoolUser",
									FirstName:    "John",
									LastName:     "Doe",
									EmailAddress: "john@example.com",
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("12345"),
							result:     nil,
						},
					},
				},
			},
			wantResult: &LegacyUserSearchResult{
				UIN:       12345,
				Nickname:  "CoolUser",
				FirstName: "John",
				LastName:  "Doe",
				Email:     "john@example.com",
			},
		},
		{
			name: "not found",
			uin:  99999,
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByUINParams: findByUINParams{
						{
							UIN: 99999,
							err: state.ErrNoUser,
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, p := range tc.mockParams.findByUINParams {
				userFinder.EXPECT().
					FindByUIN(matchContext(), p.UIN).
					Return(p.result, p.err)
			}

			sessionRetriever := newMockSessionRetriever(t)
			for _, p := range tc.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(p.screenName).
					Return(p.result)
			}

			svc := NewICQLegacyService(
				newMockUserManager(t),
				newMockAccountManager(t),
				sessionRetriever,
				newMockMessageRelayer(t),
				newMockBuddyBroadcaster(t),
				newMockOfflineMessageManager(t),
				userFinder,
				newMockICQUserUpdater(t),
				newMockFeedbagManager(t),
				newMockRelationshipFetcher(t),
				newMockBuddyListRegistry(t),
				newMockClientSideBuddyListManager(t),
				newMockICBMService(t),
				slog.Default(),
			)

			got, err := svc.SearchByUIN(context.Background(), tc.uin)

			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tc.wantResult.UIN, got.UIN)
			assert.Equal(t, tc.wantResult.Nickname, got.Nickname)
			assert.Equal(t, tc.wantResult.FirstName, got.FirstName)
			assert.Equal(t, tc.wantResult.LastName, got.LastName)
			assert.Equal(t, tc.wantResult.Email, got.Email)
		})
	}
}

func TestICQLegacyService_SearchByName(t *testing.T) {
	tests := []struct {
		name       string
		mockParams mockParams
		nick       string
		first      string
		last       string
		email      string
		wantCount  int
	}{
		{
			name:  "matches by name",
			first: "John",
			last:  "Doe",
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByICQNameParams: findByICQNameParams{
						{
							firstName: "John",
							lastName:  "Doe",
							nickName:  "",
							result: []state.User{
								{
									IdentScreenName: state.NewIdentScreenName("12345"),
									ICQBasicInfo: state.ICQBasicInfo{
										Nickname:  "JD",
										FirstName: "John",
										LastName:  "Doe",
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("12345"),
							result:     nil,
						},
					},
				},
			},
			wantCount: 1,
		},
		{
			name:  "matches by email",
			email: "john@example.com",
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByICQEmailParams: findByICQEmailParams{
						{
							email: "john@example.com",
							result: state.User{
								IdentScreenName: state.NewIdentScreenName("12345"),
								ICQBasicInfo: state.ICQBasicInfo{
									Nickname:     "JD",
									EmailAddress: "john@example.com",
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams: retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("12345"),
							result:     nil,
						},
					},
				},
			},
			wantCount: 1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, p := range tc.mockParams.findByICQNameParams {
				userFinder.EXPECT().
					FindByICQName(matchContext(), p.firstName, p.lastName, p.nickName).
					Return(p.result, p.err)
			}
			for _, p := range tc.mockParams.findByICQEmailParams {
				userFinder.EXPECT().
					FindByICQEmail(matchContext(), p.email).
					Return(p.result, p.err)
			}

			sessionRetriever := newMockSessionRetriever(t)
			for _, p := range tc.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(p.screenName).
					Return(p.result)
			}

			svc := NewICQLegacyService(
				newMockUserManager(t),
				newMockAccountManager(t),
				sessionRetriever,
				newMockMessageRelayer(t),
				newMockBuddyBroadcaster(t),
				newMockOfflineMessageManager(t),
				userFinder,
				newMockICQUserUpdater(t),
				newMockFeedbagManager(t),
				newMockRelationshipFetcher(t),
				newMockBuddyListRegistry(t),
				newMockClientSideBuddyListManager(t),
				newMockICBMService(t),
				slog.Default(),
			)

			got, err := svc.SearchByName(context.Background(), tc.nick, tc.first, tc.last, tc.email)

			assert.NoError(t, err)
			assert.Len(t, got, tc.wantCount)
		})
	}
}

func TestICQLegacyService_GetOfflineMessages(t *testing.T) {
	fixedTime := time.Date(2024, 1, 15, 10, 30, 0, 0, time.UTC)

	tests := []struct {
		name       string
		mockParams mockParams
		uin        uint32
		wantCount  int
	}{
		{
			name: "messages exist",
			uin:  12345,
			mockParams: mockParams{
				offlineMessageManagerParams: offlineMessageManagerParams{
					retrieveMessagesParams: retrieveMessagesParams{
						{
							recip: state.NewIdentScreenName("12345"),
							messages: []state.OfflineMessage{
								{
									Sender:    state.NewIdentScreenName("99999"),
									Recipient: state.NewIdentScreenName("12345"),
									Sent:      fixedTime,
									Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
										ChannelID: wire.ICBMChannelIM,
										TLVRestBlock: wire.TLVRestBlock{
											TLVList: func() wire.TLVList {
												frags, _ := wire.ICBMFragmentList("hello offline")
												return wire.TLVList{
													wire.NewTLVBE(wire.ICBMTLVAOLIMData, frags),
												}
											}(),
										},
									},
								},
							},
						},
					},
				},
			},
			wantCount: 1,
		},
		{
			name: "no messages",
			uin:  12345,
			mockParams: mockParams{
				offlineMessageManagerParams: offlineMessageManagerParams{
					retrieveMessagesParams: retrieveMessagesParams{
						{
							recip:    state.NewIdentScreenName("12345"),
							messages: []state.OfflineMessage{},
						},
					},
				},
			},
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			offlineMsgMgr := newMockOfflineMessageManager(t)
			for _, p := range tc.mockParams.retrieveMessagesParams {
				offlineMsgMgr.EXPECT().
					RetrieveMessages(matchContext(), p.recip).
					Return(p.messages, p.err)
			}

			svc := NewICQLegacyService(
				newMockUserManager(t),
				newMockAccountManager(t),
				newMockSessionRetriever(t),
				newMockMessageRelayer(t),
				newMockBuddyBroadcaster(t),
				offlineMsgMgr,
				newMockICQUserFinder(t),
				newMockICQUserUpdater(t),
				newMockFeedbagManager(t),
				newMockRelationshipFetcher(t),
				newMockBuddyListRegistry(t),
				newMockClientSideBuddyListManager(t),
				newMockICBMService(t),
				slog.Default(),
			)

			got, err := svc.GetOfflineMessages(context.Background(), tc.uin)

			assert.NoError(t, err)
			assert.Len(t, got, tc.wantCount)
			if tc.wantCount > 0 {
				assert.Equal(t, uint32(99999), got[0].FromUIN)
				assert.Equal(t, tc.uin, got[0].ToUIN)
			}
		})
	}
}

func TestICQLegacyService_RegisterNewUser(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name: "success",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userManager := newMockUserManager(t)
			// generateNewUIN calls User() to find an available UIN.
			// Return nil (available) for the first UIN checked (100000).
			userManager.EXPECT().
				User(matchContext(), state.NewIdentScreenName(strconv.FormatUint(100000, 10))).
				Return(nil, nil)
			// InsertUser is called with the new user
			userManager.EXPECT().
				InsertUser(matchContext(), mock.Anything).
				Return(nil)

			svc := NewICQLegacyService(
				userManager,
				newMockAccountManager(t),
				newMockSessionRetriever(t),
				newMockMessageRelayer(t),
				newMockBuddyBroadcaster(t),
				newMockOfflineMessageManager(t),
				newMockICQUserFinder(t),
				newMockICQUserUpdater(t),
				newMockFeedbagManager(t),
				newMockRelationshipFetcher(t),
				newMockBuddyListRegistry(t),
				newMockClientSideBuddyListManager(t),
				newMockICBMService(t),
				slog.Default(),
			)

			uin, err := svc.RegisterNewUser(context.Background(), "Nick", "First", "Last", "test@example.com", "password123")

			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, uint32(100000), uin)
		})
	}
}

func TestICQLegacyService_DeleteUser(t *testing.T) {
	authKey := "test-auth-key"
	password := "secret123"
	passHash := wire.StrongMD5PasswordHash(password, authKey)

	tests := []struct {
		name       string
		mockParams mockParams
		uin        uint32
		password   string
		wantErr    bool
	}{
		{
			name:     "success",
			uin:      12345,
			password: password,
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					userParams: userParams{
						{
							screenName: state.NewIdentScreenName("12345"),
							result: &state.User{
								AuthKey:       authKey,
								StrongMD5Pass: passHash,
							},
						},
					},
					deleteUserParams: deleteUserParams{
						{
							screenName: state.NewIdentScreenName("12345"),
						},
					},
				},
			},
		},
		{
			name:     "wrong password",
			uin:      12345,
			password: "wrongpass",
			mockParams: mockParams{
				userManagerParams: userManagerParams{
					userParams: userParams{
						{
							screenName: state.NewIdentScreenName("12345"),
							result: &state.User{
								AuthKey:       authKey,
								StrongMD5Pass: passHash,
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userManager := newMockUserManager(t)
			for _, p := range tc.mockParams.userParams {
				userManager.EXPECT().
					User(matchContext(), p.screenName).
					Return(p.result, p.err)
			}
			for _, p := range tc.mockParams.deleteUserParams {
				userManager.EXPECT().
					DeleteUser(matchContext(), p.screenName).
					Return(p.err)
			}

			svc := NewICQLegacyService(
				userManager,
				newMockAccountManager(t),
				newMockSessionRetriever(t),
				newMockMessageRelayer(t),
				newMockBuddyBroadcaster(t),
				newMockOfflineMessageManager(t),
				newMockICQUserFinder(t),
				newMockICQUserUpdater(t),
				newMockFeedbagManager(t),
				newMockRelationshipFetcher(t),
				newMockBuddyListRegistry(t),
				newMockClientSideBuddyListManager(t),
				newMockICBMService(t),
				slog.Default(),
			)

			err := svc.DeleteUser(context.Background(), tc.uin, tc.password)

			if tc.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid password")
				return
			}
			assert.NoError(t, err)
		})
	}
}
