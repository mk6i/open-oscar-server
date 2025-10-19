package foodgroup

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/retro-aim-server/state"
	"github.com/mk6i/retro-aim-server/wire"
)

func TestICQService_DeleteMsgReq(t *testing.T) {
	tests := []struct {
		name       string
		seq        uint16
		sess       *state.Session
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "send offline IM, offline friend request",
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			mockParams: mockParams{
				offlineMessageManagerParams: offlineMessageManagerParams{
					deleteMessagesParams: deleteMessagesParams{
						{
							recipIn: state.NewIdentScreenName("11111111"),
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offlineMessageManager := newMockOfflineMessageManager(t)
			for _, params := range tt.mockParams.deleteMessagesParams {
				offlineMessageManager.EXPECT().
					DeleteMessages(matchContext(), params.recipIn).
					Return(params.err)
			}

			s := NewICQService(nil, nil, nil, slog.Default(), nil, offlineMessageManager)
			err := s.DeleteMsgReq(context.Background(), tt.sess, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_FindByICQName(t *testing.T) {
	tests := []struct {
		name       string
		timeNow    func() time.Time
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x0515_DBQueryMetaReqSearchByDetails
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x0515_DBQueryMetaReqSearchByDetails{
				FirstName: "John",
				LastName:  "Doe",
				NickName:  "Johnny",
			},
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByDetailsParams: findByDetailsParams{
						{
							firstName: "John",
							lastName:  "Doe",
							nickName:  "Johnny",
							result: []state.User{
								{
									IdentScreenName: state.NewIdentScreenName("987654321"),
									ICQBasicInfo: state.ICQBasicInfo{
										EmailAddress: "janey@example.com",
										FirstName:    "Jane",
										LastName:     "Doe",
										Nickname:     "Janey",
									},
									ICQPermissions: state.ICQPermissions{
										AuthRequired: false,
									},
									ICQMoreInfo: state.ICQMoreInfo{
										BirthDay:   31,
										BirthMonth: 7,
										BirthYear:  1995,
										Gender:     2,
									},
								},
								{
									IdentScreenName: state.NewIdentScreenName("123456789"),
									ICQBasicInfo: state.ICQBasicInfo{
										EmailAddress: "john@example.com",
										FirstName:    "John",
										LastName:     "Doe",
										Nickname:     "Johnny",
									},
									ICQPermissions: state.ICQPermissions{
										AuthRequired: true,
									},
									ICQMoreInfo: state.ICQMoreInfo{
										Gender:     1,
										BirthDay:   31,
										BirthMonth: 7,
										BirthYear:  1999,
									},
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           987654321,
														Nickname:      "Janey",
														FirstName:     "Jane",
														LastName:      "Doe",
														Email:         "janey@example.com",
														Authorization: 0,
														OnlineStatus:  0,
														Gender:        2,
														Age:           25,
													},
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           123456789,
														Nickname:      "Johnny",
														FirstName:     "John",
														LastName:      "Doe",
														Email:         "john@example.com",
														Authorization: 1,
														OnlineStatus:  1,
														Gender:        1,
														Age:           21,
													},
													LastMessageFooter: &struct {
														FoundUsersLeft uint32
													}{
														FoundUsersLeft: 0,
													},
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("987654321"),
							result:     nil,
						},
						{
							screenName: state.NewIdentScreenName("123456789"),
							result:     &state.Session{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, params := range tt.mockParams.findByDetailsParams {
				userFinder.EXPECT().
					FindByICQName(matchContext(), params.firstName, params.lastName, params.nickName).
					Return(params.result, params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tt.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName, params.sessionNum).
					Return(params.result)
			}

			s := ICQService{
				messageRelayer:   messageRelayer,
				sessionRetriever: sessionRetriever,
				timeNow:          tt.timeNow,
				userFinder:       userFinder,
			}
			err := s.FindByICQName(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_FindByICQEmail(t *testing.T) {
	tests := []struct {
		name       string
		timeNow    func() time.Time
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x0529_DBQueryMetaReqSearchByEmail
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x0529_DBQueryMetaReqSearchByEmail{
				Email: "john@example.com",
			},
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByEmailParams: findByEmailParams{
						{
							email: "john@example.com",
							result: state.User{
								IdentScreenName: state.NewIdentScreenName("123456789"),
								ICQBasicInfo: state.ICQBasicInfo{
									EmailAddress: "john@example.com",
									FirstName:    "John",
									LastName:     "Doe",
									Nickname:     "Johnny",
								},
								ICQPermissions: state.ICQPermissions{
									AuthRequired: true,
								},
								ICQMoreInfo: state.ICQMoreInfo{
									BirthDay:   31,
									BirthMonth: 7,
									BirthYear:  1999,
									Gender:     1,
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           123456789,
														Nickname:      "Johnny",
														FirstName:     "John",
														LastName:      "Doe",
														Email:         "john@example.com",
														Authorization: 1,
														OnlineStatus:  1,
														Gender:        1,
														Age:           21,
													},
													LastMessageFooter: &struct {
														FoundUsersLeft uint32
													}{
														FoundUsersLeft: 0,
													},
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("123456789"),
							result:     &state.Session{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, params := range tt.mockParams.findByEmailParams {
				userFinder.EXPECT().
					FindByICQEmail(matchContext(), params.email).
					Return(params.result, params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tt.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName, params.sessionNum).
					Return(params.result)
			}

			s := ICQService{
				messageRelayer:   messageRelayer,
				sessionRetriever: sessionRetriever,
				timeNow:          tt.timeNow,
				userFinder:       userFinder,
			}
			err := s.FindByICQEmail(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_FindByEmail3(t *testing.T) {
	tests := []struct {
		name       string
		timeNow    func() time.Time
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x0573_DBQueryMetaReqSearchByEmail3
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x0573_DBQueryMetaReqSearchByEmail3{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICQTLVTagsEmail, wire.ICQEmail{
							Email: "john@example.com",
						}),
					},
				},
			},
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByEmailParams: findByEmailParams{
						{
							email: "john@example.com",
							result: state.User{
								IdentScreenName: state.NewIdentScreenName("123456789"),
								ICQBasicInfo: state.ICQBasicInfo{
									EmailAddress: "john@example.com",
									FirstName:    "John",
									LastName:     "Doe",
									Nickname:     "Johnny",
								},
								ICQPermissions: state.ICQPermissions{
									AuthRequired: true,
								},
								ICQMoreInfo: state.ICQMoreInfo{
									BirthDay:   31,
									BirthMonth: 7,
									BirthYear:  1999,
									Gender:     1,
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           123456789,
														Nickname:      "Johnny",
														FirstName:     "John",
														LastName:      "Doe",
														Email:         "john@example.com",
														Authorization: 1,
														OnlineStatus:  1,
														Gender:        1,
														Age:           21,
													},
													LastMessageFooter: &struct {
														FoundUsersLeft uint32
													}{
														FoundUsersLeft: 0,
													},
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("123456789"),
							result:     &state.Session{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, params := range tt.mockParams.findByEmailParams {
				userFinder.EXPECT().
					FindByICQEmail(matchContext(), params.email).
					Return(params.result, params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tt.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName, params.sessionNum).
					Return(params.result)
			}

			s := ICQService{
				messageRelayer:   messageRelayer,
				sessionRetriever: sessionRetriever,
				timeNow:          tt.timeNow,
				userFinder:       userFinder,
			}
			err := s.FindByEmail3(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_FindByUIN(t *testing.T) {
	tests := []struct {
		name       string
		timeNow    func() time.Time
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN{
				UIN: 123456789,
			},
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByUINParams: findByUINParams{
						{
							UIN: 123456789,
							result: state.User{
								IdentScreenName: state.NewIdentScreenName("123456789"),
								ICQPermissions: state.ICQPermissions{
									AuthRequired: true,
								},
								ICQBasicInfo: state.ICQBasicInfo{
									EmailAddress: "john@example.com",
									FirstName:    "John",
									LastName:     "Doe",
									Nickname:     "Johnny",
								},
								ICQMoreInfo: state.ICQMoreInfo{
									Gender:     1,
									BirthDay:   31,
									BirthMonth: 7,
									BirthYear:  1999,
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           123456789,
														Nickname:      "Johnny",
														FirstName:     "John",
														LastName:      "Doe",
														Email:         "john@example.com",
														Authorization: 1,
														OnlineStatus:  1,
														Gender:        1,
														Age:           21,
													},
													LastMessageFooter: &struct {
														FoundUsersLeft uint32
													}{
														FoundUsersLeft: 0,
													},
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("123456789"),
							result:     &state.Session{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, params := range tt.mockParams.findByUINParams {
				userFinder.EXPECT().
					FindByUIN(matchContext(), params.UIN).
					Return(params.result, params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tt.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName, params.sessionNum).
					Return(params.result)
			}

			s := ICQService{
				messageRelayer:   messageRelayer,
				sessionRetriever: sessionRetriever,
				timeNow:          tt.timeNow,
				userFinder:       userFinder,
			}
			err := s.FindByUIN(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_FindByUIN2(t *testing.T) {
	tests := []struct {
		name       string
		timeNow    func() time.Time
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x0569_DBQueryMetaReqSearchByUIN2{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICQTLVTagsUIN, uint32(123456789)),
					},
				},
			},
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByUINParams: findByUINParams{
						{
							UIN: 123456789,
							result: state.User{
								IdentScreenName: state.NewIdentScreenName("123456789"),
								ICQPermissions: state.ICQPermissions{
									AuthRequired: true,
								},
								ICQBasicInfo: state.ICQBasicInfo{
									EmailAddress: "john@example.com",
									FirstName:    "John",
									LastName:     "Doe",
									Nickname:     "Johnny",
								},
								ICQMoreInfo: state.ICQMoreInfo{
									Gender:     1,
									BirthDay:   31,
									BirthMonth: 7,
									BirthYear:  1999,
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           123456789,
														Nickname:      "Johnny",
														FirstName:     "John",
														LastName:      "Doe",
														Email:         "john@example.com",
														Authorization: 1,
														OnlineStatus:  1,
														Gender:        1,
														Age:           21,
													},
													LastMessageFooter: &struct {
														FoundUsersLeft uint32
													}{
														FoundUsersLeft: 0,
													},
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("123456789"),
							result:     &state.Session{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, params := range tt.mockParams.findByUINParams {
				userFinder.EXPECT().
					FindByUIN(matchContext(), params.UIN).
					Return(params.result, params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tt.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName, params.sessionNum).
					Return(params.result)
			}

			s := ICQService{
				messageRelayer:   messageRelayer,
				sessionRetriever: sessionRetriever,
				timeNow:          tt.timeNow,
				userFinder:       userFinder,
			}
			err := s.FindByUIN2(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_FindByWhitePages(t *testing.T) {
	tests := []struct {
		name       string
		timeNow    func() time.Time
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x0533_DBQueryMetaReqSearchWhitePages
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x0533_DBQueryMetaReqSearchWhitePages{
				InterestsCode:    10,
				InterestsKeyword: "knitting,crocheting,sewing",
			},
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByInterestsParams: findByInterestsParams{
						{
							code:     10,
							keywords: []string{"knitting", "crocheting", "sewing"},
							result: []state.User{
								{
									IdentScreenName: state.NewIdentScreenName("987654321"),
									ICQBasicInfo: state.ICQBasicInfo{
										EmailAddress: "janey@example.com",
										FirstName:    "Jane",
										LastName:     "Doe",
										Nickname:     "Janey",
									},
									ICQPermissions: state.ICQPermissions{
										AuthRequired: false,
									},
									ICQMoreInfo: state.ICQMoreInfo{
										BirthDay:   31,
										BirthMonth: 7,
										BirthYear:  1995,
										Gender:     2,
									},
								},
								{
									IdentScreenName: state.NewIdentScreenName("123456789"),
									ICQBasicInfo: state.ICQBasicInfo{
										EmailAddress: "alice@example.com",
										FirstName:    "Alice",
										LastName:     "Smith",
										Nickname:     "Ally123",
									},
									ICQPermissions: state.ICQPermissions{
										AuthRequired: true,
									},
									ICQMoreInfo: state.ICQMoreInfo{
										BirthDay:   31,
										BirthMonth: 7,
										BirthYear:  1999,
										Gender:     1,
									},
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           987654321,
														Nickname:      "Janey",
														FirstName:     "Jane",
														LastName:      "Doe",
														Email:         "janey@example.com",
														Authorization: 0,
														OnlineStatus:  0,
														Gender:        2,
														Age:           25,
													},
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           123456789,
														Nickname:      "Ally123",
														FirstName:     "Alice",
														LastName:      "Smith",
														Email:         "alice@example.com",
														Authorization: 1,
														OnlineStatus:  1,
														Gender:        1,
														Age:           21,
													},
													LastMessageFooter: &struct {
														FoundUsersLeft uint32
													}{
														FoundUsersLeft: 0,
													},
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("987654321"),
							result:     nil,
						},
						{
							screenName: state.NewIdentScreenName("123456789"),
							result:     &state.Session{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, params := range tt.mockParams.findByInterestsParams {
				userFinder.EXPECT().
					FindByICQInterests(matchContext(), params.code, params.keywords).
					Return(params.result, params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tt.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName, params.sessionNum).
					Return(params.result)
			}

			s := ICQService{
				messageRelayer:   messageRelayer,
				sessionRetriever: sessionRetriever,
				timeNow:          tt.timeNow,
				userFinder:       userFinder,
			}
			err := s.FindByICQInterests(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_FindByWhitePages2(t *testing.T) {
	tests := []struct {
		name       string
		timeNow    func() time.Time
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "search by keyword",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICQTLVTagsWhitepagesSearchKeywords, struct {
							Val string `oscar:"len_prefix=uint16,nullterm"`
						}{
							Val: "knitting",
						}),
					},
				},
			},
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByKeywordParams: findByKeywordParams{
						{
							keyword: "knitting",
							result: []state.User{
								{
									IdentScreenName: state.NewIdentScreenName("987654321"),
									ICQBasicInfo: state.ICQBasicInfo{
										EmailAddress: "janey@example.com",
										FirstName:    "Jane",
										LastName:     "Doe",
										Nickname:     "Janey",
									},
									ICQPermissions: state.ICQPermissions{
										AuthRequired: false,
									},
									ICQMoreInfo: state.ICQMoreInfo{
										BirthDay:   31,
										BirthMonth: 7,
										BirthYear:  1995,
										Gender:     2,
									},
								},
								{
									IdentScreenName: state.NewIdentScreenName("123456789"),
									ICQBasicInfo: state.ICQBasicInfo{
										EmailAddress: "alice@example.com",
										FirstName:    "Alice",
										LastName:     "Smith",
										Nickname:     "Ally123",
									},
									ICQPermissions: state.ICQPermissions{
										AuthRequired: true,
									},
									ICQMoreInfo: state.ICQMoreInfo{
										BirthDay:   31,
										BirthMonth: 7,
										BirthYear:  1999,
										Gender:     1,
									},
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           987654321,
														Nickname:      "Janey",
														FirstName:     "Jane",
														LastName:      "Doe",
														Email:         "janey@example.com",
														Authorization: 0,
														OnlineStatus:  0,
														Gender:        2,
														Age:           25,
													},
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           123456789,
														Nickname:      "Ally123",
														FirstName:     "Alice",
														LastName:      "Smith",
														Email:         "alice@example.com",
														Authorization: 1,
														OnlineStatus:  1,
														Gender:        1,
														Age:           21,
													},
													LastMessageFooter: &struct {
														FoundUsersLeft uint32
													}{
														FoundUsersLeft: 0,
													},
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("987654321"),
							result:     nil,
						},
						{
							screenName: state.NewIdentScreenName("123456789"),
							result:     &state.Session{},
						},
					},
				},
			},
		},
		{
			name: "search by name",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x055F_DBQueryMetaReqSearchWhitePages2{
				TLVRestBlock: wire.TLVRestBlock{
					TLVList: wire.TLVList{
						wire.NewTLVLE(wire.ICQTLVTagsNickname, struct {
							Val string `oscar:"len_prefix=uint16,nullterm"`
						}{
							Val: "Janey",
						}),
						wire.NewTLVLE(wire.ICQTLVTagsFirstName, struct {
							Val string `oscar:"len_prefix=uint16,nullterm"`
						}{
							Val: "Jane",
						}),
						wire.NewTLVLE(wire.ICQTLVTagsLastName, struct {
							Val string `oscar:"len_prefix=uint16,nullterm"`
						}{
							Val: "Janey",
						}),
					},
				},
			},
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByDetailsParams: findByDetailsParams{
						{
							nickName:  "Janey",
							firstName: "Jane",
							lastName:  "Janey",
							result: []state.User{
								{
									IdentScreenName: state.NewIdentScreenName("987654321"),
									ICQBasicInfo: state.ICQBasicInfo{
										EmailAddress: "janey@example.com",
										FirstName:    "Jane",
										LastName:     "Doe",
										Nickname:     "Janey",
									},
									ICQPermissions: state.ICQPermissions{
										AuthRequired: false,
									},
									ICQMoreInfo: state.ICQMoreInfo{
										BirthDay:   31,
										BirthMonth: 7,
										BirthYear:  1995,
										Gender:     2,
									},
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x01AE_DBQueryMetaReplyLastUserFound{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyLastUserFound,
													Details: wire.ICQUserSearchRecord{
														UIN:           987654321,
														Nickname:      "Janey",
														FirstName:     "Jane",
														LastName:      "Doe",
														Email:         "janey@example.com",
														Authorization: 0,
														OnlineStatus:  0,
														Gender:        2,
														Age:           25,
													},
													LastMessageFooter: &struct {
														FoundUsersLeft uint32
													}{
														FoundUsersLeft: 0,
													},
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("987654321"),
							result:     nil,
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, params := range tt.mockParams.findByKeywordParams {
				userFinder.EXPECT().
					FindByICQKeyword(matchContext(), params.keyword).
					Return(params.result, params.err)
			}
			for _, params := range tt.mockParams.findByDetailsParams {
				userFinder.EXPECT().
					FindByICQName(matchContext(), params.firstName, params.lastName, params.nickName).
					Return(params.result, params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			sessionRetriever := newMockSessionRetriever(t)
			for _, params := range tt.mockParams.retrieveSessionParams {
				sessionRetriever.EXPECT().
					RetrieveSession(params.screenName, params.sessionNum).
					Return(params.result)
			}

			s := ICQService{
				messageRelayer:   messageRelayer,
				sessionRetriever: sessionRetriever,
				timeNow:          tt.timeNow,
				userFinder:       userFinder,
			}
			err := s.FindByWhitePages2(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_FullUserInfo(t *testing.T) {
	tests := []struct {
		name       string
		timeNow    func() time.Time
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x051F_DBQueryMetaReqSearchByUIN{
				UIN: 123456789,
			},
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByUINParams: findByUINParams{
						{
							UIN: 123456789,
							result: state.User{
								IdentScreenName: state.NewIdentScreenName("123456789"),
								ICQNotes: state.ICQUserNotes{
									Notes: "This is a test user.",
								},
								ICQPermissions: state.ICQPermissions{
									AuthRequired: true,
								},
								ICQMoreInfo: state.ICQMoreInfo{
									BirthDay:     15,
									BirthMonth:   6,
									BirthYear:    1990,
									Gender:       1,
									HomePageAddr: "https://johnsdomain.com",
									Lang1:        1,
									Lang2:        2,
									Lang3:        3,
								},
								ICQBasicInfo: state.ICQBasicInfo{
									CellPhone:    "987-654-3210",
									CountryCode:  1,
									EmailAddress: "john.doe@example.com",
									FirstName:    "John",
									GMTOffset:    5,
									Address:      "123 Main St, New York, NY 10001",
									City:         "New York",
									Fax:          "123-456-7891",
									Phone:        "123-456-7890",
									State:        "NY",
									LastName:     "Doe",
									Nickname:     "CoolUser123",
									PublishEmail: true,
									ZIPCode:      "10001",
								},
								ICQWorkInfo: state.ICQWorkInfo{
									Company:        "TechCorp",
									Department:     "Engineering",
									OccupationCode: 1234,
									Position:       "Staff Software Engineer",
									Address:        "456 Work St, Los Angeles, CA 90001",
									City:           "Los Angeles",
									CountryCode:    1,
									Fax:            "234-567-8902",
									Phone:          "234-567-8901",
									State:          "CA",
									WebPage:        "https://techcorp.com",
									ZIPCode:        "90001",
								},
								ICQInterests: state.ICQInterests{
									Code1:    5678,
									Keyword1: "Programming",
									Code2:    6789,
									Keyword2: "Gaming",
									Code3:    7890,
									Keyword3: "Music",
									Code4:    8901,
									Keyword4: "Traveling",
								},
								ICQAffiliations: state.ICQAffiliations{
									CurrentCode1:    4567,
									CurrentKeyword1: "Professional Org",
									CurrentCode2:    5678,
									CurrentKeyword2: "Alumni Group",
									CurrentCode3:    6789,
									CurrentKeyword3: "Community Group",
									PastCode1:       9012,
									PastKeyword1:    "College",
									PastCode2:       1233,
									PastKeyword2:    "High School",
									PastCode3:       3456,
									PastKeyword3:    "Previous Job",
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00C8_DBQueryMetaReplyBasicInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyBasicInfo,

													Nickname:     "CoolUser123",
													FirstName:    "John",
													LastName:     "Doe",
													Email:        "john.doe@example.com",
													City:         "New York",
													State:        "NY",
													Phone:        "123-456-7890",
													Fax:          "123-456-7891",
													Address:      "123 Main St, New York, NY 10001",
													CellPhone:    "987-654-3210",
													ZIP:          "10001",
													CountryCode:  1,
													GMTOffset:    5,
													AuthFlag:     0,
													WebAware:     1,
													DCPerms:      0,
													PublishEmail: wire.ICQUserFlagPublishEmailYes,
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyMoreInfo,
													ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo: wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo{
														Age:          30,
														Gender:       1,
														HomePageAddr: "https://johnsdomain.com",
														BirthYear:    1990,
														BirthMonth:   6,
														BirthDay:     15,
														Lang1:        1,
														Lang2:        2,
														Lang3:        3,
													},
													City:        "New York",
													State:       "NY",
													CountryCode: 1,
													TimeZone:    5,
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00EB_DBQueryMetaReplyExtEmailInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyExtEmailInfo,
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x010E_DBQueryMetaReplyHomePageCat{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyHomePageCat,
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00D2_DBQueryMetaReplyWorkInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyWorkInfo,
													ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo: wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo{
														City:           "Los Angeles",
														State:          "CA",
														Phone:          "234-567-8901",
														Fax:            "234-567-8902",
														Address:        "456 Work St, Los Angeles, CA 90001",
														ZIP:            "90001",
														CountryCode:    1,
														Company:        "TechCorp",
														Department:     "Engineering",
														Position:       "Staff Software Engineer",
														OccupationCode: 1234,
														WebPage:        "https://techcorp.com",
													},
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00E6_DBQueryMetaReplyNotes{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyNotes,
													ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes: wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes{
														Notes: "This is a test user.",
													},
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00F0_DBQueryMetaReplyInterests{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyInterests,
													Interests: []struct {
														Code    uint16
														Keyword string `oscar:"len_prefix=uint16,nullterm"`
													}{
														{
															Code:    5678,
															Keyword: "Programming",
														},
														{
															Code:    6789,
															Keyword: "Gaming",
														},
														{
															Code:    7890,
															Keyword: "Music",
														},
														{
															Code:    8901,
															Keyword: "Traveling",
														},
													},
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00FA_DBQueryMetaReplyAffiliations{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:    wire.ICQStatusCodeOK,
													ReqSubType: wire.ICQDBQueryMetaReplyAffiliations,
													ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations: wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations{
														PastAffiliations: []struct {
															Code    uint16
															Keyword string `oscar:"len_prefix=uint16,nullterm"`
														}{
															{
																Code:    9012,
																Keyword: "College",
															},
															{
																Code:    1233,
																Keyword: "High School",
															},
															{
																Code:    3456,
																Keyword: "Previous Job",
															},
														},
														Affiliations: []struct {
															Code    uint16
															Keyword string `oscar:"len_prefix=uint16,nullterm"`
														}{
															{
																Code:    4567,
																Keyword: "Professional Org",
															},
															{
																Code:    5678,
																Keyword: "Alumni Group",
															},
															{
																Code:    6789,
																Keyword: "Community Group",
															},
														},
													},
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("123456789"),
							result:     &state.Session{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, params := range tt.mockParams.findByUINParams {
				userFinder.EXPECT().
					FindByUIN(matchContext(), params.UIN).
					Return(params.result, params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := ICQService{
				messageRelayer: messageRelayer,
				timeNow:        tt.timeNow,
				userFinder:     userFinder,
			}
			err := s.FullUserInfo(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_OfflineMsgReq(t *testing.T) {
	tests := []struct {
		name       string
		seq        uint16
		sess       *state.Session
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "send offline IM, offline friend request",
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			mockParams: mockParams{
				offlineMessageManagerParams: offlineMessageManagerParams{
					retrieveMessagesParams: retrieveMessagesParams{
						{
							recipIn: state.NewIdentScreenName("11111111"),
							messagesOut: []state.OfflineMessage{
								{
									Sender:    state.NewIdentScreenName("22222222"),
									Recipient: state.NewIdentScreenName("11111111"),
									Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
										ChannelID: wire.ICBMChannelIM,
										TLVRestBlock: wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.ICBMTLVAOLIMData, func() []wire.ICBMCh1Fragment {
													frags, err := wire.ICBMFragmentList("hello!")
													assert.NoError(t, err)
													return frags
												}()),
											},
										},
									},
									Sent: time.Date(2024, time.August, 2, 12, 5, 0, 0, time.UTC),
								},
								{
									Sender:    state.NewIdentScreenName("33333333"),
									Recipient: state.NewIdentScreenName("11111111"),
									Message: wire.SNAC_0x04_0x06_ICBMChannelMsgToHost{
										ChannelID: wire.ICBMChannelICQ,
										TLVRestBlock: wire.TLVRestBlock{
											TLVList: wire.TLVList{
												wire.NewTLVBE(wire.ICBMTLVData, func() []byte {
													msg := wire.ICBMCh4Message{
														UIN:         33333333,
														MessageType: wire.ICBMExtendedMsgTypeAuthReq,
														Flags:       0,
														Message:     "please add me to your contacts list",
													}
													buf := &bytes.Buffer{}
													assert.NoError(t, wire.MarshalLE(msg, buf))
													return buf.Bytes()
												}()),
											},
										},
									},
									Sent: time.Date(2024, time.August, 1, 8, 2, 0, 0, time.UTC),
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x0041_DBQueryOfflineMsgReply{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryOfflineMsgReply,
														Seq:     1,
													},
													SenderUIN: 22222222,
													Year:      uint16(2024),
													Month:     uint8(8),
													Day:       uint8(2),
													Hour:      uint8(12),
													Minute:    uint8(5),
													MsgType:   wire.ICBMExtendedMsgTypePlain,
													Message:   "hello!",
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x0041_DBQueryOfflineMsgReply{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryOfflineMsgReply,
														Seq:     1,
													},
													SenderUIN: 33333333,
													Year:      uint16(2024),
													Month:     uint8(8),
													Day:       uint8(1),
													Hour:      uint8(8),
													Minute:    uint8(2),
													MsgType:   wire.ICBMExtendedMsgTypeAuthReq,
													Message:   "please add me to your contacts list",
												},
											}),
										},
									},
								},
							},
						},
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x0042_DBQueryOfflineMsgReplyLast{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryOfflineMsgReplyLast,
														Seq:     1,
													},
													DroppedMessages: 0,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offlineMessageManager := newMockOfflineMessageManager(t)
			for _, params := range tt.mockParams.retrieveMessagesParams {
				offlineMessageManager.EXPECT().
					RetrieveMessages(matchContext(), params.recipIn).
					Return(params.messagesOut, params.err)
			}
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := NewICQService(messageRelayer, nil, nil, slog.Default(), nil, offlineMessageManager)
			err := s.OfflineMsgReq(context.Background(), tt.sess, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_SetAffiliations(t *testing.T) {
	tests := []struct {
		name       string
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			seq:  1,
			sess: newTestSession("100003", sessOptUIN(100003)),
			req: wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations{
				PastAffiliations: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{
					{
						Code:    1,
						Keyword: "kw1",
					},
					{
						Code:    2,
						Keyword: "kw2",
					},
					{
						Code:    3,
						Keyword: "kw3",
					},
				},
				Affiliations: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{
					{
						Code:    4,
						Keyword: "kw4",
					},
					{
						Code:    5,
						Keyword: "kw5",
					},
					{
						Code:    6,
						Keyword: "kw6",
					},
				},
			},
			mockParams: mockParams{
				icqUserUpdaterParams: icqUserUpdaterParams{
					setAffiliationsParams: setAffiliationsParams{
						{
							name: state.NewIdentScreenName("100003"),
							data: state.ICQAffiliations{
								PastCode1:       1,
								PastKeyword1:    "kw1",
								PastCode2:       2,
								PastKeyword2:    "kw2",
								PastCode3:       3,
								PastKeyword3:    "kw3",
								CurrentCode1:    4,
								CurrentKeyword1: "kw4",
								CurrentCode2:    5,
								CurrentKeyword2: "kw5",
								CurrentCode3:    6,
								CurrentKeyword3: "kw6",
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     100003,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													ReqSubType: wire.ICQDBQueryMetaReplySetAffiliations,
													Success:    wire.ICQStatusCodeOK,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "err: unexpected affiliations count",
			seq:  1,
			sess: newTestSession("100003", sessOptUIN(100003)),
			req: wire.ICQ_0x07D0_0x041A_DBQueryMetaReqSetAffiliations{
				PastAffiliations: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{
					{
						Code:    1,
						Keyword: "kw1",
					},
				},
				Affiliations: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{
					{
						Code:    4,
						Keyword: "kw4",
					},
				},
			},
			wantErr: errICQBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userUpdater := newMockICQUserUpdater(t)
			for _, params := range tt.mockParams.setAffiliationsParams {
				userUpdater.EXPECT().
					SetAffiliations(matchContext(), params.name, params.data).
					Return(params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := ICQService{
				userUpdater:    userUpdater,
				messageRelayer: messageRelayer,
			}
			err := s.SetAffiliations(context.Background(), tt.sess, tt.req, tt.seq)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestICQService_SetEmails(t *testing.T) {
	tests := []struct {
		name       string
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x040B_DBQueryMetaReqSetEmails
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			seq:  1,
			sess: newTestSession("100003", sessOptUIN(100003)),
			req: wire.ICQ_0x07D0_0x040B_DBQueryMetaReqSetEmails{
				Emails: []struct {
					Publish uint8
					Email   string `oscar:"len_prefix=uint16,nullterm"`
				}{
					{
						Publish: 1,
						Email:   "test@aol.com",
					},
				},
			},
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     100003,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													ReqSubType: wire.ICQDBQueryMetaReplySetEmails,
													Success:    wire.ICQStatusCodeOK,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := ICQService{
				logger:         slog.Default(),
				messageRelayer: messageRelayer,
			}
			err := s.SetEmails(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_SetBasicInfo(t *testing.T) {
	tests := []struct {
		name       string
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			seq:  1,
			sess: newTestSession("100003", sessOptUIN(100003)),
			req: wire.ICQ_0x07D0_0x03EA_DBQueryMetaReqSetBasicInfo{
				CellPhone:    "123-456-7890",
				CountryCode:  1,
				EmailAddress: "test@example.com",
				FirstName:    "John",
				GMTOffset:    5,
				HomeAddress:  "123 Main St",
				City:         "Anytown",
				Fax:          "098-765-4321",
				Phone:        "111-222-3333",
				State:        "CA",
				LastName:     "Doe",
				Nickname:     "Johnny",
				PublishEmail: wire.ICQUserFlagPublishEmailYes,
				ZIP:          "12345",
			},
			mockParams: mockParams{
				icqUserUpdaterParams: icqUserUpdaterParams{
					setBasicInfoParams: setBasicInfoParams{
						{
							name: state.NewIdentScreenName("100003"),
							data: state.ICQBasicInfo{
								CellPhone:    "123-456-7890",
								CountryCode:  1,
								EmailAddress: "test@example.com",
								FirstName:    "John",
								GMTOffset:    5,
								Address:      "123 Main St",
								City:         "Anytown",
								Fax:          "098-765-4321",
								Phone:        "111-222-3333",
								State:        "CA",
								LastName:     "Doe",
								Nickname:     "Johnny",
								PublishEmail: true,
								ZIPCode:      "12345",
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     100003,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													ReqSubType: wire.ICQDBQueryMetaReplySetBasicInfo,
													Success:    wire.ICQStatusCodeOK,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userUpdater := newMockICQUserUpdater(t)
			for _, params := range tt.mockParams.setBasicInfoParams {
				userUpdater.EXPECT().
					SetBasicInfo(matchContext(), params.name, params.data).
					Return(params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := ICQService{
				userUpdater:    userUpdater,
				messageRelayer: messageRelayer,
			}
			err := s.SetBasicInfo(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_SetInterests(t *testing.T) {
	tests := []struct {
		name       string
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			seq:  1,
			sess: newTestSession("100003", sessOptUIN(100003)),
			req: wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests{
				Interests: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{
					{
						Code:    1,
						Keyword: "kw1",
					},
					{
						Code:    2,
						Keyword: "kw2",
					},
					{
						Code:    3,
						Keyword: "kw3",
					},
					{
						Code:    4,
						Keyword: "kw4",
					},
				},
			},
			mockParams: mockParams{
				icqUserUpdaterParams: icqUserUpdaterParams{
					setInterestsParams: setInterestsParams{
						{
							name: state.NewIdentScreenName("100003"),
							data: state.ICQInterests{
								Code1:    1,
								Keyword1: "kw1",
								Code2:    2,
								Keyword2: "kw2",
								Code3:    3,
								Keyword3: "kw3",
								Code4:    4,
								Keyword4: "kw4",
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     100003,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													ReqSubType: wire.ICQDBQueryMetaReplySetInterests,
													Success:    wire.ICQStatusCodeOK,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "err: unexpected interest count",
			seq:  1,
			sess: newTestSession("100003", sessOptUIN(100003)),
			req: wire.ICQ_0x07D0_0x0410_DBQueryMetaReqSetInterests{
				Interests: []struct {
					Code    uint16
					Keyword string `oscar:"len_prefix=uint16,nullterm"`
				}{
					{
						Code:    1,
						Keyword: "kw1",
					},
					{
						Code:    2,
						Keyword: "kw2",
					},
				},
			},
			wantErr: errICQBadRequest,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userUpdater := newMockICQUserUpdater(t)
			for _, params := range tt.mockParams.setInterestsParams {
				userUpdater.EXPECT().
					SetInterests(matchContext(), params.name, params.data).
					Return(params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := ICQService{
				userUpdater:    userUpdater,
				messageRelayer: messageRelayer,
			}
			err := s.SetInterests(context.Background(), tt.sess, tt.req, tt.seq)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestICQService_SetMoreInfo(t *testing.T) {
	tests := []struct {
		name       string
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			seq:  1,
			sess: newTestSession("100003", sessOptUIN(100003)),
			req: wire.ICQ_0x07D0_0x03FD_DBQueryMetaReqSetMoreInfo{
				Age:          0,
				BirthDay:     7,
				BirthMonth:   8,
				BirthYear:    1994,
				Gender:       1,
				HomePageAddr: "http://www.johndoe.com",
				Lang1:        1,
				Lang2:        2,
				Lang3:        3,
			},
			mockParams: mockParams{
				icqUserUpdaterParams: icqUserUpdaterParams{
					setMoreInfoParams: setMoreInfoParams{
						{
							name: state.NewIdentScreenName("100003"),
							data: state.ICQMoreInfo{
								BirthDay:     7,
								BirthMonth:   8,
								BirthYear:    1994,
								Gender:       1,
								HomePageAddr: "http://www.johndoe.com",
								Lang1:        1,
								Lang2:        2,
								Lang3:        3,
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     100003,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													ReqSubType: wire.ICQDBQueryMetaReplySetMoreInfo,
													Success:    wire.ICQStatusCodeOK,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userUpdater := newMockICQUserUpdater(t)
			for _, params := range tt.mockParams.setMoreInfoParams {
				userUpdater.EXPECT().
					SetMoreInfo(matchContext(), params.name, params.data).
					Return(params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := ICQService{
				userUpdater:    userUpdater,
				messageRelayer: messageRelayer,
			}
			err := s.SetMoreInfo(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_SetPermissions(t *testing.T) {
	tests := []struct {
		name       string
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			seq:  1,
			sess: newTestSession("100003", sessOptUIN(100003)),
			req:  wire.ICQ_0x07D0_0x0424_DBQueryMetaReqSetPermissions{},
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     100003,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													ReqSubType: wire.ICQDBQueryMetaReplySetPermissions,
													Success:    wire.ICQStatusCodeOK,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := ICQService{
				logger:         slog.Default(),
				messageRelayer: messageRelayer,
			}
			err := s.SetPermissions(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_SetUserNotes(t *testing.T) {
	tests := []struct {
		name       string
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			seq:  1,
			sess: newTestSession("100003", sessOptUIN(100003)),
			req: wire.ICQ_0x07D0_0x0406_DBQueryMetaReqSetNotes{
				Notes: "here is my note",
			},
			mockParams: mockParams{
				icqUserUpdaterParams: icqUserUpdaterParams{
					setUserNotesParams: setUserNotesParams{
						{
							name: state.NewIdentScreenName("100003"),
							data: state.ICQUserNotes{
								Notes: "here is my note",
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     100003,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													ReqSubType: wire.ICQDBQueryMetaReplySetNotes,
													Success:    wire.ICQStatusCodeOK,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userUpdater := newMockICQUserUpdater(t)
			for _, params := range tt.mockParams.setUserNotesParams {
				userUpdater.EXPECT().
					SetUserNotes(matchContext(), params.name, params.data).
					Return(params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := ICQService{
				userUpdater:    userUpdater,
				messageRelayer: messageRelayer,
			}
			err := s.SetUserNotes(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_SetWorkInfo(t *testing.T) {
	tests := []struct {
		name       string
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			seq:  1,
			sess: newTestSession("100003", sessOptUIN(100003)),
			req: wire.ICQ_0x07D0_0x03F3_DBQueryMetaReqSetWorkInfo{
				Company:        "TechCorp Inc.",
				Department:     "Engineering",
				OccupationCode: 1023,
				Position:       "Staff Software Engineer",
				Address:        "456 Technology Blvd",
				City:           "Innovate City",
				CountryCode:    1,
				Fax:            "987-654-3210",
				Phone:          "222-333-4444",
				State:          "CA",
				WebPage:        "http://www.techcorp.com",
				ZIP:            "67890",
			},
			mockParams: mockParams{
				icqUserUpdaterParams: icqUserUpdaterParams{
					setWorkInfoParams: setWorkInfoParams{
						{
							name: state.NewIdentScreenName("100003"),
							data: state.ICQWorkInfo{
								Company:        "TechCorp Inc.",
								Department:     "Engineering",
								OccupationCode: 1023,
								Position:       "Staff Software Engineer",
								Address:        "456 Technology Blvd",
								City:           "Innovate City",
								CountryCode:    1,
								Fax:            "987-654-3210",
								Phone:          "222-333-4444",
								State:          "CA",
								WebPage:        "http://www.techcorp.com",
								ZIPCode:        "67890",
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("100003"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x00DC_DBQueryMetaReplyMoreInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     100003,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													ReqSubType: wire.ICQDBQueryMetaReplySetWorkInfo,
													Success:    wire.ICQStatusCodeOK,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userUpdater := newMockICQUserUpdater(t)
			for _, params := range tt.mockParams.setWorkInfoParams {
				userUpdater.EXPECT().
					SetWorkInfo(matchContext(), params.name, params.data).
					Return(params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := ICQService{
				userUpdater:    userUpdater,
				messageRelayer: messageRelayer,
			}
			err := s.SetWorkInfo(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_ShortUserInfo(t *testing.T) {
	tests := []struct {
		name       string
		timeNow    func() time.Time
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x04BA_DBQueryMetaReqShortInfo
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x04BA_DBQueryMetaReqShortInfo{
				UIN: 123456789,
			},
			mockParams: mockParams{
				icqUserFinderParams: icqUserFinderParams{
					findByUINParams: findByUINParams{
						{
							UIN: 123456789,
							result: state.User{
								IdentScreenName: state.NewIdentScreenName("123456789"),
								ICQPermissions: state.ICQPermissions{
									AuthRequired: true,
								},
								ICQMoreInfo: state.ICQMoreInfo{
									Gender: 2,
								},
								ICQBasicInfo: state.ICQBasicInfo{
									EmailAddress: "john.doe@example.com",
									FirstName:    "John",
									LastName:     "Doe",
									Nickname:     "CoolUser123",
								},
							},
						},
					},
				},
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x0104_DBQueryMetaReplyShortInfo{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													Success:       wire.ICQStatusCodeOK,
													ReqSubType:    wire.ICQDBQueryMetaReplyShortInfo,
													Nickname:      "CoolUser123",
													FirstName:     "John",
													LastName:      "Doe",
													Email:         "john.doe@example.com",
													Authorization: 1,
													Gender:        2,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
				sessionRetrieverParams: sessionRetrieverParams{
					retrieveSessionParams{
						{
							screenName: state.NewIdentScreenName("123456789"),
							result:     &state.Session{},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userFinder := newMockICQUserFinder(t)
			for _, params := range tt.mockParams.findByUINParams {
				userFinder.EXPECT().
					FindByUIN(matchContext(), params.UIN).
					Return(params.result, params.err)
			}

			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}

			s := ICQService{
				messageRelayer: messageRelayer,
				timeNow:        tt.timeNow,
				userFinder:     userFinder,
			}
			err := s.ShortUserInfo(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}

func TestICQService_XMLReqData(t *testing.T) {
	tests := []struct {
		name       string
		timeNow    func() time.Time
		seq        uint16
		sess       *state.Session
		req        wire.ICQ_0x07D0_0x0898_DBQueryMetaReqXMLReq
		mockParams mockParams
		wantErr    error
	}{
		{
			name: "happy path",
			timeNow: func() time.Time {
				return time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
			},
			seq:  1,
			sess: newTestSession("11111111", sessOptUIN(11111111)),
			req: wire.ICQ_0x07D0_0x0898_DBQueryMetaReqXMLReq{
				XMLRequest: "<xml></xml>",
			},
			mockParams: mockParams{
				messageRelayerParams: messageRelayerParams{
					relayToScreenNameParams: relayToScreenNameParams{
						{
							screenName: state.NewIdentScreenName("11111111"),
							message: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.ICQ,
									SubGroup:  wire.ICQDBReply,
								},
								Body: wire.SNAC_0x15_0x02_DBReply{
									TLVRestBlock: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ICQTLVTagsMetadata, wire.ICQMessageReplyEnvelope{
												Message: wire.ICQ_0x07DA_0x08A2_DBQueryMetaReplyXMLData{
													ICQMetadata: wire.ICQMetadata{
														UIN:     11111111,
														ReqType: wire.ICQDBQueryMetaReply,
														Seq:     1,
													},
													ReqSubType: wire.ICQDBQueryMetaReplyXMLData,
													Success:    wire.ICQStatusCodeFail,
												},
											}),
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			messageRelayer := newMockMessageRelayer(t)
			for _, params := range tt.mockParams.relayToScreenNameParams {
				messageRelayer.EXPECT().RelayToScreenName(mock.Anything, params.screenName, params.message)
			}
			s := ICQService{
				messageRelayer: messageRelayer,
				timeNow:        tt.timeNow,
			}
			err := s.XMLReqData(context.Background(), tt.sess, tt.req, tt.seq)
			assert.NoError(t, err)
		})
	}
}
