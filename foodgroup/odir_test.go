package foodgroup

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestODirService_KeywordListQuery(t *testing.T) {
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
			name: "get full list",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirKeywordListReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x04_KeywordListReply{
					Status: 0x01,
					Interests: []wire.ODirKeywordListItem{
						{
							ID:   0,
							Name: "Animals",
							Type: wire.ODirKeyword,
						},
						{
							ID:   1,
							Name: "Music",
							Type: wire.ODirKeywordCategory,
						},
						{
							ID:   1,
							Name: "Rock",
							Type: wire.ODirKeyword,
						},
						{
							ID:   1,
							Name: "Jazz",
							Type: wire.ODirKeyword,
						},
					},
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					interestListParams: interestListParams{
						{
							result: []wire.ODirKeywordListItem{
								{
									ID:   0,
									Name: "Animals",
									Type: wire.ODirKeyword,
								},
								{
									ID:   1,
									Name: "Music",
									Type: wire.ODirKeywordCategory,
								},
								{
									ID:   1,
									Name: "Rock",
									Type: wire.ODirKeyword,
								},
								{
									ID:   1,
									Name: "Jazz",
									Type: wire.ODirKeyword,
								},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profileManager := newMockProfileManager(t)
			for _, params := range tc.mockParams.interestListParams {
				profileManager.EXPECT().
					InterestList(matchContext()).
					Return(params.result, params.err)
			}

			svc := NewODirService(slog.Default(), profileManager)
			actual, err := svc.KeywordListQuery(context.Background(), tc.inputSNAC.Frame)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectOutput, actual)
		})
	}
}

func TestODirService_InfoQuery(t *testing.T) {
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
			name: "search by name and address - results found",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x02_InfoQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVFirstName, "joe"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirInfoReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x03_InfoReply{
					Status: wire.ODirSearchResponseOK,
					Results: struct {
						List []wire.TLVBlock `oscar:"count_prefix=uint16"`
					}{List: []wire.TLVBlock{
						{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.ODirTLVFirstName, "Joe"),
								wire.NewTLVBE(wire.ODirTLVLastName, "Doe"),
								wire.NewTLVBE(wire.ODirTLVState, "California"),
								wire.NewTLVBE(wire.ODirTLVCity, "Los Angeles"),
								wire.NewTLVBE(wire.ODirTLVCountry, "USA"),
								wire.NewTLVBE(wire.ODirTLVScreenName, "joe123"),
							},
						},
						{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.ODirTLVFirstName, "Joe"),
								wire.NewTLVBE(wire.ODirTLVLastName, "Smith"),
								wire.NewTLVBE(wire.ODirTLVState, "New York"),
								wire.NewTLVBE(wire.ODirTLVCity, "New York City"),
								wire.NewTLVBE(wire.ODirTLVCountry, "USA"),
								wire.NewTLVBE(wire.ODirTLVScreenName, "joe321"),
							},
						},
					}},
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					findByAIMNameAndAddrParams: findByAIMNameAndAddrParams{
						{
							info: state.AIMNameAndAddr{
								FirstName: "joe",
							},
							result: []state.User{
								{
									DisplayScreenName: "joe123",
									AIMDirectoryInfo: state.AIMNameAndAddr{
										FirstName: "Joe",
										LastName:  "Doe",
										Country:   "USA",
										State:     "California",
										City:      "Los Angeles",
									},
								},
								{
									DisplayScreenName: "joe321",
									AIMDirectoryInfo: state.AIMNameAndAddr{
										FirstName: "Joe",
										LastName:  "Smith",
										Country:   "USA",
										State:     "New York",
										City:      "New York City",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "search by name and address - no results found",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x02_InfoQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVFirstName, "joe"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirInfoReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x03_InfoReply{
					Status: wire.ODirSearchResponseOK,
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					findByAIMNameAndAddrParams: findByAIMNameAndAddrParams{
						{
							info: state.AIMNameAndAddr{
								FirstName: "joe",
							},
							result: []state.User{},
						},
					},
				},
			},
		},
		{
			name: "search by name and address - no first or last name",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x02_InfoQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVCity, "new york"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirInfoReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x03_InfoReply{
					Status: wire.ODirSearchResponseNameMissing,
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					findByAIMNameAndAddrParams: findByAIMNameAndAddrParams{},
				},
			},
		},
		{
			name: "search by email - results found",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x02_InfoQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVEmailAddress, "test@aol.com"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirInfoReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x03_InfoReply{
					Status: wire.ODirSearchResponseOK,
					Results: struct {
						List []wire.TLVBlock `oscar:"count_prefix=uint16"`
					}{List: []wire.TLVBlock{
						{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.ODirTLVFirstName, "Joe"),
								wire.NewTLVBE(wire.ODirTLVLastName, "Doe"),
								wire.NewTLVBE(wire.ODirTLVState, "California"),
								wire.NewTLVBE(wire.ODirTLVCity, "Los Angeles"),
								wire.NewTLVBE(wire.ODirTLVCountry, "USA"),
								wire.NewTLVBE(wire.ODirTLVScreenName, "joe123"),
							},
						},
					}},
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					findByAIMEmailParams: findByAIMEmailParams{
						{
							email: "test@aol.com",
							result: state.User{
								DisplayScreenName: "joe123",
								AIMDirectoryInfo: state.AIMNameAndAddr{
									FirstName: "Joe",
									LastName:  "Doe",
									Country:   "USA",
									State:     "California",
									City:      "Los Angeles",
								},
							},
						},
					},
				},
			},
		},
		{
			name: "search by email - no results found",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x02_InfoQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVEmailAddress, "test@aol.com"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirInfoReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x03_InfoReply{
					Status: wire.ODirSearchResponseOK,
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					findByAIMEmailParams: findByAIMEmailParams{
						{
							email: "test@aol.com",
							err:   state.ErrNoUser,
						},
					},
				},
			},
		},
		{
			name: "search by interest - results found",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x02_InfoQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVInterest, "Computers"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirInfoReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x03_InfoReply{
					Status: wire.ODirSearchResponseOK,
					Results: struct {
						List []wire.TLVBlock `oscar:"count_prefix=uint16"`
					}{List: []wire.TLVBlock{
						{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.ODirTLVFirstName, "Joe"),
								wire.NewTLVBE(wire.ODirTLVLastName, "Doe"),
								wire.NewTLVBE(wire.ODirTLVState, "California"),
								wire.NewTLVBE(wire.ODirTLVCity, "Los Angeles"),
								wire.NewTLVBE(wire.ODirTLVCountry, "USA"),
								wire.NewTLVBE(wire.ODirTLVScreenName, "joe123"),
							},
						},
						{
							TLVList: wire.TLVList{
								wire.NewTLVBE(wire.ODirTLVFirstName, "Joe"),
								wire.NewTLVBE(wire.ODirTLVLastName, "Smith"),
								wire.NewTLVBE(wire.ODirTLVState, "New York"),
								wire.NewTLVBE(wire.ODirTLVCity, "New York City"),
								wire.NewTLVBE(wire.ODirTLVCountry, "USA"),
								wire.NewTLVBE(wire.ODirTLVScreenName, "joe321"),
							},
						},
					}},
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					findByAIMKeywordParams: findByAIMKeywordParams{
						{
							keyword: "Computers",
							result: []state.User{
								{
									DisplayScreenName: "joe123",
									AIMDirectoryInfo: state.AIMNameAndAddr{
										FirstName: "Joe",
										LastName:  "Doe",
										Country:   "USA",
										State:     "California",
										City:      "Los Angeles",
									},
								},
								{
									DisplayScreenName: "joe321",
									AIMDirectoryInfo: state.AIMNameAndAddr{
										FirstName: "Joe",
										LastName:  "Smith",
										Country:   "USA",
										State:     "New York",
										City:      "New York City",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "search by interest - no results found",
			inputSNAC: wire.SNACMessage{
				Frame: wire.SNACFrame{
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x02_InfoQuery{
					TLVRestBlock: wire.TLVRestBlock{
						TLVList: wire.TLVList{
							wire.NewTLVBE(wire.ODirTLVInterest, "Computers"),
						},
					},
				},
			},
			expectOutput: wire.SNACMessage{
				Frame: wire.SNACFrame{
					FoodGroup: wire.ODir,
					SubGroup:  wire.ODirInfoReply,
					RequestID: 1234,
				},
				Body: wire.SNAC_0x0F_0x03_InfoReply{
					Status: wire.ODirSearchResponseOK,
				},
			},
			mockParams: mockParams{
				profileManagerParams: profileManagerParams{
					findByAIMKeywordParams: findByAIMKeywordParams{
						{
							keyword: "Computers",
							result:  []state.User{},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profileManager := newMockProfileManager(t)
			for _, params := range tc.mockParams.findByAIMNameAndAddrParams {
				profileManager.EXPECT().
					FindByAIMNameAndAddr(matchContext(), params.info).
					Return(params.result, params.err)
			}
			for _, params := range tc.mockParams.findByAIMEmailParams {
				profileManager.EXPECT().
					FindByAIMEmail(matchContext(), params.email).
					Return(params.result, params.err)
			}
			for _, params := range tc.mockParams.findByAIMKeywordParams {
				profileManager.EXPECT().
					FindByAIMKeyword(matchContext(), params.keyword).
					Return(params.result, params.err)
			}

			svc := NewODirService(slog.Default(), profileManager)
			actual, err := svc.InfoQuery(context.Background(), tc.inputSNAC.Frame, tc.inputSNAC.Body.(wire.SNAC_0x0F_0x02_InfoQuery))
			assert.NoError(t, err)
			assert.Equal(t, tc.expectOutput, actual)
		})
	}
}
