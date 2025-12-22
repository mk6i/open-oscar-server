package toc

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/time/rate"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestOSCARProxy_NewServeMux(t *testing.T) {
	cookieBaker, err := state.NewHMACCookieBaker()
	assert.NoError(t, err)

	p := OSCARProxy{
		CookieBaker: cookieBaker,
		Logger:      slog.Default(),
	}
	cookie, err := p.newHTTPAuthToken(state.NewIdentScreenName("me"))
	assert.NoError(t, err)

	cases := []struct {
		// name is the unit test name
		name string
		// path is the HTTP request path
		path string
		// expectedStatus is the expected HTTP response code
		expectedStatus int
		// expectedBody is the expected body payload
		expectedBody string
		// mockParams is the list of params sent to mocks that satisfy this
		// method's dependencies
		mockParams mockParams
	}{
		{
			name:           "Successfully retrieve HTML profile",
			path:           "/info?from=me&user=them&cookie=" + cookie,
			expectedStatus: http.StatusOK,
			expectedBody:   `<font lang="0"><a href="aim:GoChat?RoomName=General&amp;Exchange=4">Let's chat</font></a><br><br><font color="#ff0000" lang="0">colorfg</font><font color="#000000"> </font><font back="#00ff00">colorbg</font><font> </font><font size="4">big</font><font size="3"> <b></font><font>bold</b></font><font> <i></font><font>italic</i></font><font> <u></font><font>underline</u></font><font> 8-)</font><hr><s>strike</s><sub>sub</sub><sup>sup</sup>`,
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								Type:       uint16(wire.LocateTypeSig),
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Locate,
									SubGroup:  wire.LocateUserInfoReply,
								},
								Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
									TLVUserInfo: newTestSession("them").TLVUserInfo(),
									LocateInfo: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, `"<HTML><BODY BGCOLOR="#ffffff"><FONT LANG="0"><A HREF="aim:GoChat?RoomName=General&Exchange=4">Let's chat</FONT></A><BR><BR><FONT COLOR="#ff0000" LANG="0">colorfg</FONT><FONT COLOR="#000000"> </FONT><FONT BACK="#00ff00">colorbg</FONT><FONT> </FONT><FONT SIZE=4>big</FONT><FONT SIZE=3> <B></FONT><FONT>bold</B></FONT><FONT> <I></FONT><FONT>italic</I></FONT><FONT> <U></FONT><FONT>underline</U></FONT><FONT> 8-)</FONT><HR><S>strike</S><SUB>sub</SUB><SUP>sup</SUP></BODY></HTML>"`),
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
			name:           "Successfully retrieve plaintext profile",
			path:           "/info?from=me&user=them&cookie=" + cookie,
			expectedStatus: http.StatusOK,
			expectedBody:   "My profile!",
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								Type:       uint16(wire.LocateTypeSig),
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Locate,
									SubGroup:  wire.LocateUserInfoReply,
								},
								Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
									TLVUserInfo: newTestSession("them").TLVUserInfo(),
									LocateInfo: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "My profile!"),
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
			name:           "Retrieve profile with missing `from` query param",
			path:           "/info?user=them&cookie=" + cookie,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "required `from` param is missing",
		},
		{
			name:           "Retrieve profile with missing `from` query param",
			path:           "/info?from=me&cookie=" + cookie,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "required `user` param is missing",
		},
		{
			name:           "Retrieve profile with missing `cookie` query param",
			path:           "/info?from=me&user=them",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "required `cookie` param is missing",
		},
		{
			name: "Retrieve profile with invalid auth cookie",
			path: func() string {
				return "/info?from=me&user=them&cookie=" + base64.URLEncoding.EncodeToString([]byte("blahblah"))
			}(),
			expectedStatus: http.StatusForbidden,
			expectedBody:   "invalid auth cookie",
		},
		{
			name:           "Retrieve profile, receive error from locate svc",
			path:           "/info?from=me&user=them&cookie=" + cookie,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error",
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								Type:       uint16(wire.LocateTypeSig),
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Locate,
									SubGroup:  wire.LocateUserInfoReply,
								},
								Body: wire.SNAC_0x02_0x06_LocateUserInfoReply{
									TLVUserInfo: newTestSession("them").TLVUserInfo(),
									LocateInfo: wire.TLVRestBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.LocateTLVTagsInfoSigData, "<HTML><BODY>My profile!</BODY></HTML>"),
										},
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
		},
		{
			name:           "Retrieve profile, receive unknown response from locate svc",
			path:           "/info?from=me&user=them&cookie=" + cookie,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error",
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								Type:       uint16(wire.LocateTypeSig),
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Locate,
									SubGroup:  wire.LocateUserInfoReply,
								},
								Body: wire.SNAC_0x04_0x09_ICBMEvilReply{},
							},
						},
					},
				},
			},
		},
		{
			name:           "Retrieve profile, user offline",
			path:           "/info?from=me&user=them&cookie=" + cookie,
			expectedStatus: http.StatusNotFound,
			expectedBody:   "user is unavailable",
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								Type:       uint16(wire.LocateTypeSig),
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Locate,
									SubGroup:  wire.LocateUserInfoReply,
								},
								Body: wire.SNACError{
									Code: wire.ErrorCodeNotLoggedOn,
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "Retrieve profile, receive error code from locate svc",
			path:           "/info?from=me&user=them&cookie=" + cookie,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error",
			mockParams: mockParams{
				locateParams: locateParams{
					userInfoQueryParams: userInfoQueryParams{
						{
							me: state.NewIdentScreenName("me"),
							inBody: wire.SNAC_0x02_0x05_LocateUserInfoQuery{
								Type:       uint16(wire.LocateTypeSig),
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Frame: wire.SNACFrame{
									FoodGroup: wire.Locate,
									SubGroup:  wire.LocateUserInfoReply,
								},
								Body: wire.SNACError{
									Code: wire.ErrorCodeInvalidSnac,
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "Successfully retrieve directory info",
			path:           "/dir_info?user=them&cookie=" + cookie,
			expectedStatus: http.StatusOK,
			expectedBody:   "their_first_name",
			mockParams: mockParams{
				locateParams: locateParams{
					dirInfoParams: dirInfoParams{
						{
							body: wire.SNAC_0x02_0x0B_LocateGetDirInfo{
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{
									Status: wire.LocateGetDirReplyOK,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ODirTLVFirstName, "their_first_name"),
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
			name:           "Retrieve directory info, no results found",
			path:           "/dir_info?user=them&cookie=" + cookie,
			expectedStatus: http.StatusNotFound,
			expectedBody:   "no user directory info found",
			mockParams: mockParams{
				locateParams: locateParams{
					dirInfoParams: dirInfoParams{
						{
							body: wire.SNAC_0x02_0x0B_LocateGetDirInfo{
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{
									Status: wire.LocateGetDirReplyOK,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "Retrieve directory info, unexpected response from locate svc",
			path:           "/dir_info?user=them&cookie=" + cookie,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error",
			mockParams: mockParams{
				locateParams: locateParams{
					dirInfoParams: dirInfoParams{
						{
							body: wire.SNAC_0x02_0x0B_LocateGetDirInfo{
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNACError{},
							},
						},
					},
				},
			},
		},
		{
			name:           "Search directory with missing `user` query param",
			path:           "/dir_info?cookie=" + cookie,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "required `user` param is missing",
		},
		{
			name:           "Retrieve directory info, receive err from locate svc",
			path:           "/dir_info?user=them&cookie=" + cookie,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error",
			mockParams: mockParams{
				locateParams: locateParams{
					dirInfoParams: dirInfoParams{
						{
							body: wire.SNAC_0x02_0x0B_LocateGetDirInfo{
								ScreenName: "them",
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x02_0x0C_LocateGetDirReply{
									Status: wire.LocateGetDirReplyOK,
									TLVBlock: wire.TLVBlock{
										TLVList: wire.TLVList{
											wire.NewTLVBE(wire.ODirTLVFirstName, "their_first_name"),
										},
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
		},
		{
			name: "Successfully search directory by name and address",
			path: "/dir_search?first_name=their_first_name" +
				"&middle_name=their_middle_name" +
				"&last_name=their_last_name" +
				"&maiden_name=their_maiden_name" +
				"&city=their_city" +
				"&state=their_state" +
				"&country=their_country" +
				"&cookie=" + cookie,
			expectedStatus: http.StatusOK,
			expectedBody:   "their_first_name",
			mockParams: mockParams{
				dirSearchParams: dirSearchParams{
					infoQueryParams: infoQueryParams{
						{
							inBody: wire.SNAC_0x0F_0x02_InfoQuery{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ODirTLVFirstName, "their_first_name"),
										wire.NewTLVBE(wire.ODirTLVMiddleName, "their_middle_name"),
										wire.NewTLVBE(wire.ODirTLVLastName, "their_last_name"),
										wire.NewTLVBE(wire.ODirTLVMaidenName, "their_maiden_name"),
										wire.NewTLVBE(wire.ODirTLVCity, "their_city"),
										wire.NewTLVBE(wire.ODirTLVState, "their_state"),
										wire.NewTLVBE(wire.ODirTLVCountry, "their_country"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x0F_0x03_InfoReply{
									Status: wire.ODirSearchResponseOK,
									Results: struct {
										List []wire.TLVBlock `oscar:"count_prefix=uint16"`
									}{
										List: []wire.TLVBlock{
											{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ODirTLVFirstName, "their_first_name"),
												},
											},
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
			name:           "Successfully search directory by email",
			path:           "/dir_search?email=their_email@aol.com&cookie=" + cookie,
			expectedStatus: http.StatusOK,
			expectedBody:   "their_first_name",
			mockParams: mockParams{
				dirSearchParams: dirSearchParams{
					infoQueryParams: infoQueryParams{
						{
							inBody: wire.SNAC_0x0F_0x02_InfoQuery{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ODirTLVEmailAddress, "their_email@aol.com"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x0F_0x03_InfoReply{
									Status: wire.ODirSearchResponseOK,
									Results: struct {
										List []wire.TLVBlock `oscar:"count_prefix=uint16"`
									}{
										List: []wire.TLVBlock{
											{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ODirTLVFirstName, "their_first_name"),
												},
											},
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
			name:           "Successfully search directory by keyword",
			path:           "/dir_search?keyword=their_keyword&cookie=" + cookie,
			expectedStatus: http.StatusOK,
			expectedBody:   "their_first_name",
			mockParams: mockParams{
				dirSearchParams: dirSearchParams{
					infoQueryParams: infoQueryParams{
						{
							inBody: wire.SNAC_0x0F_0x02_InfoQuery{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ODirTLVInterest, "their_keyword"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x0F_0x03_InfoReply{
									Status: wire.ODirSearchResponseOK,
									Results: struct {
										List []wire.TLVBlock `oscar:"count_prefix=uint16"`
									}{
										List: []wire.TLVBlock{
											{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ODirTLVFirstName, "their_first_name"),
												},
											},
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
			name:           "Search directory by email, receive err from dir search svc",
			path:           "/dir_search?email=their_email@aol.com&cookie=" + cookie,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error",
			mockParams: mockParams{
				dirSearchParams: dirSearchParams{
					infoQueryParams: infoQueryParams{
						{
							inBody: wire.SNAC_0x0F_0x02_InfoQuery{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ODirTLVEmailAddress, "their_email@aol.com"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x0F_0x03_InfoReply{
									Status: wire.ODirSearchResponseOK,
									Results: struct {
										List []wire.TLVBlock `oscar:"count_prefix=uint16"`
									}{
										List: []wire.TLVBlock{
											{
												TLVList: wire.TLVList{
													wire.NewTLVBE(wire.ODirTLVFirstName, "their_first_name"),
												},
											},
										},
									},
								},
							},
							err: io.EOF,
						},
					},
				},
			},
		},
		{
			name:           "Search directory by email, receive unknown response from dir search svc",
			path:           "/dir_search?email=their_email@aol.com&cookie=" + cookie,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error",
			mockParams: mockParams{
				dirSearchParams: dirSearchParams{
					infoQueryParams: infoQueryParams{
						{
							inBody: wire.SNAC_0x0F_0x02_InfoQuery{
								TLVRestBlock: wire.TLVRestBlock{
									TLVList: wire.TLVList{
										wire.NewTLVBE(wire.ODirTLVEmailAddress, "their_email@aol.com"),
									},
								},
							},
							msg: wire.SNACMessage{
								Body: wire.SNACError{},
							},
						},
					},
				},
			},
		},
		{
			name:           "Search directory without any correct search parameters",
			path:           "/dir_search?cookie=" + cookie,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "missing search parameters",
			mockParams: mockParams{
				dirSearchParams: dirSearchParams{
					infoQueryParams: infoQueryParams{
						{
							inBody: wire.SNAC_0x0F_0x02_InfoQuery{},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x0F_0x03_InfoReply{
									Status: wire.ODirSearchResponseNameMissing,
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "Search directory, receive error code from search dir svc",
			path:           "/dir_search?cookie=" + cookie,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error",
			mockParams: mockParams{
				dirSearchParams: dirSearchParams{
					infoQueryParams: infoQueryParams{
						{
							inBody: wire.SNAC_0x0F_0x02_InfoQuery{},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x0F_0x03_InfoReply{
									Status: wire.ODirSearchResponseUnavailable1,
								},
							},
						},
					},
				},
			},
		},
		{
			name:           "Search directory, receive unknown response from search dir svc",
			path:           "/dir_search?cookie=" + cookie,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   "internal server error",
			mockParams: mockParams{
				dirSearchParams: dirSearchParams{
					infoQueryParams: infoQueryParams{
						{
							inBody: wire.SNAC_0x0F_0x02_InfoQuery{},
							msg: wire.SNACMessage{
								Body: wire.SNAC_0x0F_0x03_InfoReply{
									Status: wire.ODirSearchResponseUnavailable1,
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
			locateSvc := newMockLocateService(t)
			for _, params := range tc.mockParams.userInfoQueryParams {
				locateSvc.EXPECT().
					UserInfoQuery(mock.Anything, matchSession(params.me), wire.SNACFrame{}, params.inBody).
					Return(params.msg, params.err)
			}
			for _, params := range tc.mockParams.dirInfoParams {
				locateSvc.EXPECT().
					DirInfo(mock.Anything, wire.SNACFrame{}, params.body).
					Return(params.msg, params.err)
			}
			dirSearchSvc := newMockDirSearchService(t)
			for _, params := range tc.mockParams.infoQueryParams {
				dirSearchSvc.EXPECT().
					InfoQuery(mock.Anything, wire.SNACFrame{}, params.inBody).
					Return(params.msg, params.err)
			}

			svc := OSCARProxy{
				CookieBaker:       cookieBaker,
				DirSearchService:  dirSearchSvc,
				LocateService:     locateSvc,
				Logger:            slog.Default(),
				HTTPIPRateLimiter: NewIPRateLimiter(rate.Every(1*time.Minute), 10, 1*time.Minute),
				SNACRateLimits:    wire.DefaultSNACRateLimits(),
			}

			req, err := http.NewRequest(http.MethodGet, tc.path, nil)
			req.RemoteAddr = "127.0.0.1:1234"
			if err != nil {
				t.Fatalf("Failed to create request: %v", err)
			}

			rr := httptest.NewRecorder()

			svc.NewServeMux().ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			assert.Contains(t, rr.Body.String(), tc.expectedBody)
		})
	}
}
