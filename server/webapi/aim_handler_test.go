package webapi

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

func TestBuildMyInfo_UserType(t *testing.T) {
	tests := []struct {
		name       string
		screenName string
		wantType   string
	}{
		{"aim screen name", "mikekelly", "aim"},
		{"icq uin", "123456789", "icq"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := buildMyInfo(state.DisplayScreenName(tt.screenName), "online", "", "")
			assert.Equal(t, tt.wantType, mi.UserType)
		})
	}
}

func TestBuildMyInfo_BuddyIcon(t *testing.T) {
	t.Run("included when set", func(t *testing.T) {
		mi := buildMyInfo(state.DisplayScreenName("mikekelly"), "away", "http://x/icon", "")
		assert.Equal(t, "http://x/icon", mi.BuddyIcon)
	})
	t.Run("omitted when empty so the client merge preserves the current icon", func(t *testing.T) {
		mi := buildMyInfo(state.DisplayScreenName("mikekelly"), "away", "", "")
		assert.Empty(t, mi.BuddyIcon)

		// omitempty is what actually keeps it out of the payload.
		body, err := json.Marshal(mi)
		assert.NoError(t, err)
		assert.NotContains(t, string(body), "buddyIcon")
	})
}

func TestAimHandler_AddTempBuddy(t *testing.T) {
	tests := []struct {
		name               string
		queryParams        map[string][]string
		respond            func(req wire.SNACMessage) []wire.SNACMessage
		sendErr            error
		limited            bool
		wantSent           []any
		expectedStatusCode int
		expectedResponse   string
	}{
		{
			name: "Success_SingleBuddy",
			queryParams: map[string][]string{
				"aimsid": {"aimsid-1"},
				"t":      {"buddy1"},
			},
			wantSent:           []any{tempBuddiesSNAC("buddy1")},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name: "Success_MultipleBuddies",
			queryParams: map[string][]string{
				"aimsid": {"aimsid-1"},
				"t":      {"buddy1", "buddy2", "buddy3"},
			},
			wantSent:           []any{tempBuddiesSNAC("buddy1", "buddy2", "buddy3")},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name: "Success_WhitespaceTrimmed",
			queryParams: map[string][]string{
				"aimsid": {"aimsid-1"},
				"t":      {"  buddy1  ", "", "buddy2 "},
			},
			wantSent:           []any{tempBuddiesSNAC("buddy1", "buddy2")},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name: "Success_RejectionIsNotReportedToTheClient",
			queryParams: map[string][]string{
				"aimsid": {"aimsid-1"},
				"t":      {"buddy1", "100000"},
			},
			respond: func(req wire.SNACMessage) []wire.SNACMessage {
				return []wire.SNACMessage{reply(wire.Buddy, wire.BuddyRejectNotification,
					wire.SNAC_0x03_0x0A_BuddyRejectNotification{
						Buddies: []struct {
							ScreenName string `oscar:"len_prefix=uint8"`
						}{
							{ScreenName: "100000"},
						},
					})}
			},
			wantSent:           []any{tempBuddiesSNAC("buddy1", "100000")},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name: "Success_CommaSeparatedList",
			queryParams: map[string][]string{
				"aimsid": {"aimsid-1"},
				"t":      {"buddy1,buddy2", "buddy3"},
			},
			wantSent:           []any{tempBuddiesSNAC("buddy1", "buddy2", "buddy3")},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name: "Error_MissingBuddyNames",
			queryParams: map[string][]string{
				"aimsid": {"aimsid-1"},
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy names (t parameter)","data":{}}}`,
		},
		{
			name: "Error_SendFailure",
			queryParams: map[string][]string{
				"aimsid": {"aimsid-1"},
				"t":      {"buddy1"},
			},
			sendErr:            io.ErrUnexpectedEOF,
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse:   `{"response":{"statusCode":500,"statusText":"unable to add temporary buddies","data":{}}}`,
		},
		{
			name: "Error_RateLimited",
			queryParams: map[string][]string{
				"aimsid": {"aimsid-1"},
				"t":      {"buddy1"},
			},
			limited:            true,
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":430,"statusText":"rate limit exceeded","data":{}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn().answering(tt.respond)
			conn.sendErr = tt.sendErr
			session := newTestSession(t, conn)
			if tt.limited {
				limitRateClass(session, wire.Buddy, wire.BuddyAddTempBuddies)
			}

			handler := &AimHandler{
				Logger: slog.Default(),
			}

			values := url.Values{}
			for key, vals := range tt.queryParams {
				for _, val := range vals {
					values.Add(key, val)
				}
			}
			req := httptest.NewRequest(http.MethodGet, "/aim/addTempBuddy?"+values.Encode(), nil)

			rr := httptest.NewRecorder()
			handler.AddTempBuddy(rr, req, session)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			assert.JSONEq(t, tt.expectedResponse, rr.Body.String())
			assert.Equal(t, tt.wantSent, conn.sentOf(wire.Buddy, wire.BuddyAddTempBuddies))
		})
	}
}

func TestAimHandler_RemoveTempBuddy(t *testing.T) {
	tests := []struct {
		name               string
		query              string
		sendErr            error
		wantSent           []any
		expectedStatusCode int
		expectedResponse   string
	}{
		{
			name:  "Success",
			query: "aimsid=aimsid-1&t=buddy1&t=+buddy2+&t=",
			wantSent: []any{wire.SNAC_0x03_0x10_BuddyDelTempBuddies{
				Buddies: []struct {
					ScreenName string `oscar:"len_prefix=uint8"`
				}{
					{ScreenName: "buddy1"},
					{ScreenName: "buddy2"},
				},
			}},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{}}}`,
		},
		{
			name:               "Error_MissingBuddyNames",
			query:              "aimsid=aimsid-1",
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy names (t parameter)","data":{}}}`,
		},
		{
			name:               "Error_SendFailure",
			query:              "aimsid=aimsid-1&t=buddy1",
			sendErr:            io.ErrUnexpectedEOF,
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse:   `{"response":{"statusCode":500,"statusText":"unable to remove temporary buddies","data":{}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newFakeConn()
			conn.sendErr = tt.sendErr
			session := newTestSession(t, conn)

			handler := &AimHandler{
				Logger: slog.Default(),
			}

			req := httptest.NewRequest(http.MethodGet, "/aim/removeTempBuddy?"+tt.query, nil)

			rr := httptest.NewRecorder()
			handler.RemoveTempBuddy(rr, req, session)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			assert.JSONEq(t, tt.expectedResponse, rr.Body.String())
			assert.Equal(t, tt.wantSent, conn.sentOf(wire.Buddy, wire.BuddyDelTempBuddies))
		})
	}
}

func TestAimHandler_AddTempBuddy_RejectsOversizedList(t *testing.T) {
	conn := newFakeConn()
	session := newTestSession(t, conn)

	names := make([]string, 0, maxTempBuddies+1)
	for i := range cap(names) {
		names = append(names, fmt.Sprintf("buddy%d", i))
	}

	handler := &AimHandler{
		Logger: slog.Default(),
	}

	values := url.Values{"aimsid": {"aimsid-1"}, "t": names}
	req := httptest.NewRequest(http.MethodGet, "/aim/addTempBuddy?"+values.Encode(), nil)

	rr := httptest.NewRecorder()
	handler.AddTempBuddy(rr, req, session)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.JSONEq(t, `{"response":{"statusCode":400,"statusText":"too many buddy names (max 160)","data":{}}}`, rr.Body.String())
	// an oversized list is rejected before anything reaches the OSCAR server
	assert.Empty(t, conn.sentSNACs())
}

// tempBuddiesSNAC builds the add-temp-buddies SNAC the handler is expected to
// hand the buddy service.
func tempBuddiesSNAC(screenNames ...string) wire.SNAC_0x03_0x0F_BuddyAddTempBuddies {
	snac := wire.SNAC_0x03_0x0F_BuddyAddTempBuddies{}
	for _, screenName := range screenNames {
		snac.Buddies = append(snac.Buddies, struct {
			ScreenName string `oscar:"len_prefix=uint8"`
		}{ScreenName: screenName})
	}
	return snac
}

// testListener is a listener group whose SSL half is present only when the
// test asks for it.
func testListener(sslAvailable bool) config.ListenerGroup {
	g := config.ListenerGroup{
		Name:                   "local",
		BOSListenAddress:       "0.0.0.0:5190",
		BOSAdvertisedHostPlain: "bos.example.com:5190",
	}
	if sslAvailable {
		g.BOSListenAddressSSL = "0.0.0.0:5191"
		g.BOSAdvertisedHostSSL = "ssl.example.com:5193"
	}
	return g
}

// bridgeRequest builds a startOSCARSession request.
func bridgeRequest(query string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "/aim/startOSCARSession?"+query, nil)
}

// bridgeData is the data object of a successful startOSCARSession response.
type bridgeData struct {
	Response struct {
		StatusCode int `json:"statusCode"`
		Data       struct {
			Host        string `json:"host"`
			Port        int    `json:"port"`
			Cookie      string `json:"cookie"`
			TLSCertName string `json:"tlsCertName"`
		} `json:"data"`
	} `json:"response"`
}

func TestAimHandler_StartOSCARSession(t *testing.T) {
	validToken := base64.URLEncoding.EncodeToString(signedCookieFor("testuser"))

	tests := []struct {
		name         string
		query        string
		sslAvailable bool
		expectedCode int
		checkBody    func(t *testing.T, body string)
	}{
		{
			// No tlsCertName, which is how the client reads "connect in the clear".
			name:         "Success_Plaintext",
			query:        "a=" + validToken,
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				got := decodeBridgeData(t, body)
				assert.Equal(t, 200, got.Response.StatusCode)
				assert.Equal(t, "bos.example.com", got.Response.Data.Host)
				assert.Equal(t, 5190, got.Response.Data.Port)
				assert.Empty(t, got.Response.Data.TLSCertName)
			},
		},
		{
			name:         "Success_TLS",
			query:        "a=" + validToken + "&useTLS=1",
			sslAvailable: true,
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				got := decodeBridgeData(t, body)
				assert.Equal(t, "ssl.example.com", got.Response.Data.Host)
				assert.Equal(t, 5193, got.Response.Data.Port)
				// The certificate is issued to the host the client is sent to.
				assert.Equal(t, "ssl.example.com", got.Response.Data.TLSCertName)
			},
		},
		{
			// Encryption the server cannot provide degrades to a plaintext host
			// rather than failing the handoff.
			name:         "TLSRequestedButUnavailable_DegradesToPlaintext",
			query:        "a=" + validToken + "&useTLS=true",
			sslAvailable: false,
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				got := decodeBridgeData(t, body)
				assert.Equal(t, "bos.example.com", got.Response.Data.Host)
				assert.Empty(t, got.Response.Data.TLSCertName)
			},
		},
		{
			name:         "Error_MissingToken",
			query:        "",
			expectedCode: http.StatusUnauthorized,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "authentication token required")
			},
		},
		{
			name:         "Error_TokenNotBase64",
			query:        "a=not!valid!base64",
			expectedCode: http.StatusUnauthorized,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid or expired token")
			},
		},
		{
			// A well-formed token the baker refuses to crack: wrong signature or
			// past its expiry.
			name:         "Error_TokenFailsSignatureCheck",
			query:        "a=" + base64.URLEncoding.EncodeToString([]byte("forged")),
			expectedCode: http.StatusUnauthorized,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid or expired token")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &AimHandler{
				AuthService: &testAuthService{crackCookie: crackSignedCookie},
				BOSListener: testListener(tt.sslAvailable),
				Logger:      slog.Default(),
			}

			rr := httptest.NewRecorder()
			handler.StartOSCARSession(rr, bridgeRequest(tt.query))

			assert.Equal(t, tt.expectedCode, rr.Code)
			tt.checkBody(t, rr.Body.String())
		})
	}
}

// The token arrives URL-safe, the way clientLogin minted it, and goes back out in
// standard base64, the alphabet the client decodes the sign-on cookie with. The
// cookie bytes here encode differently under each.
func TestAimHandler_StartOSCARSession_ReencodesCookie(t *testing.T) {
	rawCookie := []byte{0xff, 0xef, 0xbe}
	urlSafe := base64.URLEncoding.EncodeToString(rawCookie)
	standard := base64.StdEncoding.EncodeToString(rawCookie)
	assert.NotEqual(t, urlSafe, standard, "test cookie must distinguish the two alphabets")

	var cracked []byte
	handler := &AimHandler{
		AuthService: &testAuthService{
			crackCookie: func(authCookie []byte) (state.ServerCookie, time.Time, error) {
				cracked = authCookie
				return state.ServerCookie{ScreenName: "testuser"}, time.Now().Add(shortTermTTL), nil
			},
		},
		BOSListener: testListener(false),
		Logger:      slog.Default(),
	}

	rr := httptest.NewRecorder()
	handler.StartOSCARSession(rr, bridgeRequest("a="+urlSafe))

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, rawCookie, cracked, "the baker sees the decoded cookie")
	assert.Equal(t, standard, decodeBridgeData(t, rr.Body.String()).Response.Data.Cookie)
}

func decodeBridgeData(t *testing.T, body string) bridgeData {
	t.Helper()
	got := bridgeData{}
	assert.NoError(t, json.Unmarshal([]byte(body), &got))
	return got
}

// The monitor broadcasts transitions, not current state, so without a seed a
// session signing on mid-limit shows no banner while its sends are rejected — and
// the client's alert is sticky, so the eventual "clear" has nothing to dismiss.
func TestSeedRateLimitAlert(t *testing.T) {
	imClass, ok := wire.DefaultSNACRateLimits().RateClassLookup(wire.ICBM, wire.ICBMChannelMsgToHost)
	require.True(t, ok)

	// limitedSession returns a session that signed on to an account whose IM
	// class is limited.
	limitedSession := func(t *testing.T) *Session {
		t.Helper()
		session := newTestSession(t, newFakeConn())
		limitRateClass(session, wire.ICBM, wire.ICBMChannelMsgToHost)
		return session
	}

	t.Run("a session starting on a limited account is told", func(t *testing.T) {
		session := limitedSession(t)

		seedRateLimitAlert(session, imClass)

		assert.Equal(t, []string{"limit"}, rateLimitEventStatuses(t, session))
	})

	t.Run("a session starting on a clear account is told nothing", func(t *testing.T) {
		session := newTestSession(t, newFakeConn())

		seedRateLimitAlert(session, imClass)

		assert.Empty(t, rateLimitEventStatuses(t, session))
	})

	t.Run("a zero class id disables the alert", func(t *testing.T) {
		session := limitedSession(t)

		seedRateLimitAlert(session, 0)

		assert.Empty(t, rateLimitEventStatuses(t, session))
	})
}

// A temp buddy stops being watched the moment it is removed, so no departure for
// it ever arrives and its cached presence would otherwise be served forever. This
// is the most reachable form of that bug: add a temp buddy, remove it, and the
// target's state is frozen at whatever it was when they were last observed.
func TestAimHandler_RemoveTempBuddy_ForgetsPresence(t *testing.T) {
	session := newTestSession(t, newFakeConn(), "presence")

	buddyArrives(session, onlineBuddy("Mike Kelly"))
	buddyArrives(session, onlineBuddy("keeper"))

	handler := &AimHandler{
		Logger: slog.Default(),
	}

	req := httptest.NewRequest(http.MethodGet, "/aim/removeTempBuddy?aimsid="+session.AimSID+"&t=mikekelly", nil)
	rr := httptest.NewRecorder()
	handler.RemoveTempBuddy(rr, req, session)
	require.Equal(t, http.StatusOK, rr.Code)

	_, ok := session.BuddyPresence(state.NewIdentScreenName("mikekelly"))
	assert.False(t, ok, "removed temp buddy should be forgotten")

	// Only the named buddies are forgotten.
	_, ok = session.BuddyPresence(state.NewIdentScreenName("keeper"))
	assert.True(t, ok)
}

// A failed removal leaves the buddy watched, so their presence must survive.
func TestAimHandler_RemoveTempBuddy_KeepsPresenceOnFailure(t *testing.T) {
	conn := newFakeConn()
	conn.sendErr = io.ErrUnexpectedEOF
	session := newTestSession(t, conn, "presence")

	buddyArrives(session, onlineBuddy("Mike Kelly"))

	handler := &AimHandler{
		Logger: slog.Default(),
	}

	req := httptest.NewRequest(http.MethodGet, "/aim/removeTempBuddy?aimsid="+session.AimSID+"&t=mikekelly", nil)
	rr := httptest.NewRecorder()
	handler.RemoveTempBuddy(rr, req, session)
	require.Equal(t, http.StatusInternalServerError, rr.Code)

	got, ok := session.BuddyPresence(state.NewIdentScreenName("mikekelly"))
	require.True(t, ok)
	assert.Equal(t, "online", got.State)
}

func TestClientAddr(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       net.Addr
	}{
		{
			name:       "IPv4",
			remoteAddr: "192.0.2.1:1234",
			want:       &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1).To4(), Port: 1234},
		},
		{
			name:       "IPv6",
			remoteAddr: "[2001:db8::1]:443",
			want:       &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 443},
		},
		{
			// The OSCAR server still gets an address it can split.
			name:       "unparsable",
			remoteAddr: "pipe",
			want:       &net.TCPAddr{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/aim/startSession", nil)
			r.RemoteAddr = tt.remoteAddr
			got := clientAddr(r)
			assert.Equal(t, tt.want.String(), got.String())
			_, _, err := net.SplitHostPort(got.String())
			assert.NoError(t, err)
		})
	}
}
