package webapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
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

func TestBuildMyInfo_UserTypeAndService(t *testing.T) {
	tests := []struct {
		name       string
		screenName string
		wantType   string
		wantSvc    string
	}{
		{"aim screen name", "mikekelly", "aim", "AIM"},
		{"icq uin", "123456789", "icq", "ICQ"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mi := buildMyInfo(state.DisplayScreenName(tt.screenName), "online", "")
			assert.Equal(t, tt.wantType, mi.UserType)
			assert.Equal(t, tt.wantSvc, mi.Service)
		})
	}
}

func TestBuildMyInfo_BuddyIcon(t *testing.T) {
	t.Run("included when set", func(t *testing.T) {
		mi := buildMyInfo(state.DisplayScreenName("mikekelly"), "away", "http://x/icon")
		assert.Equal(t, "http://x/icon", mi.BuddyIcon)
	})
	t.Run("omitted when empty so the client merge preserves the current icon", func(t *testing.T) {
		mi := buildMyInfo(state.DisplayScreenName("mikekelly"), "away", "")
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
		session            *Session
		expectedStatusCode int
		expectedResponse   string
		checkSession       func(*testing.T, *Session)
	}{
		{
			name: "Success_SingleBuddy",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
				"t":      {"buddy1"},
			},
			session: &Session{
				AimSID:       "test-session-id",
				ScreenName:   state.DisplayScreenName("testuser"),
				EventQueue:   NewEventQueue(100),
				TempBuddies:  nil,
				LastAccessed: time.Now(),
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"buddyNames":["buddy1"],"resultCode":"success"}}}`,
			checkSession: func(t *testing.T, session *Session) {
				assert.NotNil(t, session.TempBuddies)
				assert.True(t, session.TempBuddies["buddy1"])
				assert.Equal(t, 1, len(session.TempBuddies))
			},
		},
		{
			name: "Success_MultipleBuddies",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
				"t":      {"buddy1", "buddy2", "buddy3"},
			},
			session: &Session{
				AimSID:       "test-session-id",
				ScreenName:   state.DisplayScreenName("testuser"),
				EventQueue:   NewEventQueue(100),
				TempBuddies:  nil,
				LastAccessed: time.Now(),
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"buddyNames":["buddy1","buddy2","buddy3"],"resultCode":"success"}}}`,
			checkSession: func(t *testing.T, session *Session) {
				assert.NotNil(t, session.TempBuddies)
				assert.True(t, session.TempBuddies["buddy1"])
				assert.True(t, session.TempBuddies["buddy2"])
				assert.True(t, session.TempBuddies["buddy3"])
				assert.Equal(t, 3, len(session.TempBuddies))
			},
		},
		{
			name: "Success_AddToExistingTempBuddies",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
				"t":      {"buddy2"},
			},
			session: &Session{
				AimSID:     "test-session-id",
				ScreenName: state.DisplayScreenName("testuser"),
				EventQueue: NewEventQueue(100),
				TempBuddies: map[string]bool{
					"buddy1": true,
				},
				LastAccessed: time.Now(),
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"buddyNames":["buddy2"],"resultCode":"success"}}}`,
			checkSession: func(t *testing.T, session *Session) {
				assert.NotNil(t, session.TempBuddies)
				assert.True(t, session.TempBuddies["buddy1"])
				assert.True(t, session.TempBuddies["buddy2"])
				assert.Equal(t, 2, len(session.TempBuddies))
			},
		},
		{
			name: "Error_MissingBuddyNames",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
			},
			session: &Session{
				AimSID:       "test-session-id",
				ScreenName:   state.DisplayScreenName("testuser"),
				EventQueue:   NewEventQueue(100),
				LastAccessed: time.Now(),
			},
			expectedStatusCode: http.StatusBadRequest,
			expectedResponse:   `{"response":{"statusCode":400,"statusText":"missing buddy names (t parameter)","data":{}}}`,
		},
		{
			name: "Success_WithWhitespace",
			queryParams: map[string][]string{
				"aimsid": {"test-session-id"},
				"t":      {"  buddy1  ", "buddy2 ", " buddy3"},
			},
			session: &Session{
				AimSID:       "test-session-id",
				ScreenName:   state.DisplayScreenName("testuser"),
				EventQueue:   NewEventQueue(100),
				TempBuddies:  nil,
				LastAccessed: time.Now(),
			},
			expectedStatusCode: http.StatusOK,
			expectedResponse:   `{"response":{"statusCode":200,"statusText":"Ok","data":{"buddyNames":["  buddy1  ","buddy2 "," buddy3"],"resultCode":"success"}}}`,
			checkSession: func(t *testing.T, session *Session) {
				assert.NotNil(t, session.TempBuddies)
				assert.True(t, session.TempBuddies["buddy1"])
				assert.True(t, session.TempBuddies["buddy2"])
				assert.True(t, session.TempBuddies["buddy3"])
				assert.Equal(t, 3, len(session.TempBuddies))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &AimHandler{
				Logger: slog.Default(),
			}

			reqURL := "/aim/addTempBuddy"
			if len(tt.queryParams) > 0 {
				values := url.Values{}
				for key, vals := range tt.queryParams {
					for _, val := range vals {
						values.Add(key, val)
					}
				}
				reqURL += "?" + values.Encode()
			}

			req, err := http.NewRequest("GET", reqURL, nil)
			assert.NoError(t, err)

			rr := httptest.NewRecorder()
			handler.AddTempBuddy(rr, req, tt.session)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)
			assert.JSONEq(t, tt.expectedResponse, rr.Body.String())

			if tt.checkSession != nil && tt.session != nil {
				tt.checkSession(t, tt.session)
			}
		})
	}
}

func TestAimHandler_AddTempBuddy_DoesNotPushBuddyListEvent(t *testing.T) {
	handler := &AimHandler{Logger: slog.Default()}

	eventQueue := NewEventQueue(100)
	session := &Session{
		AimSID:       "test-session",
		ScreenName:   state.DisplayScreenName("testuser"),
		EventQueue:   eventQueue,
		TempBuddies:  nil,
		LastAccessed: time.Now(),
	}

	req, err := http.NewRequest("GET", "/aim/addTempBuddy?aimsid=test-session&t=buddy1&t=buddy2", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.AddTempBuddy(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Empty(t, eventQueue.GetAllEvents(), "addTempBuddy must not push buddylist events")
}

func TestAimHandler_RemoveTempBuddy(t *testing.T) {
	handler := &AimHandler{Logger: slog.Default()}

	session := &Session{
		AimSID:     "test-session",
		ScreenName: state.DisplayScreenName("testuser"),
		TempBuddies: map[string]bool{
			"buddy1": true,
			"buddy2": true,
		},
		LastAccessed: time.Now(),
	}

	req, err := http.NewRequest("GET", "/aim/removeTempBuddy?aimsid=test-session&t=buddy1", nil)
	assert.NoError(t, err)

	rr := httptest.NewRecorder()
	handler.RemoveTempBuddy(rr, req, session)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.False(t, session.TempBuddies["buddy1"])
	assert.True(t, session.TempBuddies["buddy2"])
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

// bridgeRequest builds a startOSCARSession request carrying the API key the
// middleware would have put on the context.
func bridgeRequest(query string, apiKey *state.WebAPIKey) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/aim/startOSCARSession?"+query, nil)
	if apiKey != nil {
		req = req.WithContext(context.WithValue(req.Context(), ContextKeyAPIKey, apiKey))
	}
	return req
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
	unrestrictedKey := &state.WebAPIKey{DevID: "dev123"}

	tests := []struct {
		name         string
		query        string
		apiKey       *state.WebAPIKey
		sslAvailable bool
		expectedCode int
		checkBody    func(t *testing.T, body string)
	}{
		{
			// No tlsCertName, which is how the client reads "connect in the clear".
			name:         "Success_Plaintext",
			query:        "a=" + validToken,
			apiKey:       unrestrictedKey,
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
			apiKey:       unrestrictedKey,
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
			apiKey:       unrestrictedKey,
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
			apiKey:       unrestrictedKey,
			expectedCode: http.StatusUnauthorized,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "authentication token required")
			},
		},
		{
			name:         "Error_TokenNotBase64",
			query:        "a=not!valid!base64",
			apiKey:       unrestrictedKey,
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
			apiKey:       unrestrictedKey,
			expectedCode: http.StatusUnauthorized,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid or expired token")
			},
		},
		{
			name:         "Error_NoAPIKeyOnContext",
			query:        "a=" + validToken,
			apiKey:       nil,
			expectedCode: http.StatusInternalServerError,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "internal server error")
			},
		},
		{
			name:         "Error_APIKeyLacksBridgeCapability",
			query:        "a=" + validToken,
			apiKey:       &state.WebAPIKey{DevID: "dev123", Capabilities: []string{"presence"}},
			expectedCode: http.StatusForbidden,
			checkBody: func(t *testing.T, body string) {
				assert.Contains(t, body, "OSCAR bridge not enabled")
			},
		},
		{
			name:         "Success_APIKeyGrantsBridgeCapability",
			query:        "a=" + validToken,
			apiKey:       &state.WebAPIKey{DevID: "dev123", Capabilities: []string{"presence", "oscar_bridge"}},
			expectedCode: http.StatusOK,
			checkBody: func(t *testing.T, body string) {
				assert.Equal(t, 200, decodeBridgeData(t, body).Response.StatusCode)
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
			handler.StartOSCARSession(rr, bridgeRequest(tt.query, tt.apiKey))

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
	handler.StartOSCARSession(rr, bridgeRequest("a="+urlSafe, &state.WebAPIKey{DevID: "dev123"}))

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

	// limitedSession returns a session on an account already in the limited state.
	limitedSession := func(t *testing.T) *Session {
		t.Helper()

		session := newTestWebAPISession(t, tightRateLimitClasses())
		sess := session.OSCARSession.Session()
		for i := 0; sess.RateLimitStates()[imClass-1].CurrentStatus != wire.RateLimitStatusLimited; i++ {
			require.Less(t, i, 100, "class never reached the limited state")
			sess.EvaluateRateLimit(time.Now(), imClass)
		}
		return session
	}

	t.Run("a session starting on a limited account is told", func(t *testing.T) {
		session := limitedSession(t)

		seedRateLimitAlert(session, imClass)

		assert.Equal(t, []string{"limit"}, rateLimitEventStatuses(t, session))
	})

	t.Run("a session starting on a clear account is told nothing", func(t *testing.T) {
		session := newTestWebAPISession(t, tightRateLimitClasses())

		seedRateLimitAlert(session, imClass)

		assert.Empty(t, rateLimitEventStatuses(t, session))
	})

	t.Run("a zero class id disables the alert", func(t *testing.T) {
		session := limitedSession(t)

		seedRateLimitAlert(session, 0)

		assert.Empty(t, rateLimitEventStatuses(t, session))
	})
}
