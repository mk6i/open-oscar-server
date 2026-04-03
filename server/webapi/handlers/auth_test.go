package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// testAuthService implements AuthService for ClientLogin tests (only FLAPLogin is exercised).
type testAuthService struct {
	flapLogin func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error)
}

func (t *testAuthService) BUCPChallenge(ctx context.Context, bodyIn wire.SNAC_0x17_0x06_BUCPChallengeRequest, newUUID func() uuid.UUID) (wire.SNACMessage, error) {
	return wire.SNACMessage{}, nil
}

func (t *testAuthService) BUCPLogin(ctx context.Context, bodyIn wire.SNAC_0x17_0x02_BUCPLoginRequest, advertisedHost string) (wire.SNACMessage, error) {
	return wire.SNACMessage{}, nil
}

func (t *testAuthService) CrackCookie(authCookie []byte) (state.ServerCookie, error) {
	return state.ServerCookie{}, nil
}

func (t *testAuthService) RegisterBOSSession(ctx context.Context, authCookie state.ServerCookie, conf func(sess *state.Session)) (*state.SessionInstance, error) {
	return nil, nil
}

func (t *testAuthService) FLAPLogin(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
	if t.flapLogin != nil {
		return t.flapLogin(ctx, inFrame, advertisedHost)
	}
	return wire.TLVRestBlock{}, nil
}

func (t *testAuthService) Signout(ctx context.Context, session *state.Session) {}

func (t *testAuthService) SignoutChat(ctx context.Context, sess *state.Session) {}

func successfulLoginBlock() wire.TLVRestBlock {
	var b wire.TLVRestBlock
	b.Append(wire.NewTLVBE(wire.OServiceTLVTagsLoginCookie, []byte("fake-auth-cookie-bytes")))
	return b
}

func failedLoginBlock() wire.TLVRestBlock {
	var b wire.TLVRestBlock
	b.Append(wire.NewTLVBE(wire.LoginTLVTagsErrorSubcode, uint16(1)))
	return b
}

func TestAuthHandler_ClientLogin(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		contentType        string
		body               string
		auth               *testAuthService
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_JSONBody",
			method:      "POST",
			contentType: "application/json",
			body:        `{"username":"testuser","password":"testpass","devId":"dev123"}`,
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
					return successfulLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"loginId":"testuser"`)
				assert.Contains(t, body, `"screenName":"testuser"`)
				assert.Contains(t, body, `"token"`)
				assert.Contains(t, body, `"sessionSecret"`)
			},
		},
		{
			name:        "Success_FormEncoded",
			method:      "POST",
			contentType: "application/x-www-form-urlencoded",
			body:        "s=testuser&pwd=testpass&devId=dev123",
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
					return successfulLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"loginId":"testuser"`)
			},
		},
		{
			name:               "Error_MissingUsername",
			method:             "POST",
			contentType:        "application/json",
			body:               `{"username":"","password":"testpass"}`,
			auth:               &testAuthService{},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "username and password required")
			},
		},
		{
			name:               "Error_MissingPassword",
			method:             "POST",
			contentType:        "application/json",
			body:               `{"username":"testuser","password":""}`,
			auth:               &testAuthService{},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "username and password required")
			},
		},
		{
			name:        "Error_AuthFailed",
			method:      "POST",
			contentType: "application/json",
			body:        `{"username":"testuser","password":"wrongpass"}`,
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
					return failedLoginBlock(), nil
				},
			},
			expectedStatusCode: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "username and password required")
			},
		},
		{
			name:        "Error_FLAPLoginError",
			method:      "POST",
			contentType: "application/json",
			body:        `{"username":"testuser","password":"testpass"}`,
			auth: &testAuthService{
				flapLogin: func(ctx context.Context, inFrame wire.FLAPSignonFrame, advertisedHost string) (wire.TLVRestBlock, error) {
					return wire.TLVRestBlock{}, errors.New("boom")
				},
			},
			expectedStatusCode: http.StatusInternalServerError,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "internal server error")
			},
		},
		{
			name:               "Error_InvalidJSON",
			method:             "POST",
			contentType:        "application/json",
			body:               `{invalid json`,
			auth:               &testAuthService{},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid JSON format")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := slog.Default()

			handler := &AuthHandler{
				AuthService: tt.auth,
				Logger:      logger,
			}

			req, err := http.NewRequest(tt.method, "/auth/clientLogin", strings.NewReader(tt.body))
			assert.NoError(t, err)
			req.Header.Set("Content-Type", tt.contentType)

			rr := httptest.NewRecorder()

			handler.ClientLogin(rr, req)

			assert.Equal(t, tt.expectedStatusCode, rr.Code)

			responseBody := strings.TrimSpace(rr.Body.String())
			if tt.checkResponse != nil {
				tt.checkResponse(t, responseBody)
			}
		})
	}
}
