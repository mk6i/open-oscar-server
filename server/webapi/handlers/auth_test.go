package handlers

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/mk6i/open-oscar-server/state"
)

// MockUserManager is a mock implementation of UserManager
type MockUserManager struct {
	mock.Mock
}

func (m *MockUserManager) AuthenticateUser(ctx context.Context, username, password string) (*state.User, error) {
	args := m.Called(ctx, username, password)
	if user := args.Get(0); user != nil {
		return user.(*state.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockUserManager) FindUserByScreenName(ctx context.Context, screenName state.IdentScreenName) (*state.User, error) {
	args := m.Called(ctx, screenName)
	if user := args.Get(0); user != nil {
		return user.(*state.User), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *MockUserManager) InsertUser(ctx context.Context, u state.User) error {
	args := m.Called(ctx, u)
	return args.Error(0)
}

// MockTokenStore is a mock implementation of TokenStore
type MockTokenStore struct {
	mock.Mock
}

func (m *MockTokenStore) StoreToken(ctx context.Context, token string, screenName state.IdentScreenName, expiresAt time.Time) error {
	args := m.Called(ctx, token, screenName, expiresAt)
	return args.Error(0)
}

func (m *MockTokenStore) ValidateToken(ctx context.Context, token string) (state.IdentScreenName, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(state.IdentScreenName), args.Error(1)
}

func (m *MockTokenStore) DeleteToken(ctx context.Context, token string) error {
	args := m.Called(ctx, token)
	return args.Error(0)
}

func TestAuthHandler_ClientLogin(t *testing.T) {
	tests := []struct {
		name               string
		method             string
		contentType        string
		body               string
		setupMocks         func(*MockUserManager, *MockTokenStore)
		disableAuth        bool
		expectedStatusCode int
		checkResponse      func(*testing.T, string)
	}{
		{
			name:        "Success_JSONBody",
			method:      "POST",
			contentType: "application/json",
			body:        `{"username":"testuser","password":"testpass","devId":"dev123"}`,
			setupMocks: func(um *MockUserManager, ts *MockTokenStore) {
				user := &state.User{
					IdentScreenName:   state.NewIdentScreenName("testuser"),
					DisplayScreenName: state.DisplayScreenName("testuser"),
				}
				um.On("AuthenticateUser", mock.Anything, "testuser", "testpass").Return(user, nil)
				ts.On("StoreToken", mock.Anything, mock.AnythingOfType("string"), state.NewIdentScreenName("testuser"), mock.AnythingOfType("time.Time")).Return(nil)
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
			setupMocks: func(um *MockUserManager, ts *MockTokenStore) {
				user := &state.User{
					IdentScreenName:   state.NewIdentScreenName("testuser"),
					DisplayScreenName: state.DisplayScreenName("testuser"),
				}
				um.On("AuthenticateUser", mock.Anything, "testuser", "testpass").Return(user, nil)
				ts.On("StoreToken", mock.Anything, mock.AnythingOfType("string"), state.NewIdentScreenName("testuser"), mock.AnythingOfType("time.Time")).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"loginId":"testuser"`)
			},
		},
		{
			name:        "Success_DisableAuth_NewUser",
			method:      "POST",
			contentType: "application/json",
			body:        `{"username":"newuser","password":"pass123"}`,
			disableAuth: true,
			setupMocks: func(um *MockUserManager, ts *MockTokenStore) {
				// First auth attempt fails - user not found
				um.On("AuthenticateUser", mock.Anything, "newuser", "pass123").Return(nil, errors.New("user not found")).Once()
				// User is created
				um.On("InsertUser", mock.Anything, mock.MatchedBy(func(u state.User) bool {
					return u.IdentScreenName == state.NewIdentScreenName("newuser")
				})).Return(nil)
				// Second auth attempt succeeds
				user := &state.User{
					IdentScreenName:   state.NewIdentScreenName("newuser"),
					DisplayScreenName: state.DisplayScreenName("newuser"),
				}
				um.On("AuthenticateUser", mock.Anything, "newuser", "pass123").Return(user, nil)
				ts.On("StoreToken", mock.Anything, mock.AnythingOfType("string"), state.NewIdentScreenName("newuser"), mock.AnythingOfType("time.Time")).Return(nil)
			},
			expectedStatusCode: http.StatusOK,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, `"statusCode":200`)
				assert.Contains(t, body, `"loginId":"newuser"`)
			},
		},
		{
			name:               "Error_MissingUsername",
			method:             "POST",
			contentType:        "application/json",
			body:               `{"username":"","password":"testpass"}`,
			setupMocks:         func(um *MockUserManager, ts *MockTokenStore) {},
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
			setupMocks:         func(um *MockUserManager, ts *MockTokenStore) {},
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
			setupMocks: func(um *MockUserManager, ts *MockTokenStore) {
				um.On("AuthenticateUser", mock.Anything, "testuser", "wrongpass").Return(nil, errors.New("invalid credentials"))
			},
			expectedStatusCode: http.StatusUnauthorized,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "authentication failed")
			},
		},
		{
			name:               "Error_InvalidJSON",
			method:             "POST",
			contentType:        "application/json",
			body:               `{invalid json`,
			setupMocks:         func(um *MockUserManager, ts *MockTokenStore) {},
			expectedStatusCode: http.StatusBadRequest,
			checkResponse: func(t *testing.T, body string) {
				assert.Contains(t, body, "invalid JSON format")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			userManager := &MockUserManager{}
			tokenStore := &MockTokenStore{}
			logger := slog.Default()

			handler := &AuthHandler{
				UserManager: userManager,
				TokenStore:  tokenStore,
				Logger:      logger,
				DisableAuth: tt.disableAuth,
			}

			tt.setupMocks(userManager, tokenStore)

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

			userManager.AssertExpectations(t)
			tokenStore.AssertExpectations(t)
		})
	}
}
