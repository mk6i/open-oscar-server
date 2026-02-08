package state

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewAccountCreator(t *testing.T) {
	tests := []struct {
		name          string
		screenName    DisplayScreenName
		password      string
		insertUserErr error
		wantErr       error
		validateUser  func(*testing.T, User)
	}{
		{
			name:       "Success with valid AIM handle",
			screenName: "TestUser123",
			password:   "validpass123",
			wantErr:    nil,
			validateUser: func(t *testing.T, u User) {
				assert.Equal(t, DisplayScreenName("TestUser123"), u.DisplayScreenName)
				assert.Equal(t, NewIdentScreenName("testuser123"), u.IdentScreenName)
				assert.False(t, u.IsICQ)
				assert.NotEmpty(t, u.AuthKey)
				assert.NotNil(t, u.WeakMD5Pass)
				assert.NotNil(t, u.StrongMD5Pass)
			},
		},
		{
			name:       "Success with valid UIN",
			screenName: "12345678",
			password:   "valid12",
			wantErr:    nil,
			validateUser: func(t *testing.T, u User) {
				assert.Equal(t, DisplayScreenName("12345678"), u.DisplayScreenName)
				assert.Equal(t, NewIdentScreenName("12345678"), u.IdentScreenName)
				assert.True(t, u.IsICQ)
				assert.NotEmpty(t, u.AuthKey)
				assert.NotNil(t, u.WeakMD5Pass)
				assert.NotNil(t, u.StrongMD5Pass)
			},
		},
		{
			name:       "Success with AIM handle containing spaces",
			screenName: "Test User 123",
			password:   "validpass123",
			wantErr:    nil,
			validateUser: func(t *testing.T, u User) {
				assert.Equal(t, DisplayScreenName("Test User 123"), u.DisplayScreenName)
				assert.Equal(t, NewIdentScreenName("test user 123"), u.IdentScreenName)
				assert.False(t, u.IsICQ)
			},
		},
		{
			name:       "Invalid AIM handle - too short",
			screenName: "Us",
			password:   "validpass123",
			wantErr:    ErrAIMHandleLength,
		},
		{
			name:       "Invalid AIM handle - starts with number",
			screenName: "1User",
			password:   "validpass123",
			wantErr:    ErrAIMHandleInvalidFormat,
		},
		{
			name:       "Invalid AIM handle - ends with space",
			screenName: "User123 ",
			password:   "validpass123",
			wantErr:    ErrAIMHandleInvalidFormat,
		},
		{
			name:       "Invalid UIN - too small",
			screenName: "9999",
			password:   "valid12",
			wantErr:    ErrICQUINInvalidFormat,
		},
		{
			name:       "Invalid UIN - too large",
			screenName: "2147483647",
			password:   "valid12",
			wantErr:    ErrICQUINInvalidFormat,
		},
		{
			name:       "Invalid UIN - contains non-digits",
			screenName: "12345abc",
			password:   "valid12",
			wantErr:    ErrAIMHandleInvalidFormat, // Will be validated as AIM handle since IsUIN() returns false
		},
		{
			name:          "insertUser error",
			screenName:    "TestUser123",
			password:      "validpass123",
			insertUserErr: assert.AnError,
			wantErr:       assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedUser User

			insertUser := func(ctx context.Context, u User) error {
				capturedUser = u
				return tt.insertUserErr
			}

			createAccount := NewAccountCreator(insertUser)
			err := createAccount(context.Background(), tt.screenName, tt.password)

			assert.ErrorIs(t, err, tt.wantErr)

			if tt.validateUser != nil {
				tt.validateUser(t, capturedUser)
			}
		})
	}
}
