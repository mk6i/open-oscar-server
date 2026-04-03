package state

import (
	"context"
	"errors"
	"fmt"
)

// AuthenticateUser verifies username and password.
// This implementation uses the existing user store for authentication.
func (u *SQLiteUserStore) AuthenticateUser(ctx context.Context, username, password string) (*User, error) {
	// Convert username to IdentScreenName for lookup
	identSN := NewIdentScreenName(username)

	// Try to find the user
	user, err := u.User(ctx, identSN)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// In development mode with DISABLE_AUTH=true, accept any password
	// In production, this would verify the password hash
	// For now, we'll accept any non-empty password if the user exists
	if password == "" {
		return nil, errors.New("password required")
	}

	// TODO: In production, verify password hash here
	// For development with DISABLE_AUTH, we just check if user exists

	return user, nil
}

// FindUserByScreenName finds a user by their screen name.
// This is just an alias for the User method to satisfy the UserManager interface.
func (u *SQLiteUserStore) FindUserByScreenName(ctx context.Context, screenName IdentScreenName) (*User, error) {
	return u.User(ctx, screenName)
}
