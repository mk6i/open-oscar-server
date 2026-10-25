package toc

import (
	"context"
	"net"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// OSCARServer serves OSCAR connections that the TOC server opens on behalf of
// its users.
type OSCARServer interface {
	// ServeConn serves conn as if it had been accepted on the listener at
	// endpointCfg, and returns when the connection ends.
	ServeConn(conn net.Conn, endpointCfg config.Endpoint)
}

// LocateService looks up user profiles and directory info for the TOC HTTP
// pages.
type LocateService interface {
	UserInfoQuery(ctx context.Context, instance *state.SessionInstance, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x05_LocateUserInfoQuery) (wire.SNACMessage, error)
	DirInfo(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x02_0x0B_LocateGetDirInfo) (wire.SNACMessage, error)
}

// DirSearchService searches the user directory for the TOC HTTP pages.
type DirSearchService interface {
	InfoQuery(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x0F_0x02_InfoQuery) (wire.SNACMessage, error)
}

type TOCConfigStore interface {
	// SetTOCConfig sets the user's TOC config. The TOC config is the server-side
	// buddy list functionality for TOC. This configuration is not available to
	// OSCAR clients.
	SetTOCConfig(ctx context.Context, user state.IdentScreenName, config string) error
	User(ctx context.Context, screenName state.IdentScreenName) (*state.User, error)
}

// CookieBaker defines methods for issuing and verifying AIM authentication tokens ("cookies").
// These tokens are used for authenticating client sessions with AIM services.
type CookieBaker interface {
	// Crack verifies and decodes a previously issued authentication token.
	// Returns the original payload and the token's expiry if it is valid.
	Crack(data []byte) ([]byte, time.Time, error)

	// Issue creates a new authentication token from the given payload that
	// stays valid for ttl. The resulting token can later be verified using
	// Crack.
	Issue(data []byte, ttl time.Duration) ([]byte, error)
}

// SessionRetriever defines a method for retrieving an active session
// associated with a given screen name.
type SessionRetriever interface {
	// RetrieveSession returns the session associated with the given screen name,
	// or nil if no active session exists. Returns the Session object if there
	// are active instances with complete signon.
	RetrieveSession(screenName state.IdentScreenName) *state.Session
}
