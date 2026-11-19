package webapi

import (
	"context"
	"time"

	"github.com/mk6i/open-oscar-server/config"
	"github.com/mk6i/open-oscar-server/state"
	"github.com/mk6i/open-oscar-server/wire"
)

// oscarConn is a session's connection to the OSCAR BOS service.
type oscarConn interface {
	// Run reads SNACs from the server into Messages until the connection
	// closes or ctx is done.
	Run(ctx context.Context)
	// SendSNAC sends a SNAC to the OSCAR server.
	SendSNAC(frame wire.SNACFrame, body any) error
	// Messages returns the SNACs received from the server, replies and
	// server-initiated messages alike, in arrival order.
	Messages() <-chan wire.SNACMessage
	// Closed returns a channel that is closed when the connection closes.
	Closed() <-chan struct{}
	// Close closes the connection.
	Close()
}

// SessionResolver resolves and refreshes Web API sessions by aimsid.
type SessionResolver interface {
	GetSession(ctx context.Context, aimsid string) (*Session, error)
	TouchSession(ctx context.Context, aimsid string) error
}

// AuthService logs users in and cracks the auth cookies it issues.
type AuthService interface {
	CrackCookie(authCookie []byte) (state.ServerCookie, time.Time, error)
	FLAPLogin(ctx context.Context, inFrame wire.FLAPSignonFrame, endpointCfg config.Endpoint) (wire.TLVRestBlock, error)
}

// BARTService retrieves BART (buddy art) assets by content hash.
type BARTService interface {
	RetrieveItem(ctx context.Context, inFrame wire.SNACFrame, inBody wire.SNAC_0x10_0x04_BARTDownloadQuery) (wire.SNACMessage, error)
}

// BuddyIconRetriever resolves a user's icon reference from their feedbag, which
// is where it lives, so it resolves for offline users too.
type BuddyIconRetriever interface {
	BuddyIconMetadata(ctx context.Context, screenName state.IdentScreenName) (*wire.BARTID, error)
}
