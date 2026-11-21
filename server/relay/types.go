package relay

import "github.com/mk6i/open-oscar-server/state"

// SessionRetriever defines a method for retrieving an active session
// associated with a given screen name.
type SessionRetriever interface {
	// RetrieveSession returns the session associated with the given screen name,
	// or nil if no active session exists. Returns the Session object if there
	// are active instances with complete signon.
	RetrieveSession(screenName state.IdentScreenName) *state.Session
}
