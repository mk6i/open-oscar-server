package webapi

import (
	"net"
	"strconv"
	"strings"

	"github.com/mk6i/open-oscar-server/config"
)

// OSCARConfigAdapter adapts the main server configuration to provide
// OSCAR-specific configuration for the Web API bridge.
type OSCARConfigAdapter struct {
	cfg       config.Config
	listeners []config.Listener
}

// NewOSCARConfigAdapter creates a new OSCAR configuration adapter.
func NewOSCARConfigAdapter(cfg config.Config) *OSCARConfigAdapter {
	listeners, _ := cfg.ParseListenersCfg()
	return &OSCARConfigAdapter{
		cfg:       cfg,
		listeners: listeners,
	}
}

// GetBOSAddress returns the plain (non-SSL) BOS server address for client connections.
// This parses the configured BOS advertised host to extract the hostname and port.
func (a *OSCARConfigAdapter) GetBOSAddress() (host string, port int) {
	// Default to first listener configuration
	if len(a.listeners) == 0 {
		return "localhost", 5190 // Default OSCAR port
	}

	listener := a.listeners[0]

	// Parse the advertised host for plain connections
	if listener.BOSAdvertisedHostPlain != "" {
		host, portStr := splitHostPort(listener.BOSAdvertisedHostPlain)
		if portStr != "" {
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
		}
		if port == 0 {
			port = 5190 // Default OSCAR port
		}
		return host, port
	}

	// Fall back to parsing the listen address
	if listener.BOSListenAddress != "" {
		host, portStr, err := net.SplitHostPort(listener.BOSListenAddress)
		if err == nil {
			if host == "" {
				host = "localhost"
			}
			if p, err := strconv.Atoi(portStr); err == nil {
				port = p
			}
		}
		if port == 0 {
			port = 5190
		}
		return host, port
	}

	return "localhost", 5190
}

// GetSSLBOSAddress returns the SSL-enabled BOS server address for client connections.
func (a *OSCARConfigAdapter) GetSSLBOSAddress() (host string, port int) {
	// Default to first listener configuration with SSL
	for _, listener := range a.listeners {
		if listener.HasSSL && listener.BOSAdvertisedHostSSL != "" {
			host, portStr := splitHostPort(listener.BOSAdvertisedHostSSL)
			if portStr != "" {
				if p, err := strconv.Atoi(portStr); err == nil {
					port = p
				}
			}
			if port == 0 {
				port = 5190 // Default OSCAR SSL port (could be different)
			}
			return host, port
		}
	}

	// Fall back to plain address if no SSL configured
	return a.GetBOSAddress()
}

// IsSSLAvailable checks if any listener has SSL configured.
func (a *OSCARConfigAdapter) IsSSLAvailable() bool {
	for _, listener := range a.listeners {
		if listener.HasSSL {
			return true
		}
	}
	return false
}

// IsAuthDisabled returns whether authentication is disabled.
func (a *OSCARConfigAdapter) IsAuthDisabled() bool {
	return a.cfg.DisableAuth
}

// splitHostPort splits a host:port string, handling IPv6 addresses correctly.
// Unlike net.SplitHostPort, this doesn't return an error for missing ports.
func splitHostPort(hostport string) (host string, port string) {
	// Handle IPv6 addresses
	if strings.HasPrefix(hostport, "[") {
		endIdx := strings.LastIndex(hostport, "]")
		if endIdx != -1 {
			host = hostport[1:endIdx]
			if endIdx+1 < len(hostport) && hostport[endIdx+1] == ':' {
				port = hostport[endIdx+2:]
			}
			return
		}
	}

	// Handle IPv4 and hostnames
	lastColon := strings.LastIndex(hostport, ":")
	if lastColon != -1 {
		// Check if this might be an IPv6 address without brackets
		if strings.Count(hostport, ":") > 1 {
			// Multiple colons, likely IPv6 without port
			host = hostport
			return
		}
		host = hostport[:lastColon]
		port = hostport[lastColon+1:]
		return
	}

	// No port specified
	host = hostport
	return
}
