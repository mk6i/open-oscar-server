package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

var (
	// Simple error for duplicate listener definitions
	errDuplicateListener = errors.New("duplicate listener definition")
	// Simple error for missing BOS listeners
	errNoBOSListeners = errors.New("at least one BOS listener is required")
)

// Custom error types for URI-related errors
type uriFormatError struct {
	URI string
	Err error
}

func (e uriFormatError) Error() string {
	return fmt.Sprintf("invalid listener URI %q: %v. Valid format: SCHEME://HOST:PORT (e.g., LOCAL://0.0.0.0:5190)", e.URI, e.Err)
}

type Build struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// ListenerGroup is a set of related BOS endpoints: one plaintext, and
// optionally one for SSL clients. Both listen in plaintext — a load balancer
// terminates TLS and forwards decrypted traffic to the SSL endpoint. Pairing
// them lets a redirect hand a client the sibling endpoint's advertised host,
// so a session can upgrade to SSL or downgrade to plaintext on reconnect.
type ListenerGroup struct {
	// Name is the URI scheme the group was parsed from, e.g. "LOCAL".
	Name                   string
	BOSListenAddress       string
	BOSListenAddressSSL    string
	BOSAdvertisedHostPlain string
	BOSAdvertisedHostSSL   string
	KerberosListenAddress  string
}

// HasSSL reports whether clients can reach this group over SSL. Config
// validation guarantees such a group also has an SSL listen address.
func (g ListenerGroup) HasSSL() bool {
	return g.BOSAdvertisedHostSSL != ""
}

// PlainEndpoint returns the group's plaintext BOS socket.
func (g ListenerGroup) PlainEndpoint() Endpoint {
	return Endpoint{Group: g, ListenAddress: g.BOSListenAddress}
}

// SSLEndpoint returns the socket that receives decrypted traffic from the
// group's SSL terminator. ok is false when SSL is not enabled for the group.
func (g ListenerGroup) SSLEndpoint() (ep Endpoint, ok bool) {
	if !g.HasSSL() {
		return Endpoint{}, false
	}
	return Endpoint{Group: g, ListenAddress: g.BOSListenAddressSSL, IsSSL: true}, true
}

// Endpoints returns every BOS socket the group binds.
func (g ListenerGroup) Endpoints() []Endpoint {
	eps := []Endpoint{g.PlainEndpoint()}
	if ssl, ok := g.SSLEndpoint(); ok {
		eps = append(eps, ssl)
	}
	return eps
}

// Endpoint is a single BOS socket. IsSSL means traffic arrives from an SSL
// terminator, so clients that connect here stay on the SSL path.
type Endpoint struct {
	Group         ListenerGroup
	ListenAddress string
	IsSSL         bool
}

// AdvertisedHost returns the BOS host clients on this endpoint reconnect to.
func (e Endpoint) AdvertisedHost() string {
	if e.IsSSL {
		return e.Group.BOSAdvertisedHostSSL
	}
	return e.Group.BOSAdvertisedHostPlain
}

//go:generate go run ../cmd/config_generator unix settings.env ssl
type Config struct {
	BOSListeners            []string `envconfig:"OSCAR_LISTENERS" required:"true" basic:"LOCAL://0.0.0.0:5190" ssl:"LOCAL://0.0.0.0:5190" description:"Network listeners for core OSCAR services. For multi-homed servers, allows users to connect from multiple networks. For example, you can allow both LAN and Internet clients to connect to the same server using different connection settings.\n\nFormat:\n\t- Comma-separated list of [NAME]://[HOSTNAME]:[PORT]\n\t- Listener names and ports must be unique\n\t- Listener names are user-defined\n\t- Each listener needs a listener in OSCAR_ADVERTISED_LISTENERS_PLAIN\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:5190\n\t// Separate Internet and LAN config\n\tWAN://142.250.176.206:5190,LAN://192.168.1.10:5191"`
	BOSAdvertisedHostsPlain []string `envconfig:"OSCAR_ADVERTISED_LISTENERS_PLAIN" required:"true" basic:"LOCAL://127.0.0.1:5190" ssl:"LOCAL://ras.dev:5190" description:"Hostnames published by the server that clients connect to for accessing various OSCAR services. These hostnames are NOT the bind addresses. For multi-homed use servers, allows clients to connect using separate hostnames per network.\n\nFormat:\n\t- Comma-separated list of [NAME]://[HOSTNAME]:[PORT]\n\t- Each listener config must correspond to a config in OSCAR_LISTENERS\n\t- Clients MUST be able to connect to these hostnames\n\nExamples:\n\t// Local LAN config, server behind NAT\n\tLAN://192.168.1.10:5190\n\t// Separate Internet and LAN config\n\tWAN://aim.example.com:5190,LAN://192.168.1.10:5191"`
	BOSListenersSSL         []string `envconfig:"OSCAR_LISTENERS_SSL" required:"false" basic:"" ssl:"LOCAL://0.0.0.0:5191" description:"Network listeners for core OSCAR services that receive decrypted traffic from an SSL terminator such as nginx. Clients that connect through these listeners are redirected to the hostnames in OSCAR_ADVERTISED_LISTENERS_SSL, keeping them on the SSL path for the rest of the session.\n\nFormat:\n\t- Comma-separated list of [NAME]://[HOSTNAME]:[PORT]\n\t- Listener names and ports must be unique\n\t- Each listener needs a listener in OSCAR_LISTENERS and OSCAR_ADVERTISED_LISTENERS_SSL\n\t- A listener without a matching OSCAR_ADVERTISED_LISTENERS_SSL entry is not started\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:5191\n\t// Separate Internet and LAN config\n\tWAN://142.250.176.206:5191,LAN://192.168.1.10:5192"`
	BOSAdvertisedHostsSSL   []string `envconfig:"OSCAR_ADVERTISED_LISTENERS_SSL" required:"false" basic:"" ssl:"LOCAL://ras.dev:5193" description:"Same as OSCAR_ADVERTISED_LISTENERS_PLAIN, except the hostname is for the server that terminates SSL. Each listener defined here must have a matching listener in OSCAR_LISTENERS_SSL for the terminator to forward decrypted traffic to."`
	KerberosListeners       []string `envconfig:"KERBEROS_LISTENERS" required:"false" basic:"" ssl:"LOCAL://0.0.0.0:1088" description:"Network listeners for Kerberos authentication. See OSCAR_LISTENERS doc for more details.\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:1088\n\t// Separate Internet and LAN config\n\tWAN://142.250.176.206:1088,LAN://192.168.1.10:1087"`
	TOCListeners            []string `envconfig:"TOC_LISTENERS" required:"true" basic:"0.0.0.0:9898" ssl:"0.0.0.0:9898" description:"Network listeners for TOC protocol service.\n\nFormat: Comma-separated list of hostname:port pairs.\n\nExamples:\n\t// All interfaces\n\t0.0.0.0:9898\n\t// Multiple listeners\n\t0.0.0.0:9898,192.168.1.10:9899"`
	APIListener             string   `envconfig:"API_LISTENER" required:"true" basic:"127.0.0.1:8080" ssl:"127.0.0.1:8080" description:"Network listener for management API binds to. Only 1 listener can be specified. (Default 127.0.0.1 restricts to same machine only)."`
	WebAPIListeners         []string `envconfig:"WEBAPI_LISTENERS" required:"false" basic:"0.0.0.0:8081" ssl:"0.0.0.0:8081" description:"Network listeners for WebAPI. See OSCAR_LISTENERS doc for more details.\n\nExamples:\n\t// Listen on all interfaces\n\tLAN://0.0.0.0:8081\n\t// Separate Internet and LAN config\n\tWAN://142.250.176.206:8081,LAN://192.168.1.10:8082"`

	DBPath                 string `envconfig:"DB_PATH" required:"true" basic:"oscar.sqlite" ssl:"oscar.sqlite" description:"The path to the SQLite database file. The file and DB schema are auto-created if they doesn't exist."`
	DisableAuth            bool   `envconfig:"DISABLE_AUTH" required:"true" basic:"true" ssl:"true" description:"Disable password check and auto-create new users at login time. Useful for quickly creating new accounts during development without having to register new users via the management API."`
	DisableMultiLoginNotif bool   `envconfig:"DISABLE_MULTI_LOGIN_NOTIF" required:"false" basic:"true" ssl:"true" description:"Disable notification sent when another client signs in with the same screen name."`
	LogLevel               string `envconfig:"LOG_LEVEL" required:"true" basic:"info" ssl:"info" description:"Set logging granularity. Possible values: 'trace', 'debug', 'info', 'warn', 'error'."`

	// ICQ Legacy Protocol Configuration
	ICQLegacy ICQLegacyConfig
}

// ICQLegacyConfig holds configuration for legacy ICQ protocol support (v2-v5)
type ICQLegacyConfig struct {
	Enabled            bool          `envconfig:"ICQ_LEGACY_ENABLED" required:"false" basic:"true" ssl:"true" description:"Enable legacy ICQ protocol support (v2-v5). Allows vintage ICQ clients to connect."`
	UDPListener        string        `envconfig:"ICQ_LEGACY_UDP_LISTENER" required:"false" basic:"0.0.0.0:4000" ssl:"0.0.0.0:4000" description:"UDP listener address for legacy ICQ protocols.\n\nFormat: HOST:PORT\n\nExamples:\n\t// All interfaces\n\t0.0.0.0:4000\n\t// Specific interface\n\t192.168.1.10:4000"`
	SupportedVersions  []int         `envconfig:"ICQ_LEGACY_VERSIONS" required:"false" basic:"2,3,4,5" ssl:"2,3,4,5" description:"Comma-separated list of supported ICQ protocol versions. Valid values: 1, 2, 3, 4, 5 (V1 is experimental)."`
	SessionTimeout     time.Duration `envconfig:"ICQ_LEGACY_SESSION_TIMEOUT" required:"false" basic:"120s" ssl:"120s" description:"Session timeout for legacy ICQ connections. Sessions are cleaned up after this duration of inactivity."`
	KeepAliveInterval  time.Duration `envconfig:"ICQ_LEGACY_KEEPALIVE_INTERVAL" required:"false" basic:"120s" ssl:"120s" description:"Expected keep-alive interval from clients. Used for timeout calculations."`
	AutoRegistration   bool          `envconfig:"ICQ_LEGACY_AUTO_REGISTRATION" required:"false" basic:"false" ssl:"false" description:"Allow automatic user registration from legacy clients. When enabled, new UINs can be created via the legacy protocol."`
	DepartmentsEnabled bool          `envconfig:"ICQ_LEGACY_DEPARTMENTS_ENABLED" required:"false" basic:"false" ssl:"false" description:"Enable department listing feature (groupware functionality)."`
	BroadcastEnabled   bool          `envconfig:"ICQ_LEGACY_BROADCAST_ENABLED" required:"false" basic:"true" ssl:"true" description:"Enable broadcast message functionality."`
	WWPEnabled         bool          `envconfig:"ICQ_LEGACY_WWP_ENABLED" required:"false" basic:"true" ssl:"true" description:"Enable Web Pager (WWP) message support."`
	DirectConnections  []int         `envconfig:"ICQ_LEGACY_DIRECT_CONNECTIONS" required:"false" basic:"5" ssl:"5" description:"Comma-separated list of protocol versions that send real connection info (IP, port) in user online notifications. Disabled for privacy and interoperability. Required for peer-to-peer features (file transfer, direct chat). Example: 5 or 3,4,5"`
}

// DefaultICQLegacyConfig returns the default configuration for ICQ legacy protocol
func DefaultICQLegacyConfig() ICQLegacyConfig {
	return ICQLegacyConfig{
		Enabled:            true,
		UDPListener:        "0.0.0.0:4000",
		SupportedVersions:  []int{2, 3, 4, 5},
		SessionTimeout:     120 * time.Second,
		KeepAliveInterval:  120 * time.Second,
		AutoRegistration:   false,
		DepartmentsEnabled: false,
		BroadcastEnabled:   true,
		WWPEnabled:         true,
	}
}

// SupportsVersion checks if a specific protocol version is enabled
func (c *ICQLegacyConfig) SupportsVersion(version int) bool {
	for _, v := range c.SupportedVersions {
		if v == version {
			return true
		}
	}
	return false
}

// DirectConnectionEnabled checks if direct connections are enabled for a specific protocol version
func (c *ICQLegacyConfig) DirectConnectionEnabled(version int) bool {
	for _, v := range c.DirectConnections {
		if v == version {
			return true
		}
	}
	return false
}

func (c *Config) ParseListenersCfg() ([]ListenerGroup, error) {
	// Helper function to parse and validate a single URI
	parseURI := func(uriStr string) (*url.URL, error) {
		uriStr = strings.TrimSpace(uriStr)
		if uriStr == "" {
			return nil, nil
		}

		u, err := url.Parse(uriStr)
		if err != nil {
			return nil, uriFormatError{URI: uriStr, Err: err}
		}
		switch {
		case u.Scheme == "":
			return nil, uriFormatError{URI: uriStr, Err: errors.New("missing scheme")}
		case u.Hostname() == "":
			return nil, uriFormatError{URI: uriStr, Err: errors.New("missing host")}
		case u.Port() == "":
			return nil, uriFormatError{URI: uriStr, Err: errors.New("missing port")}
		}

		return u, nil
	}

	m := make(map[string]*ListenerGroup)

	// Parse BOS listeners
	for _, uriStr := range c.BOSListeners {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].BOSListenAddress != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSListenAddress = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse SSL BOS listeners
	for _, uriStr := range c.BOSListenersSSL {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].BOSListenAddressSSL != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSListenAddressSSL = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse plaintext BOS advertised listeners
	for _, uriStr := range c.BOSAdvertisedHostsPlain {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].BOSAdvertisedHostPlain != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSAdvertisedHostPlain = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse SSL BOS advertised listeners
	for _, uriStr := range c.BOSAdvertisedHostsSSL {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].BOSAdvertisedHostSSL != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].BOSAdvertisedHostSSL = net.JoinHostPort(u.Hostname(), u.Port())
	}

	// Parse Kerberos listeners
	for _, uriStr := range c.KerberosListeners {
		u, err := parseURI(uriStr)
		if err != nil {
			return nil, err
		}
		if u == nil {
			continue
		}

		if _, ok := m[u.Scheme]; !ok {
			m[u.Scheme] = &ListenerGroup{}
		}
		if m[u.Scheme].KerberosListenAddress != "" {
			return nil, errDuplicateListener
		}
		m[u.Scheme].KerberosListenAddress = net.JoinHostPort(u.Hostname(), u.Port())
	}

	ret := make([]ListenerGroup, 0, len(m))

	for k, v := range m {
		switch {
		case v.BOSAdvertisedHostPlain == "":
			return nil, fmt.Errorf("missing BOS advertise address for listener `%s://`", k)
		case v.BOSListenAddress == "":
			return nil, fmt.Errorf("missing BOS listen address for listener `%s://`", k)
		case v.HasSSL() && v.BOSListenAddressSSL == "":
			return nil, fmt.Errorf("missing SSL BOS listen address for listener `%s://`", k)
		}
		v.Name = k
		ret = append(ret, *v)
	}

	if len(ret) == 0 {
		return nil, errNoBOSListeners
	}

	// Catch sockets that collide across lists or groups, which would otherwise
	// surface at bind time as a bare "address already in use".
	seen := make(map[string]string, len(ret)*3)
	for _, l := range ret {
		for _, socket := range []struct{ envVar, addr string }{
			{"OSCAR_LISTENERS", l.BOSListenAddress},
			{"OSCAR_LISTENERS_SSL", l.BOSListenAddressSSL},
			{"KERBEROS_LISTENERS", l.KerberosListenAddress},
		} {
			if socket.addr == "" {
				continue
			}
			src := fmt.Sprintf("%s `%s://`", socket.envVar, l.Name)
			if prev, ok := seen[socket.addr]; ok {
				return nil, fmt.Errorf("listen address %s is configured for both %s and %s", socket.addr, prev, src)
			}
			seen[socket.addr] = src
		}
	}

	return ret, nil
}

func (c *Config) Validate() error {
	// Validate TOCListeners (format: hostname:port pairs)
	for _, listener := range c.TOCListeners {
		listener = strings.TrimSpace(listener)
		if listener == "" {
			continue
		}

		host, port, err := net.SplitHostPort(listener)
		if err != nil {
			return fmt.Errorf("invalid TOC listener %q: %v. Valid format: HOST:PORT (e.g., 0.0.0.0:9898)", listener, err)
		}

		if host == "" {
			return fmt.Errorf("invalid TOC listener %q: missing host. Valid format: HOST:PORT (e.g., 0.0.0.0:9898)", listener)
		}

		if port == "" {
			return fmt.Errorf("invalid TOC listener %q: missing port. Valid format: HOST:PORT (e.g., 0.0.0.0:9898)", listener)
		}
	}

	// Validate APIListener (format: hostname:port pair, no scheme)
	apiListener := strings.TrimSpace(c.APIListener)
	if apiListener == "" {
		return fmt.Errorf("APIListener is required and cannot be empty")
	}

	host, port, err := net.SplitHostPort(apiListener)
	if err != nil {
		return fmt.Errorf("invalid API listener %q: %v. Valid format: HOST:PORT (e.g., 127.0.0.1:8080)", c.APIListener, err)
	}

	if host == "" {
		return fmt.Errorf("invalid API listener %q: missing host. Valid format: HOST:PORT (e.g., 127.0.0.1:8080)", c.APIListener)
	}

	if port == "" {
		return fmt.Errorf("invalid API listener %q: missing port. Valid format: HOST:PORT (e.g., 127.0.0.1:8080)", c.APIListener)
	}

	// Validate WebAPIListeners (format: hostname:port pairs, no scheme)
	for _, listener := range c.WebAPIListeners {
		listener = strings.TrimSpace(listener)
		if listener == "" {
			continue
		}

		host, port, err := net.SplitHostPort(listener)
		if err != nil {
			return fmt.Errorf("invalid web API listener %q: %v. Valid format: HOST:PORT (e.g., 0.0.0.0:8081)", listener, err)
		}

		if host == "" {
			return fmt.Errorf("invalid web API listener %q: missing host. Valid format: HOST:PORT (e.g., 0.0.0.0:8081)", listener)
		}

		if port == "" {
			return fmt.Errorf("invalid web API listener %q: missing port. Valid format: HOST:PORT (e.g., 0.0.0.0:8081)", listener)
		}
	}

	return nil
}
