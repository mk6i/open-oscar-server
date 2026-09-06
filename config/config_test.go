package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestParseListenersCfg(t *testing.T) {
	tests := []struct {
		name                   string
		bosListeners           []string
		bosAdvertisedListeners []string
		bosAdvertisedHostsSSL  []string
		kerberosListeners      []string
		want                   []ListenerGroup
		wantErr                bool
		errContains            string
		bosListenersSSL        []string
	}{
		{
			name:                   "valid single listener with kerberos",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{"LOCAL://0.0.0.0:1088"},
			want: []ListenerGroup{
				{
					Name:                   "local",
					BOSListenAddress:       "0.0.0.0:5190",
					BOSAdvertisedHostPlain: "127.0.0.1:5190",
					KerberosListenAddress:  "0.0.0.0:1088",
				},
			},
			wantErr: false,
		},
		{
			name:                   "valid single listener without kerberos",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want: []ListenerGroup{
				{
					Name:                   "local",
					BOSListenAddress:       "0.0.0.0:5190",
					BOSAdvertisedHostPlain: "127.0.0.1:5190",
					KerberosListenAddress:  "",
				},
			},
			wantErr: false,
		},
		{
			name:                   "valid multiple listeners with mixed kerberos",
			bosListeners:           []string{"LAN://192.168.1.10:5190", "WAN://0.0.0.0:5191"},
			bosAdvertisedListeners: []string{"LAN://192.168.1.10:5190", "WAN://example.com:5191"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{"LAN://192.168.1.10:1088"},
			want: []ListenerGroup{
				{
					Name:                   "lan",
					BOSListenAddress:       "192.168.1.10:5190",
					BOSAdvertisedHostPlain: "192.168.1.10:5190",
					KerberosListenAddress:  "192.168.1.10:1088",
				},
				{
					Name:                   "wan",
					BOSListenAddress:       "0.0.0.0:5191",
					BOSAdvertisedHostPlain: "example.com:5191",
					KerberosListenAddress:  "",
				},
			},
			wantErr: false,
		},
		{
			name:                   "missing BOS advertised host",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing BOS advertise address",
		},
		{
			name:                   "missing BOS listen address",
			bosListeners:           []string{},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing BOS listen address for listener `local://`",
		},
		{
			name:                   "duplicate listener definition in BOS",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190", "LOCAL://0.0.0.0:5191"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "duplicate listener definition",
		},
		{
			name:                   "duplicate listener definition in advertised",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190", "LOCAL://127.0.0.1:5191"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "duplicate listener definition",
		},
		{
			name:                   "duplicate listener definition in kerberos",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{"LOCAL://0.0.0.0:1088", "LOCAL://0.0.0.0:1089"},
			want:                   nil,
			wantErr:                true,
			errContains:            "duplicate listener definition",
		},
		{
			name:                   "invalid URI format in BOS",
			bosListeners:           []string{"invalid-uri"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing scheme. Valid format",
		},
		{
			name:                   "invalid URI format in advertised",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"invalid-uri"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing scheme. Valid format",
		},
		{
			name:                   "invalid URI format in kerberos",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{"invalid-uri"},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing scheme. Valid format",
		},
		{
			name:                   "URI with underscore in scheme",
			bosListeners:           []string{"LOCAL_://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "Valid format: SCHEME://HOST:PORT",
		},
		{
			name:                   "BOS listener missing port",
			bosListeners:           []string{"LOCAL://0.0.0.0"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing port",
		},
		{
			name:                   "BOS listener missing host",
			bosListeners:           []string{"LOCAL://:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing host",
		},
		{
			name:                   "complex multi-listener setup",
			bosListeners:           []string{"LAN://192.168.1.10:5190", "WAN://0.0.0.0:5191", "DOCKER://172.17.0.1:5192"},
			bosAdvertisedListeners: []string{"DOCKER://172.17.0.1:5192", "LAN://192.168.1.10:5190", "WAN://example.com:5191"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{"WAN://0.0.0.0:1089", "LAN://192.168.1.10:1088"},
			want: []ListenerGroup{
				{
					Name:                   "docker",
					BOSListenAddress:       "172.17.0.1:5192",
					BOSAdvertisedHostPlain: "172.17.0.1:5192",
					BOSAdvertisedHostSSL:   "",
					KerberosListenAddress:  "",
				},
				{
					Name:                   "lan",
					BOSListenAddress:       "192.168.1.10:5190",
					BOSAdvertisedHostPlain: "192.168.1.10:5190",
					BOSAdvertisedHostSSL:   "",
					KerberosListenAddress:  "192.168.1.10:1088",
				},
				{
					Name:                   "wan",
					BOSListenAddress:       "0.0.0.0:5191",
					BOSAdvertisedHostPlain: "example.com:5191",
					BOSAdvertisedHostSSL:   "",
					KerberosListenAddress:  "0.0.0.0:1089",
				},
			},
			wantErr: false,
		},
		{
			name:                   "empty strings for all inputs",
			bosListeners:           []string{},
			bosAdvertisedListeners: []string{},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "at least one BOS listener is required",
		},
		{
			name:                   "whitespace-only strings",
			bosListeners:           []string{"   "},
			bosAdvertisedListeners: []string{"   "},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{"   "},
			want:                   nil,
			wantErr:                true,
			errContains:            "at least one BOS listener is required",
		},
		{
			name:                   "only kerberos listeners provided",
			bosListeners:           []string{},
			bosAdvertisedListeners: []string{},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{"LOCAL://0.0.0.0:1088"},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing BOS advertise address for listener `local://`",
		},
		{
			name:                   "valid single listener with SSL",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosListenersSSL:        []string{"LOCAL://0.0.0.0:5191"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"LOCAL://127.0.0.1:5193"},
			kerberosListeners:      []string{},
			want: []ListenerGroup{
				{
					Name:                   "local",
					BOSListenAddress:       "0.0.0.0:5190",
					BOSListenAddressSSL:    "0.0.0.0:5191",
					BOSAdvertisedHostPlain: "127.0.0.1:5190",
					BOSAdvertisedHostSSL:   "127.0.0.1:5193",
					KerberosListenAddress:  "",
				},
			},
			wantErr: false,
		},
		{
			name:                   "valid multiple listeners with mixed SSL",
			bosListeners:           []string{"LAN://192.168.1.10:5190", "WAN://0.0.0.0:5191"},
			bosListenersSSL:        []string{"LAN://192.168.1.10:5195"},
			bosAdvertisedListeners: []string{"LAN://192.168.1.10:5190", "WAN://example.com:5191"},
			bosAdvertisedHostsSSL:  []string{"LAN://192.168.1.10:5193"},
			kerberosListeners:      []string{},
			want: []ListenerGroup{
				{
					Name:                   "lan",
					BOSListenAddress:       "192.168.1.10:5190",
					BOSListenAddressSSL:    "192.168.1.10:5195",
					BOSAdvertisedHostPlain: "192.168.1.10:5190",
					BOSAdvertisedHostSSL:   "192.168.1.10:5193",
					KerberosListenAddress:  "",
				},
				{
					Name:                   "wan",
					BOSListenAddress:       "0.0.0.0:5191",
					BOSAdvertisedHostPlain: "example.com:5191",
					BOSAdvertisedHostSSL:   "",
					KerberosListenAddress:  "",
				},
			},
			wantErr: false,
		},
		{
			name:                   "advertised SSL host without an SSL listen address",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"LOCAL://127.0.0.1:5193"},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing SSL BOS listen address for listener `local://`",
		},
		{
			name:                   "SSL listen address without advertised SSL host",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosListenersSSL:        []string{"LOCAL://0.0.0.0:5191"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want: []ListenerGroup{
				{
					Name:                   "local",
					BOSListenAddress:       "0.0.0.0:5190",
					BOSListenAddressSSL:    "0.0.0.0:5191",
					BOSAdvertisedHostPlain: "127.0.0.1:5190",
					BOSAdvertisedHostSSL:   "",
					KerberosListenAddress:  "",
				},
			},
			wantErr: false,
		},
		{
			name:                   "SSL listener with kerberos",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosListenersSSL:        []string{"LOCAL://0.0.0.0:5191"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"LOCAL://127.0.0.1:5193"},
			kerberosListeners:      []string{"LOCAL://0.0.0.0:1088"},
			want: []ListenerGroup{
				{
					Name:                   "local",
					BOSListenAddress:       "0.0.0.0:5190",
					BOSListenAddressSSL:    "0.0.0.0:5191",
					BOSAdvertisedHostPlain: "127.0.0.1:5190",
					BOSAdvertisedHostSSL:   "127.0.0.1:5193",
					KerberosListenAddress:  "0.0.0.0:1088",
				},
			},
			wantErr: false,
		},
		{
			name:                   "duplicate SSL BOS listen address",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosListenersSSL:        []string{"LOCAL://0.0.0.0:5191", "LOCAL://0.0.0.0:5192"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"LOCAL://127.0.0.1:5193"},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "duplicate listener definition",
		},
		{
			name:                   "plaintext and SSL BOS listeners share an address",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosListenersSSL:        []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"LOCAL://127.0.0.1:5193"},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "listen address 0.0.0.0:5190 is configured for both OSCAR_LISTENERS `local://` and OSCAR_LISTENERS_SSL `local://`",
		},
		{
			name:                   "BOS listeners in different groups share an address",
			bosListeners:           []string{"LAN://0.0.0.0:5190", "WAN://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LAN://192.168.1.10:5190", "WAN://example.com:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "listen address 0.0.0.0:5190 is configured for both OSCAR_LISTENERS `lan://` and OSCAR_LISTENERS `wan://`",
		},
		{
			name:                   "BOS and kerberos listeners share an address",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{},
			kerberosListeners:      []string{"LOCAL://0.0.0.0:5190"},
			want:                   nil,
			wantErr:                true,
			errContains:            "listen address 0.0.0.0:5190 is configured for both OSCAR_LISTENERS `local://` and KERBEROS_LISTENERS `local://`",
		},
		{
			name:                   "SSL BOS listener missing port",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosListenersSSL:        []string{"LOCAL://0.0.0.0"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"LOCAL://127.0.0.1:5193"},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing port",
		},
		{
			name:                   "SSL host without corresponding BOS listener",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"WAN://ssl.example.com:5193"},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing BOS advertise address for listener `wan://`",
		},
		{
			name:                   "duplicate SSL listener definition",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"LOCAL://127.0.0.1:5193", "LOCAL://127.0.0.1:5194"},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "duplicate listener definition",
		},
		{
			name:                   "invalid URI format in SSL",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"invalid-uri"},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing scheme. Valid format",
		},
		{
			name:                   "SSL listener missing port",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"LOCAL://127.0.0.1"},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing port",
		},
		{
			name:                   "SSL listener missing host",
			bosListeners:           []string{"LOCAL://0.0.0.0:5190"},
			bosAdvertisedListeners: []string{"LOCAL://127.0.0.1:5190"},
			bosAdvertisedHostsSSL:  []string{"LOCAL://:5193"},
			kerberosListeners:      []string{},
			want:                   nil,
			wantErr:                true,
			errContains:            "missing host",
		},
		{
			name:                   "complex multi-listener setup with SSL",
			bosListeners:           []string{"LAN://192.168.1.10:5190", "WAN://0.0.0.0:5191", "DOCKER://172.17.0.1:5192"},
			bosListenersSSL:        []string{"LAN://192.168.1.10:5195", "WAN://0.0.0.0:5196"},
			bosAdvertisedListeners: []string{"DOCKER://172.17.0.1:5192", "LAN://192.168.1.10:5190", "WAN://example.com:5191"},
			bosAdvertisedHostsSSL:  []string{"LAN://192.168.1.10:5193", "WAN://ssl.example.com:5194"},
			kerberosListeners:      []string{"WAN://0.0.0.0:1089", "LAN://192.168.1.10:1088"},
			want: []ListenerGroup{
				{
					Name:                   "docker",
					BOSListenAddress:       "172.17.0.1:5192",
					BOSAdvertisedHostPlain: "172.17.0.1:5192",
					BOSAdvertisedHostSSL:   "",
					KerberosListenAddress:  "",
				},
				{
					Name:                   "lan",
					BOSListenAddress:       "192.168.1.10:5190",
					BOSListenAddressSSL:    "192.168.1.10:5195",
					BOSAdvertisedHostPlain: "192.168.1.10:5190",
					BOSAdvertisedHostSSL:   "192.168.1.10:5193",
					KerberosListenAddress:  "192.168.1.10:1088",
				},
				{
					Name:                   "wan",
					BOSListenAddress:       "0.0.0.0:5191",
					BOSListenAddressSSL:    "0.0.0.0:5196",
					BOSAdvertisedHostPlain: "example.com:5191",
					BOSAdvertisedHostSSL:   "ssl.example.com:5194",
					KerberosListenAddress:  "0.0.0.0:1089",
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				BOSListeners:            tt.bosListeners,
				BOSListenersSSL:         tt.bosListenersSSL,
				BOSAdvertisedHostsPlain: tt.bosAdvertisedListeners,
				BOSAdvertisedHostsSSL:   tt.bosAdvertisedHostsSSL,
				KerberosListeners:       tt.kerberosListeners,
			}
			got, err := config.ParseListenersCfg()

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseListenersCfg() expected error but got none")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("ParseListenersCfg() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseListenersCfg() unexpected error = %v", err)
				return
			}

			// groups come back in map order; want is listed by name
			slices.SortFunc(got, func(a, b ListenerGroup) int {
				return strings.Compare(a.Name, b.Name)
			})

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseListenersCfg() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		wantErr     bool
		errContains string
	}{
		{
			name: "valid config with all fields",
			config: Config{
				TOCListeners:    []string{"0.0.0.0:9898", "192.168.1.10:9899"},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{"0.0.0.0:8081"},
			},
			wantErr: false,
		},
		{
			name: "valid config with single TOC listener",
			config: Config{
				TOCListeners:    []string{"0.0.0.0:9898"},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{"0.0.0.0:8081"},
			},
			wantErr: false,
		},
		{
			name: "valid config with empty TOC listeners",
			config: Config{
				TOCListeners:    []string{},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{"0.0.0.0:8081"},
			},
			wantErr: false,
		},
		{
			name: "valid config with empty API listener",
			config: Config{
				TOCListeners: []string{"0.0.0.0:9898"},
				APIListener:  "",
			},
			wantErr:     true,
			errContains: "APIListener is required and cannot be empty",
		},
		{
			name: "valid config with all empty",
			config: Config{
				TOCListeners: []string{},
				APIListener:  "",
			},
			wantErr:     true,
			errContains: "APIListener is required and cannot be empty",
		},
		{
			name: "invalid TOC listener - missing port",
			config: Config{
				TOCListeners: []string{"0.0.0.0"},
				APIListener:  "127.0.0.1:8080",
			},
			wantErr:     true,
			errContains: "invalid TOC listener \"0.0.0.0\": address 0.0.0.0: missing port in address",
		},
		{
			name: "invalid TOC listener - missing host",
			config: Config{
				TOCListeners: []string{":9898"},
				APIListener:  "127.0.0.1:8080",
			},
			wantErr:     true,
			errContains: "invalid TOC listener \":9898\": missing host",
		},
		{
			name: "invalid TOC listener - malformed",
			config: Config{
				TOCListeners: []string{"invalid-format"},
				APIListener:  "127.0.0.1:8080",
			},
			wantErr:     true,
			errContains: "invalid TOC listener \"invalid-format\": address invalid-format: missing port in address",
		},
		{
			name: "invalid TOC listener in comma-separated list",
			config: Config{
				TOCListeners: []string{"0.0.0.0:9898", "invalid-format", "192.168.1.10:9899"},
				APIListener:  "127.0.0.1:8080",
			},
			wantErr:     true,
			errContains: "invalid TOC listener \"invalid-format\": address invalid-format: missing port in address",
		},
		{
			name: "invalid API listener - missing port",
			config: Config{
				TOCListeners: []string{"0.0.0.0:9898"},
				APIListener:  "127.0.0.1",
			},
			wantErr:     true,
			errContains: "invalid API listener \"127.0.0.1\": address 127.0.0.1: missing port in address",
		},
		{
			name: "invalid API listener - missing host",
			config: Config{
				TOCListeners: []string{"0.0.0.0:9898"},
				APIListener:  ":8080",
			},
			wantErr:     true,
			errContains: "invalid API listener \":8080\": missing host",
		},
		{
			name: "invalid API listener - malformed",
			config: Config{
				TOCListeners: []string{"0.0.0.0:9898"},
				APIListener:  "invalid-format",
			},
			wantErr:     true,
			errContains: "invalid API listener \"invalid-format\": address invalid-format: missing port in address",
		},
		{
			name: "whitespace-only TOC listeners",
			config: Config{
				TOCListeners:    []string{"   ", "  ", "  "},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{"0.0.0.0:8081"},
			},
			wantErr: false,
		},
		{
			name: "whitespace-only API listener",
			config: Config{
				TOCListeners:    []string{"0.0.0.0:9898"},
				APIListener:     "   ",
				WebAPIListeners: []string{"0.0.0.0:8081"},
			},
			wantErr:     true,
			errContains: "APIListener is required and cannot be empty",
		},
		{
			name: "valid multiple web API listeners",
			config: Config{
				TOCListeners:    []string{"0.0.0.0:9898"},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{"0.0.0.0:8081", "192.168.1.10:8082"},
			},
			wantErr: false,
		},
		{
			name: "whitespace-only web API listeners",
			config: Config{
				TOCListeners:    []string{"0.0.0.0:9898"},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{"   ", "  "},
			},
			wantErr: false,
		},
		{
			name: "invalid web API listener - missing port",
			config: Config{
				TOCListeners:    []string{"0.0.0.0:9898"},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{"0.0.0.0"},
			},
			wantErr:     true,
			errContains: "invalid web API listener \"0.0.0.0\": address 0.0.0.0: missing port in address",
		},
		{
			name: "invalid web API listener - missing host",
			config: Config{
				TOCListeners:    []string{"0.0.0.0:9898"},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{":8081"},
			},
			wantErr:     true,
			errContains: "invalid web API listener \":8081\": missing host",
		},
		{
			name: "invalid web API listener - malformed",
			config: Config{
				TOCListeners:    []string{"0.0.0.0:9898"},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{"invalid-format"},
			},
			wantErr:     true,
			errContains: "invalid web API listener \"invalid-format\": address invalid-format: missing port in address",
		},
		{
			name: "invalid web API listener in comma-separated list",
			config: Config{
				TOCListeners:    []string{"0.0.0.0:9898"},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{"0.0.0.0:8081", "invalid-format", "192.168.1.10:8082"},
			},
			wantErr:     true,
			errContains: "invalid web API listener \"invalid-format\": address invalid-format: missing port in address",
		},
		{
			name: "valid multiple web API allowed origins",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"https://aim.example.com", "http://localhost:8000", " http://ras.dev "},
			},
			wantErr: false,
		},
		{
			name: "wildcard web API allowed origin",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"*"},
			},
			wantErr: false,
		},
		{
			// An empty list is a valid setting meaning "allow any origin", not a
			// misconfiguration. There is no way to express "deny all".
			name: "empty web API allowed origins",
			config: Config{
				TOCListeners:    []string{"0.0.0.0:9898"},
				APIListener:     "127.0.0.1:8080",
				WebAPIListeners: []string{"0.0.0.0:8081"},
			},
			wantErr: false,
		},
		{
			name: "whitespace-only web API allowed origins",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"  ", ""},
			},
			wantErr: false,
		},
		{
			name: "invalid web API allowed origin - trailing slash",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"http://localhost:8000/"},
			},
			wantErr:     true,
			errContains: "invalid web API allowed origin \"http://localhost:8000/\": must not have a trailing slash, path, query, fragment or userinfo",
		},
		{
			name: "invalid web API allowed origin - has a path",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"https://aim.example.com/client"},
			},
			wantErr:     true,
			errContains: "must not have a trailing slash, path, query, fragment or userinfo",
		},
		{
			name: "invalid web API allowed origin - missing scheme",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"aim.example.com"},
			},
			wantErr:     true,
			errContains: "scheme must be http or https",
		},
		{
			name: "invalid web API allowed origin - unsupported scheme",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"ftp://aim.example.com"},
			},
			wantErr:     true,
			errContains: "scheme must be http or https",
		},
		{
			name: "valid web API allowed origin - port wildcard",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"http://localhost:*"},
			},
			wantErr: false,
		},
		{
			name: "valid web API allowed origin - host wildcard with port",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"http://*:8000", "https://*"},
			},
			wantErr: false,
		},
		{
			// Underscores are legal in a host and browsers send them verbatim.
			name: "valid web API allowed origin - underscore host",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"http://my_host:8080"},
			},
			wantErr: false,
		},
		{
			name: "valid web API allowed origin - IPv6 literal",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"http://[::1]:8000"},
			},
			wantErr: false,
		},
		{
			name: "invalid web API allowed origin - two wildcards",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"http://*.example.*"},
			},
			wantErr:     true,
			errContains: "only one wildcard is allowed per origin",
		},
		{
			name: "invalid web API allowed origin - wildcard scheme",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"*://example.com"},
			},
			wantErr:     true,
			errContains: "cannot itself be a wildcard",
		},
		{
			name: "invalid web API allowed origin - wildcard with default port",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"https://*.example.com:443"},
			},
			wantErr:     true,
			errContains: "a browser omits the default port, so this would never match. Use \"https://*.example.com\"",
		},
		{
			name: "invalid web API allowed origin - wildcard with path",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"http://localhost:*/x"},
			},
			wantErr:     true,
			errContains: "must not have a trailing slash, path, query, fragment or userinfo",
		},
		{
			name: "invalid web API allowed origin - explicit https default port",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"https://ras.dev:443"},
			},
			wantErr:     true,
			errContains: "a browser omits the default port, so this would never match. Use \"https://ras.dev\"",
		},
		{
			name: "invalid web API allowed origin - explicit http default port",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"http://localhost:80"},
			},
			wantErr:     true,
			errContains: "a browser omits the default port, so this would never match. Use \"http://localhost\"",
		},
		{
			name: "invalid web API allowed origin - userinfo",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"http://user@example.com"},
			},
			wantErr:     true,
			errContains: "must not have a trailing slash, path, query, fragment or userinfo",
		},
		{
			name: "invalid web API allowed origin - forced empty query",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"https://example.com?"},
			},
			wantErr:     true,
			errContains: "must not have a trailing slash, path, query, fragment or userinfo",
		},
		{
			// A non-default port is part of the origin and must be kept.
			name: "valid web API allowed origin - non-default port",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"http://localhost:8000", "https://ras.dev:8443"},
			},
			wantErr: false,
		},
		{
			// rs/cors matches case-insensitively, so this does work at runtime.
			name: "valid web API allowed origin - uppercase",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"HTTPS://RAS.DEV"},
			},
			wantErr: false,
		},
		{
			// rs/cors supports one wildcard per entry.
			name: "valid web API allowed origin - subdomain wildcard",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"https://*.example.com"},
			},
			wantErr: false,
		},
		{
			name: "invalid web API allowed origin - missing host",
			config: Config{
				TOCListeners:         []string{"0.0.0.0:9898"},
				APIListener:          "127.0.0.1:8080",
				WebAPIListeners:      []string{"0.0.0.0:8081"},
				WebAPIAllowedOrigins: []string{"https://"},
			},
			wantErr:     true,
			errContains: "missing host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Config.Validate() expected error but got none")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("Config.Validate() error = %v, want error containing %q", err, tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("Config.Validate() unexpected error = %v", err)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr ||
			func() bool {
				for i := 1; i <= len(s)-len(substr); i++ {
					if s[i:i+len(substr)] == substr {
						return true
					}
				}
				return false
			}())))
}
