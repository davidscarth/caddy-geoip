// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

// MaxMind's anonymizer test databases. Addresses used below, from the
// source JSON in github.com/maxmind/MaxMind-DB:
//
//	1.2.0.0/16      anonymous, vpn                  (Anonymous IP, Plus)
//	1.124.213.1/32  anonymous, vpn, tor             (Anonymous IP)
//	81.2.69.0/24    all six                         (Anonymous IP)
//	186.30.236.0/24 anonymous, public_proxy         (Anonymous IP)
//	6.1.2.1/32      anonymous, vpn, with ip_risk    (IP Risk)
//	55.0.0.1/32     ip_risk only, no flags          (IP Risk)
//	8.8.8.8         clean: empty record in Anonymous IP, absent in IP Risk
const (
	anonDB     = "testdata/GeoIP2-Anonymous-IP-Test.mmdb"
	anonPlusDB = "testdata/GeoIP-Anonymous-Plus-Test.mmdb"
	ipRiskDB   = "testdata/GeoIP2-IP-Risk-Test.mmdb"
	resProxyDB = "testdata/GeoIP-Residential-Proxy-Test.mmdb"
)

func TestAnonymousUnmarshalCaddyfile(t *testing.T) {
	for _, tc := range []struct {
		input     string
		wantTypes int
		wantErr   bool
	}{
		{
			input: `geoip_anonymous {
				db /tmp/Anon.mmdb
				type vpn tor
			}`,
			wantTypes: 2,
		},
		{
			input: `geoip_anonymous {
				db /tmp/Anon.mmdb
				type anonymous
				type hosting public_proxy residential_proxy
			}`,
			wantTypes: 4,
		},
		{
			// case is folded, like the codes on the other matchers
			input: `geoip_anonymous {
				db /tmp/Anon.mmdb
				type VPN
			}`,
			wantTypes: 1,
		},
		{
			input:   `geoip_anonymous /tmp/Anon.mmdb`,
			wantErr: true,
		},
		{
			input: `geoip_anonymous {
				db /tmp/Anon.mmdb
				type
			}`,
			wantErr: true,
		},
		{
			input: `geoip_anonymous {
				db /tmp/Anon.mmdb
				type proxy
			}`,
			wantErr: true,
		},
		{
			// there is no match_unknown on this matcher
			input: `geoip_anonymous {
				db /tmp/Anon.mmdb
				type vpn
				match_unknown
			}`,
			wantErr: true,
		},
		{
			input: `geoip_anonymous {
				db /tmp/Anon.mmdb
				db /tmp/Other.mmdb
				type vpn
			}`,
			wantErr: true,
		},
	} {
		var m MatchGeoIPAnonymous
		err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if (err != nil) != tc.wantErr {
			t.Errorf("UnmarshalCaddyfile(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
		}
		if err == nil && len(m.Types) != tc.wantTypes {
			t.Errorf("UnmarshalCaddyfile(%q) got %d types, want %d", tc.input, len(m.Types), tc.wantTypes)
		}
	}
}

func TestAnonymousValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		m       MatchGeoIPAnonymous
		wantErr bool
	}{
		{name: "complete", m: MatchGeoIPAnonymous{DB: "x.mmdb", Types: []string{"vpn"}}},
		{name: "no db", m: MatchGeoIPAnonymous{Types: []string{"vpn"}}, wantErr: true},
		{name: "no types", m: MatchGeoIPAnonymous{DB: "x.mmdb"}, wantErr: true},
	} {
		if err := tc.m.Validate(); (err != nil) != tc.wantErr {
			t.Errorf("%s: Validate() error = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestAnonymousProvisionRejects(t *testing.T) {
	// An unknown kind is rejected by name.
	m := MatchGeoIPAnonymous{DB: anonDB, Types: []string{"vpn", "proxy"}}
	err := m.Provision(caddy.Context{})
	if err == nil || !strings.Contains(err.Error(), "proxy") {
		t.Errorf("expected provision to reject type proxy by name, got %v", err)
	}

	// Databases without the flags are rejected by type: a Country file,
	// and MaxMind's Residential Proxy edition, which carries a confidence
	// score but none of the booleans.
	for _, db := range []string{countryDB, resProxyDB} {
		m := MatchGeoIPAnonymous{DB: db, Types: []string{"vpn"}}
		if err := m.Provision(caddy.Context{}); err == nil {
			t.Errorf("expected provision to reject %s", db)
		}
	}
}

func TestAnonymousAcceptsEditions(t *testing.T) {
	// All three editions that carry the flags pass the type check.
	for _, db := range []string{anonDB, anonPlusDB, ipRiskDB} {
		m := MatchGeoIPAnonymous{DB: db, Types: []string{"vpn"}}
		if err := m.Provision(caddy.Context{}); err != nil {
			t.Fatalf("%s: provision: %v", db, err)
		}
	}
}

func TestAnonymousMatch(t *testing.T) {
	for _, tc := range []struct {
		name  string
		db    string
		types []string
		addr  string
		want  bool
	}{
		{"vpn matches vpn", anonDB, []string{"vpn"}, "1.2.0.1:1234", true},
		{"tor does not match vpn-only", anonDB, []string{"tor"}, "1.2.0.1:1234", false},
		{"tor matches vpn+tor", anonDB, []string{"tor"}, "1.124.213.1:1234", true},
		{"one of several", anonDB, []string{"hosting", "tor"}, "1.124.213.1:1234", true},
		{"anonymous is the umbrella", anonDB, []string{"anonymous"}, "186.30.236.1:1234", true},
		{"public proxy", anonDB, []string{"public_proxy"}, "186.30.236.1:1234", true},
		{"all six", anonDB, []string{"residential_proxy"}, "81.2.69.0:1234", true},
		{"lower case config", anonDB, []string{"TOR"}, "1.124.213.1:1234", true},
		// A clean address has an empty record in Anonymous IP and no
		// record at all in IP Risk; both mean not anonymous.
		{"clean, empty record", anonDB, []string{"anonymous"}, "8.8.8.8:1234", false},
		{"clean, no record", ipRiskDB, []string{"anonymous"}, "8.8.8.8:1234", false},
		{"private, no record", anonDB, []string{"anonymous"}, "10.1.2.3:1234", false},
		// Extra fields on the newer editions are ignored.
		{"anonymous plus", anonPlusDB, []string{"vpn"}, "1.2.0.1:1234", true},
		{"ip risk with flags", ipRiskDB, []string{"vpn"}, "6.1.2.1:1234", true},
		// A score with no flags is not a match for any kind.
		{"ip risk score only", ipRiskDB, []string{"anonymous"}, "55.0.0.1:1234", false},
		{"unparseable address", anonDB, []string{"anonymous"}, "not-an-address", false},
	} {
		m := MatchGeoIPAnonymous{DB: tc.db, Types: tc.types}
		if err := m.Provision(caddy.Context{}); err != nil {
			t.Fatalf("%s: provision: %v", tc.name, err)
		}
		got, err := m.MatchWithError(newRequest(tc.addr))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestAnonymousPlaceholder(t *testing.T) {
	m := MatchGeoIPAnonymous{DB: anonDB, Types: []string{"tor"}}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	for _, tc := range []struct{ addr, want string }{
		{"1.124.213.1:1234", "anonymous,vpn,tor"},
		{"81.2.69.0:1234", "anonymous,vpn,tor,hosting,public_proxy,residential_proxy"},
		{"186.30.236.1:1234", "anonymous,public_proxy"},
		// Set, to empty, whether the record is empty or absent.
		{"8.8.8.8:1234", ""},
		{"10.1.2.3:1234", ""},
	} {
		r := newRequest(tc.addr)
		if _, err := m.MatchWithError(r); err != nil {
			t.Fatal(err)
		}
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		v, known := repl.Get("geoip.anonymous")
		if !known {
			t.Errorf("%s: placeholder not set", tc.addr)
		}
		if v != tc.want {
			t.Errorf("%s: placeholder %q, want %q", tc.addr, v, tc.want)
		}
	}
}

func TestKindsOf(t *testing.T) {
	for mask, want := range map[uint8]string{
		0:  "",
		1:  "anonymous",
		2:  "vpn",
		3:  "anonymous,vpn",
		63: "anonymous,vpn,tor,hosting,public_proxy,residential_proxy",
	} {
		if got := kindsOf(mask); got != want {
			t.Errorf("kindsOf(%d) = %q, want %q", mask, got, want)
		}
	}
}
