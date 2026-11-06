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
			input: `geoip_anonymous {
				db /tmp/Anon.mmdb
				type public_proxy
				confidence 60
			}`,
			wantTypes: 1,
		},
		{
			input: `geoip_anonymous {
				db /tmp/Anon.mmdb
				type public_proxy
				confidence 0
			}`,
			wantErr: true,
		},
		{
			input: `geoip_anonymous {
				db /tmp/Anon.mmdb
				type public_proxy
				confidence 100
			}`,
			wantErr: true,
		},
		{
			input: `geoip_anonymous {
				db /tmp/Risk.mmdb
				risk 80
			}`,
			wantTypes: 0,
		},
		{
			input: `geoip_anonymous {
				db /tmp/Risk.mmdb
				risk 100
			}`,
			wantErr: true,
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
		{name: "risk alone", m: MatchGeoIPAnonymous{DB: "x.mmdb", MinRisk: 80}},
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
		t.Errorf("Provision() error = %v, want one naming type proxy", err)
	}

	// A cutoff needs a proxy type to apply to, and a database that
	// carries confidences.
	m = MatchGeoIPAnonymous{DB: anonPlusDB, Types: []string{"vpn"}, MinConfidence: 50}
	if err := m.Provision(caddy.Context{}); err == nil || !strings.Contains(err.Error(), "proxy") {
		t.Errorf("confidence without a proxy type: error = %v, want one naming proxy", err)
	}
	m = MatchGeoIPAnonymous{DB: anonDB, Types: []string{"public_proxy"}, MinConfidence: 50}
	if err := m.Provision(caddy.Context{}); err == nil || !strings.Contains(err.Error(), "Anonymous Plus") {
		t.Errorf("confidence on Anonymous IP: error = %v, want one naming Anonymous Plus", err)
	}
	for _, db := range []string{anonPlusDB, ipRiskDB} {
		m = MatchGeoIPAnonymous{DB: db, Types: []string{"residential_proxy"}, MinConfidence: 50}
		if err := m.Provision(caddy.Context{}); err != nil {
			t.Errorf("confidence on %s: %v", db, err)
		}
	}
	m = MatchGeoIPAnonymous{DB: anonPlusDB, MinRisk: 80}
	if err := m.Provision(caddy.Context{}); err == nil || !strings.Contains(err.Error(), "IP Risk") {
		t.Errorf("risk on Anonymous Plus: error = %v, want one naming IP Risk", err)
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
		{name: "vpn matches vpn", db: anonDB, types: []string{"vpn"}, addr: "1.2.0.1:1234", want: true},
		{name: "tor does not match vpn-only", db: anonDB, types: []string{"tor"}, addr: "1.2.0.1:1234", want: false},
		{name: "tor matches vpn+tor", db: anonDB, types: []string{"tor"}, addr: "1.124.213.1:1234", want: true},
		{name: "one of several", db: anonDB, types: []string{"hosting", "tor"}, addr: "1.124.213.1:1234", want: true},
		{name: "anonymous is the umbrella", db: anonDB, types: []string{"anonymous"}, addr: "186.30.236.1:1234", want: true},
		{name: "public proxy", db: anonDB, types: []string{"public_proxy"}, addr: "186.30.236.1:1234", want: true},
		{name: "all six", db: anonDB, types: []string{"residential_proxy"}, addr: "81.2.69.0:1234", want: true},
		{name: "lower case config", db: anonDB, types: []string{"TOR"}, addr: "1.124.213.1:1234", want: true},
		// A clean address has an empty record in Anonymous IP and no
		// record at all in IP Risk; both mean not anonymous.
		{name: "clean, empty record", db: anonDB, types: []string{"anonymous"}, addr: "8.8.8.8:1234", want: false},
		{name: "clean, no record", db: ipRiskDB, types: []string{"anonymous"}, addr: "8.8.8.8:1234", want: false},
		{name: "private, no record", db: anonDB, types: []string{"anonymous"}, addr: "10.1.2.3:1234", want: false},
		// Extra fields on the newer editions are ignored.
		{name: "anonymous plus", db: anonPlusDB, types: []string{"vpn"}, addr: "1.2.0.1:1234", want: true},
		{name: "ip risk with flags", db: ipRiskDB, types: []string{"vpn"}, addr: "6.1.2.1:1234", want: true},
		// A score with no flags is not a match for any kind.
		{name: "ip risk score only", db: ipRiskDB, types: []string{"anonymous"}, addr: "55.0.0.1:1234", want: false},

		{name: "unparseable address", db: anonDB, types: []string{"anonymous"}, addr: "not-an-address", want: false},
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

// TestAnonymousCutoffs pins the two cutoffs against the test data. No
// proxy there carries a confidence, so the drop itself is pinned on mask;
// here a proxy without one stands as published, a vpn's confidence is never
// consulted (1.2.0.1 is a vpn at 30), and risk matches on the score alone.
func TestAnonymousCutoffs(t *testing.T) {
	for _, tc := range []struct {
		name string
		m    MatchGeoIPAnonymous
		addr string
		want bool
	}{
		{name: "proxy without confidence stands", m: MatchGeoIPAnonymous{DB: anonPlusDB, Types: []string{"public_proxy"}, MinConfidence: 90}, addr: "6.1.0.3:1234", want: true},
		{name: "vpn below the cutoff is still a vpn", m: MatchGeoIPAnonymous{DB: anonPlusDB, Types: []string{"vpn", "public_proxy"}, MinConfidence: 90}, addr: "1.2.0.1:1234", want: true},
		{name: "risk alone, flagless record at 99", m: MatchGeoIPAnonymous{DB: ipRiskDB, MinRisk: 80}, addr: "55.0.0.4:1234", want: true},
		{name: "risk alone, flagless record at 85", m: MatchGeoIPAnonymous{DB: ipRiskDB, MinRisk: 80}, addr: "214.2.3.6:1234", want: true},
		{name: "risk alone, below at 65", m: MatchGeoIPAnonymous{DB: ipRiskDB, MinRisk: 80}, addr: "55.0.0.1:1234", want: false},
		{name: "risk at the cutoff", m: MatchGeoIPAnonymous{DB: ipRiskDB, MinRisk: 65}, addr: "55.0.0.1:1234", want: true},
		{name: "type or risk: vpn at 75 matches on vpn", m: MatchGeoIPAnonymous{DB: ipRiskDB, Types: []string{"vpn"}, MinRisk: 80}, addr: "6.1.2.1:1234", want: true},
		{name: "type or risk: hosting at 60 matches neither", m: MatchGeoIPAnonymous{DB: ipRiskDB, Types: []string{"vpn"}, MinRisk: 80}, addr: "7.1.2.2:1234", want: false},
		{name: "type or risk: flagless at 99 matches on risk", m: MatchGeoIPAnonymous{DB: ipRiskDB, Types: []string{"vpn"}, MinRisk: 80}, addr: "55.0.0.4:1234", want: true},
		{name: "risk, no record", m: MatchGeoIPAnonymous{DB: ipRiskDB, MinRisk: 1}, addr: "8.8.8.8:1234", want: false},
	} {
		if err := tc.m.Provision(caddy.Context{}); err != nil {
			t.Fatalf("%s: provision: %v", tc.name, err)
		}
		got, err := tc.m.MatchWithError(newRequest(tc.addr))
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v, want %v", tc.name, got, err, tc.want)
		}
	}
}

// TestConfidencePlaceholder pins {geoip.confidence} and {geoip.risk}: the
// number when the record carries one, empty when it does not.
func TestConfidencePlaceholder(t *testing.T) {
	m := MatchGeoIPAnonymous{DB: anonPlusDB, Types: []string{"vpn"}}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	for _, tc := range []struct{ addr, want string }{
		{addr: "1.2.0.1:1234", want: "30"},
		{addr: "1.2.0.2:1234", want: "99"},
		{addr: "1.2.0.0:1234", want: ""},
		{addr: "8.8.8.8:1234", want: ""},
	} {
		r := newRequest(tc.addr)
		if _, err := m.MatchWithError(r); err != nil {
			t.Fatal(err)
		}
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		if v := repl.ReplaceAll("{geoip.confidence}", ""); v != tc.want {
			t.Errorf("%s: {geoip.confidence} = %q, want %q", tc.addr, v, tc.want)
		}
	}
	m = MatchGeoIPAnonymous{DB: ipRiskDB, MinRisk: 1}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	for _, tc := range []struct{ addr, want string }{
		{addr: "6.1.2.1:1234", want: "75"},
		{addr: "55.0.0.4:1234", want: "99"},
		{addr: "11.1.2.3:1234", want: ""},
	} {
		r := newRequest(tc.addr)
		if _, err := m.MatchWithError(r); err != nil {
			t.Fatal(err)
		}
		repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
		if v := repl.ReplaceAll("{geoip.risk}", ""); v != tc.want {
			t.Errorf("%s: {geoip.risk} = %q, want %q", tc.addr, v, tc.want)
		}
	}
}

func TestAnonymousPlaceholder(t *testing.T) {
	m := MatchGeoIPAnonymous{DB: anonDB, Types: []string{"tor"}}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	for _, tc := range []struct{ addr, want string }{
		{addr: "1.124.213.1:1234", want: "anonymous,vpn,tor"},
		{addr: "81.2.69.0:1234", want: "anonymous,vpn,tor,hosting,public_proxy,residential_proxy"},
		{addr: "186.30.236.1:1234", want: "anonymous,public_proxy"},
		// Set, to empty, whether the record is empty or absent.
		{addr: "8.8.8.8:1234", want: ""},
		{addr: "10.1.2.3:1234", want: ""},
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

func TestAnonFlagsMask(t *testing.T) {
	for _, tc := range []struct {
		f    anonFlags
		want uint8
	}{
		{anonFlags{}, 0},
		{anonFlags{Anonymous: true}, 1},
		{anonFlags{Anonymous: true, VPN: true}, 3},
		// A file that sets a kind without the umbrella still reports both.
		{anonFlags{VPN: true}, 3},
		{anonFlags{Tor: true, Hosting: true}, 1 | 4 | 8},
		{anonFlags{Anonymous: true, VPN: true, Tor: true, Hosting: true, PublicProxy: true, ResidentialProxy: true}, 63},
	} {
		if got := tc.f.mask(0); got != tc.want {
			t.Errorf("%+v: mask %d, want %d", tc.f, got, tc.want)
		}
	}
}

// TestAnonFlagsMaskConfidence pins the cutoff: it drops public_proxy and
// residential_proxy, together, when the record carries a confidence below
// it, and touches nothing else. A record without one is not judged.
func TestAnonFlagsMaskConfidence(t *testing.T) {
	both := anonFlags{Anonymous: true, PublicProxy: true, ResidentialProxy: true}
	for _, tc := range []struct {
		name   string
		f      anonFlags
		cutoff uint8
		want   uint8
	}{
		{name: "below cutoff drops both proxies, keeps the umbrella", f: withConf(both, 54), cutoff: 60, want: 1},
		{name: "at cutoff keeps both", f: withConf(both, 54), cutoff: 54, want: 1 | 16 | 32},
		{name: "no confidence is not judged, flags stand", f: both, cutoff: 99, want: 1 | 16 | 32},
		{name: "a confidence of 0 is a confidence, and below any cutoff", f: withConf(both, 0), cutoff: 1, want: 1},
		{name: "no cutoff", f: withConf(both, 1), cutoff: 0, want: 1 | 16 | 32},
		{name: "only the set proxy is affected", f: withConf(anonFlags{Anonymous: true, PublicProxy: true}, 12), cutoff: 30, want: 1},
		{name: "vpn and tor are never in doubt", f: withConf(anonFlags{Anonymous: true, VPN: true, Tor: true, PublicProxy: true}, 12), cutoff: 30, want: 1 | 2 | 4},
		{name: "hosting is never in doubt", f: withConf(anonFlags{Anonymous: true, Hosting: true}, 12), cutoff: 30, want: 1 | 8},
	} {
		if got := tc.f.mask(tc.cutoff); got != tc.want {
			t.Errorf("%s: mask %d, want %d", tc.name, got, tc.want)
		}
	}
}

func withConf(f anonFlags, c uint16) anonFlags { f.Confidence = &c; return f }

func TestAnonNames(t *testing.T) {
	for mask, want := range map[uint8]string{
		0:  "",
		1:  "anonymous",
		2:  "vpn",
		3:  "anonymous,vpn",
		63: "anonymous,vpn,tor,hosting,public_proxy,residential_proxy",
	} {
		if got := anonNames[mask]; got != want {
			t.Errorf("anonNames[%d] = %q, want %q", mask, got, want)
		}
	}
}
