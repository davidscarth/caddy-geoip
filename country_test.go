// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestCountryUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		input         string
		wantDB        string
		wantCountries int
		wantUnknown   bool
		wantErr       bool
	}{
		{
			input: `geoip_country {
				db /tmp/Country.mmdb
				country US CA
			}`,
			wantDB:        "/tmp/Country.mmdb",
			wantCountries: 2,
		},
		{
			input: `geoip_country {
				db /tmp/Country.mmdb
				country US
				country CA ar
				match_unknown
			}`,
			wantDB:        "/tmp/Country.mmdb",
			wantCountries: 3,
			wantUnknown:   true,
		},
		{
			input: `geoip_country extra {
				db /tmp/Country.mmdb
			}`,
			wantErr: true,
		},
		{
			input: `geoip_country {
				bogus yes
			}`,
			wantErr: true,
		},
		{
			input: `geoip_country {
				db /tmp/Country.mmdb
				country
			}`,
			wantErr: true,
		},
		{
			input: `geoip_country {
				db /tmp/Country.mmdb
				db /tmp/Other.mmdb
				country US
			}`,
			wantErr: true,
		},
	} {
		var m MatchGeoIPCountry
		err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if tc.wantErr {
			if err == nil {
				t.Errorf("Test %d: UnmarshalCaddyfile() error = nil, want error", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if m.DB != tc.wantDB {
			t.Errorf("Test %d: db = %q, want %q", i, m.DB, tc.wantDB)
		}
		if len(m.Countries) != tc.wantCountries {
			t.Errorf("Test %d: got %d countries, want %d", i, len(m.Countries), tc.wantCountries)
		}
		if m.MatchUnknown != tc.wantUnknown {
			t.Errorf("Test %d: match_unknown = %v, want %v", i, m.MatchUnknown, tc.wantUnknown)
		}
	}
}

func TestIsCountryCode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"US", true},
		{"us", true},
		{"EU", true},
		{"USA", false},
		{"U", false},
		{"12", false},
		{"U1", false},
		{"", false},
		{"ÜS", false},
	} {
		if got := isCountryCode(tc.in); got != tc.want {
			t.Errorf("isCountryCode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCountryValidate(t *testing.T) {
	for i, tc := range []struct {
		m       MatchGeoIPCountry
		wantErr bool
	}{
		{m: MatchGeoIPCountry{DB: "/tmp/Country.mmdb", Countries: []string{"US"}}},
		{m: MatchGeoIPCountry{Countries: []string{"US"}}, wantErr: true},
		{m: MatchGeoIPCountry{DB: "/tmp/Country.mmdb"}, wantErr: true},
	} {
		err := tc.m.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("Test %d: Validate() error = nil, want error", i)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
		}
	}
}

func TestCountryProvisionRejects(t *testing.T) {
	for _, bad := range []string{"USA", "U", "12", ""} {
		m := MatchGeoIPCountry{DB: countryDB, Countries: []string{bad}}
		if err := m.Provision(caddy.Context{}); err == nil {
			t.Errorf("expected provision to reject country %q", bad)
		}
	}
}

func TestCountryMatch(t *testing.T) {
	m := MatchGeoIPCountry{DB: countryDB, Countries: []string{"gb", "US", "JP"}}

	// Caddy provisions before it validates.
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	for i, tc := range []struct {
		remoteAddr string
		want       bool
	}{
		{"81.2.69.142:1234", true},          // GB, lower-case in config
		{"216.160.83.56:1234", true},        // US
		{"89.160.20.128:1234", false},       // SE, not listed
		{"10.1.2.3:1234", false},            // private, no record
		{"127.0.0.1:1234", false},           // loopback, no record
		{"[::ffff:81.2.69.142]:1234", true}, // IPv4-mapped IPv6
		{"[2001:218::1]:1234", true},        // native IPv6, JP
		{"[2a02:d500::1]:1234", false},      // record with no country field
		{"not-an-address", false},           // unparseable, unknown
	} {
		got, err := m.MatchWithError(newRequest(tc.remoteAddr))
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Test %d: %s: MatchWithError() = %v, want %v", i, tc.remoteAddr, got, tc.want)
		}
	}
}

func TestCountryMatchUnknown(t *testing.T) {
	m := MatchGeoIPCountry{DB: countryDB, Countries: []string{"GB"}, MatchUnknown: true}

	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	if got, _ := m.MatchWithError(newRequest("10.1.2.3:1234")); !got {
		t.Error("expected unknown IP to match with match_unknown")
	}
	if got, _ := m.MatchWithError(newRequest("[2a02:d500::1]:1234")); !got {
		t.Error("expected record without country to count as unknown")
	}
	if got, err := m.MatchWithError(newRequest("216.160.83.56:1234")); err != nil || got {
		t.Errorf("US against GB with match_unknown: MatchWithError() = %v, %v, want false", got, err)
	}
	// A client whose address cannot be parsed at all (a Unix socket
	// listener) is unknown in the same sense as an absent record.
	if got, _ := m.MatchWithError(newRawRequest("@")); !got {
		t.Error("expected unparseable client to match with match_unknown")
	}
}

func TestCountryPlaceholder(t *testing.T) {
	m := MatchGeoIPCountry{DB: countryDB, Countries: []string{"GB"}}

	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	r := newRequest("81.2.69.142:1234")
	if _, err := m.MatchWithError(r); err != nil {
		t.Fatal(err)
	}
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}", ""); got != "GB" {
		t.Errorf("{geoip.country} = %q, want GB", got)
	}

	// An unknown IP must still set the placeholder, to an empty string.
	r = newRequest("10.1.2.3:1234")
	if _, err := m.MatchWithError(r); err != nil {
		t.Fatal(err)
	}
	repl = r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if v, known := repl.Get("geoip.country"); !known || v != "" {
		t.Errorf("unknown IP: {geoip.country} = %q, known = %v, want known and empty", v, known)
	}
}
