// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestSubdivisionUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				subdivision CA
			}`,
		},
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				subdivision CA NY
				subdivision WA
				match_unknown
			}`,
		},
		{
			// the country prefix belongs in the country subdirective
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				subdivision US-CA
			}`,
			wantErr: true,
		},
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				subdivision
			}`,
			wantErr: true,
		},
		{
			// country is a single code, unlike geoip_country's list
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US GB
				subdivision CA
			}`,
			wantErr: true,
		},
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				country GB
				subdivision CA
			}`,
			wantErr: true,
		},
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				db /tmp/Other.mmdb
				country US
				subdivision CA
			}`,
			wantErr: true,
		},
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				subdivision CA
				nonsense
			}`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		var m MatchGeoIPSubdivision
		err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if (err != nil) != tc.wantErr {
			t.Errorf("UnmarshalCaddyfile(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
		}
	}
}

func TestIsSubdivisionCode(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"CA", true},
		{"E", true},   // Östergötland County, Sweden
		{"ENG", true}, // England
		{"WBK", true}, // West Berkshire
		{"22", true},  // Jilin, China
		{"971", true}, // Guadeloupe, France
		{"ca", true},  // case is folded
		{"", false},
		{"CALI", false},
		{"US-CA", false},
		{"C A", false},
		{"C.A", false},
	}

	for _, tc := range tests {
		if got := isSubdivisionCode(tc.in); got != tc.want {
			t.Errorf("isSubdivisionCode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSubdivisionValidate(t *testing.T) {
	tests := []struct {
		name    string
		m       MatchGeoIPSubdivision
		wantErr bool
	}{
		{
			name: "complete",
			m:    MatchGeoIPSubdivision{DB: "x.mmdb", Country: "US", Subdivisions: []string{"CA"}},
		},
		{
			name:    "no db",
			m:       MatchGeoIPSubdivision{Country: "US", Subdivisions: []string{"CA"}},
			wantErr: true,
		},
		{
			name:    "no country",
			m:       MatchGeoIPSubdivision{DB: "x.mmdb", Subdivisions: []string{"CA"}},
			wantErr: true,
		},
		{
			name:    "no subdivisions",
			m:       MatchGeoIPSubdivision{DB: "x.mmdb", Country: "US"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		if err := tc.m.Validate(); (err != nil) != tc.wantErr {
			t.Errorf("%s: Validate() error = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestSubdivisionRejectsCountryDatabase(t *testing.T) {
	// A Country database has no subdivisions at all, so accepting one
	// would mean a permanent silent no-match.
	m := MatchGeoIPSubdivision{DB: countryDB, Country: "US", Subdivisions: []string{"CA"}}
	if err := m.Provision(caddy.Context{}); err == nil {
		t.Error("expected provision to reject a Country database")
	}
}

func TestSubdivisionProvisionRejects(t *testing.T) {
	// Malformed values are rejected here, naming the offender.
	for _, bad := range []string{"USA", "U", "U1", "U-", "12"} {
		m := MatchGeoIPSubdivision{DB: cityDB, Country: bad, Subdivisions: []string{"CA"}}
		if err := m.Provision(caddy.Context{}); err == nil {
			t.Errorf("expected provision to reject country %q", bad)
		}
	}
	for _, bad := range []string{"", "CALI", "US-CA", "C A", "C.A"} {
		m := MatchGeoIPSubdivision{DB: cityDB, Country: "US", Subdivisions: []string{bad}}
		if err := m.Provision(caddy.Context{}); err == nil {
			t.Errorf("expected provision to reject subdivision %q", bad)
		}
	}

	// One bad code among good ones is still caught, and named.
	m := MatchGeoIPSubdivision{DB: cityDB, Country: "US", Subdivisions: []string{"CA", "CALI", "NY"}}
	err := m.Provision(caddy.Context{})
	if err == nil {
		t.Fatal("expected provision to reject a bad code among good ones")
	}
	if !strings.Contains(err.Error(), "CALI") {
		t.Errorf("Provision() error = %v, want one naming CALI", err)
	}
}

func TestSubdivisionMissingFieldsDeferToValidate(t *testing.T) {
	// A missing required field passes Provision so that Validate can
	// report what is required and why. Both still fail the config.
	for _, tc := range []struct {
		name string
		m    MatchGeoIPSubdivision
		want string
	}{
		{
			name: "no db",
			m:    MatchGeoIPSubdivision{Country: "US", Subdivisions: []string{"CA"}},
			want: "db is required",
		},
		{
			name: "no country",
			m:    MatchGeoIPSubdivision{DB: cityDB, Subdivisions: []string{"CA"}},
			want: "country is required",
		},
		{
			name: "no subdivisions",
			m:    MatchGeoIPSubdivision{DB: cityDB, Country: "US"},
			want: "at least one subdivision is required",
		},
	} {
		if err := tc.m.Provision(caddy.Context{}); err != nil {
			t.Errorf("%s: Provision() error = %v, want nil", tc.name, err)
		}

		err := tc.m.Validate()
		if err == nil {
			t.Fatalf("%s: expected Validate to reject", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Validate() error = %v, want one mentioning %q", tc.name, err, tc.want)
		}
	}
}

func TestSubdivisionMatch(t *testing.T) {
	tests := []struct {
		name         string
		country      string
		subdivisions []string
		addr         string
		want         bool
	}{
		{"state matches", "US", []string{"WA"}, "216.160.83.56:1234", true},
		{"one of several", "US", []string{"CA", "NY", "WA"}, "216.160.83.56:1234", true},
		{"other state", "US", []string{"CA"}, "216.160.83.56:1234", false},
		{"lower case config", "us", []string{"wa"}, "216.160.83.56:1234", true},
		{"single character code", "SE", []string{"E"}, "89.160.20.128:1234", true},
		{"three character code", "GB", []string{"ENG"}, "81.2.69.142:1234", true},
		// The country scopes the subdivision: WA is a US state, so a
		// GB rule must not match it even though the code is listed.
		{"country scopes the code", "GB", []string{"WA"}, "216.160.83.56:1234", false},
		// Boxford reports ENG then WBK; the client is in both.
		{"innermost matches", "GB", []string{"WBK"}, "2.125.160.216:1234", true},
		{"outer level matches", "GB", []string{"ENG"}, "2.125.160.216:1234", true},
		// A native IPv6 record that carries a subdivision.
		{"native IPv6", "US", []string{"CA"}, "[2001:480::1]:1234", true},
	}

	for _, tc := range tests {
		m := MatchGeoIPSubdivision{DB: cityDB, Country: tc.country, Subdivisions: tc.subdivisions}
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

func TestSubdivisionMatchUnknown(t *testing.T) {
	tests := []struct {
		name    string
		country string
		addr    string
	}{
		// Not in the database at all.
		{"absent", "US", "10.1.2.3:1234"},
		// In the database and in the configured country, but the
		// record carries no subdivisions.
		{"country without subdivisions", "BT", "67.43.156.1:1234"},
	}

	for _, tc := range tests {
		for _, matchUnknown := range []bool{false, true} {
			m := MatchGeoIPSubdivision{
				DB:           cityDB,
				Country:      tc.country,
				Subdivisions: []string{"XX"},
				MatchUnknown: matchUnknown,
			}
			if err := m.Provision(caddy.Context{}); err != nil {
				t.Fatalf("%s: provision: %v", tc.name, err)
			}

			got, err := m.MatchWithError(newRequest(tc.addr))
			if err != nil {
				t.Errorf("%s: %v", tc.name, err)
			}
			if got != matchUnknown {
				t.Errorf("%s (match_unknown=%v): got %v", tc.name, matchUnknown, got)
			}
		}
	}
}

func TestSubdivisionCountryMismatchIsNotUnknown(t *testing.T) {
	// A client located elsewhere is an answer, not a gap in the data,
	// so match_unknown must not turn it into a match.
	m := MatchGeoIPSubdivision{
		DB:           cityDB,
		Country:      "GB",
		Subdivisions: []string{"ENG"},
		MatchUnknown: true,
	}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	r := newRequest("216.160.83.56:1234")
	if got, err := m.MatchWithError(r); err != nil || got {
		t.Errorf("US address against a GB rule: MatchWithError() = %v, %v, want false", got, err)
	}

	// The placeholders still report what the database knows, even
	// though this matcher did not match.
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}-{geoip.subdivision}", ""); got != "US-WA" {
		t.Errorf("placeholders on a country mismatch = %q, want US-WA", got)
	}
}

func TestSubdivisionPlaceholders(t *testing.T) {
	m := MatchGeoIPSubdivision{DB: cityDB, Country: "GB", Subdivisions: []string{"WBK"}}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	r := newRequest("2.125.160.216:1234")
	if _, err := m.MatchWithError(r); err != nil {
		t.Fatal(err)
	}
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}-{geoip.subdivision}", ""); got != "GB-WBK" {
		t.Errorf("placeholders = %q, want GB-WBK", got)
	}

	// A rule on the outer level matches, but the placeholder still
	// reports the most specific code, so the walk must not stop at
	// the hit.
	outer := MatchGeoIPSubdivision{DB: cityDB, Country: "GB", Subdivisions: []string{"ENG"}}
	if err := outer.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	r = newRequest("2.125.160.216:1234")
	if got, err := outer.MatchWithError(r); err != nil || !got {
		t.Fatalf("outer level: got %v, %v, want match", got, err)
	}
	repl = r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}-{geoip.subdivision}", ""); got != "GB-WBK" {
		t.Errorf("outer level placeholders = %q, want GB-WBK", got)
	}

	// An unknown IP must still set both, to empty strings.
	r = newRequest("10.1.2.3:1234")
	if _, err := m.MatchWithError(r); err != nil {
		t.Fatal(err)
	}
	repl = r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	for _, key := range []string{"geoip.country", "geoip.subdivision"} {
		if v, known := repl.Get(key); !known || v != "" {
			t.Errorf("unknown IP: %s known=%v value=%q", key, known, v)
		}
	}
}

// TestSubdivisionPlaceholdersMoveTogether pins that the two placeholders
// are published from one record. 2001:480::1 is US/CA in GeoLite2-City
// and JP with no subdivision in GeoIP2-Enterprise, so a matcher reading
// the second must not leave the first matcher's CA beside its JP: no
// record anywhere says JP-CA.
func TestSubdivisionPlaceholdersMoveTogether(t *testing.T) {
	const addr = "[2001:480::1]:1234"

	first := MatchGeoIPSubdivision{DB: cityDB, Country: "US", Subdivisions: []string{"CA"}}
	if err := first.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision first: %v", err)
	}

	second := MatchGeoIPSubdivision{DB: entDB, Country: "JP", Subdivisions: []string{"13"}}
	if err := second.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision second: %v", err)
	}

	r := newRequest(addr)
	if got, err := first.MatchWithError(r); err != nil || !got {
		t.Fatalf("City database: MatchWithError() = %v, %v, want true", got, err)
	}
	// The Enterprise record has a country but no subdivision, so this
	// matcher does not match; the placeholders must still describe it.
	if got, err := second.MatchWithError(r); err != nil || got {
		t.Fatalf("record without subdivisions: MatchWithError() = %v, %v, want false", got, err)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}-{geoip.subdivision}", ""); got != "JP-" {
		t.Errorf("placeholders = %q, want JP- from one record", got)
	}
}
