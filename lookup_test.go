// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Test databases from github.com/maxmind/MaxMind-DB (Apache-2.0 / MIT).
// Known contents, from source-data in that repository:
//
//	81.2.69.142    GB   (GeoLite2-Country-Test, GeoIP2-Country-Test)
//	216.160.83.56  US   (GeoLite2-Country-Test, GeoIP2-Country-Test)
//	2a02:d500::/29 record present but no country field (GeoLite2-Country-Test)
//	1.128.0.0/11   1221 (GeoLite2-ASN-Test)
//	10.0.0.0/8     absent from all
const (
	countryDB  = "testdata/GeoLite2-Country-Test.mmdb"
	countryDB2 = "testdata/GeoIP2-Country-Test.mmdb" // paid-tier naming
	asnDB      = "testdata/GeoLite2-ASN-Test.mmdb"
	cityDB     = "testdata/GeoLite2-City-Test.mmdb"
	cityDB2    = "testdata/GeoIP2-City-Test.mmdb"
	ispDB      = "testdata/GeoIP2-ISP-Test.mmdb"
	entDB      = "testdata/GeoIP2-Enterprise-Test.mmdb"
)

// newRequest builds a request from the given remote address with the
// context a Caddy server would provide: a vars table and a replacer.
func newRequest(remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	ctx := context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{})
	ctx = context.WithValue(ctx, caddy.ReplacerCtxKey, caddy.NewReplacer())
	return r.WithContext(ctx)
}

// TestModuleIDs pins the strings users type into a Caddyfile. Nothing
// else checks them: a typo here compiles, passes every other test, and
// only surfaces as an unrecognized directive in someone's config.
func TestModuleIDs(t *testing.T) {
	for want, m := range map[string]caddy.Module{
		"http.matchers.geoip_country":     MatchGeoIPCountry{},
		"http.matchers.geoip_subdivision": MatchGeoIPSubdivision{},
		"http.matchers.geoip_asn":         MatchGeoIPASN{},
	} {
		info := m.CaddyModule()
		if got := string(info.ID); got != want {
			t.Errorf("expected module ID %q, got %q", want, got)
		}
		if info.New == nil {
			t.Errorf("%s: New is nil", want)
		}
	}
}

func TestOpenDBTypeCheck(t *testing.T) {
	for _, f := range []string{countryDB, countryDB2} {
		db, err := openDB(f, "country", "city", "enterprise")
		if err != nil {
			t.Fatalf("opening %s: %v", f, err)
		}
		_ = db.Close()
	}

	if _, err := openDB(asnDB, "country", "city", "enterprise"); err == nil {
		t.Error("expected error opening ASN db as a country db")
	}
	if _, err := openDB(countryDB, "asn", "isp", "enterprise"); err == nil {
		t.Error("expected error opening country db as an ASN db")
	}
	for _, f := range []string{cityDB, cityDB2} {
		db, err := openDB(f, "city", "enterprise")
		if err != nil {
			t.Fatalf("opening %s: %v", f, err)
		}
		_ = db.Close()
	}

	// A City database carries country data too, so the country matcher
	// accepts it; a Country database has no subdivisions, so the
	// subdivision matcher must not accept one.
	if db, err := openDB(cityDB, "country", "city", "enterprise"); err != nil {
		t.Errorf("expected a City db to be usable for country matching: %v", err)
	} else {
		_ = db.Close()
	}
	if _, err := openDB(countryDB, "city", "enterprise"); err == nil {
		t.Error("expected error opening country db as a city db")
	}

	if _, err := openDB("testdata/does-not-exist.mmdb", "country"); err == nil {
		t.Error("expected error opening missing file")
	}

	// The paid editions each matcher accepts.
	if db, err := openDB(entDB, "country", "city", "enterprise"); err != nil {
		t.Errorf("expected an Enterprise db to be usable for country matching: %v", err)
	} else {
		_ = db.Close()
	}
	if db, err := openDB(entDB, "city", "enterprise"); err != nil {
		t.Errorf("expected an Enterprise db to be usable for subdivision matching: %v", err)
	} else {
		_ = db.Close()
	}
	for _, f := range []string{ispDB, entDB} {
		db, err := openDB(f, "asn", "isp", "enterprise")
		if err != nil {
			t.Fatalf("opening %s for ASN matching: %v", f, err)
		}
		_ = db.Close()
	}

	// An unset placeholder replaces to nothing; the error should say so
	// rather than report a missing file with no name.
	_, err := openDB("{env.CADDY_GEOIP_TEST_UNSET}", "country")
	if err == nil {
		t.Fatal("expected error opening an empty path")
	}
	if !strings.Contains(err.Error(), "placeholder") {
		t.Errorf("expected the error to mention placeholder replacement, got %v", err)
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
		{"81.2.69.142:1234", true},         // GB, lower-case in config
		{"216.160.83.56:1234", true},       // US
		{"89.160.20.128:1234", false},      // SE, not listed
		{"10.1.2.3:1234", false},           // private, no record
		{"127.0.0.1:1234", false},          // loopback, no record
		{"[::ffff:81.2.69.142]:1234", true}, // IPv4-mapped IPv6
		{"[2001:218::1]:1234", true},       // native IPv6, JP
		{"[2a02:d500::1]:1234", false},     // record with no country field
		{"not-an-address", false},          // unparseable, unknown
	} {
		got, err := m.MatchWithError(newRequest(tc.remoteAddr))
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Test %d: %s: expected %v, got %v", i, tc.remoteAddr, tc.want, got)
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
	if got, _ := m.MatchWithError(newRequest("216.160.83.56:1234")); got {
		t.Error("expected US not to match GB even with match_unknown")
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
		t.Errorf("placeholder: expected GB, got %q", got)
	}

	// An unknown IP must still set the placeholder, to an empty string.
	r = newRequest("10.1.2.3:1234")
	if _, err := m.MatchWithError(r); err != nil {
		t.Fatal(err)
	}
	repl = r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if v, known := repl.Get("geoip.country"); !known || v != "" {
		t.Errorf("unknown IP: expected known empty placeholder, got known=%v value=%q", known, v)
	}
}

func TestEarlyDataRejected(t *testing.T) {
	// The guard is copied into each matcher, so each copy is checked.
	matchers := map[string]caddyhttp.RequestMatcherWithError{
		"country": &MatchGeoIPCountry{DB: countryDB, Countries: []string{"GB"}},
		"asn":     &MatchGeoIPASN{DB: asnDB, ASNs: []string{"1221"}},
		"subdivision": &MatchGeoIPSubdivision{
			DB: cityDB, Country: "GB", Subdivisions: []string{"ENG"},
		},
	}

	for name, m := range matchers {
		if err := m.(caddy.Provisioner).Provision(caddy.Context{}); err != nil {
			t.Fatalf("%s: provision: %v", name, err)
		}

		// An incomplete handshake means 0-RTT early data, where the
		// client IP is not yet verified; refuse the request with 425.
		r := newRequest("81.2.69.142:1234")
		r.TLS = &tls.ConnectionState{HandshakeComplete: false}

		match, err := m.MatchWithError(r)
		if match {
			t.Errorf("%s: expected no match on incomplete handshake", name)
		}
		var handlerErr caddyhttp.HandlerError
		if !errors.As(err, &handlerErr) {
			t.Errorf("%s: expected a caddyhttp.HandlerError, got %v", name, err)
			continue
		}
		if handlerErr.StatusCode != http.StatusTooEarly {
			t.Errorf("%s: expected status %d, got %d", name, http.StatusTooEarly, handlerErr.StatusCode)
		}

		// A completed handshake is matched as usual.
		r = newRequest("81.2.69.142:1234")
		r.TLS = &tls.ConnectionState{HandshakeComplete: true}
		if _, err := m.MatchWithError(r); err != nil {
			t.Errorf("%s: unexpected error after handshake: %v", name, err)
		}
	}
}

// TestClientIP pins the address forms clientIP has to cope with. The
// client_ip var is a bare address; RemoteAddr always carries a port,
// except on a unix socket listener where it is not an address at all.
func TestClientIP(t *testing.T) {
	for _, tc := range []struct {
		name       string
		remoteAddr string
		clientVar  string // "" means the var is not set
		want       string // "" means an invalid Addr
	}{
		{"ipv4 with port", "1.2.3.4:5678", "", "1.2.3.4"},
		{"ipv6 with port", "[2001:db8::1]:443", "", "2001:db8::1"},
		{"ipv4-mapped ipv6 is unmapped", "[::ffff:1.2.3.4]:443", "", "1.2.3.4"},
		{"ipv6 zone is stripped", "[fe80::1%eth0]:443", "", "fe80::1"},
		{"bare ipv4 from client_ip var", "10.0.0.1:443", "1.2.3.4", "1.2.3.4"},
		{"bare ipv6 from client_ip var", "10.0.0.1:443", "2001:db8::1", "2001:db8::1"},
		{"bare ipv6 with zone from var", "10.0.0.1:443", "fe80::1%eth0", "fe80::1"},
		{"ipv4-mapped ipv6 from var", "10.0.0.1:443", "::ffff:1.2.3.4", "1.2.3.4"},
		{"bare ipv4 in RemoteAddr", "1.2.3.4", "", "1.2.3.4"},
		{"bracketed ipv6 without a port", "[2001:db8::1]", "", ""},
		{"unix socket", "@", "", ""},
		{"empty", "", "", ""},
		{"garbage", "not-an-address", "", ""},
		{"port but no host", ":443", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRequest(tc.remoteAddr)
			if tc.clientVar != "" {
				caddyhttp.SetVar(r.Context(), caddyhttp.ClientIPVarKey, tc.clientVar)
			}

			got := clientIP(r)
			var gotStr string
			if got.IsValid() {
				gotStr = got.String()
			}
			if gotStr != tc.want {
				t.Errorf("clientIP() = %q, want %q", gotStr, tc.want)
			}
		})
	}
}

// TestSetPlaceholder covers the write rule: a real answer is always
// recorded, an empty one only when nothing is there yet.
func TestSetPlaceholder(t *testing.T) {
	const key = "geoip.country"

	for _, tc := range []struct {
		name      string
		existing  string // "" with preset false means unset
		preset    bool
		write     string
		want      string
		wantKnown bool
	}{
		{name: "first answer is recorded", write: "US", want: "US", wantKnown: true},
		{name: "unknown sets a known empty", write: "", want: "", wantKnown: true},
		{
			name: "an answer is not erased by a later blank",
			existing: "US", preset: true, write: "", want: "US", wantKnown: true,
		},
		{
			name: "a blank is replaced by a later answer",
			preset: true, write: "GB", want: "GB", wantKnown: true,
		},
		{
			name: "a later answer wins over an earlier one",
			existing: "US", preset: true, write: "GB", want: "GB", wantKnown: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRequest("1.2.3.4:1234")
			repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
			if tc.preset {
				repl.Set(key, tc.existing)
			}

			setPlaceholder(r, key, tc.write)

			got, known := repl.Get(key)
			if known != tc.wantKnown {
				t.Fatalf("known = %v, want %v", known, tc.wantKnown)
			}
			if got != tc.want {
				t.Errorf("value = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestPlaceholderSurvivesLaterMatcher is the same rule seen through two
// real matchers: 50.114.0.1 is in the Country database but not in the
// City one, so the second matcher resolves nothing and must not erase
// the first matcher's answer.
func TestPlaceholderSurvivesLaterMatcher(t *testing.T) {
	first := MatchGeoIPCountry{DB: countryDB, Countries: []string{"US"}}
	if err := first.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision first: %v", err)
	}

	second := MatchGeoIPCountry{DB: cityDB, Countries: []string{"US"}}
	if err := second.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision second: %v", err)
	}

	r := newRequest("50.114.0.1:1234")
	if got, err := first.MatchWithError(r); err != nil || !got {
		t.Fatalf("expected the Country database to match US, got %v (%v)", got, err)
	}
	if got, err := second.MatchWithError(r); err != nil || got {
		t.Fatalf("expected the City database not to resolve this address, got %v (%v)", got, err)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}", "MISSING"); got != "US" {
		t.Errorf("expected US to survive the second matcher, got %q", got)
	}
}

func TestClientIPHonorsTrustedProxyVar(t *testing.T) {
	m := MatchGeoIPCountry{DB: countryDB, Countries: []string{"GB"}}

	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// The server sets client_ip when trusted_proxies resolved a forwarded
	// address; the matcher must prefer it over RemoteAddr.
	r := newRequest("10.1.2.3:1234")
	caddyhttp.SetVar(r.Context(), caddyhttp.ClientIPVarKey, "81.2.69.142")
	if got, _ := m.MatchWithError(r); !got {
		t.Error("expected client_ip var to be used over RemoteAddr")
	}
}

func TestASNMatch(t *testing.T) {
	m := MatchGeoIPASN{DB: asnDB, ASNs: []string{"001221"}} // leading zeros normalized

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
		{"1.128.0.1:1234", true},      // AS1221
		{"[2001:8000::1]:1234", true}, // AS1221 over native IPv6
		{"10.1.2.3:1234", false},      // private, no record
		{"8.8.8.8:1234", false},       // not in the test db
	} {
		got, err := m.MatchWithError(newRequest(tc.remoteAddr))
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Test %d: %s: expected %v, got %v", i, tc.remoteAddr, tc.want, got)
		}
	}
}

// TestASNAcrossDatabaseEditions checks the three editions the ASN
// matcher accepts. Enterprise nests the autonomous system fields under
// traits, so reading the top-level path there would match nothing at
// all, silently.
func TestASNAcrossDatabaseEditions(t *testing.T) {
	for _, tc := range []struct {
		name, db, addr string
		asn            string
	}{
		{"GeoLite2-ASN", asnDB, "1.128.0.1:1234", "1221"},
		{"GeoIP2-ISP", ispDB, "1.128.0.1:1234", "1221"},
		{"GeoIP2-Enterprise", entDB, "74.209.24.1:1234", "14671"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := MatchGeoIPASN{DB: tc.db, ASNs: []string{tc.asn}}
			if err := m.Provision(caddy.Context{}); err != nil {
				t.Fatalf("provision: %v", err)
			}

			r := newRequest(tc.addr)
			got, err := m.MatchWithError(r)
			if err != nil {
				t.Fatal(err)
			}
			if !got {
				t.Errorf("expected AS%s to match", tc.asn)
			}
			repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
			if v := repl.ReplaceAll("{geoip.asn}", ""); v != tc.asn {
				t.Errorf("placeholder: expected %s, got %q", tc.asn, v)
			}
		})
	}
}

// TestEnterpriseCountryAndSubdivision checks that the other two
// matchers read an Enterprise database, whose country and subdivision
// fields sit at the top level as in City.
func TestEnterpriseCountryAndSubdivision(t *testing.T) {
	c := MatchGeoIPCountry{DB: entDB, Countries: []string{"GB"}}
	if err := c.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision country: %v", err)
	}
	if got, _ := c.MatchWithError(newRequest("2.125.160.216:1234")); !got {
		t.Error("expected GB to match from an Enterprise database")
	}

	s := MatchGeoIPSubdivision{DB: entDB, Country: "GB", Subdivisions: []string{"WBK"}}
	if err := s.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision subdivision: %v", err)
	}
	if got, _ := s.MatchWithError(newRequest("2.125.160.216:1234")); !got {
		t.Error("expected WBK to match from an Enterprise database")
	}
}

func TestASNMatchUnknownAndPlaceholder(t *testing.T) {
	// match_unknown and the placeholder name are separate lines in
	// asn.go from the country matcher's, so they are checked here too.
	m := MatchGeoIPASN{DB: asnDB, ASNs: []string{"1221"}, MatchUnknown: true}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	if got, _ := m.MatchWithError(newRequest("10.1.2.3:1234")); !got {
		t.Error("expected an IP with no ASN record to match with match_unknown")
	}

	r := newRequest("1.128.0.1:1234")
	if _, err := m.MatchWithError(r); err != nil {
		t.Fatal(err)
	}
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.asn}", ""); got != "1221" {
		t.Errorf("placeholder: expected 1221, got %q", got)
	}
}

func TestASNProvisionRejects(t *testing.T) {
	for _, bad := range []string{"0", "AS1221", "-1", "abc", "4294967296"} {
		m := MatchGeoIPASN{DB: asnDB, ASNs: []string{bad}}
		if err := m.Provision(caddy.Context{}); err == nil {
			t.Errorf("expected provision to reject asn %q", bad)
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
		// Boxford reports ENG then WBK; only the most specific matches.
		{"most specific matches", "GB", []string{"WBK"}, "2.125.160.216:1234", true},
		{"more general does not", "GB", []string{"ENG"}, "2.125.160.216:1234", false},
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
	if got, _ := m.MatchWithError(r); got {
		t.Error("expected a US address not to match a GB rule")
	}

	// The placeholders still report what the database knows, even
	// though this matcher did not match.
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}-{geoip.subdivision}", ""); got != "US-WA" {
		t.Errorf("placeholders on a country mismatch: expected US-WA, got %q", got)
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
		t.Errorf("placeholders: expected GB-WBK, got %q", got)
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
		t.Errorf("expected the error to name the offending code, got %v", err)
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
			t.Errorf("%s: expected Provision to defer, got %v", tc.name, err)
		}

		err := tc.m.Validate()
		if err == nil {
			t.Fatalf("%s: expected Validate to reject", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: expected an error mentioning %q, got %v", tc.name, tc.want, err)
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
		t.Fatalf("expected the City database to match US-CA, got %v (%v)", got, err)
	}
	// The Enterprise record has a country but no subdivision, so this
	// matcher does not match; the placeholders must still describe it.
	if got, err := second.MatchWithError(r); err != nil || got {
		t.Fatalf("expected no match on a record without subdivisions, got %v (%v)", got, err)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}-{geoip.subdivision}", ""); got != "JP-" {
		t.Errorf("placeholders: expected JP- from one record, got %q", got)
	}
}

// TestPlaceholderSurvivesAbsentRecord is the other half of the rule: a
// matcher whose database has no entry learned nothing and must not erase
// what another matcher resolved. 50.114.0.1 is in the Country database
// but absent from the City one.
func TestPlaceholderSurvivesAbsentRecord(t *testing.T) {
	first := MatchGeoIPSubdivision{DB: cityDB, Country: "US", Subdivisions: []string{"WA"}}
	if err := first.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision first: %v", err)
	}

	r := newRequest("216.160.83.56:1234") // US-WA in the City database
	if got, err := first.MatchWithError(r); err != nil || !got {
		t.Fatalf("expected US-WA to match, got %v (%v)", got, err)
	}

	// Same request, an address the City database cannot place.
	r2 := newRequest("50.114.0.1:1234")
	*r2 = *r2.WithContext(r.Context()) // share the replacer
	if got, err := first.MatchWithError(r2); err != nil || got {
		t.Fatalf("expected no match for an absent record, got %v (%v)", got, err)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}-{geoip.subdivision}", ""); got != "US-WA" {
		t.Errorf("expected US-WA to survive an absent record, got %q", got)
	}
}
