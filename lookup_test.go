// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

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
	ipv4DB     = "testdata/MaxMind-DB-test-ipv4-24.mmdb" // ip_version 4 db test

	// Shield editions: the plain editions plus addresses MaxMind removes
	// from those on privacy opt-out requests. Same records, same layout.
	countryShieldDB = "testdata/GeoIP2-Country-Shield-Test.mmdb"
	cityShieldDB    = "testdata/GeoIP2-City-Shield-Test.mmdb"
	entShieldDB     = "testdata/GeoIP2-Enterprise-Shield-Test.mmdb"

	// Editions no matcher reads today. Kept so that adopting one flips a
	// test rather than slipping in unnoticed.
	regionsDB  = "testdata/GeoIP-Regions-Test.mmdb"          // country and subdivisions with confidence scores
	connTypeDB = "testdata/GeoIP2-Connection-Type-Test.mmdb" // cable, cellular, corporate, satellite

	// Deliberately damaged City files from the same repository.
	badMetadataDB = "testdata/GeoIP2-City-Test-Invalid-Node-Count.mmdb"
	badDoubleDB   = "testdata/GeoIP2-City-Test-Broken-Double-Format.mmdb"
)

// discard is a logger for tests that call openDB or readASNFile directly
// and don't check what they log.
var discard = slog.New(slog.DiscardHandler)

// newRequest builds a request from the given remote address with the
// context a Caddy server would provide: a vars table, a replacer, and
// the client_ip var set the way PrepareRequest sets it, to the host of
// RemoteAddr with port and zone stripped. That is the path production
// requests take through clientIP, so the suite exercises it by default.
func newRequest(remoteAddr string) *http.Request {
	r := newRawRequest(remoteAddr)
	if ipp, err := netip.ParseAddrPort(remoteAddr); err == nil {
		caddyhttp.SetVar(r.Context(), caddyhttp.ClientIPVarKey, ipp.Addr().WithZone("").String())
	}
	return r
}

// newRawRequest is newRequest without the client_ip var, for tests that
// target the RemoteAddr fallback in clientIP.
func newRawRequest(remoteAddr string) *http.Request {
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
		"http.matchers.geoip_anonymous":   MatchGeoIPAnonymous{},
	} {
		info := m.CaddyModule()
		if got := string(info.ID); got != want {
			t.Errorf("module ID = %q, want %q", got, want)
		}
		if info.New == nil {
			t.Errorf("%s: New is nil", want)
		}
	}
}

func TestOpenDBTypeCheck(t *testing.T) {
	for _, f := range []string{countryDB, countryDB2} {
		db, err := openDB(discard, f, "country", "city", "enterprise")
		if err != nil {
			t.Fatalf("opening %s: %v", f, err)
		}
		_ = db.Close()
	}

	if _, err := openDB(discard, asnDB, "country", "city", "enterprise"); err == nil {
		t.Error("expected error opening ASN db as a country db")
	}
	if _, err := openDB(discard, countryDB, "asn", "isp", "enterprise"); err == nil {
		t.Error("expected error opening country db as an ASN db")
	}
	for _, f := range []string{cityDB, cityDB2} {
		db, err := openDB(discard, f, "city", "enterprise")
		if err != nil {
			t.Fatalf("opening %s: %v", f, err)
		}
		_ = db.Close()
	}

	// A City database carries country data too, so the country matcher
	// accepts it; a Country database has no subdivisions, so the
	// subdivision matcher must not accept one.
	if db, err := openDB(discard, cityDB, "country", "city", "enterprise"); err != nil {
		t.Errorf("expected a City db to be usable for country matching: %v", err)
	} else {
		_ = db.Close()
	}
	if _, err := openDB(discard, countryDB, "city", "enterprise"); err == nil {
		t.Error("expected error opening country db as a city db")
	}

	if _, err := openDB(discard, "testdata/does-not-exist.mmdb", "country"); err == nil {
		t.Error("expected error opening missing file")
	}

	// The paid editions each matcher accepts.
	if db, err := openDB(discard, entDB, "country", "city", "enterprise"); err != nil {
		t.Errorf("expected an Enterprise db to be usable for country matching: %v", err)
	} else {
		_ = db.Close()
	}
	if db, err := openDB(discard, entDB, "city", "enterprise"); err != nil {
		t.Errorf("expected an Enterprise db to be usable for subdivision matching: %v", err)
	} else {
		_ = db.Close()
	}
	for _, f := range []string{ispDB, entDB} {
		db, err := openDB(discard, f, "asn", "isp", "enterprise")
		if err != nil {
			t.Fatalf("opening %s for ASN matching: %v", f, err)
		}
		_ = db.Close()
	}

	// An unset placeholder replaces to nothing; the error should say so
	// rather than report a missing file with no name.
	_, err := openDB(discard, "{env.CADDY_GEOIP_TEST_UNSET}", "country")
	if err == nil {
		t.Fatal("expected error opening an empty path")
	}
	if !strings.Contains(err.Error(), "placeholder") {
		t.Errorf("openDB() error = %v, want one mentioning placeholder replacement", err)
	}
}

// TestOpenDBRejectsIPv4Only pins that an ip_version 4 database is a
// config error. The reader errors on an IPv6 lookup in such a tree
// instead of reporting no record, so accepting one would turn every
// IPv6 request into a 5xx. The fixture's type is "Test", so the type
// check is satisfied deliberately to reach the version check.
func TestOpenDBRejectsIPv4Only(t *testing.T) {
	_, err := openDB(discard, ipv4DB, "test")
	if err == nil {
		t.Fatal("expected error opening an IPv4-only database")
	}
	if !strings.Contains(err.Error(), "ip_version 4") {
		t.Errorf("openDB() error = %v, want one naming ip_version 4", err)
	}

	// A type mismatch is the more common mistake and is reported
	// first, so the version check must not mask it.
	_, err = openDB(discard, ipv4DB, "country")
	if err == nil {
		t.Fatal("expected type error opening a Test database as a country db")
	}
	if strings.Contains(err.Error(), "ip_version") {
		t.Errorf("openDB() error = %v, want the type error, not the version error", err)
	}
}

// TestIPv4OnlyLookupErrors pins the library behavior openDB's version
// check exists for: an IPv6 lookup in an ip_version 4 tree is an error,
// not a missing record. If this fails, the guard has become optional.
func TestIPv4OnlyLookupErrors(t *testing.T) {
	db, err := maxminddb.Open(ipv4DB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if db.Lookup(netip.MustParseAddr("2001:db8::1")).Err() == nil {
		t.Error("expected an IPv6 lookup in an IPv4-only database to error")
	}
}

// TestLookupErrorFailsClosed pins that a lookup error reaches the caller
// as an error rather than being swallowed into "no match". Closing the
// reader is the one way to make Lookup fail without a corrupt fixture:
// v2 returns a Result carrying an error, which DecodePath propagates.
func TestLookupErrorFailsClosed(t *testing.T) {
	country := &MatchGeoIPCountry{DB: countryDB, Countries: []string{"GB"}}
	asn := &MatchGeoIPASN{DB: asnDB, ASNs: []uint32{1221}}
	subdivision := &MatchGeoIPSubdivision{DB: cityDB, Country: "US", Subdivisions: []string{"WA"}}
	anonymous := &MatchGeoIPAnonymous{DB: anonDB, Types: []string{"vpn"}}

	for name, tc := range map[string]struct {
		provision func() error
		closeDB   func() error
		match     func(*http.Request) (bool, error)
	}{
		"country": {
			func() error { return country.Provision(caddy.Context{}) },
			func() error { return country.db.Close() },
			country.MatchWithError,
		},
		"asn": {
			func() error { return asn.Provision(caddy.Context{}) },
			func() error { return asn.db.Close() },
			asn.MatchWithError,
		},
		"subdivision": {
			func() error { return subdivision.Provision(caddy.Context{}) },
			func() error { return subdivision.db.Close() },
			subdivision.MatchWithError,
		},
		"anonymous": {
			func() error { return anonymous.Provision(caddy.Context{}) },
			func() error { return anonymous.db.Close() },
			anonymous.MatchWithError,
		},
	} {
		if err := tc.provision(); err != nil {
			t.Fatalf("%s: provision: %v", name, err)
		}
		if err := tc.closeDB(); err != nil {
			t.Fatalf("%s: close: %v", name, err)
		}
		got, err := tc.match(newRequest("81.2.69.142:1234"))
		if err == nil {
			t.Errorf("%s: expected an error from a closed database", name)
		} else if !strings.Contains(err.Error(), "geoip_"+name) {
			t.Errorf("%s: error does not name the matcher: %v", name, err)
		}
		if got {
			t.Errorf("%s: expected no match on error", name)
		}
	}
}

// TestUnprovisionedFailsClosed pins that a matcher driven without a
// successful Provision returns an error rather than dereferencing a
// nil reader, even in early data, since a retry would fail the same way.
func TestUnprovisionedFailsClosed(t *testing.T) {
	r := newRequest("81.2.69.142:1234")
	r.TLS = &tls.ConnectionState{HandshakeComplete: false}
	for name, m := range map[string]caddyhttp.RequestMatcherWithError{
		"country":     &MatchGeoIPCountry{},
		"asn":         &MatchGeoIPASN{},
		"subdivision": &MatchGeoIPSubdivision{},
		"anonymous":   &MatchGeoIPAnonymous{},
	} {
		got, err := m.MatchWithError(r)
		if err == nil || !strings.Contains(err.Error(), "not provisioned") {
			t.Errorf("%s: MatchWithError() error = %v, want not provisioned", name, err)
		}
		if got {
			t.Errorf("%s: expected no match from an unprovisioned matcher", name)
		}
	}
}

func TestEarlyDataRejected(t *testing.T) {
	// Each matcher is driven to pin that it calls guard.
	matchers := map[string]caddyhttp.RequestMatcherWithError{
		"country": &MatchGeoIPCountry{DB: countryDB, Countries: []string{"GB"}},
		"asn":     &MatchGeoIPASN{DB: asnDB, ASNs: []uint32{1221}},
		"subdivision": &MatchGeoIPSubdivision{
			DB: cityDB, Country: "GB", Subdivisions: []string{"ENG"},
		},
		"anonymous": &MatchGeoIPAnonymous{DB: anonDB, Types: []string{"vpn"}},
	}

	for name, m := range matchers {
		if err := m.(caddy.Provisioner).Provision(caddy.Context{}); err != nil {
			t.Fatalf("%s: provision: %v", name, err)
		}

		r := newRequest("81.2.69.142:1234")
		r.TLS = &tls.ConnectionState{HandshakeComplete: false}

		match, err := m.MatchWithError(r)
		if match {
			t.Errorf("%s: expected no match on incomplete handshake", name)
		}
		var handlerErr caddyhttp.HandlerError
		if !errors.As(err, &handlerErr) {
			t.Errorf("%s: MatchWithError() error = %v, want a caddyhttp.HandlerError", name, err)
			continue
		}
		if handlerErr.StatusCode != http.StatusTooEarly {
			t.Errorf("%s: status = %d, want %d", name, handlerErr.StatusCode, http.StatusTooEarly)
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
//
// The var can also carry host:port if a vars handler overwrote it, so
// that form is parsed too, but only after the bare form fails; the
// rows below exist so the retry cannot be removed as redundant.
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
		{"ipv4 with port from var", "10.0.0.1:443", "1.2.3.4:5678", "1.2.3.4"},
		{"ipv6 with port from var", "10.0.0.1:443", "[2001:db8::1]:443", "2001:db8::1"},
		{"bracketed ipv6 without a port from var", "10.0.0.1:443", "[2001:db8::1]", ""},
		{"garbage from var", "10.0.0.1:443", "not-an-address", ""},
		// An unbracketed IPv6 with a trailing port is itself a valid
		// IPv6 address, so it parses as one. No parser can tell the
		// two readings apart; this pins that it is looked up as the
		// address rather than treated as unknown.
		{"unbracketed ipv6 with trailing port from var", "10.0.0.1:443", "2001:db8::1:443", "2001:db8::1:443"},
		{"bare ipv4 in RemoteAddr", "1.2.3.4", "", "1.2.3.4"},
		{"bracketed ipv6 without a port", "[2001:db8::1]", "", ""},
		{"unix socket", "@", "", ""},
		{"empty", "", "", ""},
		{"garbage", "not-an-address", "", ""},
		{"port but no host", ":443", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRawRequest(tc.remoteAddr)
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
			name:     "an answer is not erased by a later blank",
			existing: "US", preset: true, write: "", want: "US", wantKnown: true,
		},
		{
			name:   "a blank is replaced by a later answer",
			preset: true, write: "GB", want: "GB", wantKnown: true,
		},
		{
			name:     "a later answer wins over an earlier one",
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
		t.Fatalf("Country database: MatchWithError() = %v, %v, want true", got, err)
	}
	if got, err := second.MatchWithError(r); err != nil || got {
		t.Fatalf("City database: MatchWithError() = %v, %v, want false", got, err)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}", "MISSING"); got != "US" {
		t.Errorf("{geoip.country} after the second matcher = %q, want US", got)
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

// TestShieldEditions checks that each matcher accepting a plain edition
// accepts its Shield counterpart and matches the same way. The type
// check admits Shield files by name alone, so without this a layout
// change on MaxMind's side would be accepted at load and match nothing.
func TestShieldEditions(t *testing.T) {
	for _, db := range []string{countryShieldDB, cityShieldDB, entShieldDB} {
		m := MatchGeoIPCountry{DB: db, Countries: []string{"GB"}}
		if err := m.Provision(caddy.Context{}); err != nil {
			t.Fatalf("country %s: %v", db, err)
		}
		if ok, err := m.MatchWithError(newRequest("81.2.69.160:1234")); err != nil || !ok {
			t.Errorf("country %s: MatchWithError() = %v, %v, want true", db, ok, err)
		}
	}
	for _, db := range []string{cityShieldDB, entShieldDB} {
		m := MatchGeoIPSubdivision{DB: db, Country: "GB", Subdivisions: []string{"ENG"}}
		if err := m.Provision(caddy.Context{}); err != nil {
			t.Fatalf("subdivision %s: %v", db, err)
		}
		if ok, err := m.MatchWithError(newRequest("81.2.69.160:1234")); err != nil || !ok {
			t.Errorf("subdivision %s: MatchWithError() = %v, %v, want true", db, ok, err)
		}
	}
	m := MatchGeoIPASN{DB: entShieldDB, ASNs: []uint32{14671}}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("asn %s: %v", entShieldDB, err)
	}
	if ok, err := m.MatchWithError(newRequest("74.209.24.0:1234")); err != nil || !ok {
		t.Errorf("asn %s: MatchWithError() = %v, %v, want true", entShieldDB, ok, err)
	}
}

// TestRefusedEditions pins that Regions, Connection Type, and
// Residential Proxy are refused by every matcher when the config loads.
func TestRefusedEditions(t *testing.T) {
	for _, db := range []string{regionsDB, connTypeDB, resProxyDB} {
		for name, p := range map[string]caddy.Provisioner{
			"country":     &MatchGeoIPCountry{DB: db, Countries: []string{"US"}},
			"subdivision": &MatchGeoIPSubdivision{DB: db, Country: "US", Subdivisions: []string{"CA"}},
			"asn":         &MatchGeoIPASN{DB: db, ASNs: []uint32{1}},
			"anonymous":   &MatchGeoIPAnonymous{DB: db, Types: []string{"vpn"}},
		} {
			if err := p.Provision(caddy.Context{}); err == nil {
				t.Errorf("%s: Provision() error = nil for %s, want error", name, db)
			}
		}
	}
}

// TestDamagedDatabases covers two of MaxMind's deliberately broken
// files. Corrupt metadata is refused when the config loads, before any
// lookup. A malformed double in the location record is never read by
// the matchers, so that file loads and matches like an intact City file.
func TestDamagedDatabases(t *testing.T) {
	for name, p := range map[string]caddy.Provisioner{
		"country":     &MatchGeoIPCountry{DB: badMetadataDB, Countries: []string{"US"}},
		"subdivision": &MatchGeoIPSubdivision{DB: badMetadataDB, Country: "US", Subdivisions: []string{"CA"}},
		"asn":         &MatchGeoIPASN{DB: badMetadataDB, ASNs: []uint32{1}},
		"anonymous":   &MatchGeoIPAnonymous{DB: badMetadataDB, Types: []string{"vpn"}},
	} {
		if err := p.Provision(caddy.Context{}); err == nil {
			t.Errorf("%s: Provision() error = nil for %s, want error", name, badMetadataDB)
		}
	}

	c := MatchGeoIPCountry{DB: badDoubleDB, Countries: []string{"GB"}}
	if err := c.Provision(caddy.Context{}); err != nil {
		t.Fatalf("country %s: %v", badDoubleDB, err)
	}
	if ok, err := c.MatchWithError(newRequest("81.2.69.160:1234")); err != nil || !ok {
		t.Errorf("country %s: MatchWithError() = %v, %v, want true", badDoubleDB, ok, err)
	}
	s := MatchGeoIPSubdivision{DB: badDoubleDB, Country: "GB", Subdivisions: []string{"ENG"}}
	if err := s.Provision(caddy.Context{}); err != nil {
		t.Fatalf("subdivision %s: %v", badDoubleDB, err)
	}
	if ok, err := s.MatchWithError(newRequest("81.2.69.160:1234")); err != nil || !ok {
		t.Errorf("subdivision %s: MatchWithError() = %v, %v, want true", badDoubleDB, ok, err)
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
		t.Fatalf("US-WA: MatchWithError() = %v, %v, want true", got, err)
	}

	// Same request, an address the City database cannot place. Sharing
	// the context shares the vars table too, so client_ip is set again
	// for the new address, as a server would for a new request.
	r2 := newRequest("50.114.0.1:1234")
	*r2 = *r2.WithContext(r.Context()) // share the replacer
	caddyhttp.SetVar(r2.Context(), caddyhttp.ClientIPVarKey, "50.114.0.1")
	if got, err := first.MatchWithError(r2); err != nil || got {
		t.Fatalf("absent record: MatchWithError() = %v, %v, want false", got, err)
	}

	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}-{geoip.subdivision}", ""); got != "US-WA" {
		t.Errorf("placeholders after an absent record = %q, want US-WA", got)
	}
}

// TestProvisionDefersEmptySet pins that a matcher with a db but nothing
// to match leaves the error to Validate without opening the database:
// the path does not exist, so opening it would fail Provision.
func TestProvisionDefersEmptySet(t *testing.T) {
	const db = "testdata/does-not-exist.mmdb"
	for name, m := range map[string]interface {
		caddy.Provisioner
		caddy.Validator
	}{
		"country":     &MatchGeoIPCountry{DB: db},
		"subdivision": &MatchGeoIPSubdivision{DB: db, Country: "US"},
		"asn":         &MatchGeoIPASN{DB: db},
		"anonymous":   &MatchGeoIPAnonymous{DB: db},
	} {
		if err := m.Provision(caddy.Context{}); err != nil {
			t.Errorf("%s: Provision() error = %v, want nil", name, err)
		}
		if err := m.Validate(); err == nil {
			t.Errorf("%s: expected Validate to reject", name)
		}
	}
}

// logLines returns what fn logs, as JSON lines without the time, so a test
// can pin the level, message, field names, field order, and values.
func logLines(t *testing.T, fn func(*slog.Logger)) []string {
	t.Helper()
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	})
	fn(slog.New(h))
	return strings.Split(strings.TrimSpace(buf.String()), "\n")
}

// TestLogDBAge pins the line a database logs when it loads, for each age:
// INFO within 30 days, WARN past that, and WARN when the build date is
// missing, in the future, or beyond what RFC 3339 can write.
func TestLogDBAge(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		epoch uint
		want  string
	}{
		{"3 days", 1793275200, `{"level":"INFO","msg":"database loaded","path":"/db/x.mmdb","type":"GeoLite2-Country","built":"2026-10-29T12:00:00Z","age_days":3}`},
		{"30 days 23 hours", 1790859600, `{"level":"INFO","msg":"database loaded","path":"/db/x.mmdb","type":"GeoLite2-Country","built":"2026-10-01T13:00:00Z","age_days":30}`},
		{"31 days", 1790856000, `{"level":"WARN","msg":"database is more than 30 days old","path":"/db/x.mmdb","type":"GeoLite2-Country","built":"2026-10-01T12:00:00Z","age_days":31}`},
		{"missing", 0, `{"level":"WARN","msg":"database build date is missing or in the future","path":"/db/x.mmdb","type":"GeoLite2-Country","build_epoch":0}`},
		{"future", 1793538000, `{"level":"WARN","msg":"database build date is missing or in the future","path":"/db/x.mmdb","type":"GeoLite2-Country","build_epoch":1793538000,"built":"2026-11-01T13:00:00Z"}`},
		{"past year 9999", 253402300800, `{"level":"WARN","msg":"database build date is missing or in the future","path":"/db/x.mmdb","type":"GeoLite2-Country","build_epoch":253402300800}`},
	} {
		md := maxminddb.Metadata{DatabaseType: "GeoLite2-Country", BuildEpoch: tc.epoch}
		got := logLines(t, func(l *slog.Logger) { logDBAge(l, "/db/x.mmdb", md, now) })
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}
