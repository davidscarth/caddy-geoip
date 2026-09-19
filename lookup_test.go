// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
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
	if _, err := openDB("testdata/does-not-exist.mmdb", "country"); err == nil {
		t.Error("expected error opening missing file")
	}
}

func TestCountryMatch(t *testing.T) {
	m := MatchGeoIPCountry{DB: countryDB, Countries: []string{"gb", "US"}}

	if err := m.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _ = m.Cleanup() })

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
	t.Cleanup(func() { _ = m.Cleanup() })

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
	t.Cleanup(func() { _ = m.Cleanup() })

	r := newRequest("81.2.69.142:1234")
	if _, err := m.MatchWithError(r); err != nil {
		t.Fatal(err)
	}
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.country}", ""); got != "GB" {
		t.Errorf("placeholder: expected GB, got %q", got)
	}

	// An unknown IP must still set the placeholder, to an empty string,
	// so that log_append records "" rather than the literal placeholder.
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
	m := MatchGeoIPCountry{DB: countryDB, Countries: []string{"GB"}}

	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _ = m.Cleanup() })

	// An incomplete handshake means 0-RTT early data, where the client
	// IP is not yet verified; the request must be refused with 425.
	r := newRequest("81.2.69.142:1234")
	r.TLS = &tls.ConnectionState{HandshakeComplete: false}

	match, err := m.MatchWithError(r)
	if match {
		t.Error("expected no match on incomplete handshake")
	}
	var handlerErr caddyhttp.HandlerError
	if !errors.As(err, &handlerErr) {
		t.Fatalf("expected a caddyhttp.HandlerError, got %v", err)
	}
	if handlerErr.StatusCode != http.StatusTooEarly {
		t.Errorf("expected status %d, got %d", http.StatusTooEarly, handlerErr.StatusCode)
	}

	// A completed handshake is matched as usual.
	r = newRequest("81.2.69.142:1234")
	r.TLS = &tls.ConnectionState{HandshakeComplete: true}
	if match, err := m.MatchWithError(r); err != nil || !match {
		t.Errorf("expected GB to match after handshake, got %v (%v)", match, err)
	}
}

func TestClientIPHonorsTrustedProxyVar(t *testing.T) {
	m := MatchGeoIPCountry{DB: countryDB, Countries: []string{"GB"}}

	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _ = m.Cleanup() })

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

	if err := m.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	t.Cleanup(func() { _ = m.Cleanup() })

	for i, tc := range []struct {
		remoteAddr string
		want       bool
	}{
		{"1.128.0.1:1234", true},   // AS1221
		{"10.1.2.3:1234", false},   // private, no record
		{"8.8.8.8:1234", false},    // not in the test db
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

func TestASNProvisionRejects(t *testing.T) {
	for _, bad := range []string{"0", "AS1221", "-1", "abc", "4294967296"} {
		m := MatchGeoIPASN{DB: asnDB, ASNs: []string{bad}}
		if err := m.Provision(caddy.Context{}); err == nil {
			t.Cleanup(func() { _ = m.Cleanup() })
			t.Errorf("expected provision to reject asn %q", bad)
		}
	}
}

func TestCountryProvisionRejects(t *testing.T) {
	for _, bad := range []string{"USA", "U", "12", ""} {
		m := MatchGeoIPCountry{DB: countryDB, Countries: []string{bad}}
		if err := m.Provision(caddy.Context{}); err == nil {
			t.Cleanup(func() { _ = m.Cleanup() })
			t.Errorf("expected provision to reject country %q", bad)
		}
	}
}
