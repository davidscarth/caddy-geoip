// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"sync"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// TestMatchConcurrent drives each matcher from several goroutines at
// once. Matchers are read-only after Provision, so this passes today;
// under -race it fails the day mutable per-request state is added.
func TestMatchConcurrent(t *testing.T) {
	country := &MatchGeoIPCountry{DB: countryDB, Countries: []string{"GB"}}
	asn := &MatchGeoIPASN{DB: asnDB, ASNs: []uint32{1221}}
	subdivision := &MatchGeoIPSubdivision{DB: cityDB, Country: "US", Subdivisions: []string{"WA"}}
	for _, p := range []interface{ Provision(caddy.Context) error }{country, asn, subdivision} {
		if err := p.Provision(caddy.Context{}); err != nil {
			t.Fatal(err)
		}
	}

	// Each goroutine builds its own request: a replacer is per request
	// and not safe to share, and sharing one would report a race that
	// is the test's fault rather than the matcher's.
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 500 {
				if _, err := country.MatchWithError(newRequest("81.2.69.142:1234")); err != nil {
					t.Error(err)
					return
				}
				if _, err := asn.MatchWithError(newRequest("1.128.0.1:1234")); err != nil {
					t.Error(err)
					return
				}
				if _, err := subdivision.MatchWithError(newRequest("216.160.83.56:1234")); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	wg.Wait()
}
