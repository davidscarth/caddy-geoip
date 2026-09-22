// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(MatchGeoIPCountry{})
}

// MatchGeoIPCountry matches requests whose client IP is located in one of
// the configured countries, according to a MaxMind GeoLite2 or GeoIP2
// Country (or City) database. Use Caddy's `not` for the complement,
// and Caddy's `abort`, `respond`, or `redir` to act on the match.
type MatchGeoIPCountry struct {
	// Path to a Country, City, or Enterprise database. Supports placeholders.
	DB string `json:"db,omitempty"`

	// ISO 3166-1 alpha-2 country codes to match. Case-insensitive.
	Countries []string `json:"countries,omitempty"`

	// Whether an IP the database has no entry for (loopback, private
	// ranges, unallocated space) matches. Default: false.
	MatchUnknown bool `json:"match_unknown,omitempty"`

	countries map[string]struct{}
	db        *maxminddb.Reader
}

// CaddyModule returns the Caddy module information.
func (MatchGeoIPCountry) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.geoip_country",
		New: func() caddy.Module { return new(MatchGeoIPCountry) },
	}
}

// Provision builds the country set and opens the database. A missing
// db is left for Validate to report.
func (m *MatchGeoIPCountry) Provision(caddy.Context) error {
	if m.DB == "" {
		return nil
	}
	m.countries = make(map[string]struct{}, len(m.Countries))
	for _, c := range m.Countries {
		if !isCountryCode(c) {
			return fmt.Errorf("invalid country code %q", c)
		}
		m.countries[strings.ToUpper(c)] = struct{}{}
	}
	var err error
	m.db, err = openDB(m.DB, "country", "city", "enterprise")
	return err
}

// Validate ensures the configuration is usable.
func (m *MatchGeoIPCountry) Validate() error {
	if m.DB == "" {
		return fmt.Errorf("db is required")
	}
	if len(m.Countries) == 0 {
		return fmt.Errorf("at least one country is required")
	}
	return nil
}

// MatchWithError returns true if the client of r is in one of the
// configured countries.
func (m *MatchGeoIPCountry) MatchWithError(r *http.Request) (bool, error) {
	// if handshake is not finished, we infer 0-RTT that has
	// not verified remote IP; could be spoofed, so we throw
	// HTTP 425 status to tell the client to try again after
	// the handshake is complete
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return false, caddyhttp.Error(http.StatusTooEarly,
			fmt.Errorf("TLS handshake not complete, client IP cannot be verified"))
	}

	// Guard for callers outside Caddy; fails closed instead of nil-dereferencing.
	if m.db == nil {
		return false, fmt.Errorf("geoip_country: not provisioned")
	}

	code, err := lookup(r, "geoip.country", m.country)
	if err != nil {
		return false, err
	}
	if code == "" {
		return m.MatchUnknown, nil
	}
	_, ok := m.countries[strings.ToUpper(code)]
	return ok, nil
}

// country returns the ISO country code for ip, or an empty string if
// the database has no entry for it.
func (m *MatchGeoIPCountry) country(ip netip.Addr) (string, error) {
	var code string
	err := m.db.Lookup(ip).DecodePath(&code, countryPath...)
	return code, err
}

// isCountryCode reports whether s has the shape of an ISO 3166-1
// alpha-2 code: exactly two ASCII letters. It does not check the code
// is assigned, since databases also emit codes such as EU and AP.
func isCountryCode(s string) bool {
	if len(s) != 2 {
		return false
	}
	for i := range 2 {
		c := s[i] | 0x20 // fold to lower case
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens. Syntax:
//
//	geoip_country {
//	    db      <path>
//	    country <codes...>
//	    match_unknown
//	}
func (m *MatchGeoIPCountry) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	// iterate to merge multiple matchers into one
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "db":
				if m.DB != "" {
					return d.Err("db already specified")
				}
				if !d.AllArgs(&m.DB) {
					return d.ArgErr()
				}
			case "country":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.Countries = append(m.Countries, args...)
			case "match_unknown":
				if d.NextArg() {
					return d.ArgErr()
				}
				m.MatchUnknown = true
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner                 = (*MatchGeoIPCountry)(nil)
	_ caddy.Validator                   = (*MatchGeoIPCountry)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchGeoIPCountry)(nil)
	_ caddyfile.Unmarshaler             = (*MatchGeoIPCountry)(nil)
)
