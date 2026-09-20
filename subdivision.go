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
	caddy.RegisterModule(MatchGeoIPSubdivision{})
}

// MatchGeoIPSubdivision matches requests whose client IP is located in
// one of the configured subdivisions of a country, according to a
// MaxMind GeoLite2 or GeoIP2 City (or Enterprise) database. Use Caddy's
// `not` for the complement, and Caddy's `abort`, `respond`, or `redir`
// to act on the match.
//
// The country is required because subdivision codes are only unique
// within a country: CA is California in the United States and a valid
// code elsewhere. Together the two fields form an ISO 3166-2 code, so
// country US with subdivision CA is US-CA.
//
// Where a country has nested subdivisions, only the most specific one
// is matched, following MaxMind's most_specific_subdivision convention.
// An address in Boxford, England reports ENG and WBK, and matches WBK;
// it does not match ENG.
type MatchGeoIPSubdivision struct {
	// Path to a City or Enterprise database. Supports placeholders.
	DB string `json:"db,omitempty"`

	// ISO 3166-1 alpha-2 code of the country the subdivisions belong
	// to. Required. Case-insensitive.
	Country string `json:"country,omitempty"`

	// ISO 3166-2 subdivision codes to match, without the country
	// prefix: CA, not US-CA. Case-insensitive.
	Subdivisions []string `json:"subdivisions,omitempty"`

	// Whether an IP the database cannot place (loopback, private
	// ranges, unallocated space, or a record with no subdivision)
	// matches. Default: false.
	MatchUnknown bool `json:"match_unknown,omitempty"`

	country      string
	subdivisions map[string]struct{}
	db           *maxminddb.Reader
}

// CaddyModule returns the Caddy module information.
func (MatchGeoIPSubdivision) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.geoip_subdivision",
		New: func() caddy.Module { return new(MatchGeoIPSubdivision) },
	}
}

// Provision builds the subdivision set and opens the database. A
// missing db or country is left for Validate to report, since its
// messages explain what is required and why.
func (m *MatchGeoIPSubdivision) Provision(caddy.Context) error {
	if m.DB == "" {
		return nil
	}
	if m.Country == "" {
		return nil // Validate reports the requirement, and why
	}
	if !isCountryCode(m.Country) {
		return fmt.Errorf("invalid country code %q", m.Country)
	}
	m.country = strings.ToUpper(m.Country)

	m.subdivisions = make(map[string]struct{}, len(m.Subdivisions))
	for _, s := range m.Subdivisions {
		if !isSubdivisionCode(s) {
			return fmt.Errorf("invalid subdivision code %q", s)
		}
		m.subdivisions[strings.ToUpper(s)] = struct{}{}
	}

	var err error
	m.db, err = openDB(m.DB, "city", "enterprise")
	return err
}

// Validate ensures the configuration is usable.
func (m *MatchGeoIPSubdivision) Validate() error {
	if m.DB == "" {
		return fmt.Errorf("db is required")
	}
	if m.Country == "" {
		return fmt.Errorf("country is required: subdivision codes are only unique within a country")
	}
	if len(m.Subdivisions) == 0 {
		return fmt.Errorf("at least one subdivision is required")
	}
	return nil
}

// MatchWithError returns true if the client of r is in the configured
// country and in one of the configured subdivisions.
func (m *MatchGeoIPSubdivision) MatchWithError(r *http.Request) (bool, error) {
	// if handshake is not finished, we infer 0-RTT that has
	// not verified remote IP; could be spoofed, so we throw
	// HTTP 425 status to tell the client to try again after
	// the handshake is complete
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return false, caddyhttp.Error(http.StatusTooEarly,
			fmt.Errorf("TLS handshake not complete, client IP cannot be verified"))
	}

	country, subdivision, err := lookupPlace(r, m.place)
	if err != nil {
		return false, err
	}
	if country == "" {
		return m.MatchUnknown, nil
	}
	if !strings.EqualFold(country, m.country) {
		// The client is somewhere else; that is an answer, not a
		// gap in the data, so match_unknown does not apply.
		return false, nil
	}
	if subdivision == "" {
		return m.MatchUnknown, nil
	}
	_, ok := m.subdivisions[strings.ToUpper(subdivision)]
	return ok, nil
}

// place returns the country code and the most specific subdivision
// code for ip, both decoded from one record. Either is empty if the
// database has no entry for it. Both are decoded whatever the country
// turns out to be, so the placeholders report what the database knows
// even for a request this matcher does not match.
func (m *MatchGeoIPSubdivision) place(ip netip.Addr) (string, string, error) {
	result := m.db.Lookup(ip)

	var country string
	if err := result.DecodePath(&country, "country", "iso_code"); err != nil {
		return "", "", err
	}

	var subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
	}
	if err := result.DecodePath(&subdivisions, "subdivisions"); err != nil {
		return "", "", err
	}
	// MaxMind orders subdivisions from most general to most specific,
	// so the last entry is the one to match on. If it carries no code
	// the client is unknown at this level rather than a member of a
	// more general subdivision they did not configure.
	if n := len(subdivisions); n > 0 {
		return country, subdivisions[n-1].ISOCode, nil
	}
	return country, "", nil
}

// isSubdivisionCode reports whether s has the shape of the second part
// of an ISO 3166-2 code: 1 to 3 ASCII letters or digits. Real codes use
// every combination, from E in Sweden to ENG in the United Kingdom to
// 22 in China, so nothing narrower is safe. It does not check the code
// is assigned, since the ISO list is maintained continuously and a
// database may be ahead of or behind it.
func isSubdivisionCode(s string) bool {
	if len(s) < 1 || len(s) > 3 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if c >= '0' && c <= '9' {
			continue
		}
		c |= 0x20 // fold to lower case
		if c < 'a' || c > 'z' {
			return false
		}
	}
	return true
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens. Syntax:
//
//	geoip_subdivision {
//	    db          <path>
//	    country     <code>
//	    subdivision <codes...>
//	    match_unknown
//	}
func (m *MatchGeoIPSubdivision) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
				if m.Country != "" {
					return d.Err("country already specified")
				}
				if !d.AllArgs(&m.Country) {
					return d.ArgErr()
				}
			case "subdivision":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				for _, a := range args {
					if strings.Contains(a, "-") {
						return d.Errf("invalid subdivision code '%s': write the code without the country prefix, and put the country in the country subdirective", a)
					}
				}
				m.Subdivisions = append(m.Subdivisions, args...)
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
	_ caddy.Provisioner                 = (*MatchGeoIPSubdivision)(nil)
	_ caddy.Validator                   = (*MatchGeoIPSubdivision)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchGeoIPSubdivision)(nil)
	_ caddyfile.Unmarshaler             = (*MatchGeoIPSubdivision)(nil)
)
