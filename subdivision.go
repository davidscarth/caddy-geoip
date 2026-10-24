// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/oschwald/maxminddb-golang/v2/mmdbdata"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(MatchGeoIPSubdivision{})
}

// MatchGeoIPSubdivision is a small, fast, and safe GeoIP geolocation
// matcher using MaxMind-compatible databases. It matches requests by
// state, province, or region within a country and sets {geoip.country}
// and {geoip.subdivision}.
//
// The country is required because subdivision codes are only unique
// within a country: CA is California in the United States and a valid
// code elsewhere. Together the two fields form an ISO 3166-2 code, so
// country US with subdivision CA represents US-CA.
//
// A client is in every subdivision of the record, which MaxMind orders
// from most general to most specific: an address in Boxford, England
// reports ENG then WBK and is in both, so a rule on either matches.
// The {geoip.subdivision} placeholder reports the most specific code,
// whatever the rule matched on.
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
	// Early data (0-RTT) arrives before the handshake has verified the
	// client address, so refuse it with 425 until the handshake completes,
	// same as Caddy's own IP matchers do.
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return false, caddyhttp.Error(http.StatusTooEarly,
			fmt.Errorf("TLS handshake not complete, client IP cannot be verified"))
	}

	// Guard for callers outside Caddy; fails closed instead of nil-dereferencing.
	if m.db == nil {
		return false, fmt.Errorf("geoip_subdivision: not provisioned")
	}

	country, subdivision, matched, err := lookupPlace(r, m.placeOf)
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
	return matched, nil
}

// placeOf returns the country code, the most specific subdivision
// code, and whether any subdivision of ip is in the configured set,
// read in one pass over the record. Either code is empty if the
// database has no entry for it. Both are decoded whatever the country
// turns out to be, so the placeholders report what the database knows
// even for a request this matcher does not match.
func (m *MatchGeoIPSubdivision) placeOf(ip netip.Addr) (string, string, bool, error) {
	p := place{in: m.subdivisions}
	if err := m.db.Lookup(ip).Decode(&p); err != nil {
		return "", "", false, fmt.Errorf("geoip_subdivision: %s: %w", m.DB, err)
	}
	return p.country, p.subdivision, p.matched, nil
}

// place decodes a City record directly from the reader's cursor, so the
// record is walked once rather than once per field. Only country and
// subdivisions are read; everything else is skipped. Strings come from
// the reader's cache, so decoding allocates nothing beyond p itself.
type place struct {
	in                   map[string]struct{}
	country, subdivision string
	matched              bool
}

// UnmarshalMaxMindDBCursor implements mmdbdata.CursorUnmarshaler. The
// cursor protocol is: open a container, read each value through the
// cursor it yields, and hand the successor back to Next.
func (p *place) UnmarshalMaxMindDBCursor(c mmdbdata.Cursor) (mmdbdata.Cursor, error) {
	m, err := c.Map()
	if err != nil {
		return mmdbdata.Cursor{}, err
	}
	var next mmdbdata.Cursor
	for key, val, ok := m.Next(next); ok; key, val, ok = m.Next(next) {
		if string(key) == "country" {
			next, err = isoCode(val, &p.country)
		} else if string(key) == "subdivisions" {
			next, err = p.subdivisions(val)
		} else {
			next, err = val.Skip()
		}
		if err != nil {
			return mmdbdata.Cursor{}, err
		}
	}
	if err := m.Err(); err != nil {
		return mmdbdata.Cursor{}, err
	}
	return m.End()
}

// subdivisions walks the array. MaxMind orders it from most general to
// most specific, so the last coded entry is the placeholder value; an
// entry with no iso_code is skipped, since a rule could not name it.
func (p *place) subdivisions(c mmdbdata.Cursor) (mmdbdata.Cursor, error) {
	s, err := c.Slice()
	if err != nil {
		return mmdbdata.Cursor{}, err
	}
	var next mmdbdata.Cursor
	for _, val, ok := s.Next(next); ok; _, val, ok = s.Next(next) {
		var code string
		if next, err = isoCode(val, &code); err != nil {
			return mmdbdata.Cursor{}, err
		}
		if code != "" {
			p.subdivision = code
			if _, ok := p.in[strings.ToUpper(code)]; ok {
				p.matched = true
			}
		}
	}
	if err := s.Err(); err != nil {
		return mmdbdata.Cursor{}, err
	}
	return s.End()
}

// isoCode reads iso_code from a map and skips its other fields.
func isoCode(c mmdbdata.Cursor, code *string) (mmdbdata.Cursor, error) {
	m, err := c.Map()
	if err != nil {
		return mmdbdata.Cursor{}, err
	}
	var next mmdbdata.Cursor
	for key, val, ok := m.Next(next); ok; key, val, ok = m.Next(next) {
		if string(key) == "iso_code" {
			*code, next, err = val.ReadString()
		} else {
			next, err = val.Skip()
		}
		if err != nil {
			return mmdbdata.Cursor{}, err
		}
	}
	if err := m.Err(); err != nil {
		return mmdbdata.Cursor{}, err
	}
	return m.End()
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
