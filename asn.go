// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(MatchGeoIPASN{})
}

// MatchGeoIPASN matches requests whose client IP belongs to one of the
// configured autonomous systems, according to a MaxMind GeoLite2 or
// GeoIP2 ASN database. Use Caddy's `not` for the complement, and
// Caddy's `abort`, `respond`, or `redir` to act on the match.
type MatchGeoIPASN struct {
	// Path to an ASN, ISP, or Enterprise database. Supports placeholders.
	DB string `json:"db,omitempty"`

	// Autonomous system numbers to match, as plain integers.
	ASNs []string `json:"asns,omitempty"`

	// Whether an IP the database has no entry for (loopback, private
	// ranges, unallocated space) matches. Default: false.
	MatchUnknown bool `json:"match_unknown,omitempty"`

	asns map[string]struct{}
	db   *maxminddb.Reader
}

// CaddyModule returns the Caddy module information.
func (MatchGeoIPASN) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.geoip_asn",
		New: func() caddy.Module { return new(MatchGeoIPASN) },
	}
}

// Provision builds the ASN set and opens the database. A missing db
// is left for Validate to report.
func (m *MatchGeoIPASN) Provision(caddy.Context) error {
	if m.DB == "" {
		return nil
	}
	m.asns = make(map[string]struct{}, len(m.ASNs))
	for _, a := range m.ASNs {
		n, err := strconv.ParseUint(a, 10, 32)
		if err != nil || n == 0 {
			return fmt.Errorf("invalid asn %q", a)
		}
		m.asns[strconv.FormatUint(n, 10)] = struct{}{}
	}
	var err error
	m.db, err = openDB(m.DB, "asn", "isp", "enterprise")
	return err
}

// Validate ensures the configuration is usable.
func (m *MatchGeoIPASN) Validate() error {
	if m.DB == "" {
		return fmt.Errorf("db is required")
	}
	if len(m.ASNs) == 0 {
		return fmt.Errorf("at least one asn is required")
	}
	return nil
}

// Cleanup closes the database.
func (m *MatchGeoIPASN) Cleanup() error {
	if m.db == nil {
		return nil
	}
	return m.db.Close()
}

// MatchWithError returns true if the client of r is in one of the
// configured autonomous systems.
func (m *MatchGeoIPASN) MatchWithError(r *http.Request) (bool, error) {
	asn, err := lookup(r, "geoip.asn", m.asn)
	if err != nil {
		return false, err
	}
	if asn == "" {
		return m.MatchUnknown, nil
	}
	_, ok := m.asns[asn]
	return ok, nil
}

// asn returns the autonomous system number for ip as a decimal
// string, or an empty string if the database has no entry for it.
func (m *MatchGeoIPASN) asn(ip netip.Addr) (string, error) {
	var n uint32
	if err := m.db.Lookup(ip).DecodePath(&n, "autonomous_system_number"); err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	return strconv.FormatUint(uint64(n), 10), nil
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens. Syntax:
//
//	geoip_asn {
//	    db  <path>
//	    asn <numbers...>
//	    match_unknown
//	}
func (m *MatchGeoIPASN) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
			case "asn":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.ASNs = append(m.ASNs, args...)
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
	_ caddy.Provisioner                 = (*MatchGeoIPASN)(nil)
	_ caddy.Validator                   = (*MatchGeoIPASN)(nil)
	_ caddy.CleanerUpper                = (*MatchGeoIPASN)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchGeoIPASN)(nil)
	_ caddyfile.Unmarshaler             = (*MatchGeoIPASN)(nil)
)
