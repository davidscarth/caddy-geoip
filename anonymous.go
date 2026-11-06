// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(MatchGeoIPAnonymous{})
}

// MatchGeoIPAnonymous matches VPNs, Tor, proxies, and hosting providers
// using MaxMind-compatible GeoIP databases: a small, fast, and safe
// geolocation matcher. It sets {geoip.anonymous}, {geoip.confidence},
// and {geoip.risk}.
//
// An address the database does not flag is just not anonymous, so there
// is no match_unknown.
type MatchGeoIPAnonymous struct {
	// Path to an Anonymous IP, Anonymous Plus, or IP Risk database.
	// Supports placeholders.
	DB string `json:"db,omitempty"`

	// Kinds of anonymizer to match, any of: anonymous, vpn, tor,
	// hosting, public_proxy, residential_proxy. "anonymous" is
	// MaxMind's umbrella flag, set whenever any other is.
	Types []string `json:"types,omitempty"`

	// Least anonymizer_confidence, 1 to 99, for a public_proxy or
	// residential_proxy to count. Only a record that carries a confidence
	// is judged by it; without one the flags stand as published, as vpn,
	// tor, and hosting always do. Needs an Anonymous Plus or IP Risk
	// database and a proxy type.
	MinConfidence uint8 `json:"min_confidence,omitempty"`

	// Least ip_risk, 1 to 99, to match whatever the flags say: a risky
	// address is risky. Needs an IP Risk database. With it, type may be
	// left out.
	MinRisk uint8 `json:"min_risk,omitempty"`

	types uint8
	db    *maxminddb.Reader
}

// proxyKinds are the bits confidence applies to: public_proxy and
// residential_proxy, the two kinds MaxMind infers rather than knows.
const proxyKinds = 1<<4 | 1<<5

// anonKinds lists the kinds in the order {geoip.anonymous} reports
// them. Bit i of a mask is kind i.
var anonKinds = [...]string{
	"anonymous", "vpn", "tor", "hosting", "public_proxy", "residential_proxy",
}

// anonFlags is the part of an Anonymous IP record the matcher reads.
// MaxMind writes only the flags that are true, so an absent one is
// false, and a clean address decodes to the zero value.
type anonFlags struct {
	Anonymous        bool     `maxminddb:"is_anonymous"`
	VPN              bool     `maxminddb:"is_anonymous_vpn"`
	Tor              bool     `maxminddb:"is_tor_exit_node"`
	Hosting          bool     `maxminddb:"is_hosting_provider"`
	PublicProxy      bool     `maxminddb:"is_public_proxy"`
	ResidentialProxy bool     `maxminddb:"is_residential_proxy"`
	Confidence       *uint16  `maxminddb:"anonymizer_confidence"` // nil when the record has none
	Risk             *float64 `maxminddb:"ip_risk"`
}

// mask packs the flags into bits in anonKinds order. A proxy whose
// confidence is below cutoff (0 for none) is dropped; one with no
// confidence is kept, and the other kinds and the umbrella stand as
// published. The anonymous bit is set whenever any other is.
func (f anonFlags) mask(cutoff uint8) uint8 {
	var m uint8
	for i, set := range [...]bool{
		f.Anonymous, f.VPN, f.Tor, f.Hosting, f.PublicProxy, f.ResidentialProxy,
	} {
		if set {
			m |= 1 << i
		}
	}
	if f.Confidence != nil && *f.Confidence < uint16(cutoff) {
		m &^= proxyKinds
	}
	if m != 0 {
		m |= 1
	}
	return m
}

// anonNames[mask] is the placeholder value for mask: the kinds set in
// it, comma-separated in anonKinds order, or empty for none. Built once
// as interface values, ready to hand to the replacer.
var anonNames = func() (names [1 << len(anonKinds)]any) {
	for mask := range names {
		var parts []string
		for i, kind := range anonKinds {
			if mask&(1<<i) != 0 {
				parts = append(parts, kind)
			}
		}
		names[mask] = strings.Join(parts, ",")
	}
	return names
}()

// CaddyModule returns the Caddy module information.
func (MatchGeoIPAnonymous) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.geoip_anonymous",
		New: func() caddy.Module { return new(MatchGeoIPAnonymous) },
	}
}

// Provision builds the kind mask and opens the database. A missing db,
// or no type and no risk, is left for Validate to report, so the
// database isn't opened for a config that is about to be refused.
func (m *MatchGeoIPAnonymous) Provision(ctx caddy.Context) error {
	if m.DB == "" || (len(m.Types) == 0 && m.MinRisk == 0) {
		return nil
	}
	for _, t := range m.Types {
		i, ok := anonKind(t)
		if !ok {
			return fmt.Errorf("invalid type %q", t)
		}
		m.types |= 1 << i
	}
	if m.MinConfidence > 99 || m.MinRisk > 99 {
		return fmt.Errorf("confidence and risk must be 1 to 99")
	}
	if m.MinConfidence > 0 && m.types&proxyKinds == 0 {
		return fmt.Errorf("confidence applies to public_proxy and residential_proxy, so type needs one of them")
	}
	var err error
	if m.db, err = openDB(ctx.Slogger(), m.DB, "anonymous", "ip-risk"); err != nil {
		return err
	}
	if m.MinConfidence > 0 && !hasType(m.db.Metadata.DatabaseType, []string{"anonymous-plus", "ip-risk"}) {
		return fmt.Errorf("confidence needs an Anonymous Plus or IP Risk database, not %s", m.db.Metadata.DatabaseType)
	}
	if m.MinRisk > 0 && !hasType(m.db.Metadata.DatabaseType, []string{"ip-risk"}) {
		return fmt.Errorf("risk needs an IP Risk database, not %s", m.db.Metadata.DatabaseType)
	}
	return nil
}

// anonKind returns the index of kind in anonKinds, and whether it is one.
func anonKind(kind string) (int, bool) {
	for i, k := range anonKinds {
		if strings.EqualFold(kind, k) {
			return i, true
		}
	}
	return 0, false
}

// Validate ensures the configuration is usable.
func (m *MatchGeoIPAnonymous) Validate() error {
	if m.DB == "" {
		return fmt.Errorf("db is required")
	}
	if len(m.Types) == 0 && m.MinRisk == 0 {
		return fmt.Errorf("at least one type, or a risk, is required")
	}
	return nil
}

// MatchWithError returns true if the client of r is flagged with one
// of the configured kinds, or scores at or above the configured risk.
func (m *MatchGeoIPAnonymous) MatchWithError(r *http.Request) (bool, error) {
	if err := guard(r, "geoip_anonymous", m.db); err != nil {
		return false, err
	}

	// One decode serves both the match and the placeholder, so this
	// does not go through resolve, which returns only a string.
	var f anonFlags
	if ip := clientIP(r); ip.IsValid() {
		if err := m.db.Lookup(ip).Decode(&f); err != nil {
			return false, fmt.Errorf("geoip_anonymous: %s: %w", m.DB, err)
		}
	}
	mask := f.mask(m.MinConfidence)
	setPlaceholder(r, "geoip.anonymous", anonNames[mask])
	// Numbers, not strings: the replacer formats them only when a
	// placeholder is expanded, and boxing a small int is free.
	var confidence, risk any = "", ""
	if f.Confidence != nil {
		confidence = int(*f.Confidence)
	}
	if f.Risk != nil {
		risk = *f.Risk
	}
	setPlaceholder(r, "geoip.confidence", confidence)
	setPlaceholder(r, "geoip.risk", risk)
	risky := m.MinRisk != 0 && f.Risk != nil && *f.Risk >= float64(m.MinRisk)
	return mask&m.types != 0 || risky, nil
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens. Syntax:
//
//	geoip_anonymous {
//	    db         <path>
//	    type       <kinds...>
//	    confidence <min>
//	    risk       <min>
//	}
func (m *MatchGeoIPAnonymous) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
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
			case "type":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				for _, a := range args {
					if _, ok := anonKind(a); !ok {
						return d.Errf("invalid type %q: one of %s", a, strings.Join(anonKinds[:], ", "))
					}
				}
				m.Types = append(m.Types, args...)
			case "confidence", "risk":
				name, cutoff := d.Val(), &m.MinConfidence // the name, before AllArgs moves on
				if name == "risk" {
					cutoff = &m.MinRisk
				}
				var s string
				if !d.AllArgs(&s) {
					return d.ArgErr()
				}
				n, err := strconv.ParseUint(s, 10, 8)
				if err != nil || n == 0 || n > 99 {
					return d.Errf("invalid %s %q: 1 to 99", name, s)
				}
				*cutoff = uint8(n)
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner                 = (*MatchGeoIPAnonymous)(nil)
	_ caddy.Validator                   = (*MatchGeoIPAnonymous)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchGeoIPAnonymous)(nil)
	_ caddyfile.Unmarshaler             = (*MatchGeoIPAnonymous)(nil)
)
