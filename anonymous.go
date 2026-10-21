// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(MatchGeoIPAnonymous{})
}

// MatchGeoIPAnonymous is a small, fast, and safe GeoIP matcher using
// MaxMind-compatible databases. It matches requests from known
// anonymizers, such as VPNs, Tor exit nodes, and hosting providers,
// and sets {geoip.anonymous}.
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

	types uint8
	db    *maxminddb.Reader
}

// anonKinds lists the kinds in the order {geoip.anonymous} reports
// them. Bit i of a mask is kind i.
var anonKinds = [...]string{
	"anonymous", "vpn", "tor", "hosting", "public_proxy", "residential_proxy",
}

// anonFlags is the part of an Anonymous IP record the matcher reads.
// MaxMind writes only the flags that are true, so an absent one is
// false, and a clean address decodes to the zero value.
type anonFlags struct {
	Anonymous        bool `maxminddb:"is_anonymous"`
	VPN              bool `maxminddb:"is_anonymous_vpn"`
	Tor              bool `maxminddb:"is_tor_exit_node"`
	Hosting          bool `maxminddb:"is_hosting_provider"`
	PublicProxy      bool `maxminddb:"is_public_proxy"`
	ResidentialProxy bool `maxminddb:"is_residential_proxy"`
}

// mask packs the flags into bits in anonKinds order.
func (f anonFlags) mask() uint8 {
	var m uint8
	for i, set := range [...]bool{
		f.Anonymous, f.VPN, f.Tor, f.Hosting, f.PublicProxy, f.ResidentialProxy,
	} {
		if set {
			m |= 1 << i
		}
	}
	return m
}

// kindsOf names the kinds set in mask, comma-separated in anonKinds
// order, or an empty string for none. A single kind is returned as the
// constant itself, so the common case does not allocate.
func kindsOf(mask uint8) string {
	var parts [len(anonKinds)]string
	n := 0
	for i, kind := range anonKinds {
		if mask&(1<<i) != 0 {
			parts[n] = kind
			n++
		}
	}
	switch n {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:n], ",")
}

// CaddyModule returns the Caddy module information.
func (MatchGeoIPAnonymous) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.geoip_anonymous",
		New: func() caddy.Module { return new(MatchGeoIPAnonymous) },
	}
}

// Provision builds the kind mask and opens the database. A missing db
// is left for Validate to report.
func (m *MatchGeoIPAnonymous) Provision(caddy.Context) error {
	if m.DB == "" {
		return nil
	}
	for _, t := range m.Types {
		i := anonKind(t)
		if i < 0 {
			return fmt.Errorf("invalid type %q", t)
		}
		m.types |= 1 << i
	}
	var err error
	m.db, err = openDB(m.DB, "anonymous", "ip-risk")
	return err
}

// anonKind returns the index of kind in anonKinds, or -1.
func anonKind(kind string) int {
	for i, k := range anonKinds {
		if strings.EqualFold(kind, k) {
			return i
		}
	}
	return -1
}

// Validate ensures the configuration is usable.
func (m *MatchGeoIPAnonymous) Validate() error {
	if m.DB == "" {
		return fmt.Errorf("db is required")
	}
	if len(m.Types) == 0 {
		return fmt.Errorf("at least one type is required")
	}
	return nil
}

// MatchWithError returns true if the client of r is flagged with one
// of the configured kinds.
func (m *MatchGeoIPAnonymous) MatchWithError(r *http.Request) (bool, error) {
	// Early data (0-RTT) arrives before the handshake has verified the
	// client address, so refuse it with 425 until the handshake completes,
	// same as Caddy's own IP matchers do.
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return false, caddyhttp.Error(http.StatusTooEarly,
			fmt.Errorf("TLS handshake not complete, client IP cannot be verified"))
	}

	// Guard for callers outside Caddy; fails closed instead of nil-dereferencing.
	if m.db == nil {
		return false, fmt.Errorf("geoip_anonymous: not provisioned")
	}

	// One decode serves both the match and the placeholder, so this
	// does not go through lookup, which returns only a string.
	var f anonFlags
	if ip := clientIP(r); ip.IsValid() {
		if err := m.db.Lookup(ip).Decode(&f); err != nil {
			return false, err
		}
	}
	mask := f.mask()
	setPlaceholder(r, "geoip.anonymous", kindsOf(mask))
	return mask&m.types != 0, nil
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens. Syntax:
//
//	geoip_anonymous {
//	    db   <path>
//	    type <kinds...>
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
					if anonKind(a) < 0 {
						return d.Errf("invalid type %q: one of %s", a, strings.Join(anonKinds[:], ", "))
					}
				}
				m.Types = append(m.Types, args...)
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
