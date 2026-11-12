// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(MatchGeoIPASN{})
}

// MatchGeoIPASN matches requests by the client's network (ASN) using
// MaxMind-compatible GeoIP databases: a small, fast, and safe geolocation
// matcher. The network is the client's autonomous system, such as a
// hosting provider or ISP. It sets {geoip.asn}.
type MatchGeoIPASN struct {
	// Path to an ASN, ISP, or Enterprise database.
	DB string `json:"db,omitempty"`

	// Autonomous system numbers to match.
	ASNs []uint32 `json:"asns,omitempty"`

	// Paths to files of autonomous system numbers to match. Parser will
	// validate any list, from plain numbers to CSV, Markdown, Cloudflare
	// rules, or JSON (e.g. Spamhaus ASN-DROP) with an "asn" key. Each
	// file is read on its own and must hold at least one ASN. Combined
	// with ASNs in the same Caddyfile block.
	ASNFiles []string `json:"asn_files,omitempty"`

	// Whether an IP the database has no entry for (loopback, private
	// ranges, unallocated space) matches. Default: false.
	MatchUnknown bool `json:"match_unknown,omitempty"`

	asns    map[string]struct{}
	asnPath []any
	db      *maxminddb.Reader
}

// CaddyModule returns Caddy module information for the ASN matcher.
func (MatchGeoIPASN) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.geoip_asn",
		New: func() caddy.Module { return new(MatchGeoIPASN) },
	}
}

// Provision builds the ASN set and opens the database. A missing db,
// or no asn and no asn_file, is left for Validate to report, so the
// database isn't opened for a config that is about to be refused.
func (m *MatchGeoIPASN) Provision(ctx caddy.Context) error {
	if m.DB == "" || (len(m.ASNs) == 0 && len(m.ASNFiles) == 0) {
		return nil
	}
	// The set is keyed by the decimal form so the request path can
	// compare the placeholder string it publishes anyway. ASN 0 is
	// reserved.
	m.asns = make(map[string]struct{}, len(m.ASNs))
	for _, n := range m.ASNs {
		if n == 0 {
			return fmt.Errorf("invalid asn 0")
		}
		m.asns[strconv.FormatUint(uint64(n), 10)] = struct{}{}
	}
	logger := ctx.Slogger()
	for _, path := range m.ASNFiles {
		if err := readASNFile(logger, path, m.asns); err != nil {
			return err
		}
	}
	var err error
	if m.db, err = openDB(logger, m.DB, "asn", "isp", "enterprise"); err != nil {
		return err
	}

	// An Enterprise database nests the autonomous system fields under
	// traits, ASN and ISP databases carry them at the top level. The
	// path is chosen once here rather than per request.
	m.asnPath = []any{"autonomous_system_number"}
	if hasType(m.db.Metadata.DatabaseType, []string{"enterprise"}) {
		m.asnPath = []any{"traits", "autonomous_system_number"}
	}
	return probe(m.db, func(ip netip.Addr) error { _, err := m.asnOf(ip); return err })
}

// logListAge logs one line about an ASN list that loaded: INFO with how
// many ASNs it added, its modified time, and its age, WARN when it was
// modified more than maxAgeDays before now, or WARN when its modified time is
// in the future. asns counts only ASNs not already in the set.
func logListAge(logger *slog.Logger, path string, asns int, modified, now time.Time) {
	attrs := []any{slog.String("path", path), slog.Int("asns", asns), slog.String("modified", modified.UTC().Format(time.RFC3339))}
	switch {
	case modified.After(now):
		logger.Warn("asn list modified time is in the future", attrs...)
	case ageDays(modified, now) > maxAgeDays:
		logger.Warn("asn list"+tooOldMsg, append(attrs, slog.Int("age_days", ageDays(modified, now)))...)
	default:
		logger.Info("asn list loaded", append(attrs, slog.Int("age_days", ageDays(modified, now)))...)
	}
}

// Validate ensures the configuration is usable.
func (m *MatchGeoIPASN) Validate() error {
	if m.DB == "" {
		return fmt.Errorf("db is required")
	}
	if len(m.ASNs) == 0 && len(m.ASNFiles) == 0 {
		return fmt.Errorf("at least one asn or asn_file is required")
	}
	return nil
}

// MatchWithError returns true if the client of r is in one of the
// configured autonomous systems.
func (m *MatchGeoIPASN) MatchWithError(r *http.Request) (bool, error) {
	if err := guard(r, "geoip_asn", m.db); err != nil {
		return false, err
	}

	asn, err := resolve(r, m.asnOf)
	if err != nil {
		return false, err
	}
	setPlaceholder(r, "geoip.asn", asn)
	if asn == "" {
		return m.MatchUnknown, nil
	}
	_, ok := m.asns[asn]
	return ok, nil
}

// asnOf returns the autonomous system number for ip as a decimal
// string, or an empty string if the database has no entry for it.
func (m *MatchGeoIPASN) asnOf(ip netip.Addr) (string, error) {
	var n uint32
	if err := m.db.Lookup(ip).DecodePath(&n, m.asnPath...); err != nil {
		return "", fmt.Errorf("geoip_asn: %s: %w", caddy.NewReplacer().ReplaceAll(m.DB, ""), err)
	}
	if n == 0 {
		return "", nil
	}
	return strconv.FormatUint(uint64(n), 10), nil
}

// UnmarshalCaddyfile sets up the matcher from the Caddyfile. Syntax:
//
//	geoip_asn {
//	    db       <path>
//	    asn      <numbers...>
//	    asn_file <paths...>
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
				for _, a := range args {
					n, err := strconv.ParseUint(a, 10, 32)
					if err != nil || n == 0 {
						return d.Errf("invalid asn %q", a)
					}
					m.ASNs = append(m.ASNs, uint32(n))
				}
			case "asn_file":
				// Any number of paths, and the line may repeat: each
				// file is read on its own into the same set.
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				m.ASNFiles = append(m.ASNFiles, args...)
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
	_ caddyhttp.RequestMatcherWithError = (*MatchGeoIPASN)(nil)
	_ caddyfile.Unmarshaler             = (*MatchGeoIPASN)(nil)
)
