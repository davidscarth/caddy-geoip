// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(MatchGeoIPASN{})
}

// MatchGeoIPASN is a small, fast, and safe GeoIP geolocation matcher
// using MaxMind-compatible databases. It matches requests by the
// client's network (autonomous system), such as a hosting provider or
// ISP, and sets {geoip.asn}.
type MatchGeoIPASN struct {
	// Path to an ASN, ISP, or Enterprise database. Supports placeholders.
	DB string `json:"db,omitempty"`

	// Autonomous system numbers to match.
	ASNs []uint32 `json:"asns,omitempty"`

	// Path to a file of autonomous system numbers to match, one per
	// line with or without an AS prefix, or Spamhaus ASN-DROP in its
	// JSON lines form. Combined with ASNs. Supports placeholders.
	ASNFile string `json:"asn_file,omitempty"`

	// Whether an IP the database has no entry for (loopback, private
	// ranges, unallocated space) matches. Default: false.
	MatchUnknown bool `json:"match_unknown,omitempty"`

	asns    map[string]struct{}
	asnPath []any
	db      *maxminddb.Reader
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
	// The set is keyed by the decimal form so the request path can
	// compare the placeholder string it publishes anyway. ASN 0 is
	// reserved and never appears in a database.
	m.asns = make(map[string]struct{}, len(m.ASNs))
	for _, n := range m.ASNs {
		if n == 0 {
			return fmt.Errorf("invalid asn 0")
		}
		m.asns[strconv.FormatUint(uint64(n), 10)] = struct{}{}
	}
	if m.ASNFile != "" {
		if err := readASNFile(m.ASNFile, m.asns); err != nil {
			return err
		}
	}
	var err error
	if m.db, err = openDB(m.DB, "asn", "isp", "enterprise"); err != nil {
		return err
	}

	// An Enterprise database nests the autonomous system fields under
	// traits; ASN and ISP databases carry them at the top level. The
	// path is chosen once here rather than per request.
	m.asnPath = []any{"autonomous_system_number"}
	if strings.Contains(strings.ToLower(m.db.Metadata.DatabaseType), "enterprise") {
		m.asnPath = []any{"traits", "autonomous_system_number"}
	}
	return nil
}

// readASNFile adds the autonomous system numbers in the file at path
// to the set. A line starts with the number, with or without an AS
// prefix, followed by nothing or by a space, tab, comma, semicolon, or
// comment and anything after that (a name, a column), which covers
// plain lists, "AS1234 Name" lists, and CSV. A line that is a JSON
// object is read as Spamhaus ASN-DROP writes them, by its "asn"
// member. Blank lines, comments, lines with no digits at all (a CSV
// header), and JSON lines without an "asn" member (ASN-DROP's metadata
// line) are skipped. The file must yield at least one number.
func readASNFile(path string, set map[string]struct{}) error {
	path = caddy.NewReplacer().ReplaceAll(path, "")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("asn_file: %w", err)
	}
	found, line := 0, 0
	for text := range strings.Lines(string(data)) {
		line++
		text = strings.TrimSpace(text)
		if text == "" || text[0] == '#' {
			continue
		}
		var n uint64
		if text[0] == '{' {
			var rec struct {
				ASN uint32 `json:"asn"`
			}
			if err := json.Unmarshal([]byte(text), &rec); err != nil {
				return fmt.Errorf("asn_file: %s:%d: %w", path, line, err)
			}
			if rec.ASN == 0 {
				continue
			}
			n = uint64(rec.ASN)
		} else {
			if !strings.ContainsAny(text, "0123456789") {
				continue // a header or label line
			}
			num := text
			if len(num) > 2 && strings.EqualFold(num[:2], "AS") {
				num = num[2:]
			}
			end := strings.IndexFunc(num, func(r rune) bool { return r < '0' || r > '9' })
			if end < 0 {
				end = len(num)
			} else if !strings.ContainsRune(" \t,;#", rune(num[end])) {
				end = 0
			}
			if n, err = strconv.ParseUint(num[:end], 10, 32); err != nil || n == 0 {
				return fmt.Errorf("asn_file: %s:%d: invalid asn %q", path, line, text)
			}
		}
		set[strconv.FormatUint(n, 10)] = struct{}{}
		found++
	}
	if found == 0 {
		return fmt.Errorf("asn_file: %s: no autonomous system numbers found", path)
	}
	return nil
}

// Validate ensures the configuration is usable.
func (m *MatchGeoIPASN) Validate() error {
	if m.DB == "" {
		return fmt.Errorf("db is required")
	}
	if len(m.ASNs) == 0 && m.ASNFile == "" {
		return fmt.Errorf("at least one asn or an asn_file is required")
	}
	return nil
}

// MatchWithError returns true if the client of r is in one of the
// configured autonomous systems.
func (m *MatchGeoIPASN) MatchWithError(r *http.Request) (bool, error) {
	// Early data (0-RTT) arrives before the handshake has verified the
	// client address, so refuse it with 425 until the handshake completes,
	// same as Caddy's own IP matchers do.
	if r.TLS != nil && !r.TLS.HandshakeComplete {
		return false, caddyhttp.Error(http.StatusTooEarly,
			fmt.Errorf("TLS handshake not complete, client IP cannot be verified"))
	}

	// Guard for callers outside Caddy; fails closed instead of nil-dereferencing.
	if m.db == nil {
		return false, fmt.Errorf("geoip_asn: not provisioned")
	}

	asn, err := lookup(r, "geoip.asn", m.asnOf)
	if err != nil {
		return false, err
	}
	if asn == "" {
		return m.MatchUnknown, nil
	}
	_, ok := m.asns[asn]
	return ok, nil
}

// asnOf returns the autonomous system number for ip as a decimal
// string, or an empty string if the database has no entry for it.
// MaxMind uses 0 for a record with no autonomous system, so a zero
// here means absent rather than AS0, which is reserved and rejected
// at provision time.
func (m *MatchGeoIPASN) asnOf(ip netip.Addr) (string, error) {
	var n uint32
	if err := m.db.Lookup(ip).DecodePath(&n, m.asnPath...); err != nil {
		return "", fmt.Errorf("geoip_asn: %s: %w", m.DB, err)
	}
	if n == 0 {
		return "", nil
	}
	return strconv.FormatUint(uint64(n), 10), nil
}

// UnmarshalCaddyfile sets up the matcher from Caddyfile tokens. Syntax:
//
//	geoip_asn {
//	    db       <path>
//	    asn      <numbers...>
//	    asn_file <path>
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
					if err != nil {
						return d.Errf("invalid asn %q", a)
					}
					m.ASNs = append(m.ASNs, uint32(n))
				}
			case "asn_file":
				if m.ASNFile != "" {
					return d.Err("asn_file already specified")
				}
				if !d.AllArgs(&m.ASNFile) {
					return d.ArgErr()
				}
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
