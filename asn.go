// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

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
	// Path to an ASN, ISP, or Enterprise database. Supports placeholders.
	DB string `json:"db,omitempty"`

	// Autonomous system numbers to match.
	ASNs []uint32 `json:"asns,omitempty"`

	// Paths to files of autonomous system numbers to match, one per
	// line with or without an AS prefix, optionally followed by a name
	// or CSV columns, or Spamhaus ASN-DROP in its JSON lines form. Each
	// file is read on its own and must hold at least one ASN. Combined
	// with ASNs. Supports placeholders.
	ASNFiles []string `json:"asn_files,omitempty"`

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

// Provision builds the ASN set and opens the database. A missing db,
// or no asn and no asn_file, is left for Validate to report, so the
// database isn't opened for a config that is about to be refused.
func (m *MatchGeoIPASN) Provision(ctx caddy.Context) error {
	if m.DB == "" || (len(m.ASNs) == 0 && len(m.ASNFiles) == 0) {
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
	// traits; ASN and ISP databases carry them at the top level. The
	// path is chosen once here rather than per request.
	m.asnPath = []any{"autonomous_system_number"}
	if strings.Contains(strings.ToLower(m.db.Metadata.DatabaseType), "enterprise") {
		m.asnPath = []any{"traits", "autonomous_system_number"}
	}
	return nil
}

// readASNFile adds the autonomous system numbers in the file at path to
// set, keyed by their decimal form, and logs the list's age to logger (see
// logListAge). The path may hold placeholders.
//
// A line holds one ASN, with or without an AS prefix, optionally followed
// by a space, tab, comma, or semicolon and anything after it (a name, CSV
// columns). A line may instead be a JSON object, read by its "asn" member
// as Spamhaus ASN-DROP publishes them, and an object without one is skipped.
// Blank lines, lines starting with ;, and anything after # or // are
// ignored, and the first line may be a CSV header.
//
// Anything else is refused with its line number, as is a line of several
// different ASNs, which would otherwise load only the first. The file must
// be UTF-8 text of at most 64 MiB, pipes included, with lines under 64 KiB
// and at least one ASN.
func readASNFile(logger *slog.Logger, path string, set map[string]struct{}) error {
	path = caddy.NewReplacer().ReplaceAll(path, "")
	if path == "" {
		return fmt.Errorf("asn_file: path is empty after placeholder replacement")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("asn_file: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("asn_file: %w", err)
	}
	if info.Mode().IsRegular() && info.Size() > 64<<20 {
		return fmt.Errorf("asn_file: %s: %d bytes, too large to be a list (64 MiB at most)", path, info.Size())
	}
	before := len(set)
	fail := func(line int, format string, a ...any) error {
		return fmt.Errorf("asn_file: %s:%d: %s", path, line, fmt.Sprintf(format, a...))
	}

	// Pipes and devices have no size to check. One byte past the limit tells
	// a file at the limit from a larger one, which LimitReader alone would
	// silently truncate.
	lr := &io.LimitedReader{R: f, N: 64<<20 + 1}
	sc := bufio.NewScanner(lr)
	sep := func(r rune) bool { return r == ' ' || r == '\t' || r == ',' || r == ';' }
	found, line, header := 0, 0, false
	for sc.Scan() {
		line++
		text := strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\uFEFF"))
		if strings.IndexByte(text, 0) >= 0 || !utf8.ValidString(text) {
			return fail(line, "binary data or UTF-16, not a UTF-8 list")
		}
		var n uint64
		if strings.HasPrefix(text, "{") {
			var rec struct {
				ASN *uint32 `json:"asn"`
			}
			if err := json.Unmarshal([]byte(text), &rec); err != nil {
				return fail(line, "%v (asn_file takes one JSON object per line)", err)
			}
			if rec.ASN == nil {
				continue // metadata, such as ASN-DROP's last line
			}
			if n = uint64(*rec.ASN); n == 0 {
				return fail(line, "invalid asn 0")
			}
		} else if strings.HasPrefix(text, ";") {
			continue // a comment line. Elsewhere ; separates fields, like a comma.
		} else {
			text, _, _ = strings.Cut(text, "#")
			text, _, _ = strings.Cut(text, "//")
			fields := strings.FieldsFunc(text, sep)
			if len(fields) == 0 {
				continue
			}
			first := strings.Trim(fields[0], `"`)
			var ok bool
			if n, ok = parseASN(first); !ok {
				switch {
				case found == 0 && !header && isHeader(fields):
					header = true // only the first column counts from here
					continue
				case strings.Count(first, "|") >= 3:
					return fail(line, "an RIR/NRO delegated statistics file, not a list (filter it to the ASNs you want, one per line)")
				case isAddress(first):
					return fail(line, "%.60q is an IP address or network, not an AS number", first)
				}
				return fail(line, "invalid asn %.60q", first)
			}
			// Without a header, a line whose other fields are all ASNs, not
			// all this one (AS5567 AS5567 is a name), is a list on one line.
			several, same := !header && len(fields) > 1, true
			for _, field := range fields[1:] {
				m, ok := parseASN(strings.Trim(field, `"`))
				several, same = several && ok, same && m == n
			}
			if several && !same {
				return fail(line, "several ASNs on one line, put one per line")
			}
		}
		set[strconv.FormatUint(n, 10)] = struct{}{}
		found++
	}
	switch {
	case lr.N == 0:
		return fmt.Errorf("asn_file: %s: too large to be a list (64 MiB at most)", path)
	case errors.Is(sc.Err(), bufio.ErrTooLong):
		return fail(line+1, "line longer than 64 KiB (binary data, or not a list)")
	case sc.Err() != nil:
		return fail(line+1, "%v", sc.Err())
	case found == 0:
		return fmt.Errorf("asn_file: %s: no autonomous system numbers found", path)
	}
	logListAge(logger, path, len(set)-before, info.ModTime(), time.Now())
	return nil
}

// logListAge logs one line about an ASN list that loaded: INFO with how
// many ASNs it added, its modified time, and its age, WARN when it was
// modified more than 30 days before now, or WARN when its modified time is
// in the future. asns counts only ASNs not already in the set.
func logListAge(logger *slog.Logger, path string, asns int, modified, now time.Time) {
	attrs := []any{slog.String("path", path), slog.Int("asns", asns), slog.String("modified", modified.UTC().Format(time.RFC3339))}
	switch {
	case modified.After(now):
		logger.Warn("asn list modified time is in the future", attrs...)
	case ageDays(modified, now) > maxAgeDays:
		logger.Warn("asn list is more than 30 days old", append(attrs, slog.Int("age_days", ageDays(modified, now)))...)
	default:
		logger.Info("asn list loaded", append(attrs, slog.Int("age_days", ageDays(modified, now)))...)
	}
}

// parseASN parses an AS number from 1 to 4294967295 in asplain form
// (RFC 5396), with or without an AS prefix. In base 10, ParseUint
// refuses signs, spaces, and underscores.
func parseASN(s string) (uint64, bool) {
	if len(s) > 2 && strings.EqualFold(s[:2], "AS") {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return n, err == nil && n != 0
}

// isHeader reports whether the fields of a first line are CSV column names:
// the first starts with a letter and has no digits or colons, so ASN1221,
// AS-1221, and IPv6 addresses aren't taken for one, and no other field is
// an ASN, so neither is AS 1221. A single word must name the column (asn or
// as_number), so a stray word can't turn off the several-ASNs check.
func isHeader(fields []string) bool {
	first := strings.Trim(fields[0], `"`)
	if first == "" || first[0]|0x20 < 'a' || first[0]|0x20 > 'z' || strings.ContainsAny(first, "0123456789:") {
		return false
	}
	if len(fields) == 1 {
		return strings.EqualFold(first, "asn") || strings.EqualFold(first, "as_number")
	}
	for _, f := range fields[1:] {
		if _, ok := parseASN(strings.Trim(f, `"`)); ok {
			return false
		}
	}
	return true
}

// isAddress reports whether s is an IP address or network.
func isAddress(s string) bool {
	_, err1 := netip.ParsePrefix(s)
	_, err2 := netip.ParseAddr(s)
	return err1 == nil || err2 == nil
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
