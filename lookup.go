// SPDX-License-Identifier: Apache-2.0

// Package caddygeoip provides small, fast, and safe GeoIP geolocation
// matchers for Caddy, using MaxMind-compatible databases: country,
// subdivision, autonomous system (ASN), and anonymizer.
//
// The matchers only match. Blocking, allowing, routing, logging, and
// exemptions are written with Caddy's own directives. Each lookup reads
// only the fields its matcher needs from a memory-mapped database, with
// no locks and no per-request caching. The client IP is the one Caddy
// verified through trusted_proxies; a request in TLS early data is
// refused until the handshake completes. A bad configuration is rejected
// when the config loads and a failed lookup stops the request rather than
// letting it through. The only dependencies are Caddy and maxminddb-golang.
package caddygeoip

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Path into a record for DecodePath, built once rather than per
// request. The ASN path depends on the database edition, so it lives
// on the matcher instead (see MatchGeoIPASN.Provision). The
// subdivision matcher reads its record with a cursor and has no path
// (see MatchGeoIPSubdivision.placeOf).
var countryPath = []any{"country", "iso_code"}

// openDB opens the MaxMind database at path, replacing placeholders,
// and checks that its type contains one of the given words, so that a
// Country database is not silently used for ASN matching or vice versa.
// It logs the database's age to logger (see logDBAge).
//
// No Cleanup on purpose. A Caddy reload would run it with lookups still
// in flight, triggering a race condition. Instead we rely on GC to
// release the mapping.
func openDB(logger *slog.Logger, path string, types ...string) (*maxminddb.Reader, error) {
	path = caddy.NewReplacer().ReplaceAll(path, "")
	if path == "" {
		// An unset placeholder such as {env.GEOIP_DB} replaces to
		// nothing, which would otherwise fail as a missing file with
		// no path to name.
		return nil, fmt.Errorf("db path is empty after placeholder replacement")
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening db: %w", err)
	}
	dbType := db.Metadata.DatabaseType
	if !hasType(dbType, types) {
		_ = db.Close()
		return nil, fmt.Errorf("db %s is a %s database, expected %s",
			path, dbType, strings.Join(types, " or "))
	}
	// The reader errors on IPv6 lookups in an IPv4-only tree instead of
	// reporting no record, so every IPv6 request would 5xx. Refuse it here.
	if v := db.Metadata.IPVersion; v != 6 {
		_ = db.Close()
		return nil, fmt.Errorf("db %s is an IPv4-only database (ip_version %d), which is not supported",
			path, v)
	}
	logDBAge(logger, path, db.Metadata, time.Now())
	return db, nil
}

// maxAgeDays is how old a database or list may be before loading it logs a
// warning. The log messages state it, so change them with it.
const maxAgeDays = 30

// lastRFC3339 is the last second RFC 3339 can write, 9999-12-31T23:59:59Z.
const lastRFC3339 = 253402300799

// logDBAge logs one line about a database that loaded: INFO with its build
// date and age, WARN when it was built more than 30 days before now, or
// WARN when the build date is missing or in the future, since its age is
// then unknown.
func logDBAge(logger *slog.Logger, path string, md maxminddb.Metadata, now time.Time) {
	where := []any{slog.String("path", path), slog.String("type", md.DatabaseType)}
	if md.BuildEpoch == 0 || md.BuildEpoch > uint(now.Unix()) {
		attrs := append(where, slog.Uint64("build_epoch", uint64(md.BuildEpoch)))
		if md.BuildEpoch != 0 && md.BuildEpoch <= lastRFC3339 {
			attrs = append(attrs, slog.String("built", rfc3339(int64(md.BuildEpoch))))
		}
		logger.Warn("database build date is missing or in the future", attrs...)
		return
	}
	age := ageDays(time.Unix(int64(md.BuildEpoch), 0), now)
	attrs := append(where, slog.String("built", rfc3339(int64(md.BuildEpoch))), slog.Int("age_days", age))
	if age > maxAgeDays {
		logger.Warn("database is more than 30 days old", attrs...)
		return
	}
	logger.Info("database loaded", attrs...)
}

// ageDays is the whole days from t to now, rounded down.
func ageDays(t, now time.Time) int {
	return int(now.Sub(t) / (24 * time.Hour))
}

// rfc3339 formats Unix seconds as an RFC 3339 time in UTC.
func rfc3339(sec int64) string {
	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

// hasType reports whether dbType contains any of the given words,
// case-insensitively.
func hasType(dbType string, types []string) bool {
	dbType = strings.ToLower(dbType)
	for _, t := range types {
		if strings.Contains(dbType, strings.ToLower(t)) {
			return true
		}
	}
	return false
}

// lookup returns the value for the client of r, computed by decode,
// and exposes it as the named placeholder. An IP that cannot be
// resolved yields an empty string.
func lookup(r *http.Request, placeholder string, decode func(netip.Addr) (string, error)) (string, error) {
	var value string
	if ip := clientIP(r); ip.IsValid() {
		var err error
		if value, err = decode(ip); err != nil {
			return "", err
		}
	}
	setPlaceholder(r, placeholder, value)
	return value, nil
}

// lookupPlace returns the country code, the most specific subdivision
// code, and whether the client of r matched, all decoded from one
// record by decode, and exposes the codes as the {geoip.country} and
// {geoip.subdivision} placeholders. An IP that cannot be resolved
// yields two empty strings and no match.
func lookupPlace(r *http.Request, decode func(netip.Addr) (string, string, bool, error)) (string, string, bool, error) {
	var country, subdivision string
	var matched bool
	if ip := clientIP(r); ip.IsValid() {
		var err error
		if country, subdivision, matched, err = decode(ip); err != nil {
			return "", "", false, err
		}
	}
	// Both come from one record, so they are published together or a
	// country from one record ends up beside a subdivision from
	// another. Two empty strings mean no record, so another matcher's
	// answer stands; an empty subdivision beside a country is an
	// answer, and overwrites.
	if country == "" && subdivision == "" {
		setPlaceholder(r, "geoip.country", "")
		setPlaceholder(r, "geoip.subdivision", "")
	} else {
		overwritePlaceholder(r, "geoip.country", country)
		overwritePlaceholder(r, "geoip.subdivision", subdivision)
	}
	return country, subdivision, matched, nil
}

// setPlaceholder exposes value as the named placeholder. A value is
// always recorded, but an empty one never replaces an answer already
// there: a matcher whose database has no entry for the address did
// not match either, and should not erase what another matcher
// resolved.
func setPlaceholder(r *http.Request, placeholder string, value any) {
	repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if !ok {
		return
	}
	if value == "" {
		// Get returns (nil, false) for a key that was never set, and a
		// nil any is not equal to "", so the known check is what
		// separates "nothing recorded yet" from "an answer is here".
		if current, known := repl.Get(placeholder); known && current != "" {
			return
		}
	}
	repl.Set(placeholder, value)
}

// overwritePlaceholder exposes value as the named placeholder, empty
// or not, for callers that know it is an answer rather than a gap.
func overwritePlaceholder(r *http.Request, placeholder, value string) {
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set(placeholder, value)
	}
}

// clientIP returns the client IP as resolved by the server (honoring
// trusted_proxies), falling back to the connection's remote address.
// An address that cannot be parsed, which only happens on Unix socket
// listeners, yields an invalid Addr and is treated as unknown.
//
// client_ip is always a bare address and RemoteAddr always host:port,
// so each gets its own parser rather than trying both per request.
func clientIP(r *http.Request) netip.Addr {
	var ip netip.Addr
	if addr, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); addr != "" {
		var err error
		if ip, err = netip.ParseAddr(addr); err != nil {
			// client_ip is a bare IP as Caddy sets it; a host:port
			// form only appears if a vars handler overwrote it, so
			// try that shape only after the plain parse fails.
			if ipp, perr := netip.ParseAddrPort(addr); perr == nil {
				ip = ipp.Addr()
			}
		}
	} else if ipp, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		ip = ipp.Addr()
	} else {
		// A listener that hands over a bare address. Not something
		// Caddy's own listeners do, but cheap to accept here.
		ip, _ = netip.ParseAddr(r.RemoteAddr)
	}
	// A zone on a link-local address is not something the database
	// indexes, and an IPv4-mapped address should take the IPv4 subtree.
	// Both pass an invalid Addr through unchanged.
	return ip.WithZone("").Unmap()
}
