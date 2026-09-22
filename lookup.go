// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Paths into a record for DecodePath, built once rather than per
// request. The ASN path depends on the database edition, so it lives
// on the matcher instead (see MatchGeoIPASN.Provision).
var (
	countryPath = []any{"country", "iso_code"}
	// MaxMind orders subdivisions from most general to most specific,
	// so the last entry is the most_specific_subdivision. A negative
	// index counts from the end; out of range (no subdivisions) is
	// not found, which leaves the target empty.
	subdivisionPath = []any{"subdivisions", -1, "iso_code"}
)

// openDB opens the MaxMind database at path, replacing placeholders,
// and checks that its type contains one of the given words, so that a
// Country database is not silently used for ASN matching or vice versa.
//
// No Cleanup on purpose. A Caddy reload would run it with lookups still
// in flight, triggering a race condition. Instead we rely on GC to
// release the mapping.
func openDB(path string, types ...string) (*maxminddb.Reader, error) {
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
	// The reader reports an IPv6 lookup in an IPv4-only tree as an
	// error rather than as no record, which would turn every IPv6
	// request into a 5xx with nothing in the config to explain it.
	// Every MaxMind edition is IPv6 (a tree that may also hold IPv4),
	// so refuse the other kind here, where the message can name it.
	if v := db.Metadata.IPVersion; v != 6 {
		_ = db.Close()
		return nil, fmt.Errorf("db %s is an IPv4-only database (ip_version %d), which is not supported",
			path, v)
	}
	return db, nil
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

// lookupPlace returns the country code and the most specific
// subdivision code for the client of r, decoded from one record by
// decode, and exposes them as the {geoip.country} and
// {geoip.subdivision} placeholders. An IP that cannot be resolved
// yields two empty strings.
func lookupPlace(r *http.Request, decode func(netip.Addr) (string, string, error)) (string, string, error) {
	var country, subdivision string
	if ip := clientIP(r); ip.IsValid() {
		var err error
		if country, subdivision, err = decode(ip); err != nil {
			return "", "", err
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
	return country, subdivision, nil
}

// setPlaceholder exposes value as the named placeholder. A value is
// always recorded, but an empty one never replaces an answer already
// there: a matcher whose database has no entry for the address did
// not match either, and should not erase what another matcher
// resolved.
func setPlaceholder(r *http.Request, placeholder, value string) {
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
// The two sources have different shapes, so each gets the parser for
// its shape rather than trying both on every request: the client_ip
// var is a bare address, since the server strips the port and zone
// whether or not a trusted proxy was involved, and RemoteAddr is
// host:port on every TCP and QUIC listener.
func clientIP(r *http.Request) netip.Addr {
	var ip netip.Addr
	if addr, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); addr != "" {
		var err error
		if ip, err = netip.ParseAddr(addr); err != nil {
			// client_ip is a bare IP as Caddy sets it; a host:port
			// form only appears if a vars handler overwrote it, so
			// try that shape only after the plain parse fails.
			if ipp, err := netip.ParseAddrPort(addr); err == nil {
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
