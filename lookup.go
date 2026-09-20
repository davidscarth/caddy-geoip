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

// openDB opens the MaxMind database at path, replacing placeholders,
// and checks that its type contains one of the given words, so that a
// Country database is not silently used for ASN matching or vice versa.
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
	for _, t := range types {
		if strings.Contains(strings.ToLower(dbType), strings.ToLower(t)) {
			return db, nil
		}
	}
	_ = db.Close()
	return nil, fmt.Errorf("db %s is a %s database, expected %s",
		path, dbType, strings.Join(types, " or "))
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
// always recorded so that log_append has something to write, but an
// empty one never replaces an answer already there: a matcher whose
// database has no entry for the address did not match either, and
// should not erase what another matcher resolved.
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
func clientIP(r *http.Request) netip.Addr {
	addr, _ := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string)
	if addr == "" {
		addr = r.RemoteAddr
	}
	// RemoteAddr carries a port; the client_ip var does not. A zone on
	// a link-local address is not something the database indexes.
	if ipp, err := netip.ParseAddrPort(addr); err == nil {
		return ipp.Addr().WithZone("").Unmap()
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}
	}
	return ip.WithZone("").Unmap()
}
