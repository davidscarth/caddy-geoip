// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"fmt"
	"net"
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
	if repl, ok := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set(placeholder, value)
	}
	return value, nil
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
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	addr, _, _ = strings.Cut(addr, "%")
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}
