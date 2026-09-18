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
		return nil, fmt.Errorf("opening db: %v", err)
	}
	got := strings.ToLower(db.Metadata.DatabaseType)
	for _, t := range types {
		if strings.Contains(got, t) {
			return db, nil
		}
	}
	_ = db.Close()
	return nil, fmt.Errorf("db %s is a %s database, expected %s",
		path, db.Metadata.DatabaseType, strings.Join(types, " or "))
}

// lookup returns the value for the client of r, computing it with fn
// on the first call and caching it in the request context under key.
// The value is also exposed as a placeholder of the same name.
func lookup(r *http.Request, key string, fn func(netip.Addr) (string, error)) (string, error) {
	ctx := r.Context()
	if v, ok := caddyhttp.GetVar(ctx, key).(string); ok {
		return v, nil
	}

	var v string
	if ip := clientIP(r); ip.IsValid() {
		var err error
		if v, err = fn(ip); err != nil {
			return "", err
		}
	}

	caddyhttp.SetVar(ctx, key, v)
	if repl, ok := ctx.Value(caddy.ReplacerCtxKey).(*caddy.Replacer); ok {
		repl.Set(key, v)
	}
	return v, nil
}

// clientIP returns the client IP as resolved by the server (honoring
// trusted_proxies), falling back to the connection's remote address.
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
