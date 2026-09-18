# caddy-geoip

Country and ASN request matchers for Caddy, using MaxMind GeoLite2/GeoIP2

## Why

I wanted to block a list of countries in Caddy and the popular plugin for this
requires a double negative: the matcher means "this request passes the filter,"
so to *block* a deny list you write `not` in front of it.

It works, but it always just irked me when looking at my Caddyfile.

This plugin follows three rules:

1. **A matcher means one thing.** `geoip_country { country RU CN }` is true
   when the client *is in* Russia or China. That's it. A deny list is that
   matcher plus Caddy's `abort`. An allow list is `not` on the matcher.
2. **Defer to Caddy.** Blocking, responding, redirecting, negating, combining
   conditions, exempting the LAN, logging: Caddy already does all of these.
   Don't duplicate something Caddy already does well.
3. **Current and small.** Built against Caddy v2.11.4 and maxminddb-golang
   v2.6.0. No background goroutines, no shared state, and no dependencies
   beyond those two. ~280 lines of code.

Not related to `aablinov/caddy-geoip`.

## Install

```
xcaddy build --with github.com/davidscarth/caddy-geoip
```

Requires Go 1.25+ to build.

## Syntax

```caddyfile
@name geoip_country {
    db      <path>
    country <codes...>
    match_unknown
}

@name geoip_asn {
    db  <path>
    asn <numbers...>
    match_unknown
}
```

- **db** - path to a Country, City, or Enterprise database for `geoip_country`,
  or an ASN, ISP, or Enterprise database for `geoip_asn`. The database type is
  checked when the config loads, so pointing one matcher at the other's file is
  an error rather than a silent no-match. Placeholders such as `{env.GEOIP_DB}`
  are resolved.
- **country** - ISO 3166-1 alpha-2 codes, case-insensitive.
- **asn** - autonomous system numbers as plain integers, no AS prefix.
- **match_unknown** - also match IPs the database has no entry for (loopback,
  private ranges, unallocated space). Off by default: an unknown IP is never
  *in* a set. Under `not` that means it is always *outside* one; see the
  allow-list example.

Each matcher is true when the client **is in** the listed set. That is its
only meaning; policy comes from what you attach to it.

## Examples

Deny list - drop the connection for these countries:

```caddyfile
@blocked geoip_country {
    db      "C:\Caddy\GeoLite2-Country.mmdb"
    country CU IR KP RU BY VE MM NI SD
}
abort @blocked
```

Allow list - only these countries may reach the login portal. `not` is the
real negation here. An unknown IP is never *in* the set, so under `not` your
own LAN would be blocked; exempt it with Caddy's `client_ip private_ranges`:

```caddyfile
@outside {
    not geoip_country {
        db      "C:\Caddy\GeoLite2-Country.mmdb"
        country US DE FR IT AR JP
    }
    not client_ip private_ranges
}
abort @outside
```

(`match_unknown` on the matcher is the blunter alternative: it lets every
unknown IP through, not just the LAN.)

Friendlier responses, using Caddy's own handlers:

```caddyfile
respond @blocked "Not available in {geoip.country}" 451
redir @outside https://example.com/blocked
```

Log the country. Aborted requests already get an access-log line (status 0,
with the client IP) but no country code. This `log_append` can be used to add
that detail:

```caddyfile
handle @blocked {
    log_append geo_country {geoip.country}
    log_append geo_blocked true
    abort
}
log_append geo_country {geoip.country}
```

The lines inside `handle @blocked` tag denied requests with their country, the
one after it tags everything that passed (useful for testing to see what you
might want to add to your blocklist). The placeholder is set only after a
matcher has run, so these go after the block. To log only blocked requests,
replace the last line with Caddy's `log_skip`.

Block hosting providers regardless of country:

```caddyfile
@hosting geoip_asn {
    db  "C:\Caddy\GeoLite2-ASN.mmdb"
    asn 16509 14618 14061 24940 16276
}
abort @hosting
```

Combine - matchers inside one named matcher are ANDed, so "Russia, except
this network" is a single condition rather than two rules that need ordering:

```caddyfile
@blocked {
    geoip_country { db "…Country.mmdb"  country RU }
    not geoip_asn { db "…ASN.mmdb"  asn 64496 }
}
abort @blocked
```

Two separate `abort` lines are both denies and combine as OR in any order.
An exception must be written inside one matcher, as above, because nothing
can un-abort a request.

Route by region:

```caddyfile
@eu geoip_country {
    db      /usr/share/GeoIP/GeoLite2-Country.mmdb
    country AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE
}
reverse_proxy @eu eu-backend:8080
reverse_proxy backend:8080
```

Reusable snippet:

```caddyfile
(geoblock) {
    @blocked geoip_country {
        db      "C:\Caddy\GeoLite2-Country.mmdb"
        country CU IR KP RU BY VE MM NI SD
    }
    abort @blocked
}

example.com {
    import geoblock
    reverse_proxy 127.0.0.1:3000
}
```

## Placeholders

`{geoip.country}` and `{geoip.asn}` hold the client's ISO code and AS number,
or are empty if unknown. Each is set by the corresponding matcher when it runs.

## Notes

- The client IP is Caddy's `client_ip`: the connection's remote address, unless
  that address is in the server's `trusted_proxies`, in which case Caddy takes
  the real client from `X-Forwarded-For`. With no trusted proxies configured, a
  forged `X-Forwarded-For` header has no effect.
- The database is memory-mapped when the config loads and released when it is
  unloaded, so `caddy reload` picks up a replaced file. Have whatever downloads
  your database updates run `caddy reload` afterward. Replace the file
  atomically (write to a temporary name, then rename) so a partially written
  file is never opened.
- Each matcher does its own lookup when it runs, decoding only the one field it
  needs from the record. There is no per-request caching.
- `geoip_country` matches on MaxMind's located `country`, not
  `registered_country`. An IP whose location MaxMind cannot determine is
  unknown.
- If the lookup fails, the matcher returns an error and Caddy fails the
  request rather than letting it through.

## JSON

```json
{
  "geoip_country": {
    "db": "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "countries": ["US", "DE", "FR", "IT", "AR", "JP"]
  },
  "geoip_asn": {
    "db": "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "asns": ["16509"]
  }
}
```
## Out of scope

City and subdivision matching, database auto-download, and rich placeholders
(city name, coordinates, time zone) are deliberately not here.

Database updates are either manually placed or `geoipupdate` plus `caddy reload`.

## Checks

The code passes:

- `go vet ./...` and `go test ./...`
- `golangci-lint run` using Caddy's own `.golangci.yml`
- `govulncheck ./...` with no reachable vulnerabilities
- CodeQL via GitHub code scanning

Tested against MaxMind's `GeoLite2-Country`, `GeoIP2-Country`, and
`GeoLite2-ASN` test databases, and running in production with the free
GeoLite2 editions.

## License

Apache-2.0
