# caddy-geoip

Country, subdivision, and ASN request matchers for [Caddy](https://caddyserver.com/),
using [MaxMind](https://www.maxmind.com/) GeoLite2/GeoIP2

## Why

I wanted to block a list of countries in Caddy and the popular plugin for this
requires a double negative: the matcher means "this request passes the filter,"
so to *block* a deny list you write `not` in front of it. It works, but it
always just irked me when looking at my Caddyfile.

This plugin follows three rules:

1. **A matcher means one thing.** It tests whether the IP is in the country,
   subdivision, or ASN list. That's it. You decide what happens to it...
   `geoip_country { country RU CN }` plus Caddy's `abort` is a deny list, and
   `not` on the matcher makes it an allow list.
2. **Defer to Caddy.** Blocking, responding, redirecting, negating, combining
   conditions, exempting the LAN, logging... Caddy already does all of these.
   Don't duplicate something Caddy already does well.
3. **Fail early, or fail closed.** A bad configuration is rejected when Caddy
   loads it, a failed lookup stops the request rather than letting it through.

Not related to `aablinov/caddy-geoip`.

## Install

```shell
xcaddy build --with github.com/davidscarth/caddy-geoip
```

Requires Go 1.25.1 or later to build.

## Syntax

```caddyfile
@name geoip_country {
    db      <path>
    country <codes...>
    match_unknown
}

@name geoip_subdivision {
    db          <path>
    country     <code>
    subdivision <codes...>
    match_unknown
}

@name geoip_asn {
    db  <path>
    asn <numbers...>
    match_unknown
}
```

`db` is required on every matcher, along with at least one `country`,
`subdivision`, or `asn`. `geoip_subdivision` also requires `country`, which
scopes the codes. `match_unknown` is optional everywhere.

- **db** - path to a Country, City, or Enterprise database for `geoip_country`,
  a City or Enterprise database for `geoip_subdivision`, or an ASN, ISP, or
  Enterprise database for `geoip_asn`. The database type is checked when the
  config loads, so a file that lacks the field a matcher reads is rejected
  rather than silently matching nothing. Placeholders such as `{env.GEOIP_DB}`
  are resolved.
- **country** - ISO 3166-1 alpha-2 codes, case-insensitive. On
  `geoip_subdivision` it is a single code, because subdivision codes are only
  unique within a country.
- **subdivision** - ISO 3166-2 codes without the country prefix (`CA`, not
  `US-CA`), case-insensitive. Together with **country** they form the full
  code: `country US` with `subdivision CA` is `US-CA`.
- **asn** - autonomous system numbers as plain integers, no `AS` prefix.
- **match_unknown** - use with caution. Matches IPs the database has no entry
  for (loopback, private ranges, unallocated space), so `country US` with
  `match_unknown` matches a US client and your LAN. On `geoip_subdivision` a
  record with a country but no subdivision counts as unknown too. Off by
  default. Under `not` it makes an allow list fail open, so prefer
  `client_ip private_ranges` to exempt the LAN.

## Examples

#### Deny list

Drop the connection for these countries:

```caddyfile
@blocked geoip_country {
    db      "C:\Caddy\GeoLite2-Country.mmdb"
    country CU IR KP RU BY VE MM NI SD
}
abort @blocked
```

An address the database has no record for is not in any listed country, so it
passes. That covers your LAN and unallocated space. Add `match_unknown` to deny
those too.

#### Allow list

Only these countries may reach the site. `not` is the real
negation here. An unknown IP is never *in* the set, so under `not` your own LAN
would be blocked; exempt it with Caddy's `client_ip private_ranges`:

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

#### Friendlier responses

Using Caddy's own handlers:

```caddyfile
respond @blocked "Not available in {geoip.country}" 451
redir @outside https://example.com/blocked
```

#### Log the country

These assume access logging is on for the site (Caddy's `log`
directive). `log_append` adds fields to that line rather than producing one.

```caddyfile
handle @blocked {
    log_append geo_country {geoip.country}
    log_append geo_blocked true
    abort
}
handle {
    log_append geo_country {geoip.country}
}
```

The lines inside `handle @blocked` tag denied requests with their country, the
second block tags everything that passed (useful for testing to see what you
might want to add to your blocklist). Evaluating `@blocked` sets the
placeholder whether or not it matches, so the second block still has a country
to log.

If you need an audit trail, use `respond 403` instead of `abort` in the blocked
route. An aborted request is logged without a normal response. Any tool that
reads the JSON access log, such as Loki, Vector, or Elastic, can chart
`geo_country` as a rate per country. Database updates sometimes move whole IP
blocks between countries, which logging and monitoring can expose.

#### Restrict a state

The country is required and scopes the subdivision codes,
which are only unique within a country:

```caddyfile
@restricted geoip_subdivision {
    db          "C:\Caddy\GeoLite2-City.mmdb"
    country     US
    subdivision UT LA MS
}
respond @restricted "Not available in your state" 451
```

#### Block hosting providers

Regardless of country:

```caddyfile
@hosting geoip_asn {
    db  "C:\Caddy\GeoLite2-ASN.mmdb"
    asn 16509 14618 14061 24940 16276
}
abort @hosting
```

#### Combine

Matchers inside one named matcher are ANDed, so "Russia, except
this network" is a single condition rather than two rules that need ordering:

```caddyfile
@blocked {
    geoip_country { db "Country.mmdb"  country RU }
    not geoip_asn { db "ASN.mmdb"  asn 64496 }
}
abort @blocked
```

Two separate `abort` lines are both denies and combine as OR in any order.
An exception must be written inside one matcher, as above, because nothing
can un-abort a request.

#### Route by region

```caddyfile
@eu geoip_country {
    db      /usr/share/GeoIP/GeoLite2-Country.mmdb
    country AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE
}
reverse_proxy @eu eu-backend:8080
reverse_proxy backend:8080
```

#### Reusable snippet

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

`{geoip.country}`, `{geoip.subdivision}`, and `{geoip.asn}` hold the client's
ISO codes and AS number, or are empty if unknown. Each is set by the
corresponding matcher when it runs. `geoip_subdivision` sets both of the first
two, since it reads both from one record.

A matcher that finds nothing writes nothing. A matcher that finds a record
writes the whole record. When two matchers write the same placeholder, the last
one to run wins.

## Notes

- The client IP is Caddy's `client_ip`: the connection's remote address, unless
  that address is in the server's `trusted_proxies`, in which case Caddy takes
  the real client from `X-Forwarded-For`. With no trusted proxies configured, a
  forged `X-Forwarded-For` header has no effect.
- The database is memory-mapped when the config loads. After `caddy reload`
  the new config opens the file fresh, so a replaced file is picked up. The
  old mapping is released by the garbage collector once the old config has
  finished draining. Have whatever downloads your database updates run
  `caddy reload` afterward.
- **Never overwrite the database file in place while Caddy is running.** The
  server reads it through a shared memory mapping, so writing into it can
  crash Caddy or corrupt lookups. Either stop Caddy first, or write the new
  file under a temporary name and rename it over the old one, which is what
  `geoipupdate` does by default.
- Each matcher does its own lookup when it runs, decoding only the fields it
  needs from the record. There is no per-request caching.
- The matchers use MaxMind's located `country`, not `registered_country`. An
  IP whose location MaxMind cannot determine is unknown and treated as such.
- `geoip_subdivision` matches the most specific subdivision MaxMind reports,
  following their `most_specific_subdivision` convention. Where a country has
  nested subdivisions - an address in Boxford reports `ENG` then `WBK` - only
  the innermost (`WBK`) matches.
- Territories with their own ISO 3166-1 code, such as Puerto Rico and Guam, are
  reported under that code rather than as subdivisions of the parent country.
- Use the Country database for country matching (it's roughly an eighth the
  size of City). One City database could serve both `geoip_country` and
  `geoip_subdivision` if you'd rather keep one file. `geoip_asn` always needs
  its own database unless you have Enterprise.

## JSON

```json
{
  "geoip_country": {
    "db": "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "countries": ["US", "DE", "FR", "IT", "AR", "JP"]
  },
  "geoip_subdivision": {
    "db": "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "country": "US",
    "subdivisions": ["CA", "NY"]
  },
  "geoip_asn": {
    "db": "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "asns": [16509]
  }
}
```

## Out of scope

City-level matching, database auto-download, and rich placeholders (city name,
coordinates, time zone) are deliberately not here.

Database updates are either manually placed or
[`geoipupdate`](https://github.com/maxmind/geoipupdate) plus `caddy reload`.

## Checks

Built and tested against Caddy v2.11.4 and maxminddb-golang v2.6.0, with no
other dependencies.

The code passes:

- `go vet ./...` and `go test ./...`
- `golangci-lint run` using Caddy's own `.golangci.yml`
- `govulncheck ./...` with no reachable vulnerabilities
- CodeQL via GitHub code scanning

Tested against MaxMind's `GeoLite2-Country`, `GeoIP2-Country`, `GeoLite2-City`,
`GeoIP2-City`, `GeoLite2-ASN`, `GeoIP2-ISP`, and `GeoIP2-Enterprise` test
databases, and running in production with the free GeoLite2 editions.

DB-IP compatibility is **not supported** and depends on the vendor shipping
compliant databases. A smoke test was performed with DB-IP's Lite databases
(September 2026). The Country Lite and ASN Lite MMDB files appear to work with
`geoip_country` and `geoip_asn` as drop-in replacements for GeoLite2, no code
changes needed. *However* City Lite **does not work** for `geoip_subdivision`,
as the free version does not appear to include ISO 3166-2 codes.

## License

Apache-2.0
