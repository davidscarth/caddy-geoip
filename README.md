# caddy-geoip

Country, subdivision, and ASN request matchers for [Caddy](https://caddyserver.com/),
using [MaxMind](https://www.maxmind.com/) GeoLite2/GeoIP2

## Why

I wanted a simple GeoIP matcher that was small, fast, and secure. I didn't like
the options available for one reason or another, so I made this. These are the rules
it follows:

1. **The matcher just matches.** It tests whether the IP is in the country,
   subdivision, or ASN list. That's it. You decide what happens to it...
   `geoip_country { country RU CN }` plus Caddy's `abort` is a deny list, and
   `not` on the matcher makes it an allow list.
2. **Defer to Caddy.** Blocking, responding, redirecting, negating, combining
   conditions, exempting the LAN, logging... Caddy already does all of these.
   Don't duplicate something Caddy already does well.
3. **Fail early, or fail closed.** A bad configuration is rejected when Caddy
   loads, a failed lookup stops the request rather than letting it through.
4. **Use standard identifiers.** Countries are ISO 3166-1, subdivisions are
   ISO 3166-2, ASNs are IANA numbers.

## Install

```shell
xcaddy build --with github.com/davidscarth/caddy-geoip
```

Requires Go 1.26.0 or later to build.

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

@name geoip_anonymous {
    db   <path>
    type <kinds...>
}
```

`db` is required on every matcher, along with at least one `country`,
`subdivision`, or `asn`. `geoip_subdivision` also requires `country`, which
scopes the codes. `match_unknown` is optional on the geolocation matchers.

- **db** - path to a Country, City, or Enterprise database for `geoip_country`,
  a City or Enterprise database for `geoip_subdivision`, or an ASN, ISP, or
  Enterprise database for `geoip_asn`. The database type is checked when the
  config loads, so a Country file is not silently used for ASN matching or vice
  versa. Placeholders such as `{env.GEOIP_DB}` are resolved.
- **country** - ISO 3166-1 alpha-2 codes, case-insensitive. On
  `geoip_subdivision` it is a single code, because subdivision codes are only
  unique within a country.
- **subdivision** - ISO 3166-2 codes without the country prefix (`CA`, not
  `US-CA`), case-insensitive. Together with **country** they represent the full
  code: `country US` with `subdivision CA` is how `US-CA` is written.
- **asn** - autonomous system numbers as plain integers, no `AS` prefix.
- **type** - kinds of anonymizer to match, any of `anonymous`, `vpn`, `tor`,
  `hosting`, `public_proxy`, `residential_proxy`. These are MaxMind's
  Anonymous IP flags; `anonymous` is the umbrella, set whenever any other is.
  Needs an Anonymous IP, Anonymous Plus, or IP Risk database.
- **match_unknown** - use with caution. Matches IPs the database has no entry
  for (loopback, private ranges, unallocated space), so `country US` with
  `match_unknown` matches a US client and your LAN. On `geoip_subdivision` a
  record with a country but no subdivision counts as unknown too. Off by
  default. Under `not` it makes an allow list fail open, so prefer
  `client_ip private_ranges` to exempt the LAN. Doesn't exist for
  `geoip_anonymous` (as there is no unknown state, anything not in the db
  is just not considered anonymous).

## Examples

#### Deny list

Drop the connection for these countries:

```caddyfile
@blocked geoip_country {
    db      "C:\Caddy\GeoLite2-Country.mmdb"
    country CN RU PK KP IR ID IN VN BR NG BY CU SY VE SD
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
        country US CA GB FR DE IT ES AR AU JP
    }
    not client_ip private_ranges
}
abort @outside
```

(`match_unknown` on the matcher is the blunter alternative: it lets every
unknown IP through, not just the LAN.)

#### Friendlier responses

Using Caddy's own handlers (pick one):

```caddyfile
respond @blocked "Not available in {geoip.country}" 403
respond @blocked "Access from {geoip.country} is restricted due to legal/regulatory requirements." 451
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

#### Block anonymizers

```caddyfile
@anon geoip_anonymous {
    db   "C:\Caddy\GeoIP2-Anonymous-IP.mmdb"
    type vpn tor public_proxy
}
abort @anon
```

Or let identified VPNs through, but only from where the site is meant to be
reached:

```caddyfile
@vpn_abroad {
    geoip_anonymous {
        db   "Anonymous.mmdb"
        type vpn
    }
    not geoip_country {
        db      "Country.mmdb"
        country US CA
    }
}
respond @vpn_abroad "VPN access is limited to North America" 403
```

#### Combine

Matchers inside one named matcher are ANDed, so "Russia, except
this network" is a single condition rather than two rules that need ordering:

```caddyfile
@blocked {
    geoip_country {
        db "Country.mmdb"
        country RU
    }
    not geoip_asn {
        db "ASN.mmdb"
        asn 64496
    }
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
        country CN RU PK KP IR ID IN VN BR NG BY CU SY VE SD
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
ISO codes and AS number, or are empty if unknown. `{geoip.anonymous}` holds
the kinds the client is flagged with, comma-separated in the order listed
under **type** (`anonymous,vpn,tor`), or is empty. Each is set by the
corresponding matcher when it runs. `geoip_subdivision` sets both of the first
two, since it reads both from one record.

A matcher that finds nothing writes nothing. A matcher that finds a record
writes the whole record. When two matchers write the same placeholder, the last
one to run wins.

## Notes

#### Matching
- An IP that isn't in the database is unknown, not a match. Use
  `match_unknown` cautiously if that matters to you.
- A code the database doesn't use won't throw an error, but it won't match
  anything. `country UK` will load fine but do nothing, because the database
  uses `GB` (ISO 3166-1). Check your codes.
- The matchers use MaxMind's located `country`, not `registered_country`.
- Territories with their own ISO 3166-1 code, such as Puerto Rico and Guam, are
  reported under that code rather than as subdivisions of the parent country.
- `geoip_subdivision` matches any level. Boxford reports `ENG` then `WBK`, so
  a rule on either matches. For that example `{geoip.subdivision}` reports `WBK`.

#### Client IP
- The client IP is Caddy's `client_ip`: the connection's remote address, unless
  that address is in the server's `trusted_proxies`, in which case Caddy takes
  the real client from `X-Forwarded-For`. With no trusted proxies configured, a
  forged `X-Forwarded-For` header has no effect.
- If you set `trusted_proxies`, also set `trusted_proxies_strict` (or
  `client_ip_headers` naming a single-value header your proxy sets, such as
  `CF-Connecting-IP`). Without it Caddy takes the left-most `X-Forwarded-For`
  entry, which a client can forge if your proxy appends to the header rather
  than replacing it.
- Don't trust `private_ranges` when something in front of Caddy rewrites the
  source address (Docker's userland proxy, some load balancers). Every client
  then looks like a trusted proxy, and a forged `X-Forwarded-For` picks its
  own location.

#### Database
- Use the Country database for country matching (it's a fraction of the size
  of City). One City database could serve both `geoip_country` and
  `geoip_subdivision` if you'd rather keep one file. `geoip_asn` always needs
  its own database unless you have Enterprise.
- The database is memory-mapped when the config loads. Run `caddy reload
  --force` after replacing the file (since the Caddyfile is unchanged on just a
  database update, need --force to actually make the reload happen).
- **Never overwrite the database file in place while Caddy is running.** The
  server reads it through a shared memory mapping, so writing into it can
  crash Caddy or corrupt lookups. Either stop Caddy first, or replace atomically,
  which is what `geoipupdate` does by default.

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
  },
  "geoip_anonymous": {
    "db": "/usr/share/GeoIP/GeoIP2-Anonymous-IP.mmdb",
    "types": ["vpn", "tor"]
  }
}
```

## Out of scope

City-level matching, database auto-download, and rich placeholders (city name,
coordinates, time zone) are deliberately not here.

Database updates are either manually placed or
[`geoipupdate`](https://github.com/maxmind/geoipupdate) plus `caddy reload
--force`.

## Checks

Built and tested against Caddy v2.11.7 and maxminddb-golang v2.8.0, with no
other dependencies.

The code passes:

- `go vet ./...` and `go test ./...`
- `golangci-lint run` using Caddy's own `.golangci.yml`
- `govulncheck ./...` with no reachable vulnerabilities
- CodeQL via GitHub code scanning

Tested against MaxMind's `GeoLite2-Country`, `GeoIP2-Country`, `GeoLite2-City`,
`GeoIP2-City`, `GeoLite2-ASN`, `GeoIP2-ISP`, `GeoIP2-Enterprise`,
`GeoIP2-Anonymous-IP`, `GeoIP-Anonymous-Plus`, and `GeoIP2-IP-Risk` test
databases, and running in production with the free GeoLite2 editions.

## Other vendors

The matchers read MaxMind's GeoIP2 record layout: `country.iso_code`,
`subdivisions[].iso_code`, `autonomous_system_number`, and the `is_*`
anonymizer flags. A file that uses that layout will work regardless of who
built it. A file that doesn't will still load, since the type check only
looks at the database name, but then it won't work. Below were checked with
October 2026 files. None of them are supported, and results may change with
any update on their side.

#### Tested, seems working

- DB-IP Lite [Country](https://db-ip.com/db/download/ip-to-country-lite)
  and [ASN](https://db-ip.com/db/download/ip-to-asn-lite) (CC BY 4.0): drop-in
  replacements for GeoLite2.
- IP2Location LITE
  [Country (DB1)](https://lite.ip2location.com/database/db1-ip-country)
  (CC BY-SA 4.0),
  [City (DB11)](https://lite.ip2location.com/database/db11-ip-country-region-city-latitude-longitude-zipcode-timezone)
  and [ASN](https://lite.ip2location.com/database-asn)
  ([Proprietary](https://lite.ip2location.com/terms-of-use)): all three
  work as drop-in replacements, in MMDB format. Their City DB carries ISO
  3166-2 codes (in their MMDB, not in their CSV, so don't convert it
  yourself).
- IP2Location [IP2Proxy LITE PX10](https://lite.ip2location.com/ip2proxy-lite)
  in MMDB format ([Proprietary](https://lite.ip2location.com/terms-of-use)):
  works with `geoip_anonymous`. The LITE edition lists public proxies only,
  so every address carries the same two flags, `anonymous` and
  `public_proxy`. Others such as `type vpn` or `type tor` match nothing. Use
  `type anonymous` as a block-all-known-proxies switch.
- Geoacumen [Country](https://github.com/geoacumen/geoacumen-country)
  (Apache-2.0): works. Private and reserved ranges carry the literal code
  `None` rather than no record, so `match_unknown` does not cover them. Exempt
  the LAN with `client_ip private_ranges` as usual.
- sapics [origin-asn IPv4+IPv6](https://github.com/sapics/ip-location-db#asn)
  (PDDL): works with `geoip_asn`. Built from BGP routing data, updated daily.

#### Tested, not working

- DB-IP Lite City: subdivision names are without ISO 3166-2 codes, so
  `geoip_subdivision` matches nothing and `{geoip.subdivision}` is always
  empty. **Do not use the DB-IP City database.**
- IPLocate.io free databases: own record layout (`country_code`, `asn` as
  text). Both files load and every address is unknown. **Do not use the
  IPLocate databases.**
- sapics `user-country` and `server-country`: own record layout
  (`country_code`), so `geoip_country` loads them and every address is
  unknown. Their ASN file above is the exception. **Do not use the sapics
  country databases.**

To check a file not listed here, use MaxMind's
[`mmdbinspect`](https://github.com/maxmind/mmdbinspect) tool:
`mmdbinspect -db file.mmdb 216.160.83.56`. It should work if the record
has `country` with `iso_code` inside for `geoip_country`, `subdivisions`
whose entries have `iso_code` for `geoip_subdivision`,
`autonomous_system_number` for `geoip_asn`, or `is_anonymous` and its
siblings for `geoip_anonymous`. YMMV.

## License

Apache-2.0
