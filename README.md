# caddy-geoip

[![Tests](https://github.com/davidscarth/caddy-geoip/actions/workflows/test.yml/badge.svg)](https://github.com/davidscarth/caddy-geoip/actions/workflows/test.yml) [![CodeQL](https://github.com/davidscarth/caddy-geoip/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/davidscarth/caddy-geoip/actions/workflows/github-code-scanning/codeql) [![Go Reference](https://pkg.go.dev/badge/github.com/davidscarth/caddy-geoip.svg)](https://pkg.go.dev/github.com/davidscarth/caddy-geoip) [![release](https://img.shields.io/github/v/release/davidscarth/caddy-geoip)](https://github.com/davidscarth/caddy-geoip/releases)

Country, subdivision, ASN, and anonymizer request matchers for
[Caddy](https://caddyserver.com/), using
[MaxMind](https://www.maxmind.com/) GeoLite2/GeoIP2

## Why

I wanted a simple GeoIP matcher that was small, fast, and safe. I didn't
like the options available for one reason or another, so I made this.
These are the rules it follows:

1. **The matcher just matches.** It tests whether the IP is in the country,
   subdivision, ASN, or anonymizer list. That's it. You decide what happens
   to it... `geoip_country { country RU CN }` plus Caddy's `abort` is a deny
   list, and `not` on the matcher makes it an allow list.
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
	db <path>
	country <codes...>
	match_unknown		# optional
}

@name geoip_subdivision {
	db <path>
	country <code>
	subdivision <codes...>
	match_unknown		# optional
}

@name geoip_asn {
	db <path>
	asn <numbers...>	# at least one of asn or asn_file
	asn_file <paths...>	# at least one of asn or asn_file
	match_unknown		# optional
}

@name geoip_anonymous {
	db <path>
	type <kinds...>		# at least one of type or risk
	confidence <1-99>	# optional
	risk <1-99>		# at least one of type or risk
}
```

`db` is required on every matcher. `geoip_subdivision` also requires `country`,
which scopes the codes. `match_unknown` is optional on the geolocation matchers.

- **db** - path to a Country, City, or Enterprise database for `geoip_country`,
  a City or Enterprise database for `geoip_subdivision`, or an ASN, ISP, or
  Enterprise database for `geoip_asn`. The database type is checked when the
  config loads, so a Country file is not silently used for ASN matching or vice
  versa.
- **country** - ISO 3166-1 alpha-2 codes, case-insensitive. On
  `geoip_subdivision` it is a single code, because subdivision codes are only
  unique within a country.
- **subdivision** - ISO 3166-2 codes without the country prefix (`CA`, not
  `US-CA`), case-insensitive. Together with **country** they represent the full
  code: `country US` with `subdivision CA` is how `US-CA` is written.
- **asn** - autonomous system numbers as plain integers, no `AS` prefix.
- **asn_file** - one or more files of autonomous system numbers, added to any
  `asn` list. Several paths can go on one `asn_file` line, or on separate
  lines. Files are UTF-8 text. A number counts as an ASN when something defines
  it: a JSON record's `asn` member, a Cloudflare expression's `.asnum` field, a
  header naming the column, or an `AS` prefix. Otherwise the number leads its
  line, alone, or a one-line file holds many. A line with two bare numbers,
  such as a rank or a count beside an ASN, is an error naming the line, since
  nothing says which is which. `#` and `//` start a comment anywhere on a line,
  a line starting with `;` is a comment, and blank lines are skipped. The forms
  tested are in [docs/sources.md](docs/sources.md#lists-for-asn_file).
- **type** - kinds of anonymizer to match, any of `anonymous`, `vpn`, `tor`,
  `hosting`, `public_proxy`, `residential_proxy`. These are MaxMind's
  Anonymous IP flags (`anonymous` is the umbrella, set whenever any other is).
  Needs an Anonymous IP, Anonymous Plus, or IP Risk database.
- **confidence** - for `public_proxy` and `residential_proxy`, the least
  confidence a record must carry to count, 1 to 99. A record with no confidence
  is unaffected. Needs an Anonymous Plus or IP Risk database.
- **risk** - match any address whose risk score is at least this, 1 to 99.
  Needs an IP Risk database, and may be used without `type`.
- **match_unknown** - use with caution. Matches IPs the database has no entry
  for (loopback, private ranges, unallocated space), so `country US` with
  `match_unknown` matches a US client and your LAN. On `geoip_subdivision` a
  record with a country but no subdivision counts as unknown too. Off by
  default. Under `not` it makes an allow list fail open, so prefer
  `client_ip private_ranges` to exempt the LAN. Doesn't exist for
  `geoip_anonymous` (as there is no unknown state, anything not in the db
  is just not considered anonymous).

## Examples

The first few examples use Windows paths, which need quotes. The rest use
`geoipupdate`'s default Linux directory. Either style works anywhere.

Caddy runs `handle` and `route` blocks before `abort` and `respond`, which can
skip the geo rule. If your site uses them, wrap it all in one `route` block
with the geo rule first, or use the `order` global option.

#### Deny list

Drop the connection for these countries:

```caddyfile
@blocked geoip_country {
	db "C:\ProgramData\Caddy\GeoLite2-Country.mmdb"
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
		db "C:\ProgramData\Caddy\GeoLite2-Country.mmdb"
		country US CA GB FR DE IT ES AR AU JP
	}
	not client_ip private_ranges
}
abort @outside
```

We avoid using `match_unknown` in the example above because it makes the allow
list fail open. `client_ip private_ranges` here exempts only the LAN.

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
	log_append <geo_country {geoip.country}
	log_append <geo_blocked true
	abort
}
handle {
	log_append <geo_country {geoip.country}
}
```

The lines inside `handle @blocked` tag denied requests with their country, the
second block tags everything that passed (useful for testing to see what you
might want to add to your blocklist). The `<` matters. Without it,
`log_append` records the field on the way back out of the route, which never
happens after `abort` or when a client drops a download. Evaluating `@blocked`
sets the placeholder whether or not it matches, so the second block still has
a country to log (and keep it inside a `handle` so it runs after the matcher).

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
	db "C:\ProgramData\Caddy\GeoLite2-City.mmdb"
	country US
	subdivision UT LA MS
}
respond @restricted "Not available in your state" 451
```

#### Block hosting providers

Regardless of country:

```caddyfile
@hosting geoip_asn {
	db /usr/share/GeoIP/GeoLite2-ASN.mmdb
	asn 16509 14618 14061 24940 16276
}
abort @hosting
```

#### Block networks from a list

`asn_file` takes any list of autonomous system numbers as published. This
example uses [ASN-DROP](https://www.spamhaus.org/drop/), Spamhaus's list of
networks run by spammers and cybercriminals, a few hundred ASNs, free to use:

```caddyfile
@asndrop geoip_asn {
	db /usr/share/GeoIP/GeoLite2-ASN.mmdb
	asn_file /etc/caddy/asndrop.json
}
abort @asndrop
```

The list changes every few days, so fetch it on a schedule and `caddy reload
--force`. It names operators, not every host that has had an abusive
customer, so it complements `geoip_anonymous { type hosting }` rather than
replacing it. For a plain "no datacenter traffic" rule, X4BNet's datacenter
ASN list loads the same way and doesn't need an Anonymous IP database.

Some useful ASN lists have been tested, with notes on what each one does,
in [docs/sources.md](docs/sources.md#lists-for-asn_file).

#### Block anonymizers

```caddyfile
@anon geoip_anonymous {
	db /usr/share/GeoIP/GeoIP2-Anonymous-IP.mmdb
	type vpn tor public_proxy
}
abort @anon
```

#### Combine

Different matchers inside one named matcher are ANDed, so "Russia, except
this network" is a single condition rather than two rules that need ordering:

```caddyfile
@blocked {
	geoip_country {
		db /usr/share/GeoIP/GeoLite2-Country.mmdb
		country RU
	}
	not geoip_asn {
		db /usr/share/GeoIP/GeoLite2-ASN.mmdb
		asn 64496
	}
}
abort @blocked
```

Two blocks of the same matcher in one named matcher are not ANDed: Caddy
merges them into one block before the plugin sees them, so their lists add up
(any of the countries, any of the ASN files) and a `db` given in both is
refused. Put the values in one block.

Two separate `abort` lines are both denies and combine as OR in any order.
An exception must be written inside one matcher, as above, because nothing
can un-abort a request.

#### More examples

Check [docs/recipes.md](docs/recipes.md) for more: a lookup with no rule,
pass the country to your app, fence a path, sanctioned countries and
regions, rate limit instead of block, VPNs only from some countries, route
by region, and a snippet to import.

## Placeholders

`{geoip.country}`, `{geoip.subdivision}`, and `{geoip.asn}` hold the client's
ISO codes and AS number, or are empty if unknown. `{geoip.anonymous}` holds
the kinds the client is flagged with, comma-separated in the order listed
under **type** (`anonymous,vpn,tor`), or is empty. Each is set by the
corresponding matcher when it runs. `geoip_subdivision` sets both of the first
two, since it reads both from one record. `{geoip.confidence}` and
`{geoip.risk}` hold the record's anonymizer confidence and risk score when the
database carries them, or are empty.

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
  server reads it through a shared memory mapping, so writing into it can crash
  Caddy or corrupt lookups. Either stop Caddy first, or replace atomically,
  which `geoipupdate` does by default. On Windows, stop Caddy to replace.

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
    "asns": [16509],
    "asn_files": ["/etc/caddy/asndrop.json"]
  },
  "geoip_anonymous": {
    "db": "/usr/share/GeoIP/GeoIP2-Anonymous-IP.mmdb",
    "types": ["vpn", "tor"]
  }
}
```

The Caddyfile's `match_unknown` is `"match_unknown": true`. `confidence` and
`risk` are `"min_confidence"` and `"min_risk"`.

## Out of scope

City-level matching, database auto-download, and rich placeholders (city name,
coordinates, time zone) are deliberately not here.

Database updates are either manually placed or
[`geoipupdate`](https://github.com/maxmind/geoipupdate) plus `caddy reload
--force`.

## Checks

Requires Caddy v2.11.6 or later and maxminddb-golang v2.9.0, with no other
direct dependencies. Built and tested against the current Caddy release.

The code passes:

- `go vet ./...` and `go test ./...`
- `golangci-lint run` using Caddy's own `.golangci.yml`
- `govulncheck ./...` with no reachable vulnerabilities
- CodeQL via GitHub code scanning

## Other data sources

Any MMDB file works if it also uses MaxMind's schema, regardless of who made
it. The format defines the container but not the fields inside, and those
names inside are the part that matters. The matchers read `country.iso_code`,
`subdivisions[].iso_code`, `autonomous_system_number`, and the `is_*`
anonymizer flags (GeoLite2/GeoIP2 style).

See [docs/sources.md](docs/sources.md) for what's been tested, what each list
stands in for, and free substitutes.

## License

Apache-2.0
