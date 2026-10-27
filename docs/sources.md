# Data sources

- [MaxMind](#maxmind)
- [Databases from other vendors](#databases-from-other-vendors)
- [Lists for `asn_file`](#lists-for-asn_file)
- [Without an Anonymous IP database](#without-an-anonymous-ip-database)

## MaxMind

The matchers are built for MaxMind's databases, tested against MaxMind's
test file for every edition below, and run in production on the free
GeoLite2 editions. The type check at load accepts the editions marked and
refuses the rest.

| Edition | Cost | `geoip_country` | `geoip_subdivision` | `geoip_asn` | `geoip_anonymous` | Notes |
|---|---|---|---|---|---|---|
| GeoLite2 Country | free | yes | - | - | - | |
| GeoIP2 Country | paid | yes | - | - | - | |
| GeoLite2 City | free | yes | yes | - | - | |
| GeoIP2 City | paid | yes | yes | - | - | |
| GeoLite2 ASN | free | - | - | yes | - | |
| GeoIP2 ISP | paid | - | - | yes | - | |
| GeoIP2 Enterprise | paid | yes | yes | yes | - | ASN under `traits` |
| GeoIP Country Shield | paid | yes | - | - | - | see 1 |
| GeoIP City Shield | paid | yes | yes | - | - | see 1 |
| GeoIP Enterprise Shield | paid | yes | yes | yes | - | see 1 |
| GeoIP2 Anonymous IP | paid | - | - | - | yes | |
| GeoIP Anonymous Plus | paid | - | - | - | yes | extra fields ignored |
| GeoIP2 IP Risk | paid | - | - | - | yes | score ignored |
| GeoIP Residential Proxy | paid | - | - | - | - | see 2 |
| GeoIP Regions | paid | - | - | - | - | see 2 |
| GeoIP2 Connection Type | paid | - | - | - | - | see 2 |

1. The Shield editions carry the same records as their plain
   counterparts plus the addresses MaxMind removes from those on privacy
   opt-out requests. MaxMind licenses them for fraud prevention,
   compliance, and security use only, by arrangement rather than
   download. They load the same way.
2. Nothing the matchers read today. Residential Proxy carries a
   confidence score and none of the anonymizer flags, Regions carries
   country and subdivisions with confidence scores, and Connection Type
   (cable, cellular, corporate, satellite) carries one field. These are
   tested just to check that each is refused by name.

## Databases from other vendors

Other vendors are not supported, and results here are provided for
convenience. Results may change with any update on their side.

The matchers read MaxMind's GeoIP2 record layout: `country.iso_code`,
`subdivisions[].iso_code`, `autonomous_system_number`, and the `is_*`
anonymizer flags. A file that uses that layout will work regardless of who
built it. A file that doesn't will still load, since the type check only
looks at the database name, but then it won't work.

| File | License | Matcher | Seems to work | Notes |
|---|---|---|---|---|
| DB-IP Lite [Country][dbip-country] | CC BY 4.0 | `geoip_country` | yes | |
| DB-IP Lite City | CC BY 4.0 | `geoip_subdivision` | **no** | see 1 |
| DB-IP Lite [ASN][dbip-asn] | CC BY 4.0 | `geoip_asn` | yes | |
| IP2Location LITE [DB1][ip2l-db1] | CC BY-SA 4.0 | `geoip_country` | yes | |
| IP2Location LITE [DB11][ip2l-db11] | CC BY-SA 4.0 | `geoip_subdivision` | yes | MMDB only, see 2 |
| IP2Location LITE [ASN][ip2l-asn] | [proprietary][ip2l-terms] | `geoip_asn` | yes | |
| IP2Location [IP2Proxy LITE PX10][ip2proxy] | [proprietary][ip2l-terms] | `geoip_anonymous` | yes | public proxies only, see 3 |
| Geoacumen [Country][geoacumen] | Apache-2.0 | `geoip_country` | yes | |
| sapics user-country, server-country | PDDL | `geoip_country` | **no** | own schema, see 4 |
| sapics [origin-asn][sapics-asn] | PDDL | `geoip_asn` | yes | from BGP, daily |
| IPLocate.io free databases | CC BY-SA 4.0 | any | **no** | own schema, see 4 |

All MMDB format, checked with October 2026 files.

1. Subdivision names without ISO 3166-2 codes, so `geoip_subdivision`
   matches nothing and `{geoip.subdivision}` is always empty.
2. Carries ISO 3166-2 codes in their MMDB, not in their CSV, so don't
   convert it yourself.
3. The LITE edition lists public proxies only, so every address carries
   the same two flags, `anonymous` and `public_proxy`. `type vpn` or
   `type tor` match nothing. Use `type anonymous` as a block-all-known-
   proxies switch.
4. Own record layout (e.g. `country_code`), so the file loads but every
   address is unknown.

#### Checking a file yourself

Use MaxMind's [`mmdbinspect`](https://github.com/maxmind/mmdbinspect):
`mmdbinspect -db file.mmdb 216.160.83.56`. Other databases should work
if the record has `country` with `iso_code` inside for `geoip_country`,
`subdivisions` whose entries have `iso_code` for `geoip_subdivision`,
`autonomous_system_number` for `geoip_asn`, or `is_anonymous` and its
siblings for `geoip_anonymous`. YMMV.

## Lists for `asn_file`

Any list of autonomous system numbers loads as published. The plugin
accepts a few forms:

- plain numbers (`14061`)
- numbers with names (`AS14061 DigitalOcean, LLC` or `14061 # DigitalOcean`)
- CSV with a header (`ASN,Entity`)
- Spamhaus ASN-DROP's JSON lines (`{"asn":14061,...}`)

The parser expects the number first on every line, `AS` prefix or not,
and ignores whatever follows a space, tab, comma, semicolon, or `#`.
Blank lines, `#` comments, and lines with no digits such as a CSV header
are skipped. A line that does not start with a number, a file over 64
MiB, or binary data (including UTF-16, save as UTF-8) is an error at
load, naming the file and line. None of the forms is preferred, use whichever
one you like.

| List | Format | ASNs | Stands in for |
|---|---|---|---|
| Spamhaus [ASN-DROP][asndrop] | JSON lines | 443 | nothing else, operators with a bad reputation |
| X4BNet [datacenter][x4b-dc] | `AS1234 # name` | 934 | `geoip_anonymous { type hosting }` |
| X4BNet [vpn][x4b-vpn] | `AS1234 # name` | 16 | `type vpn`, for VPNs that run their own network |
| brianhama [bad-asn-list][bah] | CSV, `ASN,Entity` | 723 | `type hosting`, with names |
| bountyyfi [bad-asn-list][bfi] | `AS1234 Name` | 2,213 | `type hosting`, larger fork of the above |

These were checked in October 2026, counts are distinct ASNs at that time.

## Without an Anonymous IP database

MaxMind's Anonymous IP database is paid. For each `type`, what a free
source can do instead:

| `type` | Free substitute | Where | Coverage |
|---|---|---|---|
| `hosting` | X4BNet [datacenter ASNs][x4b-dc], brianhama or bountyyfi [bad-asn-list][bah] | `geoip_asn` + `asn_file` | good, hosting is a property of the network, so ASN is the natural key |
| `vpn` | X4BNet [VPN ASNs][x4b-vpn] | `geoip_asn` + `asn_file` | thin, 16 providers that run their own network. Most VPN exits sit in hosting space, so the hosting list catches them, along with every other hosting customer |
| `public_proxy` | IP2Location [IP2Proxy LITE][ip2proxy], MMDB | `geoip_anonymous` with `type anonymous` | good, it is an open-proxy list in the same record layout |
| `anonymous` | the three rows above together | both matchers | partial, umbrella minus Tor and residential |
| `tor` | Tor Project [exit list][torbulk] | **not in this plugin.** Exits are addresses, not networks, so an IP source, CrowdSec's Tor blocklist, or the firewall | good, the list is authoritative and hourly |
| `residential_proxy` | none | none | by design these are addresses on consumer ISPs, only commercial data such as MaxMind's sees them |

[dbip-country]: https://db-ip.com/db/download/ip-to-country-lite
[dbip-asn]: https://db-ip.com/db/download/ip-to-asn-lite
[ip2l-db1]: https://lite.ip2location.com/database/db1-ip-country
[ip2l-db11]: https://lite.ip2location.com/database/db11-ip-country-region-city-latitude-longitude-zipcode-timezone
[ip2l-asn]: https://lite.ip2location.com/database-asn
[ip2l-terms]: https://lite.ip2location.com/terms-of-use
[ip2proxy]: https://lite.ip2location.com/ip2proxy-lite
[geoacumen]: https://github.com/geoacumen/geoacumen-country
[sapics-asn]: https://github.com/sapics/ip-location-db#asn
[asndrop]: https://www.spamhaus.org/drop/
[x4b-dc]: https://github.com/X4BNet/lists_vpn/blob/main/input/datacenter/ASN.txt
[x4b-vpn]: https://github.com/X4BNet/lists_vpn/blob/main/input/vpn/ASN.txt
[bah]: https://github.com/brianhama/bad-asn-list
[bfi]: https://github.com/bountyyfi/bad-asn-list
[torbulk]: https://check.torproject.org/torbulkexitlist
