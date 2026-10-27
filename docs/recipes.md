# Recipes

The README.md was getting a little long, so the more fundamental use cases
were kept in the README and this supplement is designed to feature additional
examples where the plugin can help Caddy do more.

#### Look up without a rule

A matcher only runs when a directive uses it, and the placeholder is only
set once it has run. So if you want the country without a block or allow rule,
give the matcher a code the database never emits. ISO 3166-1 reserves `ZZ` for
unknown, so you can take advantage of that. In this example `@geo` never
matches, but evaluating it sets `{geoip.country}` for everything after it:

```caddyfile
@geo geoip_country {
	db "C:\ProgramData\Caddy\GeoLite2-Country.mmdb"
	country ZZ
}
handle @geo {
}
handle {
	log_append <geo_country {geoip.country}
}
```

The recipes below reuse this pattern. Anywhere `@geo` appears, assume the ZZ
matcher trick is being used. If you already have allow or deny rules in your
Caddyfile, skip this and build off those instead.

#### Pass the country to your app

Look up once here, read it everywhere behind Caddy. `request_header`
replaces the field:

```caddyfile
handle @geo {
}
handle {
	request_header X-Country-Code {geoip.country}
	reverse_proxy 127.0.0.1:3000
}
```

The app sees `X-Country-Code: US`, or an empty value for an unknown address,
and needs no database of its own. `{geoip.asn}` and `{geoip.anonymous}` can
be used the same way.

#### Fence a path

In this example the site is open, but the admin panel is gated by region
or LAN. `/admin/*` doesn't match `/admin` itself, so list both.

```caddyfile
@admin_abroad {
	path /admin /admin/*
	not geoip_country {
		db "C:\ProgramData\Caddy\GeoLite2-Country.mmdb"
		country US
	}
	not client_ip private_ranges
}
abort @admin_abroad
```

#### Sanctioned countries and regions

Sanctions may name regions inside a country as well as countries. Crimea,
Sevastopol, Donetsk, and Luhansk are subdivisions of `UA` in the database:

```caddyfile
@sanctioned_country geoip_country {
	db "C:\ProgramData\Caddy\GeoLite2-City.mmdb"
	country CU IR KP SY
}
@sanctioned_region geoip_subdivision {
	db "C:\ProgramData\Caddy\GeoLite2-City.mmdb"
	country UA
	subdivision 43 40 14 09
}
respond @sanctioned_country "Not available in your region" 451
respond @sanctioned_region "Not available in your region" 451
```

That is how MaxMind files them, other vendors may differ, and coverage of
occupied territory is thin, so treat this as one layer, not the only one.
Some of these networks are registered to `RU` and some to `UA`, a country
rule on either misses part of the set.

Refer to OFAC's [Sanctions Programs and Country Information][ofac] for the
current list, it changes.

#### Rate limit instead of block

A matcher is a condition, so it works inside any directive that takes one.
With [caddy-ratelimit](https://github.com/mholt/caddy-ratelimit), hosting
networks can be limited instead of blocked. Write the matcher out inside the
zone, named matchers are not available there:

```caddyfile
rate_limit {
	zone hosting {
		match {
			geoip_asn {
				db "C:\ProgramData\Caddy\GeoLite2-ASN.mmdb"
				asn_file "C:\ProgramData\Caddy\datacenter-asns.txt"
			}
		}
		key {client_ip}
		events 30
		window 1m
	}
}
```

If you subscribe to the paid MaxMind Anonymous IP database, you can use
`geoip_anonymous { type hosting }` in place of the ASN matcher.

To cap a whole provider rather than each of its addresses, use
`key {geoip.asn}`. The zone's matcher has run by the time the key is read.

Inside another plugin's directive, our rule 3 ("fail closed") no longer holds.
caddy-ratelimit treats a matcher error as no match, so a failed lookup, or a
refused HTTP/3 0-RTT request, skips the zone instead of stopping the request.

#### VPNs, but only from some countries

Let identified VPNs through, but only from where the site is meant to be
reached:

```caddyfile
@vpn_abroad {
	geoip_anonymous {
		db "C:\ProgramData\Caddy\GeoIP2-Anonymous-IP.mmdb"
		type vpn
	}
	not geoip_country {
		db "C:\ProgramData\Caddy\GeoLite2-Country.mmdb"
		country US CA
	}
}
respond @vpn_abroad "VPN access is limited to North America" 403
```

#### Route by region

```caddyfile
@eu geoip_country {
	db /usr/share/GeoIP/GeoLite2-Country.mmdb
	country AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE
}
reverse_proxy @eu eu-backend:8080
reverse_proxy backend:8080
```

The example list is the [EU][eu]. GDPR territory is the [EEA][eea], which
adds `IS LI NO`. The UK applies its own UK GDPR, so add `GB` too where
GDPR-style rules apply.

#### Reusable snippet

```caddyfile
(geoblock) {
	@blocked geoip_country {
		db "C:\ProgramData\Caddy\GeoLite2-Country.mmdb"
		country CN RU PK KP IR ID IN VN BR NG BY CU SY VE SD
	}
	abort @blocked
}

example.com {
	import geoblock
	reverse_proxy 127.0.0.1:3000
}
```

[ofac]: https://ofac.treasury.gov/sanctions-programs-and-country-information
[eu]: https://european-union.europa.eu/principles-countries-history/eu-countries_en
[eea]: https://www.efta.int/eea
