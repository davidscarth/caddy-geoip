// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestCountryUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		input         string
		wantDB        string
		wantCountries int
		wantUnknown   bool
		wantErr       bool
	}{
		{
			input: `geoip_country {
				db /tmp/Country.mmdb
				country US CA
			}`,
			wantDB:        "/tmp/Country.mmdb",
			wantCountries: 2,
		},
		{
			input: `geoip_country {
				db /tmp/Country.mmdb
				country US
				country CA ar
				match_unknown
			}`,
			wantDB:        "/tmp/Country.mmdb",
			wantCountries: 3,
			wantUnknown:   true,
		},
		{
			input: `geoip_country extra {
				db /tmp/Country.mmdb
			}`,
			wantErr: true,
		},
		{
			input: `geoip_country {
				bogus yes
			}`,
			wantErr: true,
		},
		{
			input: `geoip_country {
				db /tmp/Country.mmdb
				country
			}`,
			wantErr: true,
		},
		{
			input: `geoip_country {
				db /tmp/Country.mmdb
				db /tmp/Other.mmdb
				country US
			}`,
			wantErr: true,
		},
	} {
		var m MatchGeoIPCountry
		err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if tc.wantErr {
			if err == nil {
				t.Errorf("Test %d: expected error but got none", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if m.DB != tc.wantDB {
			t.Errorf("Test %d: expected db %q, got %q", i, tc.wantDB, m.DB)
		}
		if len(m.Countries) != tc.wantCountries {
			t.Errorf("Test %d: expected %d countries, got %d", i, tc.wantCountries, len(m.Countries))
		}
		if m.MatchUnknown != tc.wantUnknown {
			t.Errorf("Test %d: expected match_unknown=%v, got %v", i, tc.wantUnknown, m.MatchUnknown)
		}
	}
}

func TestIsCountryCode(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"US", true},
		{"us", true},
		{"EU", true},
		{"USA", false},
		{"U", false},
		{"12", false},
		{"U1", false},
		{"", false},
		{"ÜS", false},
	} {
		if got := isCountryCode(tc.in); got != tc.want {
			t.Errorf("isCountryCode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCountryValidate(t *testing.T) {
	for i, tc := range []struct {
		m       MatchGeoIPCountry
		wantErr bool
	}{
		{m: MatchGeoIPCountry{DB: "/tmp/Country.mmdb", Countries: []string{"US"}}},
		{m: MatchGeoIPCountry{Countries: []string{"US"}}, wantErr: true},
		{m: MatchGeoIPCountry{DB: "/tmp/Country.mmdb"}, wantErr: true},
	} {
		err := tc.m.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("Test %d: expected error but got none", i)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
		}
	}
}
