// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestSubdivisionUnmarshalCaddyfile(t *testing.T) {
	tests := []struct {
		input   string
		wantErr bool
	}{
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				subdivision CA
			}`,
		},
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				subdivision CA NY
				subdivision WA
				match_unknown
			}`,
		},
		{
			// the country prefix belongs in the country subdirective
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				subdivision US-CA
			}`,
			wantErr: true,
		},
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				subdivision
			}`,
			wantErr: true,
		},
		{
			// country is a single code, unlike geoip_country's list
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US GB
				subdivision CA
			}`,
			wantErr: true,
		},
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				country GB
				subdivision CA
			}`,
			wantErr: true,
		},
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				db /tmp/Other.mmdb
				country US
				subdivision CA
			}`,
			wantErr: true,
		},
		{
			input: `geoip_subdivision {
				db /tmp/City.mmdb
				country US
				subdivision CA
				nonsense
			}`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		var m MatchGeoIPSubdivision
		err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
		if (err != nil) != tc.wantErr {
			t.Errorf("UnmarshalCaddyfile(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
		}
	}
}

func TestIsSubdivisionCode(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"CA", true},
		{"E", true},    // Östergötland County, Sweden
		{"ENG", true},  // England
		{"WBK", true},  // West Berkshire
		{"22", true},   // Jilin, China
		{"971", true},  // Guadeloupe, France
		{"ca", true},   // case is folded
		{"", false},
		{"CALI", false},
		{"US-CA", false},
		{"C A", false},
		{"C.A", false},
	}

	for _, tc := range tests {
		if got := isSubdivisionCode(tc.in); got != tc.want {
			t.Errorf("isSubdivisionCode(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestSubdivisionValidate(t *testing.T) {
	tests := []struct {
		name    string
		m       MatchGeoIPSubdivision
		wantErr bool
	}{
		{
			name: "complete",
			m:    MatchGeoIPSubdivision{DB: "x.mmdb", Country: "US", Subdivisions: []string{"CA"}},
		},
		{
			name:    "no db",
			m:       MatchGeoIPSubdivision{Country: "US", Subdivisions: []string{"CA"}},
			wantErr: true,
		},
		{
			name:    "no country",
			m:       MatchGeoIPSubdivision{DB: "x.mmdb", Subdivisions: []string{"CA"}},
			wantErr: true,
		},
		{
			name:    "no subdivisions",
			m:       MatchGeoIPSubdivision{DB: "x.mmdb", Country: "US"},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		if err := tc.m.Validate(); (err != nil) != tc.wantErr {
			t.Errorf("%s: Validate() error = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}
