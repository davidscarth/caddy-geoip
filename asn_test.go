// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestASNUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		input       string
		wantASNs    int
		wantUnknown bool
		wantErr     bool
	}{
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				asn 16509 14618
			}`,
			wantASNs: 2,
		},
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				asn 16509
				match_unknown
			}`,
			wantASNs:    1,
			wantUnknown: true,
		},
		{
			input:   `geoip_asn /tmp/ASN.mmdb`,
			wantErr: true,
		},
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				asn
			}`,
			wantErr: true,
		},
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				db /tmp/Other.mmdb
				asn 16509
			}`,
			wantErr: true,
		},
	} {
		var m MatchGeoIPASN
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
		if len(m.ASNs) != tc.wantASNs {
			t.Errorf("Test %d: expected %d asns, got %d", i, tc.wantASNs, len(m.ASNs))
		}
		if m.MatchUnknown != tc.wantUnknown {
			t.Errorf("Test %d: expected match_unknown=%v, got %v", i, tc.wantUnknown, m.MatchUnknown)
		}
	}
}

func TestASNValidate(t *testing.T) {
	for i, tc := range []struct {
		m       MatchGeoIPASN
		wantErr bool
	}{
		{m: MatchGeoIPASN{DB: "/tmp/ASN.mmdb", ASNs: []string{"16509"}}},
		{m: MatchGeoIPASN{ASNs: []string{"16509"}}, wantErr: true},
		{m: MatchGeoIPASN{DB: "/tmp/ASN.mmdb"}, wantErr: true},
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
