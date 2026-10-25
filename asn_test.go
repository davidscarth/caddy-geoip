// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestASNUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		input       string
		wantASNs    int
		wantFile    string
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
		// Digits only, in uint32 range. Leading zeros are accepted by
		// ParseUint and simply have no representation in the type.
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				asn 001221
			}`,
			wantASNs: 1,
		},
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				asn AS16509
			}`,
			wantErr: true,
		},
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				asn -1
			}`,
			wantErr: true,
		},
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				asn abc
			}`,
			wantErr: true,
		},
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				asn 4294967296
			}`,
			wantErr: true,
		},
		{
			input: `geoip_asn {
				db       /tmp/ASN.mmdb
				asn_file /tmp/asndrop.json
			}`,
			wantFile: "/tmp/asndrop.json",
		},
		{
			input: `geoip_asn {
				db       /tmp/ASN.mmdb
				asn      16509
				asn_file /tmp/asndrop.json
			}`,
			wantASNs: 1,
			wantFile: "/tmp/asndrop.json",
		},
		{
			input: `geoip_asn {
				db       /tmp/ASN.mmdb
				asn_file /tmp/a.txt
				asn_file /tmp/b.txt
			}`,
			wantErr: true,
		},
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				asn_file
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
		if m.ASNFile != tc.wantFile {
			t.Errorf("Test %d: expected asn_file %q, got %q", i, tc.wantFile, m.ASNFile)
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
		{m: MatchGeoIPASN{DB: "/tmp/ASN.mmdb", ASNs: []uint32{16509}}},
		{m: MatchGeoIPASN{ASNs: []uint32{16509}}, wantErr: true},
		{m: MatchGeoIPASN{DB: "/tmp/ASN.mmdb"}, wantErr: true},
		{m: MatchGeoIPASN{DB: "/tmp/ASN.mmdb", ASNFile: "/tmp/asndrop.json"}},
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

// TestASNFile covers the line forms asn_file accepts (plain, AS-prefixed
// with names, CSV with a header, Spamhaus JSON lines) and the ways a
// file can be wrong. The Spamhaus sample mirrors ASN-DROP: a metadata
// line with no "asn" member, then one record per line.
func TestASNFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	spamhaus := write("asndrop.json", `{"type":"metadata","timestamp":1792903442,"size":39393,"records":2,"copyright":"(c) 2026 The Spamhaus Project SLU"}
{"asn":1221,"rir":"apnic","domain":"telstra.net","cc":"AU","asname":"ASN-TELSTRA"}
{"asn":64496,"rir":"arin","domain":"example.net","cc":"US","asname":"EXAMPLE"}
`)
	plain := write("asns.txt", "# hosting\n\n1221\n  64496  \r\n")
	named := write("bad-asn-list.txt", "AS1221 Telstra Corporation Ltd\nas64496 Example, LLC\n64497\t# tabbed comment\n")

	for i, tc := range []struct {
		file    string
		inline  []uint32
		wantLen int
		wantErr string
	}{
		{file: spamhaus, wantLen: 2},
		{file: plain, wantLen: 2},
		{file: named, wantLen: 3},
		{file: plain, inline: []uint32{64497}, wantLen: 3},
		{file: write("dup.txt", "1221\n1221\n"), inline: []uint32{1221}, wantLen: 1},
		{file: filepath.Join(dir, "missing.txt"), wantErr: "asn_file"},
		{file: write("empty.txt", "# nothing here\n"), wantErr: "no autonomous system numbers"},
		{file: write("meta.json", `{"type":"metadata"}`+"\n"), wantErr: "no autonomous system numbers"},
		{file: write("list.csv", "ASN,Entity\n1442,\"Surehosting Internet Solutions, Inc.\"\n3223;Voxility\n"), wantLen: 2},
		{file: write("word.txt", "1221\nASN64496\n"), wantErr: "word.txt:2"},
		{file: write("gap.txt", "AS 1221\n"), wantErr: "gap.txt:1"},
		{file: write("frac.txt", "1221.5\n"), wantErr: "frac.txt:1"},
		{file: write("mixed.txt", "12a21\n"), wantErr: "mixed.txt:1"},
		{file: write("zero.txt", "0\n"), wantErr: "zero.txt:1"},
		{file: write("big.txt", "4294967296\n"), wantErr: "big.txt:1"},
		{file: write("badjson.json", "{\"asn\":\n"), wantErr: "badjson.json:1"},
		{file: write("bigjson.json", `{"asn":4294967296}`+"\n"), wantErr: "bigjson.json:1"},
	} {
		m := MatchGeoIPASN{DB: asnDB, ASNs: tc.inline, ASNFile: tc.file}
		err := m.Provision(caddy.Context{})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Test %d: expected error containing %q, got %v", i, tc.wantErr, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if len(m.asns) != tc.wantLen {
			t.Errorf("Test %d: expected %d asns, got %d", i, tc.wantLen, len(m.asns))
		}
		if err := m.Validate(); err != nil {
			t.Errorf("Test %d: validate: %v", i, err)
		}
	}

	// The set from a file matches like one written inline: AS1221 is in
	// the test database, AS64496 is not.
	m := MatchGeoIPASN{DB: asnDB, ASNFile: spamhaus}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		remoteAddr string
		want       bool
	}{
		{"1.128.0.1:1234", true},
		{"8.8.8.8:1234", false},
	} {
		got, err := m.MatchWithError(newRequest(tc.remoteAddr))
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("%s: expected %v, got %v", tc.remoteAddr, tc.want, got)
		}
	}
}
