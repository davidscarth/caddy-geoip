// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
)

func TestASNUnmarshalCaddyfile(t *testing.T) {
	for i, tc := range []struct {
		input       string
		wantASNs    int
		wantFiles   []string
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
		// ASN 0 is reserved, and refused here so the error has a line.
		{
			input: `geoip_asn {
				db /tmp/ASN.mmdb
				asn 0
			}`,
			wantErr: true,
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
			wantFiles: []string{"/tmp/asndrop.json"},
		},
		{
			input: `geoip_asn {
				db       /tmp/ASN.mmdb
				asn      16509
				asn_file /tmp/asndrop.json
			}`,
			wantASNs:  1,
			wantFiles: []string{"/tmp/asndrop.json"},
		},
		// Several files on one line, the line repeated, and a quoted path
		// with a space, all collected in order.
		{
			input: `geoip_asn {
				db       /tmp/ASN.mmdb
				asn_file /tmp/a.json /tmp/b.csv
				asn_file "/tmp/my list.txt"
			}`,
			wantFiles: []string{"/tmp/a.json", "/tmp/b.csv", "/tmp/my list.txt"},
		},
		// Two blocks in one named matcher reach the matcher as one, so
		// their files add up.
		{
			input: `geoip_asn {
				db       /tmp/ASN.mmdb
				asn_file /tmp/a.txt
			}
			geoip_asn {
				asn_file /tmp/b.txt
			}`,
			wantFiles: []string{"/tmp/a.txt", "/tmp/b.txt"},
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
				t.Errorf("Test %d: UnmarshalCaddyfile() error = nil, want error", i)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if len(m.ASNs) != tc.wantASNs {
			t.Errorf("Test %d: got %d asns, want %d", i, len(m.ASNs), tc.wantASNs)
		}
		if !slices.Equal(m.ASNFiles, tc.wantFiles) {
			t.Errorf("Test %d: asn_file = %q, want %q", i, m.ASNFiles, tc.wantFiles)
		}
		if m.MatchUnknown != tc.wantUnknown {
			t.Errorf("Test %d: match_unknown = %v, want %v", i, m.MatchUnknown, tc.wantUnknown)
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
		{m: MatchGeoIPASN{DB: "/tmp/ASN.mmdb", ASNFiles: []string{"/tmp/asndrop.json"}}},
	} {
		err := tc.m.Validate()
		if tc.wantErr && err == nil {
			t.Errorf("Test %d: Validate() error = nil, want error", i)
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
	huge := write("huge.txt", "1221\n")
	if err := os.Truncate(huge, 64<<20+1); err != nil {
		t.Fatal(err)
	}

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
		{file: "{env.CADDY_GEOIP_UNSET_ASN_LIST}", wantErr: "empty after placeholder"},
		{file: asnDB, wantErr: "binary data"},
		{file: huge, wantErr: "too large"},
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
		{file: write("bom.txt", "\ufeff1221\n64496\n"), wantLen: 2},
		{file: write("utf16.txt", "\xff\xfe1\x002\x002\x001\x00\r\x00\n\x00"), wantErr: "UTF-16"},

		// Comment lines, and headers: one with a digit in a later column,
		// and a single-column one, which must name the column.
		{file: write("comments.txt", "; list\n// note\n1221 // Telstra\n64496 ; Example\n"), wantLen: 2},
		{file: write("glued.txt", "1221//Telstra\n64496#Example\n"), wantLen: 2},
		{file: write("count.csv", "asn,ipv4_count\n1221,12\n64496,40\n"), wantLen: 2},
		{file: write("column.txt", "ASN\n1221\n"), wantLen: 1},
		{file: write("tomsk.txt", "AS5567 AS5567 (Tomsk Polytechnic)\n"), wantLen: 1},

		// Files that used to load in part, without an error.
		{file: write("oneline.csv", "1221,64496,64497\n"), wantErr: "oneline.csv:1: several ASNs on one line"},
		{file: write("oneline.txt", "AS1221 AS64496\n"), wantErr: "oneline.txt:1: several ASNs on one line"},
		{file: write("wrapped.csv", "1221,64496\n64497,64498\n"), wantErr: "wrapped.csv:1: several ASNs"},
		{file: write("junk.txt", "1221\nTelstra\n64496\n"), wantErr: "junk.txt:2: invalid asn"},
		{file: write("stray.txt", "error_fetching_list\n1221,64496\n"), wantErr: "stray.txt:1: invalid asn"},
		{file: write("typo.txt", "AS-1221\n64496\n"), wantErr: "typo.txt:1: invalid asn"},
		{file: write("gap2.txt", "AS 1221\n64496\n"), wantErr: "gap2.txt:1: invalid asn"},
		{file: write("zero.json", `{"asn":1221}`+"\n"+`{"asn":0}`+"\n"), wantErr: "zero.json:2: invalid asn 0"},
		// A trailing comment used to hide the second ASN from the check.
		{file: write("masked.txt", "1221 64496 // two providers\n"), wantErr: "masked.txt:1: several ASNs"},
		{file: write("masked.csv", "1221,64496 // two providers\n"), wantErr: "masked.csv:1: several ASNs"},
		// With the comment cut, a word and a comment is one word, which is
		// only a header if it names the column.
		{file: write("stray2.txt", "fetch // failed\n1221\n"), wantErr: "stray2.txt:1: invalid asn"},

		// Other kinds of file, named in the error.
		{file: write("ips.txt", "1.2.3.0/24\n"), wantErr: "IP address or network"},
		{file: write("nro.txt", "2.3|nro|20261101|1\nnro|US|asn|1221|1|20010920|assigned\n"), wantErr: "RIR/NRO"},
		{file: write("pretty.json", "{\n  \"asn\": 1221\n}\n"), wantErr: "one JSON object per line"},
		{file: write("long.txt", strings.Repeat("x", 70000)+"\n1221\n"), wantErr: "long.txt:1: line longer than 64 KiB"},
	} {
		m := MatchGeoIPASN{DB: asnDB, ASNs: tc.inline, ASNFiles: []string{tc.file}}
		err := m.Provision(caddy.Context{})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Test %d: Provision() error = %v, want one containing %q", i, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if len(m.asns) != tc.wantLen {
			t.Errorf("Test %d: got %d asns, want %d", i, len(m.asns), tc.wantLen)
		}
		if err := m.Validate(); err != nil {
			t.Errorf("Test %d: validate: %v", i, err)
		}
	}

	// The set from a file matches like one written inline: AS1221 is in
	// the test database, AS64496 is not.
	m := MatchGeoIPASN{DB: asnDB, ASNFiles: []string{spamhaus}}
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
			t.Errorf("%s: MatchWithError() = %v, want %v", tc.remoteAddr, got, tc.want)
		}
	}
}

// TestASNFiles loads four lists in four forms into one matcher, and
// checks that one empty file among them fails the load by name rather
// than passing on the strength of the others.
func TestASNFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	files := []string{
		write("drop.json", `{"type":"metadata"}`+"\n"+`{"asn":1221}`+"\n"),
		write("hosting.csv", "ASN,Entity\n64496,Example\n1221,Telstra\n"),
		write("plain.txt", "64497\n64498\n"),
		write("named.txt", "# vpn\nAS64499 Example VPN\n64500 // other\n"),
	}
	m := MatchGeoIPASN{DB: asnDB, ASNFiles: files}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatal(err)
	}
	want := []string{"1221", "64496", "64497", "64498", "64499", "64500"}
	if got := slices.Sorted(maps.Keys(m.asns)); !slices.Equal(got, want) {
		t.Errorf("asns = %v, want %v", got, want)
	}

	empty := write("empty.txt", "# fetch failed\n")
	m = MatchGeoIPASN{DB: asnDB, ASNFiles: append(files, empty)}
	err := m.Provision(caddy.Context{})
	if err == nil || !strings.Contains(err.Error(), "empty.txt") {
		t.Errorf("Provision() error = %v, want one naming empty.txt", err)
	}
}

// FuzzReadASNFile checks the parser never panics, and that whatever it
// loads is the decimal form of an ASN from 1 to 4294967295.
func FuzzReadASNFile(f *testing.F) {
	for _, seed := range []string{
		"1221\n64496\n", "ASN,Entity\n1221,Telstra\n", "{\"asn\":1221}\n", "AS1221 AS64496\n",
		"# c\n; c\n// c\n", "1221//c\n", "\ufeff1221\r\n", "2.3|nro|1|2\n", "\x00",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		path := filepath.Join(t.TempDir(), "in")
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		set := map[string]struct{}{}
		if err := readASNFile(discard, path, set); err != nil {
			return
		}
		for k := range set {
			n, err := strconv.ParseUint(k, 10, 32)
			if err != nil || n == 0 || strconv.FormatUint(n, 10) != k {
				t.Fatalf("bad key %q", k)
			}
		}
	})
}

// TestLogListAge pins the line an ASN list logs when it loads: INFO within
// 30 days of its modified time, WARN past that, and WARN when the modified
// time is in the future.
func TestLogListAge(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		modified time.Time
		want     string
	}{
		{"3 days", now.AddDate(0, 0, -3), `{"level":"INFO","msg":"asn list loaded","path":"/etc/caddy/drop.json","asns":443,"modified":"2026-10-29T12:00:00Z","age_days":3}`},
		{"45 days", now.AddDate(0, 0, -45), `{"level":"WARN","msg":"asn list is more than 30 days old","path":"/etc/caddy/drop.json","asns":443,"modified":"2026-09-17T12:00:00Z","age_days":45}`},
		{"future", now.Add(time.Hour), `{"level":"WARN","msg":"asn list modified time is in the future","path":"/etc/caddy/drop.json","asns":443,"modified":"2026-11-01T13:00:00Z"}`},
	} {
		got := logLines(t, func(l *slog.Logger) { logListAge(l, "/etc/caddy/drop.json", 443, tc.modified, now) })
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", tc.name, got, tc.want)
		}
	}
}

// TestASNProvisionRejects covers the one value the type can hold but the
// domain cannot. Everything else is rejected at Caddyfile parse time or
// by the JSON decoder, which does not accept strings or negatives.
func TestASNProvisionRejects(t *testing.T) {
	m := MatchGeoIPASN{DB: asnDB, ASNs: []uint32{0}}
	if err := m.Provision(caddy.Context{}); err == nil {
		t.Error("expected provision to reject asn 0")
	}
}

func TestASNMatch(t *testing.T) {
	m := MatchGeoIPASN{DB: asnDB, ASNs: []uint32{1221}}

	// Caddy provisions before it validates.
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}

	for i, tc := range []struct {
		remoteAddr string
		want       bool
	}{
		{"1.128.0.1:1234", true},      // AS1221
		{"[2001:8000::1]:1234", true}, // AS1221 over native IPv6
		{"10.1.2.3:1234", false},      // private, no record
		{"8.8.8.8:1234", false},       // not in the test db
	} {
		got, err := m.MatchWithError(newRequest(tc.remoteAddr))
		if err != nil {
			t.Errorf("Test %d: unexpected error: %v", i, err)
			continue
		}
		if got != tc.want {
			t.Errorf("Test %d: %s: MatchWithError() = %v, want %v", i, tc.remoteAddr, got, tc.want)
		}
	}
}

// TestASNAcrossDatabaseEditions checks the three editions the ASN
// matcher accepts. Enterprise nests the autonomous system fields under
// traits, so reading the top-level path there would match nothing at
// all, silently.
func TestASNAcrossDatabaseEditions(t *testing.T) {
	for _, tc := range []struct {
		name, db, addr string
		asn            uint32
	}{
		{"GeoLite2-ASN", asnDB, "1.128.0.1:1234", 1221},
		{"GeoIP2-ISP", ispDB, "1.128.0.1:1234", 1221},
		{"GeoIP2-Enterprise", entDB, "74.209.24.1:1234", 14671},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := MatchGeoIPASN{DB: tc.db, ASNs: []uint32{tc.asn}}
			if err := m.Provision(caddy.Context{}); err != nil {
				t.Fatalf("provision: %v", err)
			}

			r := newRequest(tc.addr)
			got, err := m.MatchWithError(r)
			if err != nil {
				t.Fatal(err)
			}
			if !got {
				t.Errorf("expected AS%d to match", tc.asn)
			}
			want := strconv.FormatUint(uint64(tc.asn), 10)
			repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
			if v := repl.ReplaceAll("{geoip.asn}", ""); v != want {
				t.Errorf("{geoip.asn} = %q, want %s", v, want)
			}
		})
	}
}

func TestASNMatchUnknownAndPlaceholder(t *testing.T) {
	// match_unknown and the placeholder name are separate lines in
	// asn.go from the country matcher's, so they are checked here too.
	m := MatchGeoIPASN{DB: asnDB, ASNs: []uint32{1221}, MatchUnknown: true}
	if err := m.Provision(caddy.Context{}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	if got, _ := m.MatchWithError(newRequest("10.1.2.3:1234")); !got {
		t.Error("expected an IP with no ASN record to match with match_unknown")
	}

	r := newRequest("1.128.0.1:1234")
	if _, err := m.MatchWithError(r); err != nil {
		t.Fatal(err)
	}
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)
	if got := repl.ReplaceAll("{geoip.asn}", ""); got != "1221" {
		t.Errorf("{geoip.asn} = %q, want 1221", got)
	}
}
