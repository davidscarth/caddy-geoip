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
	for _, tc := range []struct {
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
		if (err != nil) != tc.wantErr {
			t.Errorf("UnmarshalCaddyfile(%q) error = %v, wantErr %v", tc.input, err, tc.wantErr)
		}
		if err != nil || tc.wantErr {
			continue
		}
		if len(m.ASNs) != tc.wantASNs {
			t.Errorf("UnmarshalCaddyfile(%q) got %d asns, want %d", tc.input, len(m.ASNs), tc.wantASNs)
		}
		if !slices.Equal(m.ASNFiles, tc.wantFiles) {
			t.Errorf("UnmarshalCaddyfile(%q) asn_file = %q, want %q", tc.input, m.ASNFiles, tc.wantFiles)
		}
		if m.MatchUnknown != tc.wantUnknown {
			t.Errorf("UnmarshalCaddyfile(%q) match_unknown = %v, want %v", tc.input, m.MatchUnknown, tc.wantUnknown)
		}
	}
}

func TestASNValidate(t *testing.T) {
	for _, tc := range []struct {
		name    string
		m       MatchGeoIPASN
		wantErr bool
	}{
		{name: "complete", m: MatchGeoIPASN{DB: "/tmp/ASN.mmdb", ASNs: []uint32{16509}}},
		{name: "no db", m: MatchGeoIPASN{ASNs: []uint32{16509}}, wantErr: true},
		{name: "no asns", m: MatchGeoIPASN{DB: "/tmp/ASN.mmdb"}, wantErr: true},
		{name: "file only", m: MatchGeoIPASN{DB: "/tmp/ASN.mmdb", ASNFiles: []string{"/tmp/asndrop.json"}}},
	} {
		if err := tc.m.Validate(); (err != nil) != tc.wantErr {
			t.Errorf("%s: Validate() error = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

// TestASNFile covers the forms asn_file accepts (plain, AS-prefixed with
// names, CSV with a header, Cloudflare expressions, Spamhaus JSON lines)
// and the ways a file can be wrong. The Spamhaus sample mirrors ASN-DROP
// (one record per line, then a line with no "asn" member).
func TestASNFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	spamhaus := write("asndrop.json", `{"asn":1221,"rir":"apnic","domain":"telstra.net","cc":"AU","asname":"ASN-TELSTRA"}
{"asn":64496,"rir":"arin","domain":"example.net","cc":"US","asname":"EXAMPLE"}
{"type":"metadata","timestamp":1792903442,"size":39393,"records":2,"copyright":"(c) 2026 The Spamhaus Project SLU"}`)
	plain := write("asns.txt", "# hosting\n\n1221\n  64496  \r\n")
	huge := write("huge.txt", "1221\n")
	if err := os.Truncate(huge, maxListBytes+1); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		file    string
		inline  []uint32
		wantLen int
		wantErr string
	}{
		// 1. Real-world list archetypes (plain, commented, AS-named, one-line, Cloudflare, CSV, JSON).
		{file: plain, wantLen: 2},
		{file: write("bad-hosting.txt", "1610 # Contegix (contegix.com)\n7738 # V tal оператор\n"), wantLen: 2},
		{file: write("qfeeds.txt", "#\tQ-Feeds list\nAS198798\nAS136621\n"), wantLen: 2},
		{file: write("named.txt", "AS1024 12393239 Canada Inc\nAS42772 AS42772\nAS201011 AS33891 Netzbetrieb GmbH\n"), wantLen: 3},
		{file: write("raw.txt", "3223 3842 4250\n"), wantLen: 3},
		{file: write("cf-in.txt", "(ip.geoip.asnum in {\n  16509 13335\n})\n"), wantLen: 2},
		{file: write("cf-eq.txt", "(ip.src.asnum eq 174) or (ip.src.asnum eq 612)\n"), wantLen: 2},
		{file: write("list.csv", "ASN,Entity\n51167,\"CONTABO to AS1299, DE\"\n54500,\"18779 - EGIHosting, US\"\n15497,COLOCALL \"ColoCALL\", UA\n"), wantLen: 3},
		{file: write("spam.csv", "#;ASN, Organization name;Country\n1;AS4134 Chinanet;China\n;AS4837 Unicom;China\n6;AS201011 AS33891 Netzbetrieb GmbH;DE\n;;\n"), wantLen: 3},
		{file: spamhaus, wantLen: 2},
		{file: write("array.json", "[\n  {\"ASN\": 174, \"Entity\": \"Cogent\"},\n  {\"ASN\": \"612\", \"peers\": [{\"asn\": 1}]}\n]\n"), wantLen: 2},
		{file: write("envelope.json", "{\"data\": [{\"asn\": 1221}, {\"asn\": \"64496\"}]}\n"), wantLen: 2},

		// 2. General supported features (inline merge, dedup, BOM, comments, Markdown, non-first CSV columns).
		{file: plain, inline: []uint32{64497}, wantLen: 3},
		{file: write("dup.txt", "1221\n1221\n"), inline: []uint32{1221}, wantLen: 1},
		{file: write("bom-comments.txt", "\ufeff; list\n// note\n1221 https://example.com // Telstra\n64496#Example\n"), wantLen: 2},
		{file: write("hash-comment.txt", "#, as of today\n#,ASN AS1221 was delisted\n64496\n"), wantLen: 1},
		{file: write("trailing-as.txt", "Telstra AS1221\nLevel 3 AS3356\nAS 64496\n"), wantLen: 3},
		{file: write("ranked.csv", "; ASN list\nrank,asn,name # rank, then the ASN\n\t# mid-table comment\n1,4134,\"Foo # bar\"\n2,4837,Unicom\n"), wantLen: 2},
		{file: write("aligned.md", "| ASN | Name |\n|:---:|---:|\n| 18779 | EGIHosting |\n"), wantLen: 1},

		// 3. Rejections: I/O, encoding, bounds, inverted rules, and ambiguous/corrupt lines.
		{file: filepath.Join(dir, "missing.txt"), wantErr: "asn_file"},
		{file: "{env.CADDY_GEOIP_UNSET_ASN_LIST}", wantErr: "empty after placeholder"},
		{file: asnDB, wantErr: "binary data"},
		{file: write("utf16.txt", "\xff\xfe1\x002\x002\x001\x00\r\x00\n\x00"), wantErr: "not UTF-8"},
		{file: huge, wantErr: "too large"},
		{file: write("empty.txt", "# nothing here\n"), wantErr: "not an acceptable list"},
		{file: write("zero.txt", "0\n"), wantErr: "zero.txt:1"},
		{file: write("big.txt", "4294967296\n"), wantErr: "big.txt:1"},
		{file: write("negative.txt", "-1234\n5678\n"), wantErr: "negative.txt:1: invalid asn"},
		{file: write("ips.txt", "1.2.3.0/24\n"), wantErr: "ips.txt:1: invalid asn"},
		{file: write("cf-not.txt", "(ip.geoip.asnum ne 174)\n"), wantErr: "not an acceptable list"},
		{file: write("cf-upper-not.txt", "(IP.GEOIP.ASNUM ne AS1221)\n"), wantErr: "not an acceptable list"},
		{file: write("cf-other.txt", "(ip.geoip.asnum eq 174) and (cf.threat_score gt 10)\n"), wantErr: "not an acceptable list"},
		{file: write("footer.txt", "1221\nTotal: 934\n"), wantErr: "footer.txt:2"},
		{file: write("peer-note.txt", "51167 CONTABO to AS1299\n"), wantErr: "peer-note.txt:1"},
		{file: write("unheaded-rank.txt", "1 AS4134 Chinanet\n2 AS4837 Unicom\n"), wantErr: "unheaded-rank.txt:1"},
		{file: write("unheaded-counts.csv", "1221,12\n64496,40\n"), wantErr: "unheaded-counts.csv:1"},
		{file: write("two-as.txt", "AS1221 AS64496\nAS64497\n"), wantErr: "two-as.txt:1"},
		{file: write("stray-quote.csv", "ASN,Entity\n1221,\"Telstra\n64496,Example\n"), wantErr: "stray-quote.csv:2"},
		{file: write("shifted.csv", "Entity,ASN\nLevel 3, 2000 Inc,3356\n"), wantErr: "shifted.csv:2"},
		{file: write("space-header.txt", "Org ASN\nTelstra 1221\nLevel 3 3356\n"), wantErr: "space-header.txt:3"},
		{file: write("cut.json", "{\"asn\":1221}\n{\"asn\":6449"), wantErr: "cut.json:2"},
		{file: write("bad-json.json", "[{\"asn\":1221},{\"asn\":\"x\"}]\n"), wantErr: "bad-json.json:1: invalid asn"},
		{file: write("dup-key.json", `{"asn":1221,"ASN":64496}`+"\n"), wantErr: "dup-key.json:1"},
	} {
		m := MatchGeoIPASN{DB: asnDB, ASNs: tc.inline, ASNFiles: []string{tc.file}}
		err := m.Provision(caddy.Context{})
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%s: Provision() error = %v, want one containing %q", filepath.Base(tc.file), err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", filepath.Base(tc.file), err)
			continue
		}
		if len(m.asns) != tc.wantLen {
			t.Errorf("%s: got %d asns, want %d", filepath.Base(tc.file), len(m.asns), tc.wantLen)
		}
		if err := m.Validate(); err != nil {
			t.Errorf("%s: validate: %v", filepath.Base(tc.file), err)
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
		"ASN,Entity\n,Example\n", "Entity,ASN\n\"a, b\",1221\n\"c\n", "#;ASN, Name\n1;AS1221 x\n;;\n", "[{\"asn\":1},\n{\"ASN\":\"AS2\"}]\n", "(ip.src.asnum in {1221})\n",
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
		{"3 days", now.AddDate(0, 0, -3), `{"level":"INFO","msg":"asn list loaded","path":"/etc/caddy/drop.json","asns":443,"added":440,"modified":"2026-10-29T12:00:00Z","age_days":3}`},
		{"45 days", now.AddDate(0, 0, -45), `{"level":"WARN","msg":"asn list is more than 30 days old","path":"/etc/caddy/drop.json","asns":443,"added":440,"modified":"2026-09-17T12:00:00Z","age_days":45}`},
		{"future", now.Add(time.Hour), `{"level":"WARN","msg":"asn list modified time is in the future","path":"/etc/caddy/drop.json","asns":443,"added":440,"modified":"2026-11-01T13:00:00Z"}`},
	} {
		got := logLines(t, func(l *slog.Logger) { logListAge(l, "/etc/caddy/drop.json", 443, 440, tc.modified, now) })
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

	for _, tc := range []struct {
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
			t.Errorf("%s: unexpected error: %v", tc.remoteAddr, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: MatchWithError() = %v, want %v", tc.remoteAddr, got, tc.want)
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
		{name: "GeoLite2-ASN", db: asnDB, addr: "1.128.0.1:1234", asn: 1221},
		{name: "GeoIP2-ISP", db: ispDB, addr: "1.128.0.1:1234", asn: 1221},
		{name: "GeoIP2-Enterprise", db: entDB, addr: "74.209.24.1:1234", asn: 14671},
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
