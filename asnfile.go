// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

var (
	jsonASN  = regexp.MustCompile(`(?i)"asn"\s*:\s*(\d+)`)
	colNames = []string{"asn", "as", "as_number", "as-number", "asnumber"}
	cfWords  = []string{"ip.geoip.asnum", "in", "eq", "or", "and"}                            // ne and not would invert the list
	isSep    = func(r rune) bool { return strings.ContainsRune(" \t,;|", r) }                 // | for Markdown tables
	markedAt = func(r []string) int { return slices.IndexFunc(r[:min(2, len(r))], isMarked) } // first, or after a rank
)

// readASNFile adds the autonomous system numbers in the file at path to set,
// keyed by their decimal form, and logs the list's age (see logListAge).
func readASNFile(logger *slog.Logger, path string, set map[string]struct{}) error {
	if path = caddy.NewReplacer().ReplaceAll(path, ""); path == "" {
		return fmt.Errorf("asn_file: path is empty after placeholder replacement")
	}
	info, err := os.Stat(path) // before Open, which blocks on a pipe with no writer
	if err != nil {
		return fmt.Errorf("asn_file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return fmt.Errorf("asn_file: %s: not a regular file, or too large (16 MiB at most)", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("asn_file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 16<<20+1))
	if err != nil {
		return fmt.Errorf("asn_file: %s: %w", path, err)
	}
	if len(data) > 16<<20 || slices.Contains(data, 0) {
		return fmt.Errorf("asn_file: %s: binary data, UTF-16, or too large (16 MiB at most)", path)
	}
	asns, err := parseASNList(path, strings.TrimPrefix(string(data), "\uFEFF"))
	if err != nil {
		return err
	}
	before := len(set)
	for _, n := range asns {
		set[strconv.FormatUint(uint64(n), 10)] = struct{}{}
	}
	logListAge(logger, path, len(set)-before, info.ModTime(), time.Now())
	return nil
}

// parseASNList takes the AS numbers a list marks by a JSON "asn" key, an
// ip.geoip.asnum rule, an AS prefix, a header, or position. Else it refuses.
func parseASNList(path, text string) ([]uint32, error) {
	refuse := fmt.Errorf("asn_file: %s: not an acceptable list, see README", path)
	fail := func(line int, tok string) error {
		return fmt.Errorf("asn_file: %s:%d: invalid asn %.60q", path, line, tok)
	}
	var asns []uint32
	add := func(line int, toks ...string) error {
		for _, t := range toks {
			n, ok := parseASN(t)
			if !ok {
				return fail(line, t)
			}
			asns = append(asns, uint32(n))
		}
		return nil
	}
	lines := strings.Split(text, "\n")
	if t := strings.TrimLeft(text, " \t\r\n"); t != "" && (t[0] == '{' || t[0] == '[') { // JSON, lines or array
		for i, l := range lines {
			if m := jsonASN.FindStringSubmatch(l); m != nil {
				if err := add(i+1, m[1]); err != nil {
					return nil, err
				}
			}
		}
	} else {
		var rows [][]string
		var at []int
		for i, l := range lines {
			if l = strings.TrimSpace(l); !strings.HasPrefix(l, ";") {
				l, _, _ = strings.Cut(l, "#")
				l, _, _ = strings.Cut(l, "//")
				toks := strings.FieldsFunc(l, isSep)
				for k, t := range toks {
					toks[k] = strings.Trim(t, `"'(){}[]-`)
				}
				if toks = slices.DeleteFunc(toks, func(t string) bool { return t == "" }); len(toks) > 0 {
					rows, at = append(rows, toks), append(at, i+1)
				}
			}
		}
		col := -1
		if len(rows) > 0 && named(rows[0]) >= 0 && !slices.ContainsFunc(rows[0], isASN) {
			col, rows, at = named(rows[0]), rows[1:], at[1:] // a header naming the column
		}
		marked := 0
		for _, r := range rows {
			if markedAt(r) >= 0 {
				marked++
			}
		}
		for k, r := range rows {
			nums := slices.DeleteFunc(slices.Clone(r), func(t string) bool { return !isASN(t) })
			switch {
			case slices.Contains(r, cfWords[0]): // a Cloudflare rule: keywords and AS numbers only
				if slices.ContainsFunc(r, func(t string) bool { return !isASN(t) && !slices.Contains(cfWords, t) }) {
					return nil, refuse
				}
				r = nums
			case col >= 0:
				r = []string{cell(r, col)}
			case len(nums) == len(r) && len(r) > 1 && len(rows) > 1: // columns of numbers, unless one number repeated
				if slices.ContainsFunc(r, func(t string) bool { return t != r[0] }) {
					return nil, refuse
				}
				r = r[:1]
			case len(nums) == len(r): // a line of numbers on its own is a list
			case marked >= len(rows)-len(rows)/100: // AS prefixes mark the number
				r = []string{cell(r, markedAt(r))}
			default:
				r = r[:1]
			}
			if err := add(at[k], r...); err != nil {
				return nil, err
			}
		}
	}
	if len(asns) == 0 {
		return nil, refuse
	}
	return asns, nil
}

func named(h []string) int {
	return slices.IndexFunc(h, func(t string) bool { return slices.Contains(colNames, strings.ToLower(t)) })
}

func cell(r []string, j int) string {
	return strings.Join(r[max(min(j, len(r)), 0):max(min(j+1, len(r)), 0)], "")
}
func isASN(t string) bool    { _, ok := parseASN(t); return ok }
func isMarked(t string) bool { return hasAS(t) && isASN(t) }
func hasAS(s string) bool    { return len(s) > 2 && strings.EqualFold(s[:2], "AS") }

// parseASN parses an asplain AS number (RFC 5396), 1 to 4294967295, AS prefix or not.
func parseASN(s string) (uint64, bool) {
	if hasAS(s) {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return n, err == nil && n != 0
}
