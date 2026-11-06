// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"encoding/json"
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

const maxListBytes = 16 << 20

var (
	jsonASN  = regexp.MustCompile(`(?i)"asn"\s*:\s*"?([^",\s}\]]*)`)
	comment  = regexp.MustCompile(`^;.*|#.*|(^|[^:])//.*`)
	colNames = []string{"asn", "as", "as_number", "as-number", "asnumber"}
	cfWords  = []string{"ip.geoip.asnum", "ip.src.asnum", "in", "eq", "or", "and"} // ne and not would invert the list
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
	if !info.Mode().IsRegular() || info.Size() > maxListBytes {
		return fmt.Errorf("asn_file: %s: not a regular file, or too large (%d MiB at most)", path, maxListBytes>>20)
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("asn_file: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxListBytes+1))
	if err != nil {
		return fmt.Errorf("asn_file: %w", err)
	}
	if len(data) > maxListBytes || slices.Contains(data, 0) {
		return fmt.Errorf("asn_file: %s: binary data, UTF-16, or too large (%d MiB at most)", path, maxListBytes>>20)
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
// ip.geoip.asnum rule, a header, an AS prefix after a rank, or position.
// Anything ambiguous, such as two bare numbers leading most rows, refuses.
func parseASNList(path, text string) ([]uint32, error) {
	p := &parser{path: path}
	parse := p.parseText
	if t := strings.TrimLeft(text, " \t\r\n"); t != "" && (t[0] == '{' || t[0] == '[') {
		parse = p.parseJSON
	}
	if err := parse(text); err != nil {
		return nil, err
	}
	if len(p.asns) == 0 {
		return nil, p.refuse()
	}
	return p.asns, nil
}

// parser collects the numbers one list yields and names the list in errors.
type parser struct {
	path string
	asns []uint32
}

func (p *parser) refuse() error {
	return fmt.Errorf("asn_file: %s: not an acceptable list, see README", p.path)
}

func (p *parser) fail(line int, tok string) error {
	return fmt.Errorf("asn_file: %s:%d: invalid asn %.60q", p.path, line, tok)
}

func (p *parser) add(line int, toks ...string) error {
	for _, t := range toks {
		n, ok := parseASN(t)
		if !ok {
			return p.fail(line, t)
		}
		p.asns = append(p.asns, uint32(n))
	}
	return nil
}

// parseJSON reads one document, or one per line, by pattern rather than by
// decoding: the one key wanted sits in an object, an array, or a line alike.
func (p *parser) parseJSON(text string) error {
	whole := json.Valid([]byte(text))
	for i, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); !whole && l != "" && !json.Valid([]byte(l)) {
			return p.fail(i+1, l)
		}
		for _, m := range jsonASN.FindAllStringSubmatch(l, -1) {
			if err := p.add(i+1, m[1]); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseText tokenizes every line, decides once which column holds the
// number, then reads each row by that decision.
func (p *parser) parseText(text string) error {
	var rows [][]string
	var at []int
	for i, l := range strings.Split(text, "\n") {
		toks := strings.FieldsFunc(comment.ReplaceAllString(strings.TrimSpace(l), "$1"), isSep)
		for k, t := range toks {
			toks[k] = strings.Trim(t, `"'(){}[]`)
		}
		toks = slices.DeleteFunc(toks, func(t string) bool { return t == "" })
		if slices.ContainsFunc(toks, func(t string) bool { return strings.Trim(t, "-:") != "" }) { // not a Markdown divider
			rows, at = append(rows, toks), append(at, i+1)
		}
	}
	col, headed, second, pairs := 0, false, 0, 0
	if len(rows) > 0 && named(rows[0]) >= 0 && !slices.ContainsFunc(rows[0], isASN) {
		col, headed, rows, at = named(rows[0]), true, rows[1:], at[1:] // a header naming the column
	}
	rule := slices.ContainsFunc(rows, func(r []string) bool { return slices.ContainsFunc(r, isCFField) })
	for _, r := range rows {
		switch {
		case len(r) > 1 && !isMarked(r[0]) && isMarked(r[1]):
			second++ // an AS prefix after a rank
		case len(r) > 1 && isBare(r[0]) && isBare(r[1]):
			pairs++ // two bare numbers: a rank or a count, which is which?
		}
	}
	if !headed && second > len(rows)/2 {
		col = 1
	} else if !headed && pairs > len(rows)/2 && len(rows) > 1 {
		return p.refuse()
	}
	for k, r := range rows {
		allNums := !slices.ContainsFunc(r, func(t string) bool { return !isASN(t) })
		switch {
		case rule: // a Cloudflare rule, on one line or several: keywords and AS numbers only
			if slices.ContainsFunc(r, func(t string) bool { return !isCFWord(t) }) {
				return p.refuse()
			}
			r = slices.DeleteFunc(r, func(t string) bool { return !isASN(t) })
		case !headed && allNums && len(rows) == 1: // a line of numbers on its own is a list
		case !headed && allNums: // columns of numbers, unless one number repeated
			if slices.ContainsFunc(r, func(t string) bool { return t != r[0] }) {
				return p.refuse()
			}
			r = r[:1]
		default:
			r = []string{cell(r, col)}
		}
		if err := p.add(at[k], r...); err != nil {
			return err
		}
	}
	return nil
}

// named is the index of the column a header names as the ASN, or -1.
func named(h []string) int {
	return slices.IndexFunc(h, func(t string) bool { return slices.Contains(colNames, strings.ToLower(t)) })
}

// cell is r[j], or "" when r has no such column.
func cell(r []string, j int) string { return strings.Join(r[min(j, len(r)):min(j+1, len(r))], "") }

func isSep(r rune) bool       { return strings.ContainsRune(" \t,;|", r) } // | for Markdown tables
func isASN(t string) bool     { _, ok := parseASN(t); return ok }
func isBare(t string) bool    { return !hasAS(t) && isASN(t) }
func isMarked(t string) bool  { return hasAS(t) && isASN(t) }
func isCFField(t string) bool { return strings.HasSuffix(strings.ToLower(t), ".asnum") }
func isCFWord(t string) bool  { return isASN(t) || slices.Contains(cfWords, strings.ToLower(t)) }
func hasAS(s string) bool     { return len(s) > 2 && strings.EqualFold(s[:2], "AS") }

// parseASN parses an asplain AS number (RFC 5396), 1 to 4294967295, AS prefix or not.
func parseASN(s string) (uint64, bool) {
	if hasAS(s) {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return n, err == nil && n != 0
}
