// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"encoding/csv"
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
	"unicode"
	"unicode/utf8"

	"github.com/caddyserver/caddy/v2"
)

const maxListBytes = 16 << 20

var (
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
	if len(data) > maxListBytes || !utf8.Valid(data) || slices.Contains(data, 0) {
		return fmt.Errorf("asn_file: %s: binary data, not UTF-8, or too large (%d MiB at most)", path, maxListBytes>>20)
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

// parseASNList takes the AS numbers a list names explicitly: a JSON record's
// asn member, a Cloudflare expression's numbers, the column a header names,
// or a token marked AS. Failing those, a line may hold one number, or a
// one-line file many. Anything else refuses, by line.
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

// parseJSON decodes the values in text, one document or one per line. An
// object with an asn member is a record and yields it. One without, and
// an array, is a container, and what it holds is read the same way.
func (p *parser) parseJSON(text string) error {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	for line, pos := 1, 0; ; {
		var v any
		if err := dec.Decode(&v); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("asn_file: %s:%d: %w", p.path, line, err)
		}
		if err := p.record(line, v); err != nil {
			return err
		}
		next := len(text) - len(strings.TrimLeft(text[dec.InputOffset():], " \t\r\n"))
		line, pos = line+strings.Count(text[pos:next], "\n"), next
	}
}

// record adds the asn member of v, or of each record inside v.
func (p *parser) record(line int, v any) error {
	switch v := v.(type) {
	case map[string]any:
		for k, m := range v {
			if strings.EqualFold(k, "asn") {
				return p.add(line, fmt.Sprint(m))
			}
		}
		for _, m := range v {
			if err := p.record(line, m); err != nil {
				return err
			}
		}
	case []any:
		for _, m := range v {
			if err := p.record(line, m); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseText reads a Cloudflare expression, a headed table, or lines.
func (p *parser) parseText(text string) error {
	lines := strings.Split(text, "\n")
	var rows []int // the lines that hold something once comments are cut
	for i, l := range lines {
		if lines[i] = comment.ReplaceAllString(strings.TrimSpace(l), "$1"); hasContent(lines[i]) {
			rows = append(rows, i)
		}
	}
	if len(rows) == 0 {
		return p.refuse()
	}
	if slices.ContainsFunc(rows, func(i int) bool { return strings.Contains(strings.ToLower(lines[i]), ".asnum") }) {
		for _, i := range rows { // keywords and numbers only; ne and not would invert the list
			for _, t := range tokens(lines[i]) {
				if isASN(t) {
					_ = p.add(i+1, t)
				} else if !slices.Contains(cfWords, strings.ToLower(t)) {
					return p.refuse()
				}
			}
		}
		return nil
	}
	if head := tokens(lines[rows[0]]); named(head) >= 0 && !slices.ContainsFunc(head, isASN) {
		delim := ' '
		if i := strings.IndexAny(lines[rows[0]], ",;\t|"); i >= 0 {
			delim = rune(lines[rows[0]][i])
		}
		return p.parseCSV(text, delim, rows[0]+1)
	}
	for _, i := range rows {
		asns, ok := pick(tokens(lines[i]), len(rows) == 1)
		if !ok {
			return p.fail(i+1, lines[i])
		}
		if err := p.add(i+1, asns...); err != nil {
			return err
		}
	}
	return nil
}

// parseCSV reads the cell a header names from each row from line hdr on.
// CSV quoting lets a cell hold the delimiter, so the text is read raw and
// comments are cut from the one cell; a row that holds nothing is a divider.
func (p *parser) parseCSV(text string, delim rune, hdr int) error {
	r := csv.NewReader(strings.NewReader(text))
	r.Comma, r.LazyQuotes, r.FieldsPerRecord, r.ReuseRecord, r.TrimLeadingSpace = delim, true, -1, true, true
	for col := -1; ; {
		rec, err := r.Read()
		line, _ := r.FieldPos(0)
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return fmt.Errorf("asn_file: %s:%d: %w", p.path, line, err)
		case line < hdr: // a comment
		case col < 0:
			if col = named(rec); delim == ' ' && col > 0 {
				r.FieldsPerRecord = len(rec) // unquoted spaces before the cell would shift it
			}
		case slices.ContainsFunc(rec, hasContent):
			cell := ""
			if col < len(rec) {
				cell = comment.ReplaceAllString(rec[col], "$1")
			}
			asns, ok := pick(tokens(cell), false)
			if !ok {
				return p.fail(line, strings.Join(rec, string(delim)))
			}
			if err := p.add(line, asns...); err != nil {
				return err
			}
		}
	}
}

// pick is the ASNs among the tokens of a line or cell: all of them when a
// one-line file holds only numbers, else the first marked AS, else the only
// bare number. Two bare numbers are a rank or a count beside an ASN, and
// nothing says which.
func pick(toks []string, oneLine bool) ([]string, bool) {
	if oneLine && len(toks) > 0 && !slices.ContainsFunc(toks, func(t string) bool { return !isASN(t) }) {
		return toks, true
	}
	if i := slices.IndexFunc(toks, isMarked); i >= 0 {
		return toks[i : i+1], true
	}
	bare, n := -1, 0
	for i, t := range toks {
		if isASN(t) {
			bare, n = i, n+1
		}
	}
	return toks[max(bare, 0) : bare+1], n == 1
}

// tokens splits a line at every separator, pipes included for Markdown.
func tokens(l string) []string {
	toks := strings.FieldsFunc(l, func(r rune) bool { return strings.ContainsRune(" \t,;|", r) })
	for k, t := range toks {
		toks[k] = strings.Trim(t, `"'(){}[]`)
	}
	return slices.DeleteFunc(toks, func(t string) bool { return t == "" })
}

// named is the index of the column whose words name the ASN, or -1.
func named(h []string) int {
	return slices.IndexFunc(h, func(c string) bool {
		return slices.ContainsFunc(strings.Fields(c), func(t string) bool { return slices.Contains(colNames, strings.ToLower(t)) })
	})
}

// hasContent reports whether s holds a letter or digit: a divider does not.
func hasContent(s string) bool {
	return strings.ContainsFunc(s, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) })
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
