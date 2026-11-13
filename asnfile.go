// SPDX-License-Identifier: Apache-2.0

package caddygeoip

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
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

const maxListBytes = 8 << 20

var (
	commentPattern  = regexp.MustCompile(`^;.*|#.*|(^|[^:])//.*`) // a leading ;, a #, or a // that is not in a URL
	asnColumnNames  = []string{"asn", "as", "as_number", "as-number", "asnumber"}
	cloudflareWords = []string{"ip.geoip.asnum", "ip.src.asnum", "in", "eq", "or", "and"} // ne and not would invert the list
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
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("asn_file: %w", err)
	}
	defer file.Close()
	if info, err = file.Stat(); err != nil || !info.Mode().IsRegular() { // the file that opened, not the path
		return fmt.Errorf("asn_file: %s: not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxListBytes+1))
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
	for _, asn := range asns {
		set[strconv.FormatUint(uint64(asn), 10)] = struct{}{}
	}
	logListAge(logger, path, len(asns), len(set)-before, info.ModTime(), time.Now())
	return nil
}

// parseASNList takes the AS numbers a list names explicitly: a JSON record's
// asn member, a Cloudflare expression's numbers, the column a header names,
// or a token marked AS. Failing those, a line may lead with one number, or a
// one-line file hold many. Anything else refuses, by line.
func parseASNList(path, text string) ([]uint32, error) {
	p := &parser{path: path}
	parse := p.parseText
	if start := strings.TrimLeft(text, " \t\r\n"); start != "" && (start[0] == '{' || start[0] == '[') {
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

func (p *parser) fail(line int, text string) error {
	return fmt.Errorf("asn_file: %s:%d: invalid asn %.60q", p.path, line, text)
}

func (p *parser) add(line int, tokens ...string) error {
	for _, token := range tokens {
		asn, ok := parseASN(token)
		if !ok {
			return p.fail(line, token)
		}
		p.asns = append(p.asns, asn)
	}
	return nil
}

// parseJSON decodes the values in text, one document or one per line. An
// object with an asn member is a record and yields it. One without, and
// an array, is a container, and what it holds is read the same way. A list
// that opens the text is read one record at a time, so an error names the
// record's line.
func (p *parser) parseJSON(text string) error {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	inList := strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "[")
	if inList {
		_, _ = decoder.Token() // the [ that opens the list, seen on the line above
	}
	for line, offset := 1, 0; ; {
		if inList && !decoder.More() {
			if _, err := decoder.Token(); err != nil { // the ] that closes it
				return fmt.Errorf("asn_file: %s:%d: list is not closed: %w", p.path, line, err)
			}
			inList = false
		}
		next := len(text) - len(strings.TrimLeft(text[decoder.InputOffset():], " \t\r\n,"))
		line, offset = line+strings.Count(text[offset:next], "\n"), next
		var value any
		if err := decoder.Decode(&value); err == io.EOF && !inList {
			return nil
		} else if err != nil {
			return fmt.Errorf("asn_file: %s:%d: %w", p.path, line, err)
		}
		if err := p.record(line, value); err != nil {
			return err
		}
	}
}

// record adds the asn member of value, or of each record inside value. The
// member goes by its name in any case and holds a number or a string, once.
func (p *parser) record(line int, value any) error {
	switch value := value.(type) {
	case map[string]any:
		var asn any
		var found bool
		for key, member := range value {
			if strings.EqualFold(key, "asn") {
				if found {
					return fmt.Errorf("asn_file: %s:%d: asn is in the record twice", p.path, line)
				}
				asn, found = member, true
			}
		}
		if found {
			switch asn.(type) {
			case json.Number, string:
				return p.add(line, fmt.Sprint(asn))
			}
			return fmt.Errorf("asn_file: %s:%d: asn is not a number or a string", p.path, line)
		}
		for _, key := range slices.Sorted(maps.Keys(value)) { // sorted, so the same error is found each time
			if err := p.record(line, value[key]); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range value {
			if err := p.record(line, item); err != nil {
				return err
			}
		}
	}
	return nil
}

// parseText reads a Cloudflare expression, a headed table, or lines.
func (p *parser) parseText(text string) error {
	raw := strings.Split(text, "\n")
	lines := make([]string, len(raw))
	var rows []int // the lines that hold something once comments are cut
	for i, line := range raw {
		if lines[i] = strings.TrimSpace(line); len(rows) > 0 || !isHashHeader(lines[i]) {
			lines[i] = stripComment(lines[i])
		}
		if hasContent(lines[i]) {
			rows = append(rows, i)
		}
	}
	if len(rows) == 0 {
		return p.refuse()
	}
	if slices.ContainsFunc(rows, func(i int) bool { return strings.Contains(strings.ToLower(lines[i]), ".asnum") }) {
		for _, i := range rows { // keywords and numbers only; ne and not would invert the list
			for _, token := range tokenize(lines[i]) {
				if isASN(token) {
					_ = p.add(i+1, token) // token is an ASN, so add cannot fail
				} else if !slices.Contains(cloudflareWords, strings.ToLower(token)) {
					return p.refuse()
				}
			}
		}
		return nil
	}
	if header := tokenize(lines[rows[0]]); asnColumn(header) >= 0 && !slices.ContainsFunc(header, isASN) {
		delimiter := ' '
		if i := strings.IndexAny(lines[rows[0]], ",;\t|"); i >= 0 {
			delimiter = rune(lines[rows[0]][i])
		}
		return p.parseTable(raw, rows[0], delimiter)
	}
	for _, i := range rows {
		asns, ok := pick(tokenize(lines[i]), len(rows) == 1) // one line is no row of columns, and may hold many
		if !ok {
			return p.fail(i+1, lines[i])
		}
		if err := p.add(i+1, asns...); err != nil {
			return err
		}
	}
	return nil
}

// isHashHeader reports whether line is a header whose first column is named
// #, as a rank is (#;ASN, Organization name;Country), and so not a comment:
// the word after the delimiter names the ASN column, and no number follows.
// A bare "as" is a word, as in "#, as of today", so it does not.
func isHashHeader(line string) bool {
	if len(line) < 2 || line[0] != '#' || !strings.ContainsRune(",;\t|", rune(line[1])) {
		return false
	}
	words := tokenize(stripComment(line[2:]))
	return len(words) > 0 && !strings.EqualFold(words[0], "as") && asnColumn(words[:1]) == 0 && !slices.ContainsFunc(words, isASN)
}

// parseTable reads the cell a header names from each row under it, header
// being that header's line. The reader is given one line at a time, so a quote
// left open cannot take the rows after it. A line that is not CSV is cells
// joined as they are, as a publisher who quotes nothing writes them, unless its
// quotes are odd in number: that may be a cell that runs on to the next line.
func (p *parser) parseTable(raw []string, header int, delimiter rune) error {
	var source strings.Reader
	reader := csv.NewReader(&source) // which buffers it, and reads on after an EOF
	reader.Comma, reader.FieldsPerRecord, reader.TrimLeadingSpace, reader.ReuseRecord = delimiter, -1, delimiter != '\t', true
	indent := " \t"
	if delimiter == '\t' {
		indent = " " // a tab that leads a tab-separated row is an empty cell
	}
	for column, width, i := -1, 0, header; i < len(raw); i++ {
		row := strings.TrimRight(strings.TrimLeft(raw[i], indent), " \r")
		if i == header && !isHashHeader(row) {
			row = strings.TrimRight(stripComment(row), " ") // the header as parseText found it
		} else if i > header && (row == "" || row[0] == '#' || strings.HasPrefix(row, "//") || row[0] == ';' && delimiter != ';') {
			continue // a comment, which a ; is only where it does not split the cells
		}
		source.Reset(row)
		cells, err := reader.Read()
		if err != nil && strings.Count(row, `"`)%2 == 0 {
			cells, err = strings.Split(row, string(delimiter)), nil
		}
		switch {
		case err != nil:
			return p.fail(i+1, row)
		case i == header:
			if column, width = asnColumn(cells), len(cells); column < 0 {
				return p.refuse()
			}
		case !slices.ContainsFunc(cells, hasContent): // a divider
		case column > 0 && len(cells) != width: // a delimiter in a cell before the ASN's would shift it
			return p.fail(i+1, row)
		default:
			asns, ok := pick(tokenize(stripComment(cells[column])), false)
			if !ok {
				return p.fail(i+1, row)
			}
			if err := p.add(i+1, asns...); err != nil {
				return err
			}
		}
	}
	return nil
}

// pick is the ASNs among the tokens of a line or cell: all of them in a
// one-line file of nothing else, else one. A number marked AS that leads is
// the ASN when words follow it, its name, or every other token is the same
// number. Words lead only one marked number. A bare number leads, and is the
// only number. Anything else is a rank, a count, or a second ASN, and is
// refused.
func pick(tokens []string, many bool) ([]string, bool) {
	if len(tokens) > 1 && strings.EqualFold(tokens[0], "AS") {
		tokens = tokens[1:] // AS 1221
	}
	if len(tokens) == 0 {
		return nil, false
	}
	asns := slices.DeleteFunc(slices.Clone(tokens), func(token string) bool { return !isASN(token) })
	allSame := !slices.ContainsFunc(asns, func(asn string) bool { return !sameASN(asn, asns[0]) })
	marked := slices.IndexFunc(tokens, isMarked) // where the first number marked AS is, or -1
	switch {
	case many && len(asns) == len(tokens):
		return tokens, true
	case marked == 0: // AS201011 AS33891 Netzbetrieb GmbH, AS42772 AS42772, but not AS1 AS2
		return tokens[:1], allSame || len(asns) < len(tokens)
	case marked > 0 && !isASN(tokens[0]): // Telstra AS1221, Level 3 AS3356, but not Contabo to AS1299 AS51167
		others := slices.DeleteFunc(asns, func(asn string) bool { return !isMarked(asn) })
		return tokens[marked : marked+1], !slices.ContainsFunc(others, func(asn string) bool { return !sameASN(asn, tokens[marked]) })
	}
	return tokens[:1], marked < 0 && len(asns) == 1 && isASN(tokens[0]) // 1221 Telstra, but not 1 AS4134 or Total: 934
}

// tokenize splits a line at every separator, pipes included for Markdown.
func tokenize(line string) []string {
	tokens := strings.FieldsFunc(line, func(r rune) bool { return strings.ContainsRune(" \t,;|", r) })
	for i, token := range tokens {
		tokens[i] = strings.Trim(token, `"'(){}[]`)
	}
	return slices.DeleteFunc(tokens, func(token string) bool { return token == "" })
}

// asnColumn is the index of the cell whose words name the ASN, or -1.
func asnColumn(cells []string) int {
	return slices.IndexFunc(cells, func(cell string) bool {
		return slices.ContainsFunc(tokenize(cell), func(word string) bool { return slices.Contains(asnColumnNames, strings.ToLower(word)) })
	})
}

// hasContent reports whether text holds a letter or digit: a divider does not.
func hasContent(text string) bool {
	return strings.ContainsFunc(text, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) })
}

// stripComment cuts a comment; $1 keeps the character ahead of a //.
func stripComment(text string) string {
	if !strings.ContainsAny(text, "#;/") {
		return text
	}
	return commentPattern.ReplaceAllString(text, "$1")
}
func isASN(token string) bool    { _, ok := parseASN(token); return ok }
func isMarked(token string) bool { return hasAS(token) && isASN(token) }
func hasAS(token string) bool    { return len(token) > 2 && strings.EqualFold(token[:2], "AS") }
func sameASN(a, b string) bool   { x, _ := parseASN(a); y, _ := parseASN(b); return x == y }

// parseASN parses an asplain AS number (RFC 5396), 1 to 4294967295, AS prefix or not.
func parseASN(token string) (uint32, bool) {
	if hasAS(token) {
		token = token[2:]
	}
	if token == "" || strings.ContainsFunc(token, func(r rune) bool { return r < '0' || r > '9' }) {
		return 0, false // not digits, so no error for strconv to build
	}
	number, err := strconv.ParseUint(token, 10, 32)
	return uint32(number), err == nil && number != 0
}
