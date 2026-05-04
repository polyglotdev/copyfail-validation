// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package hostinfo

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// ParseOSRelease parses an os-release(5) file's text content into the
// (id, versionID, prettyName) tuple. Returns the values verbatim
// (with surrounding quotes stripped and standard backslash escapes
// expanded) — does NOT lowercase or otherwise canonicalize them.
//
// The input is the typical /etc/os-release shape:
//
//	NAME="Amazon Linux"
//	VERSION="2023"
//	ID="amzn"
//	VERSION_ID="2023"
//	PRETTY_NAME="Amazon Linux 2023.4.20240108"
//
// Lines that are blank, comment-only (#-prefixed), or do not match the
// KEY=VALUE shape are silently skipped — the os-release(5) spec
// permits arbitrary additional content and we MUST be tolerant of it.
// A vendor that ships a custom key in /etc/os-release must not break
// this parser.
//
// Returns empty strings for any field not present (NOT an error). The
// only error condition is an io.Reader that returns a non-EOF read
// error; the parser never returns an error for "malformed input"
// because the os-release spec has no malformed-input concept.
//
// Quote forms supported per os-release(5):
//
//   - unquoted:  ID=ubuntu
//   - double:    ID="ubuntu"
//   - single:    ID='ubuntu'
//
// Backslash escapes inside quoted values (\", \', \\, \$, \`) are
// expanded to their unescaped forms — this matches the os-release(5)
// spec, which inherits shell quoting semantics for these specific
// metacharacters. Forward slashes and other characters are NOT escaped
// because os-release values are NOT shell input.
func ParseOSRelease(r io.Reader) (id, versionID, prettyName string, err error) {
	scanner := bufio.NewScanner(r)
	// Default 64KiB scanner buffer is plenty for /etc/os-release
	// files, which are typically <2KiB. We do not raise it — doing so
	// would invite OOM if a hostile io.Reader streams an arbitrarily
	// long single "line".

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, value, ok := splitKeyValue(line)
		if !ok {
			// Malformed line (no `=`). os-release(5) is tolerant of
			// arbitrary additional content — silently skip.
			continue
		}

		switch key {
		case "ID":
			id = value
		case "VERSION_ID":
			versionID = value
		case "PRETTY_NAME":
			prettyName = value
		}
	}

	if scanErr := scanner.Err(); scanErr != nil {
		return "", "", "", fmt.Errorf("hostinfo: scan os-release: %w", scanErr)
	}

	return id, versionID, prettyName, nil
}

// splitKeyValue splits one os-release line into its key and unquoted
// value. Returns (key, value, true) on success or (_, _, false) if the
// line does not match the KEY=VALUE shape.
//
// Quote handling per os-release(5): the value may be unquoted,
// double-quoted, or single-quoted. Surrounding quotes are stripped;
// backslash escapes inside double-quoted values are expanded.
// Single-quoted values are passed through verbatim per shell semantics.
func splitKeyValue(line string) (string, string, bool) {
	idx := strings.IndexByte(line, '=')
	if idx <= 0 {
		// No `=` at all, or the line begins with `=` (no key).
		return "", "", false
	}

	key := line[:idx]
	rawValue := line[idx+1:]

	if !isValidOSReleaseKey(key) {
		return "", "", false
	}

	value, ok := unquoteOSReleaseValue(rawValue)
	if !ok {
		// Unbalanced quotes — treat as malformed and skip per the
		// tolerance contract in the package doc.
		return "", "", false
	}

	return key, value, true
}

// isValidOSReleaseKey reports whether s is a syntactically valid key
// per os-release(5): non-empty, ASCII letters/digits/underscore only,
// not starting with a digit. Reject anything else so a stray `=` in
// the middle of free-form text never gets misinterpreted as a directive.
func isValidOSReleaseKey(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// unquoteOSReleaseValue strips surrounding double or single quotes from
// an os-release value and expands backslash escapes inside double-quoted
// values. Returns (value, true) on success and ("", false) if the value
// has unbalanced quotes (e.g., one leading `"` with no trailing `"`).
//
// Per os-release(5):
//   - Unquoted values: passed through verbatim.
//   - Double-quoted values: standard shell escapes (\\, \", \$, \`) are
//     expanded; everything else is verbatim.
//   - Single-quoted values: passed through verbatim with NO escape
//     processing (matches POSIX shell single-quote semantics).
//
// The function does NOT trim trailing whitespace inside quotes because
// the trailing whitespace is part of the value when quoted; we DO trim
// trailing whitespace in the unquoted case so a vendor that wrote
// `ID=amzn   ` does not get a value with trailing spaces.
func unquoteOSReleaseValue(raw string) (string, bool) {
	if raw == "" {
		return "", true
	}

	first := raw[0]
	switch first {
	case '"':
		if len(raw) < 2 || raw[len(raw)-1] != '"' {
			return "", false
		}
		return expandDoubleQuoteEscapes(raw[1 : len(raw)-1]), true
	case '\'':
		if len(raw) < 2 || raw[len(raw)-1] != '\'' {
			return "", false
		}
		return raw[1 : len(raw)-1], true
	default:
		// Unquoted value. Trim trailing whitespace so a stray space
		// at end-of-line does not pollute the parsed value, but
		// preserve internal whitespace (which is unusual but legal
		// for unquoted os-release values).
		return strings.TrimRight(raw, " \t"), true
	}
}

// expandDoubleQuoteEscapes replaces the os-release(5) backslash escapes
// (\\, \", \$, \`) inside a double-quoted value with their unescaped
// forms. Any other backslash sequence is preserved verbatim — the
// os-release spec does not define escape semantics for arbitrary
// characters, and silently dropping the backslash would change the
// meaning of strings that legitimately contain `\n` or `\t` literals.
func expandDoubleQuoteEscapes(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		next := s[i+1]
		switch next {
		case '"', '\'', '\\', '$', '`':
			b.WriteByte(next)
			i++
		default:
			// Unknown escape: preserve the backslash and the
			// following byte so we never silently corrupt a value
			// that happens to contain `\n` or `\t` as literal text.
			b.WriteByte(c)
		}
	}
	return b.String()
}
