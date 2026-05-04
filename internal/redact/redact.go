// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package redact removes secret-like substrings from text destined for
// audit reports. The single regex is tuned for high precision over high
// recall: false positives in operator-facing output would be more
// disruptive than the rare missed redaction.
package redact

import "regexp"

// RedactionPattern matches `keyword=VALUE` or `keyword: VALUE` shapes
// where keyword is one of the listed secret labels (case-insensitive).
// The keyword is preserved in the output; the value is replaced with
// ***REDACTED***.
const RedactionPattern = `(?i)(password|passwd|token|secret|bearer|api[_-]?key|aws_(?:access|secret)_key_id?|authorization)\s*[:=]\s*\S+`

// Replacement is the substring written in place of the matched value.
const Replacement = "***REDACTED***"

var pattern = regexp.MustCompile(RedactionPattern)

// Redact returns s with secret-like substrings replaced. Safe to call on
// large strings; the regex is anchored so worst-case complexity is
// O(len(s)).
func Redact(s string) string {
	return pattern.ReplaceAllStringFunc(s, func(match string) string {
		// Find the keyword (everything up to the first separator).
		for i, r := range match {
			if r == '=' || r == ':' {
				return match[:i] + "=" + Replacement
			}
		}
		return Replacement
	})
}
