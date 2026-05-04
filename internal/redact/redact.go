// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

// Package redact removes secret-like substrings from text destined for
// audit reports.
//
// The single regex is tuned for high precision (avoid false positives
// in operator-facing output) AND high recall on the value side (consume
// the entire rest of the line rather than the first whitespace-bounded
// token, so HTTP-header-style values like "Authorization: Bearer <jwt>"
// are fully redacted, not just the scheme keyword).
//
// Trade-off: redaction is line-bounded (the . metacharacter does not
// match newlines in Go's regexp). This means a `password=hunter2`
// followed on the same line by `was wrong` will redact the entire
// `hunter2 was wrong` substring — strictly more conservative than
// necessary, but never under-redacts. For an audit log, over-redaction
// is a non-issue; under-redaction is a vulnerability.
package redact

import "regexp"

// RedactionPattern matches `keyword=VALUE` or `keyword: VALUE` shapes
// where keyword is one of the listed secret labels (case-insensitive)
// and VALUE is everything from the separator to the end of the line.
//
// The pattern is line-bounded: `.` in Go regexp does not match newline
// without the `(?s)` flag, which we deliberately omit so a multi-line
// Evidence string redacts each affected line independently.
//
// AWS keyword coverage (the pattern was tightened on 2026-05-04 after a
// regression test caught the original spec regex missing the canonical
// AWS_SECRET_ACCESS_KEY env var name):
//   - aws_access_key, aws_access_key_id      (the access-key env vars)
//   - aws_secret_key, aws_secret_key_id      (less common but seen in legacy configs)
//   - aws_secret_access_key                  (the canonical secret env var)
//   - aws_session_token                      (the temporary-credential env var)
const RedactionPattern = `(?i)(password|passwd|token|secret|bearer|api[_-]?key|aws_(?:access_key(?:_id)?|secret_(?:access_)?key(?:_id)?|session_token)|authorization)\s*[:=]\s*.+`

// Replacement is the substring written in place of the matched VALUE.
// The keyword from the matched group is preserved (e.g.,
// `aws_secret_access_key=...` becomes `aws_secret_access_key=***REDACTED***`)
// so operators reading the redacted output can still see WHICH secret
// was found, just not its value.
const Replacement = "***REDACTED***"

var pattern = regexp.MustCompile(RedactionPattern)

// Redact returns s with secret-like substrings replaced by the
// Replacement marker. Safe to call on large strings; the regex has
// no nested quantifiers and runs in linear time on the input.
//
// The original keyword is preserved in the output. For an input like
// "Authorization: Bearer eyJ...", the output is "Authorization=***REDACTED***".
// For "password=hunter2", the output is "password=***REDACTED***".
//
// Strings that mention secret keywords without an actual value (e.g.,
// "Reset your password from the portal", "API key documentation") are
// returned unchanged — the regex requires the `:` or `=` separator.
func Redact(s string) string {
	return pattern.ReplaceAllStringFunc(s, func(match string) string {
		// Find the keyword: everything up to the first separator.
		for i, r := range match {
			if r == '=' || r == ':' {
				return match[:i] + "=" + Replacement
			}
		}
		// Defensive fallback — the regex requires a separator, so this
		// branch is unreachable in practice. Returning the marker on its
		// own is the safest behavior if the regex is ever changed and
		// this assumption breaks.
		return Replacement
	})
}
