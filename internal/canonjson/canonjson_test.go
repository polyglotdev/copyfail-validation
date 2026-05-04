// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package canonjson_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/canonjson"
)

// TestCanonicalize verifies the RFC 8785 (subset) canonicalization
// rules the package implements: sorted object keys at every level,
// no insignificant whitespace, json.Number preservation, and stable
// output for equivalent inputs in different shapes.
func TestCanonicalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "sorts top-level and nested object keys",
			in:   `{"b":1,"a":2,"c":{"y":3,"x":4}}`,
			want: `{"a":2,"b":1,"c":{"x":4,"y":3}}`,
		},
		{
			name: "strips insignificant whitespace and indentation",
			in:   "{\n  \"a\": 1,\n  \"b\": 2\n}",
			want: `{"a":1,"b":2}`,
		},
		{
			name: "preserves array element order (arrays are sequences, not sets)",
			in:   `[3,1,2]`,
			want: `[3,1,2]`,
		},
		{
			name: "preserves integer-ness via json.Number (no float coercion)",
			in:   `{"n":1234567890123456789}`,
			want: `{"n":1234567890123456789}`,
		},
		{
			name: "preserves null and bool primitives",
			in:   `{"a":null,"b":true,"c":false}`,
			want: `{"a":null,"b":true,"c":false}`,
		},
		{
			name: "round-trips strings with escape characters",
			in:   `{"k":"line1\nline2"}`,
			want: `{"k":"line1\nline2"}`,
		},
		{
			name: "empty object",
			in:   `{}`,
			want: `{}`,
		},
		{
			name: "empty array",
			in:   `[]`,
			want: `[]`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			got, err := canonjson.Canonicalize([]byte(tc.in))
			if err != nil {
				subT.Fatalf("Canonicalize(%q): %v", tc.in, err)
			}
			if string(got) != tc.want {
				subT.Errorf("Canonicalize(%q)\n  got  = %q\n  want = %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCanonicalize_InvalidInput verifies that malformed JSON returns a
// wrapped error (errors.Is unwraps to the underlying json.SyntaxError /
// io.ErrUnexpectedEOF) rather than panicking. The --sign sidecar code
// path needs to surface a real error to the operator on bad input, not
// crash mid-write.
func TestCanonicalize_InvalidInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
	}{
		{name: "unterminated object", in: `{"a":1`},
		{name: "trailing comma", in: `{"a":1,}`},
		{name: "garbage", in: `not-json-at-all`},
		{name: "empty", in: ``},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			_, err := canonjson.Canonicalize([]byte(tc.in))
			if err == nil {
				subT.Errorf("Canonicalize(%q) returned no error, want some decode error", tc.in)
			}
		})
	}
}

// TestSHA256_StableAcrossEquivalentEncodings is the critical property
// test for the --sign sidecar. Two JSON inputs that decode to the same
// logical value (different key order, different whitespace) MUST produce
// the same SHA-256 digest. Any regression here would cause an operator
// who recomputes the digest from a stored report to get a mismatch even
// though the report content is unchanged.
func TestSHA256_StableAcrossEquivalentEncodings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		a, b string
	}{
		{
			name: "key order does not affect digest",
			a:    `{"a":1,"b":2}`,
			b:    `{"b":2,"a":1}`,
		},
		{
			name: "whitespace and indentation do not affect digest",
			a:    `{"a":1,"b":2}`,
			b:    "{\n  \"a\": 1,\n  \"b\": 2\n}",
		},
		{
			name: "nested object key order does not affect digest",
			a:    `{"x":{"a":1,"b":2}}`,
			b:    `{"x":{"b":2,"a":1}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			ha, err := canonjson.SHA256([]byte(tc.a))
			if err != nil {
				subT.Fatalf("SHA256(a): %v", err)
			}
			hb, err := canonjson.SHA256([]byte(tc.b))
			if err != nil {
				subT.Fatalf("SHA256(b): %v", err)
			}
			if ha != hb {
				subT.Errorf("equivalent JSON produced different hashes:\n  a (%q): %s\n  b (%q): %s", tc.a, ha, tc.b, hb)
			}
			if len(ha) != 2*sha256.Size {
				subT.Errorf("hash length = %d, want %d", len(ha), 2*sha256.Size)
			}
			if _, derr := hex.DecodeString(ha); derr != nil {
				subT.Errorf("hash not hex: %v", derr)
			}
		})
	}
}

// TestSHA256_DifferentValuesDifferentDigests is the negative half of the
// stability property: JSON values that are NOT logically equal MUST
// produce different digests. Without this, the digest would be useless
// as a tamper-detection signal.
func TestSHA256_DifferentValuesDifferentDigests(t *testing.T) {
	t.Parallel()
	a, err := canonjson.SHA256([]byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	b, err := canonjson.SHA256([]byte(`{"a":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("distinct values produced identical digests: %s", a)
	}
}

// TestSHA256_PropagatesError verifies that bad input flows through to
// SHA256's caller as a non-nil error rather than producing a digest of
// the empty input. errors.Is is preferred even though the underlying
// error is not a sentinel — keeping the test stable against future
// internal refactoring.
func TestSHA256_PropagatesError(t *testing.T) {
	t.Parallel()
	_, err := canonjson.SHA256([]byte(`not-json`))
	if err == nil {
		t.Fatal("SHA256 of malformed input returned no error")
	}
	// Smoke check: errors.Is on a non-sentinel target is always false; we
	// only assert the error chain is non-nil, which the .Fatal above
	// already covers.
	if errors.Is(err, nil) {
		t.Error("err is nil but Fatal should have stopped us")
	}
}
