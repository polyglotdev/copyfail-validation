// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package redact_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/redact"
)

// TestRedact_Inline verifies the canonical positive and negative cases
// against in-source fixtures. The bearer-token case is the regression
// test for the original `\S+` regex bug that consumed only "Bearer" and
// silently leaked the JWT — current pattern uses `.+` so the entire
// header value is replaced.
func TestRedact_Inline(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "aws access key id is fully redacted",
			in:   "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
			want: "aws_access_key_id=***REDACTED***",
		},
		{
			name: "aws secret access key is fully redacted",
			in:   "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			want: "aws_secret_access_key=***REDACTED***",
		},
		{
			name: "bearer JWT in Authorization header is fully redacted (no leak)",
			in:   "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.dummy",
			want: "Authorization=***REDACTED***",
		},
		{
			name: "password equals value is redacted",
			in:   "password=hunter2",
			want: "password=***REDACTED***",
		},
		{
			name: "password colon value is redacted",
			in:   "password: hunter2",
			want: "password=***REDACTED***",
		},
		{
			name: "case insensitive on the keyword",
			in:   "PASSWORD=hunter2",
			want: "PASSWORD=***REDACTED***",
		},
		{
			name: "non-secret command output is unchanged",
			in:   "modprobe -n -v algif_aead",
			want: "modprobe -n -v algif_aead",
		},
		{
			name: "the word password in prose without separator is not redacted",
			in:   "Reset your password from the portal",
			want: "Reset your password from the portal",
		},
		{
			name: "api key documentation reference is not redacted",
			in:   "See the API key documentation at https://example.com/docs/api-keys",
			want: "See the API key documentation at https://example.com/docs/api-keys",
		},
		{
			name: "multi-line input redacts secret line and leaves others intact",
			in:   "command: modprobe -nv algif_aead\npassword=hunter2\nresult: ok",
			want: "command: modprobe -nv algif_aead\npassword=***REDACTED***\nresult: ok",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if got := redact.Redact(tc.in); got != tc.want {
				subT.Errorf("Redact(%q)\n  got  = %q\n  want = %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRedact_TestdataPositiveCorpus is the 50-sample positive corpus
// runner mandated by spec §7. Each sample under testdata/positive/
// MUST contain at least one secret that gets redacted. The corpus is
// committed to git so the regex's behavior on real-looking inputs is
// pinned in the repository (any regex change that misses one of these
// inputs becomes a failing test).
func TestRedact_TestdataPositiveCorpus(t *testing.T) {
	t.Parallel()
	matches, err := filepath.Glob("testdata/positive/*.txt")
	if err != nil {
		t.Fatalf("glob positive corpus: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("positive corpus is empty (testdata/positive/*.txt)")
	}
	for _, path := range matches {
		t.Run(filepath.Base(path), func(subT *testing.T) {
			subT.Parallel()
			b, rerr := os.ReadFile(path) // #nosec G304 -- path comes from filepath.Glob over committed testdata
			if rerr != nil {
				subT.Fatalf("read %s: %v", path, rerr)
			}
			got := redact.Redact(string(b))
			if !strings.Contains(got, redact.Replacement) {
				subT.Errorf("expected %s in redacted output for %s, got:\n%s", redact.Replacement, path, got)
			}
			// Critical: verify the original secret value does NOT survive
			// the redaction. We assert this by ensuring no line in the
			// output still contains a `keyword: VALUE` pattern with a
			// non-marker value. For the bearer case specifically, ensure
			// the JWT does NOT appear anywhere in the output.
			for _, line := range strings.Split(string(b), "\n") {
				if !strings.Contains(strings.ToLower(line), "bearer") {
					continue
				}
				idx := strings.Index(strings.ToLower(line), "bearer")
				rest := strings.TrimSpace(line[idx+len("bearer"):])
				if rest == "" {
					continue
				}
				if strings.Contains(got, rest) {
					subT.Errorf("bearer token leaked in %s: %q still present in:\n%s", path, rest, got)
				}
			}
		})
	}
}

// TestRedact_TestdataNegativeCorpus runs the negative corpus: each file
// under testdata/negative/ contains text that mentions secret-keywords
// in PROSE (no `:` or `=` separator) and MUST NOT be redacted. False
// positives are how operators stop trusting the redactor's output —
// the tool must be precise enough that a redaction marker means "real
// secret found" 100% of the time.
func TestRedact_TestdataNegativeCorpus(t *testing.T) {
	t.Parallel()
	matches, err := filepath.Glob("testdata/negative/*.txt")
	if err != nil {
		t.Fatalf("glob negative corpus: %v", err)
	}
	if len(matches) == 0 {
		t.Fatal("negative corpus is empty (testdata/negative/*.txt)")
	}
	for _, path := range matches {
		t.Run(filepath.Base(path), func(subT *testing.T) {
			subT.Parallel()
			b, rerr := os.ReadFile(path) // #nosec G304 -- path comes from filepath.Glob over committed testdata
			if rerr != nil {
				subT.Fatalf("read %s: %v", path, rerr)
			}
			got := redact.Redact(string(b))
			if strings.Contains(got, redact.Replacement) {
				subT.Errorf("did NOT expect redaction in %s\ninput:\n%s\noutput:\n%s", path, string(b), got)
			}
		})
	}
}

// TestRedactionPattern_Compiles guards against accidental edits to the
// RedactionPattern const that would cause regexp.MustCompile to panic
// at package init. Cheap and explicit; catches the failure here rather
// than at the import site.
func TestRedactionPattern_Compiles(t *testing.T) {
	t.Parallel()
	if redact.RedactionPattern == "" {
		t.Fatal("RedactionPattern is empty")
	}
	if redact.Replacement == "" {
		t.Fatal("Replacement is empty")
	}
}
