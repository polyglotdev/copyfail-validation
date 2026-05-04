// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package hostinfo_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/hostinfo"
)

// errReader is an io.Reader that always returns a sentinel error on
// Read. Used by TestParseOSRelease_ReaderError to exercise the
// scanner.Err() branch — the only error path in the parser.
type errReader struct{ err error }

// Read returns r.err verbatim. Implements io.Reader.
func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestParseOSRelease covers the full parser contract: real-world
// distribution fixtures (AL2023, Ubuntu 22.04, Rocky 9), the three
// quote forms (unquoted, double-quoted, single-quoted), backslash
// escape expansion in double-quoted values, comment-line skipping,
// blank-line tolerance, malformed-line tolerance, and the empty-input
// happy path. Sub-tests run in parallel because they share no state.
func TestParseOSRelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          string
		wantID         string
		wantVersionID  string
		wantPrettyName string
	}{
		{
			name:           "AL2023 fixture (read from testdata)",
			input:          mustReadFixture(t, "os-release-al2023"),
			wantID:         "amzn",
			wantVersionID:  "2023",
			wantPrettyName: "Amazon Linux 2023.4.20240108",
		},
		{
			name:           "Ubuntu 22.04 fixture mixes quoted and unquoted",
			input:          mustReadFixture(t, "os-release-ubuntu2204"),
			wantID:         "ubuntu",
			wantVersionID:  "22.04",
			wantPrettyName: "Ubuntu 22.04.3 LTS",
		},
		{
			name:           "Rocky 9 fixture",
			input:          mustReadFixture(t, "os-release-rocky9"),
			wantID:         "rocky",
			wantVersionID:  "9.3",
			wantPrettyName: "Rocky Linux 9.3 (Blue Onyx)",
		},
		{
			name:          "unquoted value",
			input:         "ID=ubuntu\nVERSION_ID=22.04\n",
			wantID:        "ubuntu",
			wantVersionID: "22.04",
		},
		{
			name:          "double-quoted value",
			input:         `ID="ubuntu"` + "\n" + `VERSION_ID="22.04"` + "\n",
			wantID:        "ubuntu",
			wantVersionID: "22.04",
		},
		{
			name:          "single-quoted value",
			input:         `ID='ubuntu'` + "\n" + `VERSION_ID='22.04'` + "\n",
			wantID:        "ubuntu",
			wantVersionID: "22.04",
		},
		{
			name:           "double-quoted with embedded escaped double-quote",
			input:          `PRETTY_NAME="Acme \"Corp\" Linux 1.0"` + "\n",
			wantPrettyName: `Acme "Corp" Linux 1.0`,
		},
		{
			name:           "double-quoted with backslash-backslash",
			input:          `PRETTY_NAME="path\\with\\backslash"` + "\n",
			wantPrettyName: `path\with\backslash`,
		},
		{
			name:           "double-quoted with dollar and backtick escapes",
			input:          `PRETTY_NAME="literal \$VAR and \` + "`" + `cmd\` + "`" + `"` + "\n",
			wantPrettyName: "literal $VAR and `cmd`",
		},
		{
			name:           "double-quoted preserves unknown escape sequence",
			input:          `PRETTY_NAME="line\nbreak"` + "\n",
			wantPrettyName: `line\nbreak`,
		},
		{
			name:   "single-quoted does NOT expand escapes",
			input:  `ID='lit\"val'` + "\n",
			wantID: `lit\"val`,
		},
		{
			name:   "comment-only lines skipped",
			input:  "# this is a comment\nID=ubuntu\n# trailing comment\n",
			wantID: "ubuntu",
		},
		{
			name:          "blank lines tolerated",
			input:         "\n\nID=ubuntu\n\n\nVERSION_ID=22.04\n\n",
			wantID:        "ubuntu",
			wantVersionID: "22.04",
		},
		{
			name:          "indented lines are still parsed",
			input:         "   ID=ubuntu\n\tVERSION_ID=22.04\n",
			wantID:        "ubuntu",
			wantVersionID: "22.04",
		},
		{
			name:          "malformed line (no equals) silently skipped",
			input:         "ID=ubuntu\nthis line is malformed\nVERSION_ID=22.04\n",
			wantID:        "ubuntu",
			wantVersionID: "22.04",
		},
		{
			name:           "unbalanced double-quote silently skipped",
			input:          `PRETTY_NAME="unbalanced` + "\nID=fallback\n",
			wantID:         "fallback",
			wantPrettyName: "",
		},
		{
			name:           "unbalanced single-quote silently skipped",
			input:          "PRETTY_NAME='unbalanced\nID=fallback\n",
			wantID:         "fallback",
			wantPrettyName: "",
		},
		{
			name: "empty input returns empty fields and no error",
		},
		{
			name:  "unrecognized keys are silently ignored",
			input: "VENDOR_NAME=AWS\nVENDOR_URL=https://aws.amazon.com/\n",
		},
		{
			name:           "unquoted value trims trailing whitespace",
			input:          "PRETTY_NAME=plain   \n",
			wantPrettyName: "plain",
		},
		{
			name:  "key starting with digit is rejected",
			input: "1ID=bogus\nID=valid\n",
			// The 1ID line is rejected as malformed (digit-leading key);
			// the ID line still parses.
			wantID: "valid",
		},
		{
			name:   "key with spaces is rejected",
			input:  "MY KEY=bogus\nID=valid\n",
			wantID: "valid",
		},
		{
			name:   "leading equals (no key) is rejected",
			input:  "=bogus\nID=valid\n",
			wantID: "valid",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()

			id, versionID, prettyName, err := hostinfo.ParseOSRelease(strings.NewReader(tc.input))
			if err != nil {
				subT.Fatalf("ParseOSRelease() error = %v; want nil", err)
			}
			if id != tc.wantID {
				subT.Errorf("id = %q; want %q", id, tc.wantID)
			}
			if versionID != tc.wantVersionID {
				subT.Errorf("versionID = %q; want %q", versionID, tc.wantVersionID)
			}
			if prettyName != tc.wantPrettyName {
				subT.Errorf("prettyName = %q; want %q", prettyName, tc.wantPrettyName)
			}
		})
	}
}

// TestParseOSRelease_ReaderError pins the only error path: when the
// underlying io.Reader returns a non-EOF error, the parser MUST
// surface it wrapped so callers can inspect with errors.Is. A nil
// error here would mean a transient I/O failure was silently masked,
// which the audit must never tolerate.
func TestParseOSRelease_ReaderError(t *testing.T) {
	t.Parallel()

	want := errors.New("disk on fire")
	_, _, _, err := hostinfo.ParseOSRelease(errReader{err: want})
	if err == nil {
		t.Fatal("ParseOSRelease() error = nil; want non-nil")
	}
	if !errors.Is(err, want) {
		t.Errorf("ParseOSRelease() error = %v; want errors.Is(_, %v)", err, want)
	}
}

// mustReadFixture reads a testdata file and fails the test on error.
// Helper kept here (not in helper_test.go) because it is the only
// shared helper across the parser test files in this package.
func mustReadFixture(subT *testing.T, name string) string {
	subT.Helper()
	path := filepath.Join("testdata", name)
	data, err := os.ReadFile(path) // #nosec G304 -- name is a hard-coded fixture filename in test code.
	if err != nil {
		subT.Fatalf("read fixture %s: %v", path, err)
	}
	return string(data)
}

// Compile-time assertion that errReader satisfies io.Reader.
var _ io.Reader = errReader{}
