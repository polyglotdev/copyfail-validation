// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package kernelmod_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/kernelmod"
)

// TestParseProcModules covers the full /proc/modules format contract:
// blank-line skipping, single and multi-user dependency lists, all
// known State values, and the abort-on-malformed behavior. The
// `UsedBy: []string{}` (vs nil) cases are pinned because the package
// doc.go promises iterators get a stable shape regardless of whether
// dependents exist; if we ever regress to nil, downstream code that
// assumes the doc'd shape would not panic but would behave inconsistently
// across the empty/non-empty boundary.
func TestParseProcModules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		wantErr error
		name    string
		input   string
		want    []kernelmod.LoadedModule
	}{
		{
			name:  "empty input returns empty slice and nil error",
			input: "",
			want:  []kernelmod.LoadedModule{},
		},
		{
			name:  "blank lines are skipped without error",
			input: "\n\n   \n\t\n",
			want:  []kernelmod.LoadedModule{},
		},
		{
			name:  "single well-formed line with no users",
			input: "algif_aead 16384 0 - Live 0x0000000000000000\n",
			want: []kernelmod.LoadedModule{
				{Name: "algif_aead", Size: 16384, RefCount: 0, UsedBy: []string{}, State: "Live"},
			},
		},
		{
			name:  "single well-formed line with one user",
			input: "ext4 901120 1 cifs Live 0x0000000000000000\n",
			want: []kernelmod.LoadedModule{
				{Name: "ext4", Size: 901120, RefCount: 1, UsedBy: []string{"cifs"}, State: "Live"},
			},
		},
		{
			name:  "single well-formed line with multiple users",
			input: "af_alg 32768 6 algif_aead,algif_hash,algif_skcipher Live 0x0000000000000000\n",
			want: []kernelmod.LoadedModule{
				{
					Name:     "af_alg",
					Size:     32768,
					RefCount: 6,
					UsedBy:   []string{"algif_aead", "algif_hash", "algif_skcipher"},
					State:    "Live",
				},
			},
		},
		{
			name:  "multiple lines parse in order",
			input: "algif_aead 16384 0 - Live 0x0000000000000000\next4 901120 1 cifs Live 0x0000000000000000\n",
			want: []kernelmod.LoadedModule{
				{Name: "algif_aead", Size: 16384, RefCount: 0, UsedBy: []string{}, State: "Live"},
				{Name: "ext4", Size: 901120, RefCount: 1, UsedBy: []string{"cifs"}, State: "Live"},
			},
		},
		{
			name:  "multiple lines with interleaved blanks",
			input: "\nalgif_aead 16384 0 - Live 0x0000000000000000\n\next4 901120 1 cifs Live 0x0000000000000000\n\n",
			want: []kernelmod.LoadedModule{
				{Name: "algif_aead", Size: 16384, RefCount: 0, UsedBy: []string{}, State: "Live"},
				{Name: "ext4", Size: 901120, RefCount: 1, UsedBy: []string{"cifs"}, State: "Live"},
			},
		},
		{
			name:  "module in Loading state",
			input: "test_mod 4096 0 - Loading 0x0000000000000000\n",
			want: []kernelmod.LoadedModule{
				{Name: "test_mod", Size: 4096, RefCount: 0, UsedBy: []string{}, State: "Loading"},
			},
		},
		{
			name:  "module in Unloading state",
			input: "test_mod 4096 0 - Unloading 0x0000000000000000\n",
			want: []kernelmod.LoadedModule{
				{Name: "test_mod", Size: 4096, RefCount: 0, UsedBy: []string{}, State: "Unloading"},
			},
		},
		{
			name:  "trailing address column is permitted but discarded",
			input: "ena 184320 0 - Live 0xffffffffc0123456\n",
			want: []kernelmod.LoadedModule{
				{Name: "ena", Size: 184320, RefCount: 0, UsedBy: []string{}, State: "Live"},
			},
		},
		{
			name:  "missing address column still parses (only first 5 fields required)",
			input: "ena 184320 0 - Live\n",
			want: []kernelmod.LoadedModule{
				{Name: "ena", Size: 184320, RefCount: 0, UsedBy: []string{}, State: "Live"},
			},
		},
		{
			name:    "malformed line with too few fields aborts and returns ErrMalformed",
			input:   "broken line\n",
			wantErr: kernelmod.ErrMalformed,
			want:    []kernelmod.LoadedModule{},
		},
		{
			name:    "malformed size column aborts and returns ErrMalformed",
			input:   "broken_mod NOT_A_NUMBER 0 - Live 0x0\n",
			wantErr: kernelmod.ErrMalformed,
			want:    []kernelmod.LoadedModule{},
		},
		{
			name:    "malformed refcount column aborts and returns ErrMalformed",
			input:   "broken_mod 4096 NOT_A_NUMBER - Live 0x0\n",
			wantErr: kernelmod.ErrMalformed,
			want:    []kernelmod.LoadedModule{},
		},
		{
			name:    "abort returns lines parsed before the malformed line",
			input:   "algif_aead 16384 0 - Live 0x0000000000000000\nbroken line\n",
			wantErr: kernelmod.ErrMalformed,
			want: []kernelmod.LoadedModule{
				{Name: "algif_aead", Size: 16384, RefCount: 0, UsedBy: []string{}, State: "Live"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			got, err := kernelmod.ParseProcModules(strings.NewReader(tc.input))

			switch {
			case tc.wantErr == nil && err != nil:
				subT.Fatalf("ParseProcModules() unexpected error: %v", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				subT.Fatalf("ParseProcModules() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				subT.Errorf("ParseProcModules() result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestParseProcModules_MalformedErrorMessageIncludesContext pins the
// human-readable shape of the wrapped ErrMalformed: it MUST include the
// 1-indexed line number and the raw text of the offending line so an
// operator reading the audit log can identify exactly which row of
// /proc/modules tripped the parser. Without this guarantee, "malformed
// line" is useless for forensics.
func TestParseProcModules_MalformedErrorMessageIncludesContext(t *testing.T) {
	t.Parallel()

	const input = "algif_aead 16384 0 - Live 0x0000000000000000\nthis line is broken\n"
	_, err := kernelmod.ParseProcModules(strings.NewReader(input))
	if err == nil {
		t.Fatal("ParseProcModules() returned nil error; want wrapped ErrMalformed")
	}

	msg := err.Error()
	if !strings.Contains(msg, "line 2") {
		t.Errorf("error message missing 1-indexed line number; got %q", msg)
	}
	if !strings.Contains(msg, "this line is broken") {
		t.Errorf("error message missing offending raw text; got %q", msg)
	}
}

// TestParseProcModules_TestdataAL2023 exercises the parser end-to-end on
// the real-world Amazon Linux 2023 sample. The fixture is committed to
// the repo so any regression in column handling, address discarding, or
// usedby-CSV splitting becomes a failing test rather than a silent
// behavioral drift.
func TestParseProcModules_TestdataAL2023(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "procmodules-al2023.txt")
	f, err := os.Open(path) // #nosec G304 -- path is a committed testdata file
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	mods, err := kernelmod.ParseProcModules(f)
	if err != nil {
		t.Fatalf("ParseProcModules(%s) returned error: %v", path, err)
	}

	if got, want := len(mods), 20; got != want {
		t.Fatalf("parsed %d modules, want %d (fixture has 20 lines)", got, want)
	}

	// Spot-check the first row (no users) and a row with one user
	// to confirm column ordering survives the round trip. Asserting
	// every row would be redundant with the table-driven test above.
	if mods[0].Name != "tls" || mods[0].Size != 159744 {
		t.Errorf("first row mismatch: got %+v, want Name=tls Size=159744", mods[0])
	}
	if !kernelmod.IsLoaded(mods, "nf_conntrack") {
		t.Error("expected nf_conntrack in AL2023 fixture")
	}

	// Find nf_defrag_ipv6: it has UsedBy=[nf_conntrack].
	var defrag kernelmod.LoadedModule
	for _, m := range mods {
		if m.Name == "nf_defrag_ipv6" {
			defrag = m
			break
		}
	}
	if defrag.Name == "" {
		t.Fatal("nf_defrag_ipv6 missing from AL2023 fixture")
	}
	if diff := cmp.Diff([]string{"nf_conntrack"}, defrag.UsedBy); diff != "" {
		t.Errorf("nf_defrag_ipv6.UsedBy mismatch (-want +got):\n%s", diff)
	}
}

// TestParseProcModules_TestdataEmpty verifies the empty-file contract:
// zero bytes in, zero modules out, no error. The parser must NOT return
// nil here — see the package doc on slice shape stability.
func TestParseProcModules_TestdataEmpty(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "procmodules-empty.txt")
	f, err := os.Open(path) // #nosec G304 -- path is a committed testdata file
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() { _ = f.Close() }()

	mods, err := kernelmod.ParseProcModules(f)
	if err != nil {
		t.Fatalf("ParseProcModules(%s) returned error: %v", path, err)
	}
	if mods == nil {
		t.Fatal("ParseProcModules() returned nil slice for empty input; want non-nil empty slice")
	}
	if len(mods) != 0 {
		t.Errorf("ParseProcModules() returned %d modules for empty input; want 0", len(mods))
	}
}

// TestIsLoaded covers the four query shapes the function promises:
// hit, miss, empty-input miss, and case-sensitivity. Case-sensitivity
// is pinned because kernel module names are themselves case-sensitive,
// and a future "convenience" addition of strings.EqualFold would silently
// collide names like `algif_aead` and `Algif_Aead` — undetectable by
// callers but a real problem for any future check that compares modprobe
// alias output (which may use a different casing convention).
func TestIsLoaded(t *testing.T) {
	t.Parallel()

	loaded := []kernelmod.LoadedModule{
		{Name: "algif_aead", Size: 16384, RefCount: 0, UsedBy: []string{}, State: "Live"},
		{Name: "ext4", Size: 901120, RefCount: 1, UsedBy: []string{"cifs"}, State: "Live"},
	}

	tests := []struct {
		name    string
		query   string
		modules []kernelmod.LoadedModule
		want    bool
	}{
		{
			name:    "module present returns true",
			modules: loaded,
			query:   "algif_aead",
			want:    true,
		},
		{
			name:    "module absent returns false",
			modules: loaded,
			query:   "not_a_real_module",
			want:    false,
		},
		{
			name:    "empty modules slice returns false",
			modules: nil,
			query:   "algif_aead",
			want:    false,
		},
		{
			name:    "empty modules slice (non-nil empty) returns false",
			modules: []kernelmod.LoadedModule{},
			query:   "algif_aead",
			want:    false,
		},
		{
			name:    "case-sensitive: capitalized variant does NOT match",
			modules: loaded,
			query:   "Algif_Aead",
			want:    false,
		},
		{
			name:    "case-sensitive: uppercase does NOT match",
			modules: loaded,
			query:   "ALGIF_AEAD",
			want:    false,
		},
		{
			name:    "second entry in slice is found",
			modules: loaded,
			query:   "ext4",
			want:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if got := kernelmod.IsLoaded(tc.modules, tc.query); got != tc.want {
				subT.Errorf("IsLoaded(_, %q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}
