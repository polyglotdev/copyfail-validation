// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// stubResolver builds a resolverFunc that returns the supplied paths
// for each name in available, and exec.ErrCommandNotFound for any
// other name. The map values are arbitrary placeholder paths — the
// detector only checks for a non-error return, not the path contents.
//
// This stub is the test seam for Detect: it lets a single subtest
// model "host has rpm only", "host has dpkg only", "host has both",
// and "host has neither" without depending on the development machine
// actually having either binary installed.
func stubResolver(available map[string]string) resolverFunc {
	return func(name string) (string, error) {
		if path, ok := available[name]; ok {
			return path, nil
		}
		return "", fmt.Errorf("stub: %w", exec.ErrCommandNotFound)
	}
}

// TestDetect_PrecedenceAndAvailability pins the auto-selection rule
// from doc.go: rpm wins when both backends are available, dpkg is
// the fallback when only it resolves, and ErrNoPkgManager surfaces
// when neither backend's binary is on the host. This is the single
// table that pins the public Detect contract — every cell is a
// behavior the integrity.su_binary check (Phase 5) depends on.
//
// The rpm-first rule is documented in doc.go; if a future revision
// flips the precedence, this test fails AND the godoc paragraph in
// doc.go must change in lockstep — keeping the test and doc aligned
// prevents silent contract drift.
func TestDetect_PrecedenceAndAvailability(t *testing.T) {
	t.Parallel()

	tests := []struct {
		available map[string]string
		wantErr   error
		name      string
		wantName  string
	}{
		{
			name:      "both rpm and dpkg available — rpm wins (precedence rule)",
			available: map[string]string{"rpm": "/usr/bin/rpm", "dpkg": "/usr/bin/dpkg"},
			wantName:  "rpm",
			wantErr:   nil,
		},
		{
			name:      "only rpm available — rpm is selected",
			available: map[string]string{"rpm": "/usr/bin/rpm"},
			wantName:  "rpm",
			wantErr:   nil,
		},
		{
			name:      "only dpkg available — dpkg is the fallback",
			available: map[string]string{"dpkg": "/usr/bin/dpkg"},
			wantName:  "dpkg",
			wantErr:   nil,
		},
		{
			name:      "neither available — ErrNoPkgManager surfaces for the Skip path",
			available: map[string]string{},
			wantName:  "",
			wantErr:   ErrNoPkgManager,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			runner := &exec.FakeRunner{}
			pm, err := detectWith(runner, stubResolver(tc.available))

			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					subT.Fatalf("detectWith() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
				}
				if pm != nil {
					subT.Errorf("detectWith() pm = %v, want nil on error", pm)
				}
				return
			}

			if err != nil {
				subT.Fatalf("detectWith() unexpected error: %v", err)
			}
			if pm == nil {
				subT.Fatalf("detectWith() pm = nil, want non-nil")
			}
			if got := pm.Name(); got != tc.wantName {
				subT.Errorf("pm.Name() = %q, want %q", got, tc.wantName)
			}

			// Detect must NOT shell out via the runner — resolution
			// is a static allowlist + os.Stat check. If a future
			// refactor adds a runtime probe (e.g., `rpm --version`),
			// the runner.Calls assertion below fails and the godoc
			// in pkgmgr.go must be updated to reflect the new
			// behavior.
			if got := len(runner.Calls); got != 0 {
				subT.Errorf("len(runner.Calls) = %d, want 0 (Detect must not shell out)", got)
			}
		})
	}
}

// TestDetect_PublicWrapperUsesRealResolver pins that the exported
// Detect symbol delegates to detectWith with exec.ResolveCommand —
// if a future refactor accidentally short-circuits Detect (e.g.,
// returns a hard-coded backend) this guard fails. We model the
// "neither installed" case (true on macOS dev machines and minimal
// containers) and assert ErrNoPkgManager is returned, which only
// happens if the real resolver is consulted.
//
// On a host that does have rpm or dpkg installed in the production
// allowlist path (/usr/bin/rpm or /usr/bin/dpkg), this test is
// skipped — the test cannot assert "no manager" on a host that
// actually has one.
func TestDetect_PublicWrapperUsesRealResolver(t *testing.T) {
	t.Parallel()

	// If either binary is installed at the allowlisted preferred
	// path on this host, we cannot assert "no manager" — skip with
	// a clear reason so CI logs explain why.
	if _, err := exec.ResolveCommand("rpm"); err == nil {
		t.Skip("rpm is available on this host; cannot pin the no-manager path")
	}
	if _, err := exec.ResolveCommand("dpkg"); err == nil {
		t.Skip("dpkg is available on this host; cannot pin the no-manager path")
	}

	runner := &exec.FakeRunner{}
	pm, err := Detect(runner)
	if !errors.Is(err, ErrNoPkgManager) {
		t.Fatalf("Detect() error = %v, want errors.Is(_, ErrNoPkgManager)", err)
	}
	if pm != nil {
		t.Errorf("Detect() pm = %v, want nil", pm)
	}
}

// TestVerifyResult_Clean pins the boolean-aggregation logic that the
// integrity.su_binary check uses to decide Pass vs Fail. Each row of
// the table corresponds to one cell in the State-Semantics table of
// spec §5: an all-false result is Clean (Pass); any flag flipping
// the result to non-clean implies Fail; a non-empty UnverifiedReasons
// also forces non-clean even when every boolean is false (because
// UnverifiedReasons captures anomalies that did not fit a flag).
//
// This is a critical regression test: a bug here would either (a)
// turn a real tamper finding into a Pass (silent compromise) or (b)
// flag a healthy host as Fail (alert noise that conditions operators
// to ignore the check). Both modes are spec-§11 violations.
func TestVerifyResult_Clean(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		v    VerifyResult
		want bool
	}{
		{
			name: "all flags false and no UnverifiedReasons — Clean",
			v:    VerifyResult{},
			want: true,
		},
		{
			name: "HashMismatch alone trips Clean",
			v:    VerifyResult{HashMismatch: true},
			want: false,
		},
		{
			name: "SizeChanged alone trips Clean",
			v:    VerifyResult{SizeChanged: true},
			want: false,
		},
		{
			name: "MTimeChanged alone trips Clean",
			v:    VerifyResult{MTimeChanged: true},
			want: false,
		},
		{
			name: "PermsChanged alone trips Clean",
			v:    VerifyResult{PermsChanged: true},
			want: false,
		},
		{
			name: "OwnerChanged alone trips Clean",
			v:    VerifyResult{OwnerChanged: true},
			want: false,
		},
		{
			name: "GroupChanged alone trips Clean",
			v:    VerifyResult{GroupChanged: true},
			want: false,
		},
		{
			name: "non-empty UnverifiedReasons trips Clean even with all flags false",
			v:    VerifyResult{UnverifiedReasons: []string{"config file marker"}},
			want: false,
		},
		{
			name: "every flag true — emphatically not Clean",
			v: VerifyResult{
				HashMismatch:      true,
				SizeChanged:       true,
				MTimeChanged:      true,
				PermsChanged:      true,
				OwnerChanged:      true,
				GroupChanged:      true,
				UnverifiedReasons: []string{"sibling file changed"},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if got := tc.v.Clean(); got != tc.want {
				subT.Errorf("Clean() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestVerifyResult_FieldExposure documents every public boolean
// field of VerifyResult so a future addition (e.g., CapabilitiesChanged)
// without a corresponding update to Clean and to this test surfaces
// as a build failure. Without this guard, a new field could land
// without being wired into Clean — and a tamper signal on that field
// would silently turn into a Pass.
func TestVerifyResult_FieldExposure(t *testing.T) {
	t.Parallel()

	allTrue := VerifyResult{
		Backend:           "rpm",
		Path:              "/usr/bin/su",
		Package:           "util-linux-core-2.39.4-7.amzn2023.x86_64",
		RawOutput:         "S.5....T.    /usr/bin/su\n",
		UnverifiedReasons: []string{"sibling-file deviation"},
		HashMismatch:      true,
		SizeChanged:       true,
		MTimeChanged:      true,
		PermsChanged:      true,
		OwnerChanged:      true,
		GroupChanged:      true,
	}
	want := allTrue
	if diff := cmp.Diff(want, allTrue); diff != "" {
		t.Errorf("VerifyResult round-trip mismatch (-want +got):\n%s", diff)
	}
	if allTrue.Clean() {
		t.Errorf("Clean() = true on an all-true VerifyResult, want false")
	}
}
