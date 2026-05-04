// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// dpkgTestPath is the canonical path the integrity.su_binary check
// queries on a dpkg-managed host (Debian/Ubuntu). Same path as the
// rpm test fixture; the spec §11 check is path-symmetric across
// backends.
const dpkgTestPath = "/usr/bin/su"

// dpkgTestPkg is the package name a real Debian/Ubuntu host returns
// for the package owning /usr/bin/su, copied verbatim from a
// production capture. Multi-arch hosts often qualify the name as
// `util-linux:amd64` — both forms are exercised in the parser tests.
const dpkgTestPkg = "util-linux"

// TestDPKG_OwnerOf_Parsing pins the canonical happy-path and unknown-
// file behaviors of the dpkg OwnerOf method. The two shapes are the
// only outcomes the spec §11 integrity.su_binary check distinguishes
// — a known package or "no package" (translate to ErrPackageUnknown).
// A regression here would silently flag a manually-placed binary as
// "verified", the worst-case false-positive for the integrity check.
func TestDPKG_OwnerOf_Parsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		stdout    string
		stderr    string
		wantErr   error
		name      string
		wantOwner string
		exitCode  int
	}{
		{
			name:      "happy path returns the package name",
			stdout:    "util-linux: " + dpkgTestPath + "\n",
			stderr:    "",
			exitCode:  0,
			wantOwner: dpkgTestPkg,
			wantErr:   nil,
		},
		{
			name:      "multi-arch qualifier (pkg:arch) is preserved verbatim",
			stdout:    "util-linux:amd64: " + dpkgTestPath + "\n",
			stderr:    "",
			exitCode:  0,
			wantOwner: "util-linux:amd64",
			wantErr:   nil,
		},
		{
			name:      "unknown file translates to ErrPackageUnknown via stderr marker",
			stdout:    "",
			stderr:    "dpkg-query: no path found matching pattern /usr/bin/wat\n",
			exitCode:  1,
			wantOwner: "",
			wantErr:   ErrPackageUnknown,
		},
	}

	pm := newDPKG()
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()

			runner := newDPKGOwnerRunner(dpkgTestPath, tc.stdout, tc.stderr, tc.exitCode, tc.wantErr != nil)

			owner, err := pm.OwnerOf(context.Background(), runner, dpkgTestPath)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					subT.Fatalf("OwnerOf() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
				}
				if owner != "" {
					subT.Errorf("OwnerOf() owner = %q, want \"\" on error", owner)
				}
				return
			}
			if err != nil {
				subT.Fatalf("OwnerOf() unexpected error: %v", err)
			}
			if owner != tc.wantOwner {
				subT.Errorf("OwnerOf() owner = %q, want %q", owner, tc.wantOwner)
			}
		})
	}
}

// TestDPKG_OwnerOf_RecordsCommandShape pins the exact subprocess
// invocation: command name "dpkg", first arg Trusted("-S"), second
// arg Untrusted(path). Same security regression-guard pattern as
// the rpm test — a refactor that retypes the path arg as Trusted
// would re-open the shell-injection vector that internal/exec was
// built to close.
func TestDPKG_OwnerOf_RecordsCommandShape(t *testing.T) {
	t.Parallel()

	pm := newDPKG()
	runner := newDPKGOwnerRunner(dpkgTestPath, dpkgTestPkg+": "+dpkgTestPath+"\n", "", 0, false)

	if _, err := pm.OwnerOf(context.Background(), runner, dpkgTestPath); err != nil {
		t.Fatalf("OwnerOf() error: %v", err)
	}

	if got, want := len(runner.Calls), 1; got != want {
		t.Fatalf("len(runner.Calls) = %d, want %d", got, want)
	}
	call := runner.Calls[0]
	if got, want := call.Name, "dpkg"; got != want {
		t.Errorf("call.Name = %q, want %q", got, want)
	}
	if got, want := len(call.Args), 2; got != want {
		t.Fatalf("len(call.Args) = %d, want %d", got, want)
	}

	flag, ok := call.Args[0].(exec.Trusted)
	if !ok {
		t.Errorf("call.Args[0] type = %T, want exec.Trusted", call.Args[0])
	}
	if string(flag) != "-S" {
		t.Errorf("call.Args[0] = %q, want %q", flag, "-S")
	}

	pathArg, ok := call.Args[1].(exec.Untrusted)
	if !ok {
		t.Errorf("call.Args[1] type = %T, want exec.Untrusted", call.Args[1])
	}
	if string(pathArg) != dpkgTestPath {
		t.Errorf("call.Args[1] = %q, want %q", pathArg, dpkgTestPath)
	}
}

// TestDPKG_OwnerOf_RejectsArgumentInjection pins the
// shell-metacharacter-injection guard at the dpkg OwnerOf boundary.
func TestDPKG_OwnerOf_RejectsArgumentInjection(t *testing.T) {
	t.Parallel()

	pm := newDPKG()
	runner := &exec.FakeRunner{}
	_, err := pm.OwnerOf(context.Background(), runner, "/usr/bin/su;rm -rf /")
	if !errors.Is(err, exec.ErrInvalidArg) {
		t.Fatalf("OwnerOf() error = %v, want errors.Is(_, exec.ErrInvalidArg)", err)
	}
	if got := len(runner.Calls); got != 0 {
		t.Errorf("len(runner.Calls) = %d, want 0 (validation must short-circuit)", got)
	}
}

// TestDPKG_Verify_Parsing pins the per-line interpretation of
// `debsums -s` STDERR output. debsums' `-s` flag means "silent on
// match", but mismatches always go to STDERR (not stdout). The
// table covers: a clean package (silent), a hash mismatch on the
// queried path (HashMismatch=true), a mismatch on a sibling file
// (recorded into UnverifiedReasons), and a malformed/diagnostic
// line (recorded informationally without flag flips).
//
// debsums does NOT report size/mtime/perm/owner deltas — only
// content-hash mismatches. The other VerifyResult booleans must
// always be false for this backend; a regression that started
// flipping them would produce false-positive findings.
func TestDPKG_Verify_Parsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		stderr   string
		want     VerifyResult
		exitCode int
		failExit bool
	}{
		{
			name:     "clean package — silent stderr, exit 0",
			stderr:   "",
			exitCode: 0,
			failExit: false,
			want: VerifyResult{
				Backend: "dpkg",
				Path:    dpkgTestPath,
				Package: dpkgTestPkg,
			},
		},
		{
			name:     "hash mismatch on queried path — HashMismatch=true",
			stderr:   "debsums: changed file " + dpkgTestPath + " (from util-linux package)\n",
			exitCode: 2,
			failExit: true,
			want: VerifyResult{
				Backend:      "dpkg",
				Path:         dpkgTestPath,
				Package:      dpkgTestPkg,
				RawOutput:    "debsums: changed file " + dpkgTestPath + " (from util-linux package)\n",
				HashMismatch: true,
			},
		},
		{
			name:     "mismatch on sibling file — UnverifiedReasons captures it; queried path stays clean",
			stderr:   "debsums: changed file /usr/bin/other (from util-linux package)\n",
			exitCode: 2,
			failExit: true,
			want: VerifyResult{
				Backend:           "dpkg",
				Path:              dpkgTestPath,
				Package:           dpkgTestPkg,
				RawOutput:         "debsums: changed file /usr/bin/other (from util-linux package)\n",
				UnverifiedReasons: []string{"additional file changed in package: /usr/bin/other"},
			},
		},
		{
			name:     "diagnostic line (no md5sums) is informational — no flag flips",
			stderr:   "debsums: no md5sums for util-linux\n",
			exitCode: 1,
			failExit: true,
			want: VerifyResult{
				Backend:           "dpkg",
				Path:              dpkgTestPath,
				Package:           dpkgTestPkg,
				RawOutput:         "debsums: no md5sums for util-linux\n",
				UnverifiedReasons: []string{"debsums diagnostic: debsums: no md5sums for util-linux"},
			},
		},
	}

	pm := newDPKG()
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()

			runner := newDPKGVerifyRunner(dpkgTestPkg, tc.stderr, tc.exitCode, tc.failExit)

			got, err := pm.Verify(context.Background(), runner, dpkgTestPkg, dpkgTestPath)
			if tc.failExit {
				if err == nil {
					subT.Fatalf("Verify() error = nil, want non-nil (debsums exits non-zero on findings)")
				}
			} else if err != nil {
				subT.Fatalf("Verify() unexpected error: %v", err)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				subT.Errorf("Verify() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDPKG_Verify_DebsumsNotInstalled pins the spec-required
// behavior when the debsums binary is not on the host: Verify must
// wrap exec.ErrCommandNotFound (or exec.ErrCommandDenied) so the
// caller can Skip cleanly. The test models the runner returning the
// resolution sentinel verbatim — exactly what NewOSRunner returns
// when ResolveCommand fails.
//
// CRITICAL: do NOT silently fall back to "no mismatches" when
// debsums is missing. That would produce a false sense of security
// on the large set of Debian/Ubuntu hosts that do not have debsums
// installed (it is not a default package). The spec §5
// State-Semantics table classifies "tool not installed" as Skip,
// not Pass.
func TestDPKG_Verify_DebsumsNotInstalled(t *testing.T) {
	t.Parallel()

	pm := newDPKG()
	key := "debsums -s " + dpkgTestPkg
	runner := &exec.FakeRunner{
		Errors: map[string]error{
			key: fmt.Errorf("simulated: %w", exec.ErrCommandNotFound),
		},
	}

	_, err := pm.Verify(context.Background(), runner, dpkgTestPkg, dpkgTestPath)
	if !errors.Is(err, exec.ErrCommandNotFound) {
		t.Fatalf("Verify() error = %v, want errors.Is(_, exec.ErrCommandNotFound)", err)
	}
	const wantPrefix = "integrity: debsums -s " + dpkgTestPkg
	if got := err.Error(); !strings.Contains(got, wantPrefix) {
		t.Errorf("error message = %q, want substring %q", got, wantPrefix)
	}
}

// TestDPKG_Verify_DebsumsDeniedByAllowlist pins the symmetric case
// where the allowlist denies debsums (which can happen if a future
// security review removes it from internal/exec/allowlist.go). The
// returned error must wrap exec.ErrCommandDenied so the caller's
// errors.Is check succeeds.
func TestDPKG_Verify_DebsumsDeniedByAllowlist(t *testing.T) {
	t.Parallel()

	pm := newDPKG()
	key := "debsums -s " + dpkgTestPkg
	runner := &exec.FakeRunner{
		Errors: map[string]error{
			key: fmt.Errorf("simulated: %w", exec.ErrCommandDenied),
		},
	}

	_, err := pm.Verify(context.Background(), runner, dpkgTestPkg, dpkgTestPath)
	if !errors.Is(err, exec.ErrCommandDenied) {
		t.Fatalf("Verify() error = %v, want errors.Is(_, exec.ErrCommandDenied)", err)
	}
}

// TestDPKG_Verify_RejectsArgumentInjection pins the Untrusted-package
// validation guard at the dpkg Verify boundary.
func TestDPKG_Verify_RejectsArgumentInjection(t *testing.T) {
	t.Parallel()

	pm := newDPKG()
	runner := &exec.FakeRunner{}
	_, err := pm.Verify(context.Background(), runner, "util-linux;rm -rf /", dpkgTestPath)
	if !errors.Is(err, exec.ErrInvalidArg) {
		t.Fatalf("Verify() error = %v, want errors.Is(_, exec.ErrInvalidArg)", err)
	}
	if got := len(runner.Calls); got != 0 {
		t.Errorf("len(runner.Calls) = %d, want 0 (validation must short-circuit)", got)
	}
}

// newDPKGOwnerRunner builds a FakeRunner that returns the given
// stdout/stderr/exitCode for the canonical `dpkg -S <path>` invocation.
func newDPKGOwnerRunner(path, stdout, stderr string, exitCode int, returnErr bool) *exec.FakeRunner {
	key := "dpkg -S " + path
	r := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			key: {
				Stdout:   []byte(stdout),
				Stderr:   []byte(stderr),
				ExitCode: exitCode,
			},
		},
	}
	if returnErr {
		r.Errors = map[string]error{
			key: errors.New("dpkg exited non-zero"),
		}
	}
	return r
}

// newDPKGVerifyRunner builds a FakeRunner that returns the given
// stderr/exitCode for the canonical `debsums -s <pkg>` invocation.
// debsums prints mismatches to STDERR by design — see the doc on
// debsumsChangedPrefix in dpkg.go for the rationale.
func newDPKGVerifyRunner(pkg, stderr string, exitCode int, failExit bool) *exec.FakeRunner {
	key := "debsums -s " + pkg
	r := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			key: {
				Stderr:   []byte(stderr),
				ExitCode: exitCode,
			},
		},
	}
	if failExit {
		r.Errors = map[string]error{
			key: errors.New("debsums exited non-zero"),
		}
	}
	return r
}
