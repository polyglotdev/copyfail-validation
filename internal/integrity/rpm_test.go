// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// rpmTestPath is the canonical path the integrity.su_binary check
// queries — kept as a package-test constant so a future spec revision
// to the queried path is a single edit.
const rpmTestPath = "/usr/bin/su"

// rpmTestNEVR is the NEVR string a real Amazon Linux 2023 host
// returns for the package owning /usr/bin/su, copied verbatim from a
// production capture. Using the real string (not a synthetic one)
// pins the parser against actual rpm output.
const rpmTestNEVR = "util-linux-core-2.39.4-7.amzn2023.x86_64"

// TestRPM_OwnerOf_Parsing pins the canonical happy-path and unknown-file
// behaviors of the rpm OwnerOf method. These two shapes are the only
// outcomes the spec §11 integrity.su_binary check distinguishes — a
// known package (record into Evidence["package"]) or "no package"
// (translate to ErrPackageUnknown so the check can branch on
// errors.Is). A regression that promoted the unknown-file message to
// a real package name (e.g., by stripping the marker phrase) would
// silently treat manually-placed binaries as "verified", which is the
// worst-case false-positive for an integrity check.
func TestRPM_OwnerOf_Parsing(t *testing.T) {
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
			name:      "happy path returns the trimmed NEVR",
			stdout:    rpmTestNEVR + "\n",
			stderr:    "",
			exitCode:  0,
			wantOwner: rpmTestNEVR,
			wantErr:   nil,
		},
		{
			name:      "unknown file translates to ErrPackageUnknown",
			stdout:    "file /usr/bin/wat is not owned by any package\n",
			stderr:    "",
			exitCode:  1,
			wantOwner: "",
			wantErr:   ErrPackageUnknown,
		},
		{
			name:      "unknown file via stderr also translates to ErrPackageUnknown",
			stdout:    "",
			stderr:    "error: file /usr/bin/wat is not owned by any package\n",
			exitCode:  1,
			wantOwner: "",
			wantErr:   ErrPackageUnknown,
		},
	}

	pm := newRPM()
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()

			runner := newRPMOwnerRunner(rpmTestPath, tc.stdout, tc.stderr, tc.exitCode, tc.wantErr != nil)

			owner, err := pm.OwnerOf(context.Background(), runner, rpmTestPath)
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

// TestRPM_OwnerOf_RecordsCommandShape pins the exact subprocess
// invocation: command name "rpm", first arg Trusted("-qf"), second
// arg Untrusted(path). This is the same security regression test
// pattern as kernelmod's command-shape assertions: if a future
// refactor retypes the path arg as Trusted, the Untrusted-input
// validation (UntrustedArgRE + flag-injection guard) is bypassed,
// re-opening the shell-injection class of vulnerability that
// internal/exec was built to close.
func TestRPM_OwnerOf_RecordsCommandShape(t *testing.T) {
	t.Parallel()

	pm := newRPM()
	runner := newRPMOwnerRunner(rpmTestPath, rpmTestNEVR+"\n", "", 0, false)

	if _, err := pm.OwnerOf(context.Background(), runner, rpmTestPath); err != nil {
		t.Fatalf("OwnerOf() error: %v", err)
	}

	if got, want := len(runner.Calls), 1; got != want {
		t.Fatalf("len(runner.Calls) = %d, want %d", got, want)
	}
	call := runner.Calls[0]
	if got, want := call.Name, "rpm"; got != want {
		t.Errorf("call.Name = %q, want %q", got, want)
	}
	if got, want := len(call.Args), 2; got != want {
		t.Fatalf("len(call.Args) = %d, want %d", got, want)
	}

	flag, ok := call.Args[0].(exec.Trusted)
	if !ok {
		t.Errorf("call.Args[0] type = %T, want exec.Trusted", call.Args[0])
	}
	if string(flag) != "-qf" {
		t.Errorf("call.Args[0] = %q, want %q", flag, "-qf")
	}

	pathArg, ok := call.Args[1].(exec.Untrusted)
	if !ok {
		t.Errorf("call.Args[1] type = %T, want exec.Untrusted", call.Args[1])
	}
	if string(pathArg) != rpmTestPath {
		t.Errorf("call.Args[1] = %q, want %q", pathArg, rpmTestPath)
	}
}

// TestRPM_OwnerOf_RejectsArgumentInjection pins the
// shell-metacharacter-injection guard at the integrity-package
// boundary: an Untrusted path containing ';' fails fast with
// ErrInvalidArg and the FakeRunner records ZERO calls. The same
// rationale as kernelmod: relying on internal/exec's runner to
// validate is insufficient because FakeRunner does NOT validate by
// design (it's a recorder).
func TestRPM_OwnerOf_RejectsArgumentInjection(t *testing.T) {
	t.Parallel()

	pm := newRPM()
	runner := &exec.FakeRunner{}
	_, err := pm.OwnerOf(context.Background(), runner, "/usr/bin/su;rm -rf /")
	if !errors.Is(err, exec.ErrInvalidArg) {
		t.Fatalf("OwnerOf() error = %v, want errors.Is(_, exec.ErrInvalidArg)", err)
	}
	if got := len(runner.Calls); got != 0 {
		t.Errorf("len(runner.Calls) = %d, want 0 (validation must short-circuit)", got)
	}
}

// TestRPM_Verify_Parsing pins the per-flag interpretation of
// `rpm -V` output. The single table covers every shape the spec §11
// integrity.su_binary check has to handle: a clean package, a
// hash+size+mtime mismatch on the queried path, a mismatch on a
// SIBLING file in the same package, a config-file marker, and an
// empty package output (no findings at all). A regression here would
// either (a) miss a real tamper finding, or (b) flag a clean file as
// tampered — both are spec-§11 contract violations.
func TestRPM_Verify_Parsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		stdout   string
		want     VerifyResult
		exitCode int
		failExit bool
	}{
		{
			name:     "clean package — silent stdout, exit 0",
			stdout:   "",
			exitCode: 0,
			failExit: false,
			want: VerifyResult{
				Backend: "rpm",
				Path:    rpmTestPath,
				Package: rpmTestNEVR,
			},
		},
		{
			name:     "hash+size+mtime mismatch on queried path",
			stdout:   "S.5....T.    " + rpmTestPath + "\n",
			exitCode: 1,
			failExit: true,
			want: VerifyResult{
				Backend:      "rpm",
				Path:         rpmTestPath,
				Package:      rpmTestNEVR,
				RawOutput:    "S.5....T.    " + rpmTestPath + "\n",
				HashMismatch: true,
				SizeChanged:  true,
				MTimeChanged: true,
			},
		},
		{
			name:     "mismatch on sibling file goes into UnverifiedReasons; queried path stays clean",
			stdout:   "S.5....T.    /usr/bin/other\n",
			exitCode: 1,
			failExit: true,
			want: VerifyResult{
				Backend:           "rpm",
				Path:              rpmTestPath,
				Package:           rpmTestNEVR,
				RawOutput:         "S.5....T.    /usr/bin/other\n",
				UnverifiedReasons: []string{"additional file changed in package: /usr/bin/other (flags=S.5....T.)"},
			},
		},
		{
			name:     "config file marker on queried path is informational only — flag flips also recorded",
			stdout:   "S.5....T.  c " + rpmTestPath + "\n",
			exitCode: 1,
			failExit: true,
			want: VerifyResult{
				Backend:           "rpm",
				Path:              rpmTestPath,
				Package:           rpmTestNEVR,
				RawOutput:         "S.5....T.  c " + rpmTestPath + "\n",
				HashMismatch:      true,
				SizeChanged:       true,
				MTimeChanged:      true,
				UnverifiedReasons: []string{"config file marker on queried path: " + rpmTestPath},
			},
		},
		{
			name:     "config file marker on sibling — recorded in UnverifiedReasons with c annotation",
			stdout:   "S.5....T.  c /etc/foo.conf\n",
			exitCode: 1,
			failExit: true,
			want: VerifyResult{
				Backend:           "rpm",
				Path:              rpmTestPath,
				Package:           rpmTestNEVR,
				RawOutput:         "S.5....T.  c /etc/foo.conf\n",
				UnverifiedReasons: []string{"additional config file changed in package: /etc/foo.conf (flags=S.5....T.)"},
			},
		},
		{
			name:     "permissions+owner+group mismatch on queried path",
			stdout:   ".M...UG..    " + rpmTestPath + "\n",
			exitCode: 1,
			failExit: true,
			want: VerifyResult{
				Backend:      "rpm",
				Path:         rpmTestPath,
				Package:      rpmTestNEVR,
				RawOutput:    ".M...UG..    " + rpmTestPath + "\n",
				PermsChanged: true,
				OwnerChanged: true,
				GroupChanged: true,
			},
		},
	}

	pm := newRPM()
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()

			runner := newRPMVerifyRunner(rpmTestNEVR, tc.stdout, tc.exitCode, tc.failExit)

			got, err := pm.Verify(context.Background(), runner, rpmTestNEVR, rpmTestPath)
			// rpm -V exits non-zero on any deviation; the partial-
			// output contract guarantees we still get a parsed result
			// alongside any wrapped error.
			if tc.failExit {
				if err == nil {
					subT.Fatalf("Verify() error = nil, want non-nil (rpm -V exits non-zero on deviations)")
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

// TestRPM_Verify_RejectsArgumentInjection pins the Untrusted-package
// validation guard at the rpm Verify boundary. A package name with
// shell metacharacters fails fast with ErrInvalidArg and the
// FakeRunner records ZERO calls. Same security regression-guard
// pattern as TestRPM_OwnerOf_RejectsArgumentInjection.
func TestRPM_Verify_RejectsArgumentInjection(t *testing.T) {
	t.Parallel()

	pm := newRPM()
	runner := &exec.FakeRunner{}
	_, err := pm.Verify(context.Background(), runner, "util-linux-core;rm -rf /", rpmTestPath)
	if !errors.Is(err, exec.ErrInvalidArg) {
		t.Fatalf("Verify() error = %v, want errors.Is(_, exec.ErrInvalidArg)", err)
	}
	if got := len(runner.Calls); got != 0 {
		t.Errorf("len(runner.Calls) = %d, want 0 (validation must short-circuit)", got)
	}
}

// TestRPM_Verify_PropagatesGenericRunnerError pins the wrapping
// contract for generic (non-resolution) runner errors: the returned
// error wraps the underlying via %w so errors.Is still works AND
// includes the integrity context prefix so audit logs identify the
// failing operation.
func TestRPM_Verify_PropagatesGenericRunnerError(t *testing.T) {
	t.Parallel()

	pm := newRPM()
	wantErr := errors.New("integrity-test: rpm simulated failure")
	key := "rpm -V " + rpmTestNEVR
	runner := &exec.FakeRunner{
		Errors: map[string]error{key: wantErr},
	}

	_, err := pm.Verify(context.Background(), runner, rpmTestNEVR, rpmTestPath)
	if !errors.Is(err, wantErr) {
		t.Fatalf("Verify() error = %v, want errors.Is(_, %v)", err, wantErr)
	}
	const wantPrefix = "integrity: rpm -V " + rpmTestNEVR
	if got := err.Error(); !strings.Contains(got, wantPrefix) {
		t.Errorf("error message = %q, want substring %q", got, wantPrefix)
	}
}

// newRPMOwnerRunner builds a FakeRunner that returns the given
// stdout/stderr/exitCode for the canonical `rpm -qf <path>` invocation.
// Centralizing the key construction here keeps the per-table-row test
// rows focused on the parser semantics rather than on FakeRunner
// plumbing — and any future change to the command shape (e.g., adding
// `--queryformat`) is a single edit.
func newRPMOwnerRunner(path, stdout, stderr string, exitCode int, returnErr bool) *exec.FakeRunner {
	key := "rpm -qf " + path
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
			key: errors.New("rpm exited non-zero"),
		}
	}
	return r
}

// newRPMVerifyRunner builds a FakeRunner that returns the given
// stdout/exitCode for the canonical `rpm -V <pkg>` invocation. failExit
// triggers a synthetic non-nil error so the partial-output contract
// is exercised — rpm -V always exits non-zero on any deviation.
func newRPMVerifyRunner(pkg, stdout string, exitCode int, failExit bool) *exec.FakeRunner {
	key := "rpm -V " + pkg
	r := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			key: {
				Stdout:   []byte(stdout),
				ExitCode: exitCode,
			},
		},
	}
	if failExit {
		r.Errors = map[string]error{
			key: errors.New("rpm exited non-zero"),
		}
	}
	return r
}
