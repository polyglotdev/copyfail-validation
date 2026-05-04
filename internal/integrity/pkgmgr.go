// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// PkgMgr is the package-manager backend that the integrity.su_binary
// check uses to (a) ask "which package owns this path?" and (b) verify
// the file against that package's manifest. Two implementations ship
// with this package: the rpm backend (newRPM) and the dpkg backend
// (newDPKG). Detect picks one at runtime.
//
// The interface is deliberately small. Both methods take a runner so
// tests inject exec.FakeRunner without shelling out and production
// callers wire exec.NewOSRunner. The context propagates the validator-
// wide deadline (spec §5 concurrency model) so a hung subprocess does
// not block the whole run.
type PkgMgr interface {
	// Name is the backend identifier — "rpm" or "dpkg" — recorded
	// verbatim in VerifyResult.Backend so audit reports can identify
	// which tool produced the verdict. Spec §11 shows the value
	// surfacing as Evidence["backend"] in the integrity.su_binary
	// check's evidence blob.
	Name() string

	// OwnerOf returns the package identifier that owns path: the NEVR
	// (Name-Epoch-Version-Release-Arch) for rpm, or the package name
	// (without architecture qualifier) for dpkg. Returns ErrPackageUnknown
	// when no installed package claims the file — callers SHOULD treat
	// that as a check-specific outcome (manually placed file) rather
	// than a backend failure.
	OwnerOf(ctx context.Context, runner exec.Runner, path string) (string, error)

	// Verify runs the backend's manifest check (rpm -V <pkg> /
	// debsums -s <pkg>) for the named package and returns a
	// VerifyResult whose flags identify the queried path's deviations
	// from the package manifest. The Path field of the returned
	// VerifyResult is the path the caller passed in; Verify itself
	// does not derive the path from the output (the output may list
	// many files; only the row matching the input path is recorded
	// into the boolean fields).
	Verify(ctx context.Context, runner exec.Runner, pkg string, path string) (VerifyResult, error)
}

// VerifyResult is the canonical, backend-agnostic shape that every
// PkgMgr.Verify returns. The integrity.su_binary check writes the
// fields directly into Evidence, and the boolean flags are signed
// positive (true means there IS a problem) so callers use a single
// `if !result.Clean()` check rather than negating each field.
//
// RawOutput preserves the verbatim subprocess stdout (or stderr, for
// debsums) so the check's Evidence captures forensic state even when
// the parser's flag interpretation was incomplete. Field order is
// laid out for govet's fieldalignment pass (string and slice headers
// first, fixed-width bools at the tail).
type VerifyResult struct {
	// Backend is the PkgMgr.Name() value of the backend that produced
	// this result. Recorded for symmetry with Evidence["backend"] in
	// spec §11 — callers reading the result do not need a separate
	// reference to the backend instance.
	Backend string

	// Path is the queried path (the value passed to PkgMgr.Verify).
	// Echoed into the result so consumers serializing the struct have
	// a single self-contained record.
	Path string

	// Package is the package identifier resolved by PkgMgr.OwnerOf
	// (or supplied directly). For rpm this is the NEVR; for dpkg this
	// is the package name.
	Package string

	// RawOutput preserves the verbatim subprocess output that the
	// parser interpreted. For rpm this is `rpm -V` stdout; for dpkg
	// this is `debsums -s` stderr (debsums prints mismatches to
	// stderr, not stdout, by design — the `-s` flag means "silent on
	// match" but does not redirect mismatches).
	RawOutput string

	// UnverifiedReasons captures backend-specific notes that do NOT
	// fit one of the boolean flags but still indicate the result is
	// not entirely clean. Examples include rpm's "c" config-file
	// marker (an informational annotation, not a hash mismatch) and
	// "this verify run also reported deviations on other files in the
	// same package" (recorded so audit logs do not lose that signal).
	// Empty when nothing was anomalous beyond the boolean flags.
	UnverifiedReasons []string

	// HashMismatch is true when the backend reported a content-hash
	// (MD5 for rpm, MD5 for debsums) deviation for the queried path.
	// This is the strongest tamper signal of any flag.
	HashMismatch bool

	// SizeChanged is true when the backend reported a file-size
	// deviation. Always set alongside HashMismatch in practice (if
	// the size differs, the hash necessarily differs) but the
	// individual flag is recorded so consumers can distinguish a
	// hash-only flag (e.g., in-place truncation that was undone) from
	// a true content rewrite.
	SizeChanged bool

	// MTimeChanged is true when the backend reported an mtime
	// deviation. Note from spec §5: a clean hash with an mtime delta
	// is a Pass with the delta noted in Evidence — this flag exists
	// so consumers can record the delta even when HashMismatch is
	// false.
	MTimeChanged bool

	// PermsChanged is true when the backend reported a mode (file
	// permissions) deviation.
	PermsChanged bool

	// OwnerChanged is true when the backend reported a UID (file
	// owner) deviation.
	OwnerChanged bool

	// GroupChanged is true when the backend reported a GID (file
	// group) deviation.
	GroupChanged bool
}

// Clean reports whether the file matches the package's manifest in
// every observable way. Returns true iff every boolean flag is false
// AND UnverifiedReasons is empty.
//
// The latter clause is critical: a non-empty UnverifiedReasons slice
// indicates SOMETHING was anomalous (e.g., a config-file marker, or a
// deviation on a sibling file in the same package) even when the
// boolean flags do not apply. Treating Clean as "all bools false"
// alone would silently drop those signals.
func (v VerifyResult) Clean() bool {
	if len(v.UnverifiedReasons) > 0 {
		return false
	}
	return !v.HashMismatch &&
		!v.SizeChanged &&
		!v.MTimeChanged &&
		!v.PermsChanged &&
		!v.OwnerChanged &&
		!v.GroupChanged
}

// Detect tries the available backends in order (rpm first, then dpkg)
// and returns the first one whose underlying binary resolves via
// internal/exec.ResolveCommand. Returns ErrNoPkgManager if neither
// backend resolves — callers should treat that as a Skip with reason
// "unsupported package manager" rather than an Error (spec §5
// State-Semantics).
//
// The runner argument is currently unused by Detect itself
// (resolution is a static allowlist + os.Stat check that does not
// need a Runner) but is reserved for future probes that may need to
// invoke the binary (e.g., `rpm --version`) to confirm the backend
// is functional rather than merely installed. Keeping it in the
// signature now avoids a breaking API change later.
func Detect(runner exec.Runner) (PkgMgr, error) {
	return detectWith(runner, exec.ResolveCommand)
}

// resolverFunc is the test seam for Detect. The production resolver is
// exec.ResolveCommand; tests inject a stub that returns whichever set
// of commands they want to model as "available" on the host. Without
// this seam Detect would only be testable on a host that actually has
// rpm or dpkg installed — which excludes the macOS / minimal-container
// development environments and CI runners we ship from.
type resolverFunc func(name string) (string, error)

// detectWith is the resolver-injected implementation of Detect.
// Exported only via the wrapper above; tests in this package call
// detectWith directly. The resolver is invoked synchronously (no
// goroutine fan-out) because there are only two probes and the
// per-probe cost is a single os.Stat call.
func detectWith(runner exec.Runner, resolve resolverFunc) (PkgMgr, error) {
	_ = runner // reserved for future runtime probes; see Detect godoc.

	// rpm is tried first; see doc.go for the precedence rationale.
	if _, err := resolve("rpm"); err == nil {
		return newRPM(), nil
	}

	if _, err := resolve("dpkg"); err == nil {
		return newDPKG(), nil
	}

	return nil, ErrNoPkgManager
}

// validateUntrustedArg is the package-internal helper that wraps a
// caller-supplied string as exec.Untrusted and validates it before
// the subprocess starts. Mirrors the pattern in kernelmod.DryRunModule:
// validation is invoked at the integrity boundary (not just inside
// the production runner) so the guard stays active when callers wire
// FakeRunner in tests, AND so the runner never records a malicious
// cmd into FakeRunner.Calls. Returns the validated arg on success so
// the caller can place it directly into Cmd.Args.
func validateUntrustedArg(s string) (exec.Arg, error) {
	arg := exec.Untrusted(s)
	if err := exec.Validate(arg); err != nil {
		return nil, err
	}
	return arg, nil
}

// classifyOwnerErr reports whether the result of an `OwnerOf`-class
// subprocess (rpm -qf / dpkg -S) indicates "the file isn't owned by
// any package". Both rpm and dpkg surface that condition by (a)
// exiting non-zero AND (b) writing a recognizable string to stderr
// (or, for rpm older than ~v4.16, stdout). The match string is
// supplied per-backend so this single helper handles both.
//
// Returns true when the error matches the unknown-file pattern; the
// caller should return ErrPackageUnknown. Returns false otherwise;
// the caller should wrap and return the original error.
func classifyOwnerErr(runErr error, res exec.Result, marker string) bool {
	if runErr == nil {
		return false
	}
	if marker == "" {
		return false
	}
	// rpm writes the "not owned by any package" message to stdout
	// (yes, stdout) on most versions; dpkg writes "no path found
	// matching pattern" to stderr. Check both streams so the helper
	// stays correct across backends.
	return strings.Contains(string(res.Stdout), marker) ||
		strings.Contains(string(res.Stderr), marker)
}

// runOwnerOf is the shared subprocess plumbing for both backends'
// OwnerOf implementations. It runs the supplied cmd and translates
// an "unknown package" stderr/stdout marker into ErrPackageUnknown.
// The actual command shape (rpm -qf vs dpkg -S) is built by the
// backend; this helper only owns the run + classify step so both
// backends behave identically with respect to error translation and
// result preservation.
func runOwnerOf(ctx context.Context, runner exec.Runner, cmd exec.Cmd, marker, opLabel string) (exec.Result, error) {
	res, runErr := runner.Run(ctx, cmd)
	if runErr != nil {
		if classifyOwnerErr(runErr, res, marker) {
			return res, fmt.Errorf("integrity: %s: %w", opLabel, ErrPackageUnknown)
		}
		return res, fmt.Errorf("integrity: %s: %w", opLabel, runErr)
	}
	return res, nil
}

// errIsCommandResolution reports whether err is one of exec's
// command-resolution sentinels (ErrCommandDenied or ErrCommandNotFound).
// Used by the backends' Verify methods so a missing tool (debsums,
// in particular) surfaces as a wrapped resolution error and the
// caller can Skip cleanly rather than treating an "absent verify
// tool" as an Error.
func errIsCommandResolution(err error) bool {
	return errors.Is(err, exec.ErrCommandDenied) || errors.Is(err, exec.ErrCommandNotFound)
}
