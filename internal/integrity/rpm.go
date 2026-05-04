// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"context"
	"fmt"
	"strings"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// rpmBackendName is the value PkgMgr.Name returns for the rpm
// implementation. Recorded verbatim into VerifyResult.Backend and into
// Evidence["backend"] so audit consumers can identify the backend at
// the granularity of the spec §11 evidence shape.
const rpmBackendName = "rpm"

// rpmUnknownMarker is the substring rpm prints (to stdout, on most
// versions) when -qf cannot identify an owning package. Both rpm
// >=4.16 and older Amazon Linux variants emit this string verbatim;
// classifying on it converts the non-zero exit into ErrPackageUnknown.
const rpmUnknownMarker = "is not owned by any package"

// rpmVerifyFlagLen is the fixed width of the per-attribute flag
// prefix in `rpm -V` output (e.g., "S.5....T.") — see the per-position
// table in the godoc on parseRPMVerify. Lines whose first whitespace-
// separated field is not exactly this width are malformed and silently
// ignored (rpm itself never emits short prefixes; truncation would
// imply terminal corruption, not a real verification finding).
const rpmVerifyFlagLen = 9

// rpmVerify is the in-package implementation of PkgMgr for the rpm
// backend. The struct is deliberately empty — all per-call state
// lives on the runner and the cmd. Holding zero state lets multiple
// goroutines share one PkgMgr instance, which the spec §5
// concurrency model relies on.
type rpmVerify struct{}

// newRPM returns the rpm-backend PkgMgr instance. Used internally by
// Detect.
func newRPM() PkgMgr { return rpmVerify{} }

// NewRPM returns the rpm-backend PkgMgr instance directly, bypassing
// Detect's auto-selection. Production code SHOULD prefer Detect — it
// returns the right backend for the host. NewRPM is exported so
// integration tests, forensic tools, and godoc examples can pin
// behavior to a specific backend without depending on Detect's
// host-resolution result. The returned value still requires the rpm
// binary to be on the allowlist when the underlying runner actually
// invokes it; calling NewRPM on a host without rpm is harmless until
// the first OwnerOf/Verify call.
func NewRPM() PkgMgr { return newRPM() }

// Name returns "rpm".
func (rpmVerify) Name() string { return rpmBackendName }

// OwnerOf invokes `rpm -qf <path>` and returns the trimmed NEVR string
// from the single output line on success. Returns ErrPackageUnknown
// when rpm reports the path is not owned by any package (translated
// from the non-zero exit + stdout marker; see classifyOwnerErr).
//
// Errors:
//   - exec.ErrInvalidArg if path fails Untrusted validation.
//   - ErrPackageUnknown if rpm reports the path has no owning package.
//   - exec.ErrCommandDenied / exec.ErrCommandNotFound if rpm is not on
//     the allowlist or not installed.
//   - Any other wrapped runner error.
func (rpmVerify) OwnerOf(ctx context.Context, runner exec.Runner, path string) (string, error) {
	pathArg, err := validateUntrustedArg(path)
	if err != nil {
		return "", fmt.Errorf("integrity: rpm -qf %q: %w", path, err)
	}

	cmd := exec.Cmd{
		Name: "rpm",
		Args: []exec.Arg{
			exec.Trusted("-qf"),
			pathArg,
		},
	}

	res, err := runOwnerOf(ctx, runner, cmd, rpmUnknownMarker, fmt.Sprintf("rpm -qf %s", path))
	if err != nil {
		return "", err
	}

	owner := strings.TrimSpace(string(res.Stdout))
	if owner == "" {
		// rpm exited zero but produced no stdout. This should never
		// happen in practice — a successful -qf always prints the
		// NEVR — but we surface the empty case as ErrPackageUnknown
		// rather than an empty success so callers do not treat ""
		// as a valid package identifier.
		return "", fmt.Errorf("integrity: rpm -qf %s: empty owner from successful exit: %w", path, ErrPackageUnknown)
	}
	return owner, nil
}

// Verify invokes `rpm -V <pkg>` and parses the captured stdout into a
// VerifyResult keyed on the queried path. Lines that report on files
// other than path are recorded into UnverifiedReasons rather than
// promoted into the boolean flags — the caller asked about ONE path,
// and silently OR-ing other-file deviations into the booleans would
// produce false-positive tamper verdicts on the queried file.
//
// `rpm -V` exits zero when the package matches and non-zero when ANY
// file in the package has a deviation. We do not treat the non-zero
// exit as a fatal error — the partial-output contract (mirrored from
// kernelmod.DryRunModule) returns the parsed VerifyResult AND the
// wrapped error so callers receive evidence even on partial failure.
//
// Errors:
//   - exec.ErrInvalidArg if pkg fails Untrusted validation.
//   - exec.ErrCommandDenied / exec.ErrCommandNotFound if rpm is not on
//     the allowlist or not installed.
//   - Any other wrapped runner error (the VerifyResult is still
//     returned with whatever was parseable).
func (rpmVerify) Verify(ctx context.Context, runner exec.Runner, pkg string, path string) (VerifyResult, error) {
	pkgArg, err := validateUntrustedArg(pkg)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("integrity: rpm -V %q: %w", pkg, err)
	}

	cmd := exec.Cmd{
		Name: "rpm",
		Args: []exec.Arg{
			exec.Trusted("-V"),
			pkgArg,
		},
	}

	res, runErr := runner.Run(ctx, cmd)

	// Always parse whatever stdout we captured. `rpm -V` exits
	// non-zero on ANY mismatch but the stdout still describes the
	// findings — returning the parsed result alongside the error
	// preserves evidence for audit logs.
	result := parseRPMVerify(res.Stdout, pkg, path)

	if runErr != nil {
		// Distinguish the "tool not installed" cases so callers can
		// Skip cleanly. Other failures (timeout, generic exit) are
		// wrapped so callers see the full chain via errors.Is.
		if errIsCommandResolution(runErr) {
			return result, fmt.Errorf("integrity: rpm -V %s: %w", pkg, runErr)
		}
		// rpm -V exits non-zero on every mismatch; that exit is
		// expected, not a backend failure. We still wrap it so the
		// caller has the option of treating it as a soft signal —
		// but the parsed result already captured the finding, so the
		// wrapped error is informational rather than load-bearing.
		return result, fmt.Errorf("integrity: rpm -V %s: %w", pkg, runErr)
	}

	return result, nil
}

// parseRPMVerify scans the per-line output of `rpm -V` and folds the
// rows into a VerifyResult. The line whose path matches the queried
// path is recorded into the boolean flags; rows for other paths in
// the same package are recorded into UnverifiedReasons. The "c"
// configuration-file marker is informational and never changes the
// boolean flags but always lands in UnverifiedReasons so audit logs
// preserve it.
//
// Output line format (per `man rpm` "VERIFY OPTIONS"):
//
//	[SM5DLUGTPc.] [c] /full/path
//
// Position 1 (S): Size differs
// Position 2 (M): Mode differs (perms)
// Position 3 (5): MD5 hash differs
// Position 4 (D): Device major/minor differs (irrelevant for files)
// Position 5 (L): Symlink target differs
// Position 6 (U): Owner UID differs
// Position 7 (G): Group GID differs
// Position 8 (T): mtime differs
// Position 9 (P): Capabilities differ
//
// Each position holds either the marker letter or '.' (no deviation).
// The optional "c" marker between flags and path indicates a config
// file. Whitespace separation between flags, marker, and path varies
// across rpm versions; we use strings.Fields to be tolerant.
func parseRPMVerify(stdout []byte, pkg, queriedPath string) VerifyResult {
	result := VerifyResult{
		Backend:   rpmBackendName,
		Package:   pkg,
		Path:      queriedPath,
		RawOutput: string(stdout),
	}

	for _, raw := range strings.Split(string(stdout), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		flags, marker, linePath, ok := splitRPMVerifyLine(line)
		if !ok {
			continue
		}

		if linePath == queriedPath {
			applyRPMFlags(&result, flags)
			if marker == "c" {
				result.UnverifiedReasons = append(result.UnverifiedReasons,
					fmt.Sprintf("config file marker on queried path: %s", linePath))
			}
		} else {
			// Record other-file deviations so audit logs preserve the
			// signal even though they do not flip the queried-path
			// boolean flags.
			if marker == "c" {
				result.UnverifiedReasons = append(result.UnverifiedReasons,
					fmt.Sprintf("additional config file changed in package: %s (flags=%s)", linePath, flags))
			} else {
				result.UnverifiedReasons = append(result.UnverifiedReasons,
					fmt.Sprintf("additional file changed in package: %s (flags=%s)", linePath, flags))
			}
		}
	}

	return result
}

// splitRPMVerifyLine separates one rpm -V output line into its three
// logical parts: the flag prefix (always rpmVerifyFlagLen characters),
// the optional "c" config-file marker, and the path.
//
// Returns ok=false when the line cannot be parsed (too few fields, or
// the flag prefix is not the expected width). Tolerant of variable
// whitespace between the parts because rpm versions differ on whether
// the separator is one space, multiple spaces, or a tab.
func splitRPMVerifyLine(line string) (flags, marker, path string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", "", "", false
	}

	candidate := fields[0]
	if len(candidate) != rpmVerifyFlagLen {
		// Some rpm versions print "missing" lines as "missing  /path"
		// — skip those; they belong in a separate "missing files"
		// signal that is not part of the v0.1 evidence shape.
		return "", "", "", false
	}

	if len(fields) >= 3 && fields[1] == "c" {
		return candidate, "c", fields[2], true
	}
	return candidate, "", fields[1], true
}

// applyRPMFlags flips the boolean flags on result for each marker
// position in flags. Positions are documented above parseRPMVerify.
// The function does NOT touch UnverifiedReasons — that is the
// caller's responsibility (it depends on whether the line was for the
// queried path or a sibling).
func applyRPMFlags(result *VerifyResult, flags string) {
	if len(flags) != rpmVerifyFlagLen {
		// Defensive: splitRPMVerifyLine guarantees the width, but
		// re-checking here means a future caller cannot violate the
		// invariant by skipping the splitter.
		return
	}
	if flags[0] == 'S' {
		result.SizeChanged = true
	}
	if flags[1] == 'M' {
		result.PermsChanged = true
	}
	if flags[2] == '5' {
		result.HashMismatch = true
	}
	// Position 3 (D) and 4 (L) are deliberately not surfaced into the
	// VerifyResult struct: D is meaningless for regular files (only
	// device nodes carry major/minor), and L is the symlink-target
	// flag (su is not a symlink in any supported distro). If a later
	// version of the spec adds device or symlink coverage, extend
	// VerifyResult and this function in lockstep.
	if flags[5] == 'U' {
		result.OwnerChanged = true
	}
	if flags[6] == 'G' {
		result.GroupChanged = true
	}
	if flags[7] == 'T' {
		result.MTimeChanged = true
	}
	// Position 8 (P) — capabilities — is similarly deferred; v0.1
	// evidence does not surface capability deltas.
}
