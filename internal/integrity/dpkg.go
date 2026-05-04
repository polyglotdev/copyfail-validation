// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package integrity

import (
	"context"
	"fmt"
	"strings"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// dpkgBackendName is the value PkgMgr.Name returns for the dpkg
// implementation.
const dpkgBackendName = "dpkg"

// dpkgUnknownMarker is the substring `dpkg-query` (the implementation
// behind `dpkg -S`) prints to stderr when the queried path matches no
// installed package. Verbatim text from `dpkg-query --search`.
const dpkgUnknownMarker = "no path found matching pattern"

// debsumsChangedPrefix is the prefix of the per-file mismatch line
// debsums prints to stderr (NOT stdout) when invoked with `-s`. The
// `-s` flag means "silent on match" but mismatches always go to
// stderr — a quirk of debsums's design that this package documents
// here so future maintainers do not "fix" the stderr capture into
// stdout and silently break detection.
const debsumsChangedPrefix = "debsums: changed file "

// dpkgVerify is the in-package implementation of PkgMgr for the dpkg
// backend.
type dpkgVerify struct{}

// newDPKG returns the dpkg-backend PkgMgr instance. Used internally
// by Detect.
func newDPKG() PkgMgr { return dpkgVerify{} }

// NewDPKG returns the dpkg-backend PkgMgr instance directly, bypassing
// Detect's auto-selection. Production code SHOULD prefer Detect — it
// returns the right backend for the host. NewDPKG is exported so
// integration tests, forensic tools, and godoc examples can pin
// behavior to a specific backend without depending on Detect's
// host-resolution result. The returned value still requires the dpkg
// and debsums binaries to be on the allowlist when the underlying
// runner actually invokes them; calling NewDPKG on a host without
// either is harmless until the first OwnerOf/Verify call.
func NewDPKG() PkgMgr { return newDPKG() }

// Name returns "dpkg".
func (dpkgVerify) Name() string { return dpkgBackendName }

// OwnerOf invokes `dpkg -S <path>` and returns the package name from
// the parsed output. dpkg's output format is `pkg: /full/path` (or
// `pkg:arch: /full/path` on multi-arch systems); we return the first
// colon-separated field verbatim. Multi-arch qualifiers (`pkg:amd64`)
// are kept in the returned string when present — they identify the
// concrete package instance the file came from, which is the right
// granularity for `Verify`.
//
// Errors:
//   - exec.ErrInvalidArg if path fails Untrusted validation.
//   - ErrPackageUnknown if dpkg reports the path has no owning package.
//   - exec.ErrCommandDenied / exec.ErrCommandNotFound if dpkg is not
//     on the allowlist or not installed.
//   - Any other wrapped runner error.
func (dpkgVerify) OwnerOf(ctx context.Context, runner exec.Runner, path string) (string, error) {
	pathArg, err := validateUntrustedArg(path)
	if err != nil {
		return "", fmt.Errorf("integrity: dpkg -S %q: %w", path, err)
	}

	cmd := exec.Cmd{
		Name: "dpkg",
		Args: []exec.Arg{
			exec.Trusted("-S"),
			pathArg,
		},
	}

	res, err := runOwnerOf(ctx, runner, cmd, dpkgUnknownMarker, fmt.Sprintf("dpkg -S %s", path))
	if err != nil {
		return "", err
	}

	owner, ok := parseDPKGOwner(res.Stdout, path)
	if !ok {
		return "", fmt.Errorf("integrity: dpkg -S %s: unable to parse owner from output: %w", path, ErrPackageUnknown)
	}
	return owner, nil
}

// Verify invokes `debsums -s <pkg>` and parses the captured stderr
// into a VerifyResult. Lines reporting on the queried path set
// HashMismatch=true; lines for other files in the same package go
// into UnverifiedReasons.
//
// debsums verifies MD5 manifests; it does not surface size, mtime,
// permissions, or ownership deviations. The corresponding boolean
// flags on VerifyResult are therefore always false for this backend
// (intentional — the spec §11 evidence shape is content-only for
// dpkg, by design).
//
// `debsums` is NOT installed by default on Debian/Ubuntu; it is a
// separate package. When debsums is missing, the runner returns
// exec.ErrCommandNotFound and Verify wraps it so the caller can Skip
// cleanly. We deliberately do NOT silently fall back to "no
// mismatches" — that would produce a false sense of security on the
// large set of hosts where debsums is not installed.
//
// Errors:
//   - exec.ErrInvalidArg if pkg fails Untrusted validation.
//   - exec.ErrCommandDenied / exec.ErrCommandNotFound if debsums is
//     not on the allowlist or not installed.
//   - Any other wrapped runner error (the VerifyResult is still
//     returned with whatever was parseable).
func (dpkgVerify) Verify(ctx context.Context, runner exec.Runner, pkg string, path string) (VerifyResult, error) {
	pkgArg, err := validateUntrustedArg(pkg)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("integrity: debsums -s %q: %w", pkg, err)
	}

	cmd := exec.Cmd{
		Name: "debsums",
		Args: []exec.Arg{
			exec.Trusted("-s"),
			pkgArg,
		},
	}

	res, runErr := runner.Run(ctx, cmd)

	// debsums prints mismatches to STDERR (the `-s` flag silences
	// matches but mismatches still go to stderr). Parse stderr, not
	// stdout — and capture stderr verbatim into RawOutput because
	// that is the audit-relevant stream for this backend.
	result := parseDebsums(res.Stderr, pkg, path)

	if runErr != nil {
		// debsums exits non-zero when ANY file in the package fails
		// verification. We still return the parsed result alongside
		// the wrapped error so audit logs preserve the evidence.
		// "Tool not installed" is differentiated so callers can Skip.
		if errIsCommandResolution(runErr) {
			return result, fmt.Errorf("integrity: debsums -s %s: %w", pkg, runErr)
		}
		return result, fmt.Errorf("integrity: debsums -s %s: %w", pkg, runErr)
	}

	return result, nil
}

// parseDPKGOwner extracts the package identifier from a single
// `dpkg -S` output line of the form `pkg: /full/path` (or
// `pkg:arch: /full/path` on multi-arch).
//
// Returns ok=false when the line cannot be parsed (unexpected format,
// or a multi-line response we cannot map to the queried path). The
// queried path is supplied so a future enhancement can disambiguate
// among multiple matching lines, though dpkg's output for an exact
// path query is always a single line in practice.
func parseDPKGOwner(stdout []byte, _ string) (string, bool) {
	for _, raw := range strings.Split(string(stdout), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// dpkg output is "pkg: /path" — split on the FIRST ": "
		// rather than the first colon because multi-arch package
		// names carry an internal colon (e.g., "libfoo:amd64").
		idx := strings.Index(line, ": ")
		if idx <= 0 {
			continue
		}
		owner := strings.TrimSpace(line[:idx])
		if owner == "" {
			continue
		}
		return owner, true
	}
	return "", false
}

// parseDebsums scans the per-line stderr output of `debsums -s` and
// folds it into a VerifyResult. Each `debsums: changed file <path>
// (from <pkg> package)` line either flips HashMismatch=true (when
// path matches the queried path) or appends to UnverifiedReasons
// (when path is a sibling in the same package).
//
// debsums does not report size, mtime, permission, or ownership
// deviations — only content-hash mismatches. The struct's other
// boolean flags are therefore always false for this backend.
func parseDebsums(stderr []byte, pkg, queriedPath string) VerifyResult {
	result := VerifyResult{
		Backend:   dpkgBackendName,
		Package:   pkg,
		Path:      queriedPath,
		RawOutput: string(stderr),
	}

	for _, raw := range strings.Split(string(stderr), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, debsumsChangedPrefix) {
			// Other debsums diagnostic lines (e.g., "no md5sums
			// for") go into UnverifiedReasons so the audit log
			// preserves them; they are informational.
			result.UnverifiedReasons = append(result.UnverifiedReasons,
				fmt.Sprintf("debsums diagnostic: %s", trimmed))
			continue
		}

		// "debsums: changed file /full/path (from <pkg> package)"
		// We only need the path between the prefix and the trailing
		// " (from " separator.
		rest := strings.TrimPrefix(trimmed, debsumsChangedPrefix)
		pathEnd := strings.Index(rest, " (from ")
		if pathEnd < 0 {
			// Malformed line; record verbatim so the audit log
			// preserves it but do not infer any flags.
			result.UnverifiedReasons = append(result.UnverifiedReasons,
				fmt.Sprintf("debsums malformed line: %s", trimmed))
			continue
		}
		linePath := rest[:pathEnd]

		if linePath == queriedPath {
			result.HashMismatch = true
		} else {
			result.UnverifiedReasons = append(result.UnverifiedReasons,
				fmt.Sprintf("additional file changed in package: %s", linePath))
		}
	}

	return result
}
