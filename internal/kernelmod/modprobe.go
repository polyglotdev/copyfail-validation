// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package kernelmod

import (
	"context"
	"fmt"
	"strings"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// blockedTarget is the canonical "module is blocked" resolution that
// modprobe -n -v prints when an `install <module> /bin/false` directive
// is in effect. Any other target (e.g., "/bin/true",
// "/sbin/modprobe --ignore-install algif_aead") does NOT count as
// blocked — only this exact string does, per spec §11.
//
// The leading "install " is part of modprobe's verbose output format:
// the line is literally `install /bin/false` (with a trailing space the
// caller has already trimmed before comparison).
const blockedTarget = "install /bin/false"

// DryRun is the parsed result of `modprobe -n -v <module>`. The -n
// flag means "don't actually load"; -v means "verbose (print what
// would happen)". The combined output is one or more lines describing
// the resolved load command — a single "install /bin/false" if the
// module is blocked, or one or more "insmod ..." lines if loadable.
//
// Field order is laid out for govet's fieldalignment pass: the two
// 16-byte string headers (ResolvedTo, RawOutput) come first so their
// data-pointers sit in the prefix [0..32), then the 24-byte slice
// header would normally follow — but here we have only the bool
// (Blocked) tail, so the layout is already minimal.
type DryRun struct {
	// ResolvedTo is the FIRST resolved command modprobe would run.
	// For a blocked module the typical value is "install /bin/false".
	// For a loadable module it is the path to insmod plus the .ko file
	// (e.g., "insmod /lib/modules/.../algif_aead.ko"). Empty when
	// modprobe printed nothing (no resolution at all).
	ResolvedTo string

	// RawOutput is the verbatim stdout from modprobe -n -v. Captured
	// for forensic logging into the Result.Evidence["raw_output"]
	// field of the modprobe.dry_run check. May be empty if modprobe
	// produced no output (rare; usually means the module name was
	// unknown to modprobe).
	RawOutput string

	// Blocked reports whether ResolvedTo is exactly "install /bin/false".
	// This is the canonical signal that the module is blocked via an
	// /etc/modprobe.d/*.conf install directive. Other install targets
	// (e.g., "/bin/true", "/sbin/modprobe --ignore-install algif_aead")
	// do NOT count as blocked — only "install /bin/false" is the
	// standard pattern documented in spec §11.
	Blocked bool
}

// DryRunModule invokes `modprobe -n -v <module>` via runner and parses
// the captured stdout into a DryRun. The module argument is wrapped in
// exec.Untrusted and validated BEFORE the subprocess runs — passing a
// module name containing shell metacharacters (e.g., "algif_aead;rm -rf /")
// or starting with '-' fails fast with exec.ErrInvalidArg and never
// reaches modprobe.
//
// Validation is invoked explicitly via exec.Validate at the kernelmod
// boundary rather than relying on the production runner alone. This
// keeps the security guard active when callers wire a Runner that does
// NOT itself validate (notably exec.FakeRunner used in unit tests of
// higher layers), and it short-circuits the call before the runner
// records the malicious cmd into FakeRunner.Calls — so audit logs and
// test assertions both see the rejection at the right layer.
//
// Errors:
//   - exec.ErrInvalidArg if module fails Untrusted validation.
//   - exec.ErrCommandDenied / exec.ErrCommandNotFound if modprobe is
//     not on the allowlist or not installed.
//   - exec.ErrTimeout if the per-Cmd timeout fires.
//   - Any wrapped error from the underlying runner.
//
// The returned DryRun is populated even on a non-zero exit (modprobe
// can produce useful output AND fail), so callers should inspect both
// the DryRun fields and the error.
func DryRunModule(ctx context.Context, runner exec.Runner, module string) (DryRun, error) {
	moduleArg := exec.Untrusted(module)
	if err := exec.Validate(moduleArg); err != nil {
		return DryRun{}, fmt.Errorf("kernelmod: modprobe -n -v %q: %w", module, err)
	}

	cmd := exec.Cmd{
		Name: "modprobe",
		Args: []exec.Arg{
			exec.Trusted("-n"),
			exec.Trusted("-v"),
			moduleArg,
		},
	}

	res, runErr := runner.Run(ctx, cmd)

	// Always attempt to parse whatever stdout we captured. modprobe can
	// emit useful verbose output AND exit non-zero (e.g., when -n -v
	// resolves to "install /bin/false" the underlying install command
	// would exit 1 if actually run; -n suppresses execution but some
	// modprobe versions still report a non-zero exit). Returning the
	// partial DryRun lets callers log the evidence even on error.
	dry := parseDryRun(res.Stdout)

	if runErr != nil {
		return dry, fmt.Errorf("kernelmod: modprobe -n -v %s: %w", module, runErr)
	}

	return dry, nil
}

// parseDryRun extracts the first non-blank line from raw modprobe -n -v
// output and reports whether it matches the canonical blocked target.
// Whitespace at line edges is trimmed because modprobe's verbose
// output is whitespace-sloppy (real output has trailing spaces).
//
// Returns the zero DryRun (with the verbatim raw stdout preserved in
// RawOutput) when stdout contains no non-blank lines.
func parseDryRun(stdout []byte) DryRun {
	dry := DryRun{RawOutput: string(stdout)}

	for _, line := range strings.Split(dry.RawOutput, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		dry.ResolvedTo = trimmed
		dry.Blocked = trimmed == blockedTarget
		return dry
	}

	return dry
}
