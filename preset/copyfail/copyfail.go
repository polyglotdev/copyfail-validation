// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail

import (
	"github.com/polyglotdev/copyfail-validation/check"
	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// CVE is the canonical identifier this preset validates.
//
// The string is part of the package's public surface so external tools
// (CI dashboards, SARIF rule IDs, vulnerability scanners) can reference
// the same constant the implementation uses, eliminating one class of
// "the dashboard says CVE-2026-31431 but the code says CVE-2026-31430"
// drift bugs.
const CVE = "CVE-2026-31431"

// DefaultModule is the kernel module name this preset blocks. Override
// via Options.Module if validating a different AF_ALG-family member
// (e.g., "algif_skcipher", "algif_hash", "algif_rng").
//
// algif_aead is the canonical entrypoint for the copyfail vulnerability:
// the kernel-crypto AEAD interface exposed via AF_ALG sockets. Disabling
// the module on hosts that do not require userspace crypto offload is
// the recommended mitigation pending kernel patches.
const DefaultModule = "algif_aead"

// DefaultConfPath is the canonical /etc/modprobe.d/ file path the
// preset expects to find the blocklist directives in. Pick a name that
// sorts EARLIER than 99-* user-overrides so the modprobe.dependency_chain
// check has a meaningful "later wins" surface to scan.
const DefaultConfPath = "/etc/modprobe.d/disable-algif-aead.conf"

// DefaultModprobeDir is the directory the modprobe.dependency_chain
// check scans for override directives. modprobe itself reads from
// several other directories (/lib/modprobe.d, /run/modprobe.d,
// /usr/lib/modprobe.d) but /etc/modprobe.d is the operator-managed
// one and the only one whose contents an audit can reasonably expect
// to control. Override via Options.ModprobeDir for tests or for
// distributions that move the operator dir.
const DefaultModprobeDir = "/etc/modprobe.d"

// Options configures the copyfail preset. The zero Options is valid
// and uses defaults — this is the shape callers want when they invoke
// [All]; richer wiring goes through [AllWithOptions].
type Options struct {
	// Runner is the subprocess runner used by checks that shell out
	// (currently only modprobe.dry_run). Default: [exec.NewOSRunner]().
	// Tests should pass an [exec.FakeRunner] so the bundle is hermetic
	// — the production runner consults the on-disk allowlist and
	// would error on hosts that lack the binary.
	Runner exec.Runner

	// Module is the kernel module name to validate. Default: [DefaultModule].
	// The value flows through to internal/kernelmod where it is wrapped
	// as exec.Untrusted before reaching modprobe; module names containing
	// shell metacharacters fail fast at the kernelmod boundary.
	Module string

	// ConfPath is the absolute path of the /etc/modprobe.d blocklist
	// file. Default: [DefaultConfPath]. Used by modprobe.conf_present
	// (existence) and modprobe.conf_correct (content).
	ConfPath string

	// ModprobeDir is the directory scanned for override directives by
	// the modprobe.dependency_chain check. Default: [DefaultModprobeDir].
	// Tests typically pass a t.TempDir() populated with fixture files.
	ModprobeDir string
}

// All returns the required checks for the copyfail mitigation posture,
// ready for [check.Runner]. Equivalent to [AllWithOptions]([Options]{}).
//
// Per-check files are added in subsequent commits; the slice grows
// from empty (this commit) to the full required-check set as the
// per-check tasks land.
//
// The advisory checks (kernel.version, hostinfo.os_release,
// afalg.no_active_users, integrity.su_binary) are not yet implemented;
// they will land in v0.1.x and appear at the tail of this slice.
func All() []check.Check {
	return AllWithOptions(Options{})
}

// AllWithOptions returns the required checks configured per opts.
// Zero-value fields in opts are filled with their defaults
// ([DefaultModule], [DefaultConfPath], [DefaultModprobeDir],
// [exec.NewOSRunner]).
//
// Per-check files are added in subsequent commits; the returned slice
// grows from empty (this commit) to the full required-check set as
// the per-check tasks land.
func AllWithOptions(opts Options) []check.Check {
	if opts.Module == "" {
		opts.Module = DefaultModule
	}
	if opts.ConfPath == "" {
		opts.ConfPath = DefaultConfPath
	}
	if opts.ModprobeDir == "" {
		opts.ModprobeDir = DefaultModprobeDir
	}
	if opts.Runner == nil {
		opts.Runner = exec.NewOSRunner()
	}

	return []check.Check{
		modprobeConfPresentCheck{confPath: opts.ConfPath},
		modprobeConfCorrectCheck{confPath: opts.ConfPath, module: opts.Module},
		modprobeDryRunCheck{module: opts.Module, runner: opts.Runner},
		modprobeDependencyChainCheck{dir: opts.ModprobeDir, module: opts.Module},
		moduleNotLoadedCheck{module: opts.Module},
	}
}
