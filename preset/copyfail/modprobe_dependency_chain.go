// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/polyglotdev/copyfail-validation/internal/kernelmod"
	"github.com/polyglotdev/copyfail-validation/report"
)

// modprobeDependencyChainCheck implements defense-in-depth on top of
// modprobe.conf_correct. Even when the canonical blocklist file is
// present and well-formed, modprobe processes /etc/modprobe.d/*.conf
// in alphabetical order with "later wins" semantics for install
// directives — a file like 99-experimental.conf that re-points the
// module at /bin/true (or a no-op modprobe wrapper) silently overrides
// the 00-* baseline. The check parses every conf file in the directory,
// finds the LAST install directive for the configured module, and
// fails if it does NOT resolve to /bin/false.
//
// The override pattern is the failure mode the check is designed to
// catch; see internal/kernelmod/testdata/99-override.conf for the
// canonical fixture demonstrating it.
type modprobeDependencyChainCheck struct {
	dir    string
	module string
}

// ID returns the stable, machine-readable identifier of the check.
func (c modprobeDependencyChainCheck) ID() string { return "modprobe.dependency_chain" }

// Title returns the short human-readable name of the check.
func (c modprobeDependencyChainCheck) Title() string {
	return "No later-sorting modprobe.d file overrides the blocklist"
}

// Description returns the long-form explanation of the check.
func (c modprobeDependencyChainCheck) Description() string {
	return "Scans every *.conf file in the modprobe.d directory in alphabetical order " +
		"and verifies the LAST install directive for the configured module resolves to " +
		"/bin/false. modprobe applies later-sorting files on top of earlier ones, so a " +
		"single override directive in 99-experimental.conf silently defeats the baseline " +
		"blocklist. This check is the defense-in-depth complement to modprobe.conf_correct."
}

// Severity returns the operational severity of the check.
func (c modprobeDependencyChainCheck) Severity() report.Severity { return report.SeverityRequired }

// Applicable always reports true.
func (c modprobeDependencyChainCheck) Applicable(_ context.Context) (bool, string) {
	return true, ""
}

// Run scans the modprobe.d directory and returns the override
// posture. The returned [report.Result] always carries CheckID,
// Title, Severity, and StartedAt; the check.Runner stamps DurationMS.
func (c modprobeDependencyChainCheck) Run(_ context.Context) report.Result {
	startedAt := time.Now().UTC()
	res := report.Result{
		CheckID:   c.ID(),
		Title:     c.Title(),
		Severity:  c.Severity(),
		StartedAt: startedAt,
		Evidence: map[string]any{
			"dir":    c.dir,
			"module": c.module,
		},
	}

	directives, err := kernelmod.ParseConfDir(c.dir)
	if err != nil {
		// fs.ErrNotExist on the directory is a hard fail: the operator
		// cannot meaningfully claim the module is blocked when there is
		// no /etc/modprobe.d at all to enforce the block from. Any other
		// error is a probe failure (permission denied, broken symlink,
		// malformed conf in one file) — partial directives may still be
		// populated, so we surface the count for diagnostics.
		res.Evidence["directive_count"] = len(directives)
		if errors.Is(err, fs.ErrNotExist) {
			res.State = report.StateFail
			res.Detail = fmt.Sprintf("%s directory missing", c.dir)
			return res
		}
		res.State = report.StateError
		res.Detail = fmt.Sprintf("scan %s: %v", c.dir, err)
		res.Err = fmt.Errorf("copyfail: scan %s: %w", c.dir, err).Error()
		return res
	}

	res.Evidence["directive_count"] = len(directives)

	lastTarget, lastSource, found := lastInstallDirective(directives, c.module)
	res.Evidence["last_install_target"] = lastTarget
	res.Evidence["last_install_source"] = lastSource

	if !found {
		// No install directive at all — the dependency chain is empty.
		// Without an install rule pointing at /bin/false, the runtime
		// block (modprobe.dry_run) cannot succeed; this check fails
		// rather than passes so the operator knows the override surface
		// is uncovered.
		res.State = report.StateFail
		res.Detail = fmt.Sprintf("no install directive for %q in any file under %s", c.module, c.dir)
		return res
	}

	if lastTarget != requiredInstallTarget {
		res.State = report.StateFail
		res.Detail = fmt.Sprintf("blocklist overridden by later directive in %s (resolves to %q, want %q)",
			lastSource, lastTarget, requiredInstallTarget)
		res.Evidence["override_source"] = lastSource
		res.Evidence["override_target"] = lastTarget
		return res
	}

	res.State = report.StatePass
	res.Detail = fmt.Sprintf("last install directive for %q in %s resolves to %s",
		c.module, lastSource, requiredInstallTarget)
	return res
}

// lastInstallDirective returns the resolution of the LAST install
// directive for module across directives, in scan order. The
// returned source is "<path>:<line>" so an operator can jump directly
// to the offending line. found distinguishes "no install directive"
// from "install directive with empty target" (a structurally-valid
// but malformed conf line).
func lastInstallDirective(directives []kernelmod.ConfDirective, module string) (target, source string, found bool) {
	for _, d := range directives {
		if d.Kind != "install" || d.Module != module {
			continue
		}
		target = strings.Join(d.Args, " ")
		source = fmt.Sprintf("%s:%d", d.Source, d.LineNum)
		found = true
	}
	return target, source, found
}
