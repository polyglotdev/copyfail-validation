// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/internal/kernelmod"
	"github.com/polyglotdev/copyfail-validation/report"
)

// modprobeDryRunCheck verifies that `modprobe -n -v <module>` resolves
// to the canonical "install /bin/false" target. The dry-run flag (-n)
// asks modprobe to print what it would do without executing; the
// verbose flag (-v) makes that output machine-parseable. A blocked
// module emits exactly "install /bin/false"; any other resolution
// (insmod path, alternate install target) means the runtime block is
// not in place even if the conf file is structurally correct — for
// example, a typo in the conf file or a higher-priority override could
// confuse modprobe into picking a different action.
type modprobeDryRunCheck struct {
	runner exec.Runner
	module string
}

// ID returns the stable, machine-readable identifier of the check.
func (c modprobeDryRunCheck) ID() string { return "modprobe.dry_run" }

// Title returns the short human-readable name of the check.
func (c modprobeDryRunCheck) Title() string {
	return "modprobe -n -v resolves the module to /bin/false"
}

// Description returns the long-form explanation of the check.
func (c modprobeDryRunCheck) Description() string {
	return "Invokes `modprobe -n -v <module>` (dry run + verbose) and verifies the first " +
		"non-blank line of stdout is exactly \"install /bin/false\". This confirms " +
		"modprobe's runtime resolution agrees with the conf-file contents — a separate " +
		"signal from the static parse so a configuration that LOOKS correct on disk but " +
		"is shadowed by a higher-priority override still surfaces as a failure."
}

// Severity returns the operational severity of the check.
func (c modprobeDryRunCheck) Severity() report.Severity { return report.SeverityRequired }

// Applicable always reports true. The check returns StateError (which
// the CLI surfaces as a runnable warning rather than as a fail) on
// hosts where the modprobe binary is not installed; we do not skip the
// check up front because skipping would silently deny the operator a
// signal they need.
func (c modprobeDryRunCheck) Applicable(_ context.Context) (bool, string) {
	return true, ""
}

// Run shells out via the configured exec.Runner. The returned
// [report.Result] always carries CheckID, Title, Severity, and
// StartedAt; the check.Runner stamps DurationMS.
func (c modprobeDryRunCheck) Run(ctx context.Context) report.Result {
	startedAt := time.Now().UTC()
	command := fmt.Sprintf("modprobe -n -v %s", c.module)

	res := report.Result{
		CheckID:   c.ID(),
		Title:     c.Title(),
		Severity:  c.Severity(),
		StartedAt: startedAt,
		Evidence: map[string]any{
			"command": command,
			"module":  c.module,
		},
	}

	dry, err := kernelmod.DryRunModule(ctx, c.runner, c.module)

	// Always populate raw_output / resolved_to from whatever DryRun
	// captured — the partial-result contract on DryRunModule means
	// these fields are usable even when err is non-nil. The Evidence
	// surfaces the operator-actionable diagnostic regardless of which
	// branch we land in below.
	res.Evidence["raw_output"] = dry.RawOutput
	res.Evidence["resolved_to"] = dry.ResolvedTo
	res.Evidence["blocked"] = dry.Blocked

	if err != nil {
		res.State = report.StateError
		res.Err = fmt.Errorf("copyfail: modprobe dry-run: %w", err).Error()
		switch {
		case errors.Is(err, exec.ErrCommandNotFound):
			res.Detail = "modprobe binary not available on this host"
		case errors.Is(err, exec.ErrCommandDenied):
			res.Detail = "modprobe binary is not on the exec allowlist"
		case errors.Is(err, exec.ErrInvalidArg):
			res.Detail = fmt.Sprintf("module name %q rejected by argument validator", c.module)
		case errors.Is(err, exec.ErrTimeout):
			res.Detail = fmt.Sprintf("modprobe -n -v %s timed out", c.module)
		default:
			res.Detail = fmt.Sprintf("modprobe -n -v %s: %v", c.module, err)
		}
		return res
	}

	if dry.Blocked {
		res.State = report.StatePass
		res.Detail = fmt.Sprintf("modprobe -n -v resolves to %q", dry.ResolvedTo)
		return res
	}

	res.State = report.StateFail
	if dry.ResolvedTo == "" {
		res.Detail = "modprobe -n -v produced no output (module may be unknown to modprobe)"
	} else {
		res.Detail = fmt.Sprintf("modprobe -n -v resolved to: %s", dry.ResolvedTo)
	}
	return res
}
