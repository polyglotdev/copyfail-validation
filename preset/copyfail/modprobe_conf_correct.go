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

// requiredInstallTarget is the canonical install-directive resolution
// the check expects. Any other target ("/bin/true",
// "/sbin/modprobe --ignore-install ...") fails the check; only this
// exact string passes. Kept in sync with internal/kernelmod's
// blockedTarget — the kernelmod constant is unexported so we mirror
// the literal here rather than pulling it through a getter that would
// add API surface for one constant.
const requiredInstallTarget = "/bin/false"

// modprobeConfCorrectCheck verifies that the blocklist conf file
// contains BOTH the canonical "install <module> /bin/false" directive
// (so modprobe -nv resolves to a no-op) AND the matching "blacklist
// <module>" directive (so the module cannot be loaded by alias). The
// two-directive pattern is the recommended mitigation for the AF_ALG
// family per CVE-2026-31431 advisories.
//
// The check overlaps with modprobe.conf_present on the "file missing"
// failure mode; the dispatch order in copyfail.All() runs conf_present
// first so the operator sees the more specific Detail in that scenario.
// We still return StateFail (not StateError) on fs.ErrNotExist so a
// caller running this check in isolation gets a meaningful posture
// signal rather than an "error: file not found" that requires
// interpretation.
type modprobeConfCorrectCheck struct {
	confPath string
	module   string
}

// ID returns the stable, machine-readable identifier of the check.
func (c modprobeConfCorrectCheck) ID() string { return "modprobe.conf_correct" }

// Title returns the short human-readable name of the check.
func (c modprobeConfCorrectCheck) Title() string {
	return "Blocklist contains both install /bin/false and blacklist directives"
}

// Description returns the long-form explanation of the check, suitable
// for the SARIF rule.help.text field.
func (c modprobeConfCorrectCheck) Description() string {
	return "Parses the blocklist conf file and verifies it contains both the canonical " +
		"\"install <module> /bin/false\" directive (so modprobe resolves the module to a " +
		"no-op) AND the matching \"blacklist <module>\" directive (so the module cannot be " +
		"loaded via an alias). Both directives are required by the recommended mitigation " +
		"for CVE-2026-31431; missing either leaves a window for the module to load."
}

// Severity returns the operational severity of the check.
func (c modprobeConfCorrectCheck) Severity() report.Severity { return report.SeverityRequired }

// Applicable always reports true: the conf file's contents must be
// correct on every host the preset runs on.
func (c modprobeConfCorrectCheck) Applicable(_ context.Context) (bool, string) {
	return true, ""
}

// Run parses the conf file and inspects the resulting directives. The
// returned [report.Result] always carries CheckID, Title, Severity,
// and StartedAt; the check.Runner stamps DurationMS.
func (c modprobeConfCorrectCheck) Run(_ context.Context) report.Result {
	startedAt := time.Now().UTC()
	res := report.Result{
		CheckID:   c.ID(),
		Title:     c.Title(),
		Severity:  c.Severity(),
		StartedAt: startedAt,
		Evidence: map[string]any{
			"path":   c.confPath,
			"module": c.module,
		},
	}

	directives, err := kernelmod.ParseConfFile(c.confPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		res.State = report.StateFail
		res.Detail = fmt.Sprintf("blocklist file does not exist: %s", c.confPath)
		res.Evidence["directive_count"] = 0
		return res
	case err != nil:
		res.State = report.StateError
		res.Detail = fmt.Sprintf("parse %s: %v", c.confPath, err)
		res.Err = fmt.Errorf("copyfail: parse %s: %w", c.confPath, err).Error()
		res.Evidence["directive_count"] = len(directives)
		return res
	}

	res.Evidence["directive_count"] = len(directives)

	target, hasInstall := kernelmod.InstallTarget(directives, c.module)
	blacklisted := kernelmod.IsBlacklisted(directives, c.module)

	res.Evidence["install_target"] = target
	res.Evidence["blacklisted"] = blacklisted

	missing := make([]string, 0, 2)
	if !hasInstall || target != requiredInstallTarget {
		missing = append(missing, fmt.Sprintf("install %s %s", c.module, requiredInstallTarget))
	}
	if !blacklisted {
		missing = append(missing, fmt.Sprintf("blacklist %s", c.module))
	}

	if len(missing) > 0 {
		res.State = report.StateFail
		res.Detail = fmt.Sprintf("missing required directive(s): %s", strings.Join(missing, ", "))
		return res
	}

	res.State = report.StatePass
	res.Detail = fmt.Sprintf("both required directives present for module %q", c.module)
	return res
}
