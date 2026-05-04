// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"

	"github.com/polyglotdev/copyfail-validation/report"
)

// modprobeConfPresentCheck verifies the /etc/modprobe.d blocklist file
// for the configured module exists and is a regular file. It is the
// first of the four modprobe.* checks; its companions verify the
// file's CONTENTS (modprobe.conf_correct), modprobe's runtime
// resolution (modprobe.dry_run), and the absence of override
// directives in later-sorting conf files (modprobe.dependency_chain).
//
// Splitting "exists" from "correct" gives operators a clearer error
// message than a single combined check would: the failure modes
// (missing vs. wrong contents vs. shadowed by a later directive) call
// for different remediation steps and benefit from distinct check IDs
// in the SARIF / JSON output.
type modprobeConfPresentCheck struct {
	confPath string
}

// ID returns the stable, machine-readable identifier of the check.
func (c modprobeConfPresentCheck) ID() string { return "modprobe.conf_present" }

// Title returns the short human-readable name of the check.
func (c modprobeConfPresentCheck) Title() string { return "Modprobe blocklist file present" }

// Description returns the long-form explanation of the check, suitable
// for the SARIF rule.help.text field.
func (c modprobeConfPresentCheck) Description() string {
	return "Verifies that the /etc/modprobe.d/*.conf file containing the AF_ALG-family " +
		"module blocklist directives exists on disk and is a regular file. A missing or " +
		"non-regular blocklist file means the modprobe-level mitigation for CVE-2026-31431 " +
		"is not deployed; remediate by writing the canonical blocklist to the path shown " +
		"in Evidence.path."
}

// Severity returns the operational severity of the check; required
// failures change the process exit code, advisory failures only appear
// in the report.
func (c modprobeConfPresentCheck) Severity() report.Severity { return report.SeverityRequired }

// Applicable always reports true: the blocklist file must exist on
// every host the preset runs on, regardless of distribution. The
// check is meaningful even when modprobe itself is missing — the
// file's presence is part of the configuration baseline.
func (c modprobeConfPresentCheck) Applicable(_ context.Context) (bool, string) {
	return true, ""
}

// Run executes the check. The returned [report.Result] always carries
// CheckID, Title, Severity, and StartedAt; the check.Runner stamps
// DurationMS so the implementation does not bother with it.
func (c modprobeConfPresentCheck) Run(_ context.Context) report.Result {
	startedAt := time.Now().UTC()
	res := report.Result{
		CheckID:   c.ID(),
		Title:     c.Title(),
		Severity:  c.Severity(),
		StartedAt: startedAt,
		Evidence: map[string]any{
			"path": c.confPath,
		},
	}

	info, err := os.Stat(c.confPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		res.State = report.StateFail
		res.Detail = fmt.Sprintf("blocklist file does not exist: %s", c.confPath)
		res.Evidence["exists"] = false
		return res
	case err != nil:
		res.State = report.StateError
		res.Detail = fmt.Sprintf("stat %s: %v", c.confPath, err)
		res.Err = fmt.Errorf("copyfail: stat %s: %w", c.confPath, err).Error()
		res.Evidence["exists"] = false
		return res
	}

	res.Evidence["exists"] = true
	res.Evidence["is_regular"] = info.Mode().IsRegular()
	res.Evidence["size_bytes"] = info.Size()

	if !info.Mode().IsRegular() {
		res.State = report.StateFail
		res.Detail = fmt.Sprintf("blocklist path is not a regular file (mode=%s): %s", info.Mode().String(), c.confPath)
		return res
	}

	res.State = report.StatePass
	res.Detail = fmt.Sprintf("blocklist file present at %s (%d bytes)", c.confPath, info.Size())
	return res
}
