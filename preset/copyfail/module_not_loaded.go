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

	"github.com/polyglotdev/copyfail-validation/internal/kernelmod"
	"github.com/polyglotdev/copyfail-validation/report"
)

// procModulesPath is the canonical /proc location the kernel exposes
// the "currently loaded modules" table at. Hardcoded rather than made
// an Options field because /proc/modules is not relocatable: the kernel
// writes there and only there. Tests that need to inject fixtures wire
// a different code path (a test-only constructor or moving the file
// path to a non-default location is rejected at code review).
const procModulesPath = "/proc/modules"

// moduleNotLoadedCheck verifies the configured module is NOT currently
// loaded into the running kernel. The check parses /proc/modules
// directly (no shell pipeline) and looks for a row whose name matches
// the configured module. The compile-time guarantee against shell
// injection is the entire reason the legacy `lsmod | grep -q` pipe
// was replaced; see internal/kernelmod for the parser.
type moduleNotLoadedCheck struct {
	module string
}

// ID returns the stable, machine-readable identifier of the check.
func (c moduleNotLoadedCheck) ID() string { return "module.not_loaded" }

// Title returns the short human-readable name of the check.
func (c moduleNotLoadedCheck) Title() string { return "Target module is not currently loaded" }

// Description returns the long-form explanation of the check.
func (c moduleNotLoadedCheck) Description() string {
	return "Reads /proc/modules and verifies the configured module name does NOT appear " +
		"in the kernel's currently-loaded table. Even with a correct blocklist on disk, a " +
		"module that was loaded BEFORE the blocklist took effect (or was loaded manually " +
		"by an operator) remains active until the next reboot or explicit `rmmod`. This " +
		"check catches that gap."
}

// Severity returns the operational severity of the check.
func (c moduleNotLoadedCheck) Severity() report.Severity { return report.SeverityRequired }

// Applicable always reports true. The check returns StateError on
// hosts where /proc is not mounted (containers built without a
// /proc bind mount, for instance) — we do not skip up front because
// the absence of /proc is itself a meaningful signal that the
// validator should surface rather than silently elide.
func (c moduleNotLoadedCheck) Applicable(_ context.Context) (bool, string) {
	return true, ""
}

// Run reads /proc/modules and inspects the parsed table. The
// returned [report.Result] always carries CheckID, Title, Severity,
// and StartedAt; the check.Runner stamps DurationMS.
func (c moduleNotLoadedCheck) Run(_ context.Context) report.Result {
	return c.runWithSource(procModulesPath)
}

// runWithSource is the testable entry point. The exported Run pins
// the canonical /proc/modules path; tests inject a fixture path via
// this internal helper so the production code stays
// configuration-free while the parser logic remains exercised.
func (c moduleNotLoadedCheck) runWithSource(path string) report.Result {
	startedAt := time.Now().UTC()
	res := report.Result{
		CheckID:   c.ID(),
		Title:     c.Title(),
		Severity:  c.Severity(),
		StartedAt: startedAt,
		Evidence: map[string]any{
			"source": path,
			"module": c.module,
		},
	}

	f, err := os.Open(path) // #nosec G304 -- path is the hard-coded /proc/modules in production; tests inject a t.TempDir() fixture.
	switch {
	case errors.Is(err, fs.ErrNotExist):
		res.State = report.StateError
		res.Detail = "/proc not mounted (cannot enumerate loaded modules)"
		res.Err = fmt.Errorf("copyfail: open %s: %w", path, err).Error()
		return res
	case err != nil:
		res.State = report.StateError
		res.Detail = fmt.Sprintf("open %s: %v", path, err)
		res.Err = fmt.Errorf("copyfail: open %s: %w", path, err).Error()
		return res
	}
	defer func() { _ = f.Close() }()

	modules, parseErr := kernelmod.ParseProcModules(f)
	res.Evidence["total_modules"] = len(modules)
	if parseErr != nil {
		res.State = report.StateError
		res.Detail = fmt.Sprintf("parse %s: %v", path, parseErr)
		res.Err = fmt.Errorf("copyfail: parse %s: %w", path, parseErr).Error()
		return res
	}

	if !kernelmod.IsLoaded(modules, c.module) {
		res.State = report.StatePass
		res.Detail = fmt.Sprintf("module %q is not loaded (scanned %d modules)", c.module, len(modules))
		res.Evidence["is_loaded"] = false
		return res
	}

	matched := matchedModule(modules, c.module)
	res.Evidence["is_loaded"] = true
	res.Evidence["matched"] = map[string]any{
		"name":     matched.Name,
		"size":     matched.Size,
		"refcount": matched.RefCount,
		"state":    matched.State,
	}
	res.State = report.StateFail
	res.Detail = fmt.Sprintf("%s is currently loaded (refcount=%d, state=%s)",
		matched.Name, matched.RefCount, matched.State)
	return res
}

// matchedModule returns the FIRST entry whose Name equals name. The
// caller has already verified IsLoaded so the result is always a
// real entry; matchedModule's responsibility is to pick the row that
// matched so its forensic fields (size, refcount, state) can land in
// the Evidence blob. /proc/modules is forbidden from listing the same
// name twice (the kernel rejects duplicate-name loads), so "first
// match" is also the only match.
func matchedModule(modules []kernelmod.LoadedModule, name string) kernelmod.LoadedModule {
	for _, m := range modules {
		if m.Name == name {
			return m
		}
	}
	return kernelmod.LoadedModule{}
}
