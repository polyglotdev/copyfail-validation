// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package hostinfo

import (
	"context"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/report"
)

// GatherWithRootForTest exposes the unexported gatherWithRoot to the
// external _test package so behavioral tests can build fake etc/
// fixtures under t.TempDir() and exercise the gather without touching
// the host's real /etc/os-release. The function is NOT exported in
// production builds (this file is excluded by the _test.go suffix) —
// production callers must use Gather, which pins etcRoot to "/".
func GatherWithRootForTest(ctx context.Context, runner exec.Runner, etcRoot string) (report.HostInfo, error) {
	return gatherWithRoot(ctx, runner, etcRoot)
}
