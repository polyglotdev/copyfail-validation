// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render_test

import (
	"errors"
	"io"
	"testing"

	_ "github.com/polyglotdev/copyfail-validation/internal/render"
	"github.com/polyglotdev/copyfail-validation/report"
)

// TestInit_RegistersAllFourFormats verifies the package init() side
// effect: blank-importing internal/render must wire renderers for
// every Format value defined in the report package, so a downstream
// caller (the CLI, integration tests) does not silently get
// ErrRendererNotRegistered for one of the four formats.
//
// Mutates the global registry only by reading; the snapshot/restore
// dance still runs to keep this test isolated from any future test
// that does mutate the registry within the same binary.
func TestInit_RegistersAllFourFormats(t *testing.T) {
	prev := report.SnapshotRenderers()
	t.Cleanup(func() { report.RestoreRenderers(prev) })

	tests := []struct {
		name   string
		format report.Format
	}{
		{name: "human format is registered", format: report.FormatHuman},
		{name: "json format is registered", format: report.FormatJSON},
		{name: "sarif format is registered", format: report.FormatSARIF},
		{name: "prometheus format is registered", format: report.FormatPrometheus},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			// No subT.Parallel(): writeto state is shared and
			// future renderer tests in this package mutate
			// EnvJSONCompact, NO_COLOR, etc.; we keep registry
			// reads serialized for stability.
			var rep report.Report
			_, err := rep.WriteTo(io.Discard, tc.format)
			if errors.Is(err, report.ErrRendererNotRegistered) {
				subT.Fatalf("Format %q has no registered renderer (init failed?)", tc.format)
			}
		})
	}
}
