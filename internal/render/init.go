// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"github.com/polyglotdev/copyfail-validation/report"
)

// init registers every renderer with the report package's registry.
// This runs exactly once, the first time the render package is loaded.
//
// Production callers (the CLI binary, integration tests) blank-import
// this package to trigger init; see the package doc for the contract.
// If this init is not invoked, report.Report.WriteTo returns
// ErrRendererNotRegistered for every Format value.
func init() {
	report.Register(report.FormatHuman, RenderHuman)
	report.Register(report.FormatJSON, RenderJSON)
	report.Register(report.FormatSARIF, RenderSARIF)
	report.Register(report.FormatPrometheus, RenderPrometheus)
}
