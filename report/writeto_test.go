// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

func TestReport_WriteTo_UnknownFormat(t *testing.T) {
	t.Parallel()
	var rep report.Report
	var buf bytes.Buffer
	_, err := rep.WriteTo(&buf, report.Format("yaml"))
	if !errors.Is(err, report.ErrUnknownFormat) {
		t.Errorf("err = %v, want ErrUnknownFormat", err)
	}
}

func TestReport_WriteTo_UnimplementedFormat(t *testing.T) {
	t.Parallel()
	// In Phase 1 the renderers are not yet wired; calling WriteTo with a
	// known format returns ErrRendererNotRegistered. Phase 4 replaces
	// this behavior by registering renderers via init().
	var rep report.Report
	var buf bytes.Buffer
	_, err := rep.WriteTo(&buf, report.FormatJSON)
	if !errors.Is(err, report.ErrRendererNotRegistered) {
		t.Errorf("err = %v, want ErrRendererNotRegistered", err)
	}
}
