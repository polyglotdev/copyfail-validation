// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

func TestSeverity_Constants(t *testing.T) {
	t.Parallel()
	if string(report.SeverityRequired) != "required" {
		t.Errorf("SeverityRequired = %q, want %q", report.SeverityRequired, "required")
	}
	if string(report.SeverityAdvisory) != "advisory" {
		t.Errorf("SeverityAdvisory = %q, want %q", report.SeverityAdvisory, "advisory")
	}
}

func TestSeverity_IsRequired(t *testing.T) {
	t.Parallel()
	if !report.SeverityRequired.IsRequired() {
		t.Error("SeverityRequired.IsRequired() should be true")
	}
	if report.SeverityAdvisory.IsRequired() {
		t.Error("SeverityAdvisory.IsRequired() should be false")
	}
}
