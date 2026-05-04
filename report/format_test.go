// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report_test

import (
	"testing"

	"github.com/polyglotdev/copyfail-validation/report"
)

func TestFormat_Constants(t *testing.T) {
	t.Parallel()
	tests := map[report.Format]string{
		report.FormatHuman:      "human",
		report.FormatJSON:       "json",
		report.FormatSARIF:      "sarif",
		report.FormatPrometheus: "prometheus",
	}
	for f, want := range tests {
		if string(f) != want {
			t.Errorf("Format(%q) = %q, want %q", want, f, want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in      string
		want    report.Format
		wantErr bool
	}{
		{"human", report.FormatHuman, false},
		{"HUMAN", report.FormatHuman, false},
		{"json", report.FormatJSON, false},
		{"sarif", report.FormatSARIF, false},
		{"prometheus", report.FormatPrometheus, false},
		{"", "", true},
		{"yaml", "", true},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, err := report.ParseFormat(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseFormat(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
