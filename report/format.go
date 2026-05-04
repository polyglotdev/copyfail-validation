// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package report

import (
	"errors"
	"fmt"
	"strings"
)

// Format selects an output renderer.
type Format string

// Format constants. The string values are the canonical CLI flag
// values (case-insensitive on parse; rendered lowercase).
const (
	FormatHuman      Format = "human"
	FormatJSON       Format = "json"
	FormatSARIF      Format = "sarif"
	FormatPrometheus Format = "prometheus"
)

// ErrUnknownFormat is returned by ParseFormat for an unrecognized value.
var ErrUnknownFormat = errors.New("unknown report format")

// ParseFormat converts a case-insensitive flag value into a Format.
// Empty input returns ErrUnknownFormat (callers must explicitly pick a
// format; we do not silently default here).
func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(s) {
	case "human":
		return FormatHuman, nil
	case "json":
		return FormatJSON, nil
	case "sarif":
		return FormatSARIF, nil
	case "prometheus":
		return FormatPrometheus, nil
	default:
		return "", fmt.Errorf("%w: %q (want one of: human, json, sarif, prometheus)", ErrUnknownFormat, s)
	}
}
