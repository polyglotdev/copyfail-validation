// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package buildinfo_test

import (
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/buildinfo"
)

func TestVarsHaveDefaults(t *testing.T) {
	t.Parallel()
	if buildinfo.Version == "" {
		t.Error("Version must have a non-empty default")
	}
	if buildinfo.Commit == "" {
		t.Error("Commit must have a non-empty default")
	}
	if buildinfo.BuildDate == "" {
		t.Error("BuildDate must have a non-empty default")
	}
}

func TestInfo_PopulatesToolInfo(t *testing.T) {
	t.Parallel()
	info := buildinfo.Info()
	if info.Name == "" {
		t.Error("Info().Name should be non-empty")
	}
	if info.Version != buildinfo.Version {
		t.Errorf("Info().Version = %q, want %q", info.Version, buildinfo.Version)
	}
}
