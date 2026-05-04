// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package buildinfo_test

import (
	"fmt"

	"github.com/polyglotdev/copyfail-validation/internal/buildinfo"
)

// ExampleInfo shows how the CLI populates Report.Tool from this package
// in a single call. The actual values shown here are the `go test`
// defaults; in a goreleaser build they would be the injected ldflags
// values (e.g., Version="v0.1.0", Commit="abc1234", BuildDate=an RFC3339
// timestamp).
func ExampleInfo() {
	info := buildinfo.Info()
	fmt.Println("name:", info.Name)
	fmt.Println("version:", info.Version)
	fmt.Println("commit:", info.Commit)
	fmt.Println("build_date:", info.BuildDate)
	// Output:
	// name: copyfail-validate
	// version: v0.0.0-dev
	// commit: unknown
	// build_date: unknown
}
