// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail_test

import (
	"fmt"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/preset/copyfail"
)

// ExampleCVE shows that the package exposes the canonical CVE
// identifier as a constant for downstream tools (CI dashboards, SARIF
// rule prefixes) to import and reference. The constant pins the
// posture the preset is responsible for validating.
func ExampleCVE() {
	fmt.Println(copyfail.CVE)
	// Output: CVE-2026-31431
}

// ExampleDefaultModule shows the default kernel module name the
// preset blocks. Override via Options.Module if validating a
// different AF_ALG-family module (algif_skcipher, algif_hash, ...).
func ExampleDefaultModule() {
	fmt.Println(copyfail.DefaultModule)
	// Output: algif_aead
}

// ExampleDefaultConfPath shows the canonical /etc/modprobe.d file
// path the conf-present and conf-correct checks expect. The path
// sorts EARLIER than user-customary 99-* override files so the
// dependency-chain check has a meaningful "later wins" surface to
// scan.
func ExampleDefaultConfPath() {
	fmt.Println(copyfail.DefaultConfPath)
	// Output: /etc/modprobe.d/disable-algif-aead.conf
}

// ExampleDefaultModprobeDir shows the canonical modprobe.d directory
// scanned by the dependency-chain check.
func ExampleDefaultModprobeDir() {
	fmt.Println(copyfail.DefaultModprobeDir)
	// Output: /etc/modprobe.d
}

// ExampleOptions shows that the zero Options is valid and uses
// defaults; the Module / ConfPath / ModprobeDir fields are populated
// by AllWithOptions when left empty so callers do not have to
// duplicate the canonical paths in their own code.
func ExampleOptions() {
	opts := copyfail.Options{}
	fmt.Println("Module empty:", opts.Module == "")
	fmt.Println("ConfPath empty:", opts.ConfPath == "")
	fmt.Println("ModprobeDir empty:", opts.ModprobeDir == "")
	fmt.Println("Runner nil:", opts.Runner == nil)
	// Output:
	// Module empty: true
	// ConfPath empty: true
	// ModprobeDir empty: true
	// Runner nil: true
}

// ExampleAll shows the canonical caller pattern: invoke All() and
// inspect the returned slice. In the bundler-only commit the slice
// is empty; subsequent commits add per-check entries and the example
// will be extended to print them.
func ExampleAll() {
	checks := copyfail.All()
	fmt.Println("required check count:", len(checks))
	// Output: required check count: 0
}

// ExampleAllWithOptions shows wiring a non-default Module and a
// FakeRunner (so the example is hermetic and exercises the
// configuration plumbing). The empty-slice output is the bundler-only
// state; each per-check commit grows the printed list.
func ExampleAllWithOptions() {
	checks := copyfail.AllWithOptions(copyfail.Options{
		Module: "algif_skcipher",
		Runner: &exec.FakeRunner{},
	})
	for _, c := range checks {
		fmt.Println(c.ID())
	}
	fmt.Println("done")
	// Output: done
}
