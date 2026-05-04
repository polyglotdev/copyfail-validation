// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package copyfail_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

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
// inspect the returned slice. The example asserts only on length and
// the first two check IDs to keep the output stable as more checks
// land in subsequent commits.
func ExampleAll() {
	checks := copyfail.All()
	fmt.Println("required check count:", len(checks))
	fmt.Println("first check ID:", checks[0].ID())
	fmt.Println("second check ID:", checks[1].ID())
	// Output:
	// required check count: 5
	// first check ID: modprobe.conf_present
	// second check ID: modprobe.conf_correct
}

// ExampleAllWithOptions shows wiring a non-default Module and a
// FakeRunner (so the example is hermetic and exercises the
// configuration plumbing). The output prints every check ID in order.
func ExampleAllWithOptions() {
	checks := copyfail.AllWithOptions(copyfail.Options{
		Module: "algif_skcipher",
		Runner: &exec.FakeRunner{},
	})
	for _, c := range checks {
		fmt.Println(c.ID())
	}
	// Output:
	// modprobe.conf_present
	// modprobe.conf_correct
	// modprobe.dry_run
	// modprobe.dependency_chain
	// module.not_loaded
}

// Example_modprobeConfPresent shows the conf-present check on a real
// fixture file. The example writes a tiny *.conf inside a temp dir,
// invokes the check via AllWithOptions, and prints the resulting
// state — the byte-stable output anchors the godoc explanation of
// what a passing posture looks like.
func Example_modprobeConfPresent() {
	dir, err := os.MkdirTemp("", "copyfail-example-*")
	if err != nil {
		fmt.Println("setup error:", err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "disable-algif-aead.conf")
	if err := os.WriteFile(path, []byte("install algif_aead /bin/false\nblacklist algif_aead\n"), 0o600); err != nil {
		fmt.Println("setup error:", err)
		return
	}

	opts := copyfail.Options{ConfPath: path, Runner: &exec.FakeRunner{}}
	for _, c := range copyfail.AllWithOptions(opts) {
		if c.ID() != "modprobe.conf_present" {
			continue
		}
		res := c.Run(context.Background())
		fmt.Println("state:", res.State)
		fmt.Println("is_regular:", res.Evidence["is_regular"])
	}
	// Output:
	// state: pass
	// is_regular: true
}

// Example_modprobeConfCorrect shows the conf-correct check on a
// blocklist fixture that contains both required directives. The
// printed Evidence values mirror the spec §11 evidence shape.
func Example_modprobeConfCorrect() {
	dir, err := os.MkdirTemp("", "copyfail-example-*")
	if err != nil {
		fmt.Println("setup error:", err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "disable-algif-aead.conf")
	if err := os.WriteFile(path, []byte("install algif_aead /bin/false\nblacklist algif_aead\n"), 0o600); err != nil {
		fmt.Println("setup error:", err)
		return
	}

	opts := copyfail.Options{ConfPath: path, Runner: &exec.FakeRunner{}}
	for _, c := range copyfail.AllWithOptions(opts) {
		if c.ID() != "modprobe.conf_correct" {
			continue
		}
		res := c.Run(context.Background())
		fmt.Println("state:", res.State)
		fmt.Println("install_target:", res.Evidence["install_target"])
		fmt.Println("blacklisted:", res.Evidence["blacklisted"])
	}
	// Output:
	// state: pass
	// install_target: /bin/false
	// blacklisted: true
}

// Example_modprobeDryRun shows the dry-run check driven by a
// FakeRunner. The runner returns the canonical
// "install /bin/false \n" stdout that a hardened host's modprobe -n -v
// would produce; the check classifies the resolution as blocked.
func Example_modprobeDryRun() {
	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"modprobe -n -v algif_aead": {Stdout: []byte("install /bin/false \n")},
		},
	}

	opts := copyfail.Options{Runner: runner}
	for _, c := range copyfail.AllWithOptions(opts) {
		if c.ID() != "modprobe.dry_run" {
			continue
		}
		res := c.Run(context.Background())
		fmt.Println("state:", res.State)
		fmt.Println("blocked:", res.Evidence["blocked"])
		fmt.Println("resolved_to:", res.Evidence["resolved_to"])
	}
	// Output:
	// state: pass
	// blocked: true
	// resolved_to: install /bin/false
}

// Example_modprobeDependencyChain shows the dependency-chain check on
// a single-file directory: the canonical 00-blacklist.conf with a
// /bin/false target. Because no later-sorting file overrides the
// install directive, the check passes.
func Example_modprobeDependencyChain() {
	dir, err := os.MkdirTemp("", "copyfail-example-*")
	if err != nil {
		fmt.Println("setup error:", err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := os.WriteFile(filepath.Join(dir, "00-blacklist.conf"),
		[]byte("install algif_aead /bin/false\nblacklist algif_aead\n"), 0o600); err != nil {
		fmt.Println("setup error:", err)
		return
	}

	opts := copyfail.Options{ModprobeDir: dir, Runner: &exec.FakeRunner{}}
	for _, c := range copyfail.AllWithOptions(opts) {
		if c.ID() != "modprobe.dependency_chain" {
			continue
		}
		res := c.Run(context.Background())
		fmt.Println("state:", res.State)
		fmt.Println("last_install_target:", res.Evidence["last_install_target"])
	}
	// Output:
	// state: pass
	// last_install_target: /bin/false
}

// Example_moduleNotLoaded shows the not-loaded check via the
// test-only NewModuleNotLoadedCheckForTest constructor. Production
// callers do NOT use this constructor — they get the check from
// AllWithOptions and it reads /proc/modules directly. The example
// uses a synthetic fixture so godoc can verify exact output.
func Example_moduleNotLoaded() {
	dir, err := os.MkdirTemp("", "copyfail-example-*")
	if err != nil {
		fmt.Println("setup error:", err)
		return
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "modules")
	body := "ext4 753664 1 - Live 0x0\nnvme 53248 4 - Live 0x0\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		fmt.Println("setup error:", err)
		return
	}

	runFn := copyfail.NewModuleNotLoadedCheckForTest("algif_aead", path)
	res := runFn(context.Background())
	fmt.Println("state:", res.State)
	fmt.Println("is_loaded:", res.Evidence["is_loaded"])
	fmt.Println("total_modules:", res.Evidence["total_modules"])
	// Output:
	// state: pass
	// is_loaded: false
	// total_modules: 2
}
