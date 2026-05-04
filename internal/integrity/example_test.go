// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package integrity_test

import (
	"context"
	"errors"
	"fmt"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
	"github.com/polyglotdev/copyfail-validation/internal/integrity"
)

// ExampleDetect demonstrates the canonical "pick whichever package
// manager is on this host" flow. The result depends on the host:
//
//   - On a host with rpm installed: returns the rpm backend.
//   - On a host with dpkg but no rpm: returns the dpkg backend.
//   - On a host with neither (e.g., macOS dev, minimal Alpine): returns
//     ErrNoPkgManager and the integrity.su_binary check records a Skip
//     with reason="no supported package manager".
//
// The example uses a FakeRunner so production-runner side-effects do
// not leak into godoc, but Detect itself probes the actual host PATH
// via internal/exec.ResolveCommand — so the runner argument is unused
// here. Production callers wire exec.NewOSRunner from internal/exec.
//
// No // Output: directive: this example is host-state-dependent (rpm
// and dpkg are installed on different CI matrix entries), so it is
// compile-checked but its printed bytes are not pinned. The runtime
// behavior is verified by TestDetect_* in the internal package tests.
func ExampleDetect() {
	pm, err := integrity.Detect(&exec.FakeRunner{})
	switch {
	case errors.Is(err, integrity.ErrNoPkgManager):
		fmt.Println("no package manager: skip integrity check")
	case err != nil:
		fmt.Println("unexpected error:", err)
	default:
		fmt.Println("backend:", pm.Name())
	}
}

// ExampleNewRPM shows direct instantiation of the rpm backend without
// going through Detect's host-resolution. Production callers SHOULD
// use Detect; NewRPM is for forensic tools or integration tests that
// need to pin behavior to one backend regardless of what's installed
// on the host.
func ExampleNewRPM() {
	pm := integrity.NewRPM()
	fmt.Println(pm.Name())
	// Output:
	// rpm
}

// ExampleNewDPKG shows direct instantiation of the dpkg backend
// without Detect's host-resolution. Same caveats as NewRPM.
func ExampleNewDPKG() {
	pm := integrity.NewDPKG()
	fmt.Println(pm.Name())
	// Output:
	// dpkg
}

// ExamplePkgMgr_OwnerOf_rpm shows the rpm OwnerOf happy path using a
// FakeRunner to stand in for `rpm -qf`. On a real host the runner
// would shell out and get the same NEVR string back from rpm
// directly. The example is hermetic so it runs on every CI matrix
// entry, including macOS where rpm is not installed.
func ExamplePkgMgr_OwnerOf_rpm() {
	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"rpm -qf /usr/bin/su": {
				Stdout:   []byte("util-linux-core-2.39.4-7.amzn2023.x86_64\n"),
				ExitCode: 0,
			},
		},
	}

	owner, err := integrity.NewRPM().OwnerOf(context.Background(), runner, "/usr/bin/su")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(owner)
	// Output:
	// util-linux-core-2.39.4-7.amzn2023.x86_64
}

// ExamplePkgMgr_Verify_rpm shows the rpm Verify clean-result path:
// `rpm -V` produces no stdout when the package matches the manifest,
// so the parsed VerifyResult is Clean.
func ExamplePkgMgr_Verify_rpm() {
	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"rpm -V util-linux-core-2.39.4-7.amzn2023.x86_64": {
				Stdout:   []byte(""),
				ExitCode: 0,
			},
		},
	}

	result, err := integrity.NewRPM().Verify(
		context.Background(),
		runner,
		"util-linux-core-2.39.4-7.amzn2023.x86_64",
		"/usr/bin/su",
	)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Printf("clean=%v hash_mismatch=%v\n", result.Clean(), result.HashMismatch)
	// Output:
	// clean=true hash_mismatch=false
}

// ExamplePkgMgr_OwnerOf_dpkg shows the dpkg OwnerOf happy path. The
// `dpkg -S` output format is `pkg: /full/path`; the parser returns
// the package name (preserving the multi-arch qualifier when
// present).
func ExamplePkgMgr_OwnerOf_dpkg() {
	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"dpkg -S /usr/bin/su": {
				Stdout:   []byte("util-linux: /usr/bin/su\n"),
				ExitCode: 0,
			},
		},
	}

	owner, err := integrity.NewDPKG().OwnerOf(context.Background(), runner, "/usr/bin/su")
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(owner)
	// Output:
	// util-linux
}

// ExampleVerifyResult_Clean shows the boolean-aggregation logic that
// the integrity.su_binary check (Phase 5) uses to decide Pass vs
// Fail. An all-zero VerifyResult is Clean; flipping any boolean OR
// adding an UnverifiedReasons entry makes it not-Clean. This is why
// callers should NOT manually negate each field.
func ExampleVerifyResult_Clean() {
	clean := integrity.VerifyResult{}
	flagged := integrity.VerifyResult{HashMismatch: true}
	noted := integrity.VerifyResult{UnverifiedReasons: []string{"sibling-file deviation"}}

	fmt.Println("clean:", clean.Clean())
	fmt.Println("flagged:", flagged.Clean())
	fmt.Println("noted:", noted.Clean())
	// Output:
	// clean: true
	// flagged: false
	// noted: false
}

// ExampleErrPackageUnknown shows the canonical caller pattern for
// the ErrPackageUnknown sentinel: try OwnerOf, and if errors.Is
// matches, treat it as "manually-placed file" rather than a backend
// failure. This is the shape spec §11 expects from the integrity.su_binary
// check.
func ExampleErrPackageUnknown() {
	runner := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"rpm -qf /usr/bin/wat": {
				Stdout:   []byte("file /usr/bin/wat is not owned by any package\n"),
				ExitCode: 1,
			},
		},
		Errors: map[string]error{
			"rpm -qf /usr/bin/wat": fmt.Errorf("rpm exited 1"),
		},
	}

	_, err := integrity.NewRPM().OwnerOf(context.Background(), runner, "/usr/bin/wat")
	if errors.Is(err, integrity.ErrPackageUnknown) {
		fmt.Println("file has no owning package — manually placed?")
		return
	}
	if err != nil {
		fmt.Println("unexpected error:", err)
	}
	// Output:
	// file has no owning package — manually placed?
}

// ExampleErrNoPkgManager shows the canonical caller pattern for the
// ErrNoPkgManager sentinel: Detect returns it when neither rpm nor
// dpkg is on the host; callers should record a Skip rather than an
// Error in the integrity.su_binary check evidence (spec §5
// State-Semantics table).
//
// No // Output: directive: this example is host-state-dependent
// (Detect probes the actual host PATH; see ExampleDetect for the
// rationale). Compile-checked but its printed bytes are not pinned.
func ExampleErrNoPkgManager() {
	_, err := integrity.Detect(&exec.FakeRunner{})
	if errors.Is(err, integrity.ErrNoPkgManager) {
		fmt.Println("skip: no supported package manager")
		return
	}
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println("backend resolved")
}
