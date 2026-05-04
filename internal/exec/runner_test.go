// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package exec_test

import (
	"context"
	"errors"
	"testing"

	"github.com/polyglotdev/copyfail-validation/internal/exec"
)

// TestFakeRunner_RecordsCalls pins the recording behavior that higher
// layers' tests rely on. Each Run appends to Calls in order, preserving
// both Name and Args (including the Trusted/Untrusted typing). Tests
// for kernelmod/integrity/procscan inspect Calls to assert the exact
// commands their checks emit.
func TestFakeRunner_RecordsCalls(t *testing.T) {
	t.Parallel()
	f := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"uname -r": {Stdout: []byte("6.1.0-25-amd64\n"), ExitCode: 0},
			"lsmod":    {Stdout: []byte("Module Size Used by\n"), ExitCode: 0},
		},
	}
	cmds := []exec.Cmd{
		{Name: "uname", Args: []exec.Arg{exec.Trusted("-r")}},
		{Name: "lsmod"},
	}
	for _, c := range cmds {
		if _, err := f.Run(context.Background(), c); err != nil {
			t.Fatalf("FakeRunner.Run(%q): %v", c.Name, err)
		}
	}
	if got, want := len(f.Calls), len(cmds); got != want {
		t.Fatalf("len(Calls) = %d, want %d", got, want)
	}
	for i, want := range cmds {
		if got := f.Calls[i].Name; got != want.Name {
			t.Errorf("Calls[%d].Name = %q, want %q", i, got, want.Name)
		}
		if got, w := len(f.Calls[i].Args), len(want.Args); got != w {
			t.Errorf("len(Calls[%d].Args) = %d, want %d", i, got, w)
		}
	}
}

// TestFakeRunner_ReturnsCannedResponse pins the Responses map lookup:
// the key is `Name + " " + each Arg.String() joined by space`. Tests
// for higher layers use this exact shape to register canned outputs.
func TestFakeRunner_ReturnsCannedResponse(t *testing.T) {
	t.Parallel()
	want := exec.Result{Stdout: []byte("hello"), ExitCode: 0}
	f := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"uname -r": want,
		},
	}
	got, err := f.Run(context.Background(), exec.Cmd{
		Name: "uname",
		Args: []exec.Arg{exec.Trusted("-r")},
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(got.Stdout) != string(want.Stdout) {
		t.Errorf("Stdout = %q, want %q", got.Stdout, want.Stdout)
	}
	if got.ExitCode != want.ExitCode {
		t.Errorf("ExitCode = %d, want %d", got.ExitCode, want.ExitCode)
	}
}

// TestFakeRunner_ReturnsCannedError pins the Errors map lookup. When a
// key appears in Errors but not in Responses, Run returns an empty
// Result and the registered error.
func TestFakeRunner_ReturnsCannedError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("fake: command unavailable")
	f := &exec.FakeRunner{
		Errors: map[string]error{
			"rpm -V coreutils": wantErr,
		},
	}
	_, err := f.Run(context.Background(), exec.Cmd{
		Name: "rpm",
		Args: []exec.Arg{exec.Trusted("-V"), exec.Untrusted("coreutils")},
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want errors.Is(_, %v)", err, wantErr)
	}
}

// TestFakeRunner_ReturnsErrorAndPartialResult pins the combined case:
// when both Responses and Errors contain the same key, Run returns
// the Result AND the error. This lets tests assert on partial output
// captures alongside the failure (e.g., "rpm -V exited 1 but printed
// these missing-file lines").
func TestFakeRunner_ReturnsErrorAndPartialResult(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("fake: rpm exited 1")
	wantStdout := []byte("missing  /usr/bin/su\n")
	f := &exec.FakeRunner{
		Responses: map[string]exec.Result{
			"rpm -V coreutils": {Stdout: wantStdout, ExitCode: 1},
		},
		Errors: map[string]error{
			"rpm -V coreutils": wantErr,
		},
	}
	res, err := f.Run(context.Background(), exec.Cmd{
		Name: "rpm",
		Args: []exec.Arg{exec.Trusted("-V"), exec.Untrusted("coreutils")},
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("err = %v, want errors.Is(_, %v)", err, wantErr)
	}
	if string(res.Stdout) != string(wantStdout) {
		t.Errorf("Stdout = %q, want %q", res.Stdout, wantStdout)
	}
	if res.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", res.ExitCode)
	}
}

// TestFakeRunner_FailsOnUnregisteredKey pins the loud-failure
// behavior: when a test forgets to register a canned response for a
// command that the code under test invokes, FakeRunner returns an
// error containing the unmocked key. Without this, a missing canned
// response would silently return the zero Result and lead to confusing
// test failures elsewhere ("why is Stdout empty?").
func TestFakeRunner_FailsOnUnregisteredKey(t *testing.T) {
	t.Parallel()
	f := &exec.FakeRunner{} // no maps
	_, err := f.Run(context.Background(), exec.Cmd{
		Name: "uname",
		Args: []exec.Arg{exec.Trusted("-r")},
	})
	if err == nil {
		t.Fatal("err = nil, want non-nil for unregistered key")
	}
}

// TestNewOSRunner_ReturnsRunner pins the trivial constructor — kept
// because the exported NewOSRunner is part of the package's public
// API and a regression that returned nil would crash every caller at
// the first Run.
func TestNewOSRunner_ReturnsRunner(t *testing.T) {
	t.Parallel()
	if r := exec.NewOSRunner(); r == nil {
		t.Fatal("NewOSRunner returned nil")
	}
}

// TestNewRunnerForTest_ReturnsRunner pins the test-only constructor.
// Same rationale as TestNewOSRunner_ReturnsRunner — the package
// guarantees a non-nil Runner.
func TestNewRunnerForTest_ReturnsRunner(t *testing.T) {
	t.Parallel()
	r := exec.NewRunnerForTest("/bin/true", []string{}, []string{})
	if r == nil {
		t.Fatal("NewRunnerForTest returned nil")
	}
}
