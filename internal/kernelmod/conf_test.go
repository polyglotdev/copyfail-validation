// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package kernelmod_test

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/polyglotdev/copyfail-validation/internal/kernelmod"
)

// TestParseConfReader covers the full /etc/modprobe.d format contract:
// comment skipping, blank-line skipping, line continuation joining,
// inline comment stripping, unknown-kind tolerance, and the
// abort-on-malformed behavior. We pin LineNum on the continuation case
// because the package doc.go promises continuations report the FIRST
// line of the joined block — operators editing the offending directive
// need to know where the directive STARTED, not where it accidentally
// terminated.
func TestParseConfReader(t *testing.T) {
	t.Parallel()

	const source = "/etc/modprobe.d/test.conf"

	tests := []struct {
		wantErr error
		name    string
		input   string
		want    []kernelmod.ConfDirective
	}{
		{
			name:  "empty file produces empty slice and nil error",
			input: "",
			want:  []kernelmod.ConfDirective{},
		},
		{
			name:  "whitespace-only file produces empty slice and nil error",
			input: "   \n\t\n  \t  \n",
			want:  []kernelmod.ConfDirective{},
		},
		{
			name:  "comment-only file produces empty slice",
			input: "# block this module\n# CVE-2026-31431\n",
			want:  []kernelmod.ConfDirective{},
		},
		{
			name:  "single install directive",
			input: "install algif_aead /bin/false\n",
			want: []kernelmod.ConfDirective{
				{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: source, LineNum: 1},
			},
		},
		{
			name:  "single blacklist directive has empty args",
			input: "blacklist algif_aead\n",
			want: []kernelmod.ConfDirective{
				{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: source, LineNum: 1},
			},
		},
		{
			name:  "blank line then directive: line number reflects directive position",
			input: "\ninstall algif_aead /bin/false\n",
			want: []kernelmod.ConfDirective{
				{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: source, LineNum: 2},
			},
		},
		{
			name:  "comment line and directive on same file: only directive emitted",
			input: "# block algif_aead\ninstall algif_aead /bin/false\n",
			want: []kernelmod.ConfDirective{
				{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: source, LineNum: 2},
			},
		},
		{
			name:  "leading-whitespace comment is still a comment",
			input: "    # indented comment\nblacklist x\n",
			want: []kernelmod.ConfDirective{
				{Kind: "blacklist", Module: "x", Args: []string{}, Source: source, LineNum: 2},
			},
		},
		{
			name:  "inline comment after directive is stripped",
			input: "install foo /bin/false # block this\n",
			want: []kernelmod.ConfDirective{
				{Kind: "install", Module: "foo", Args: []string{"/bin/false"}, Source: source, LineNum: 1},
			},
		},
		{
			name:  "line continuation joins next line; LineNum is the FIRST line",
			input: "options usbcore \\\n    use_both_schemes=Y \\\n    autosuspend=0\n",
			want: []kernelmod.ConfDirective{
				{
					Kind:    "options",
					Module:  "usbcore",
					Args:    []string{"use_both_schemes=Y", "autosuspend=0"},
					Source:  source,
					LineNum: 1,
				},
			},
		},
		{
			name:  "line continuation across blank line still joins",
			input: "options usbcore \\\n\n    autosuspend=0\n",
			want: []kernelmod.ConfDirective{
				{
					Kind:    "options",
					Module:  "usbcore",
					Args:    []string{"autosuspend=0"},
					Source:  source,
					LineNum: 1,
				},
			},
		},
		{
			name:  "unknown directive kind is tolerated",
			input: "softdep wifi pre: rfkill\n",
			want: []kernelmod.ConfDirective{
				{Kind: "softdep", Module: "wifi", Args: []string{"pre:", "rfkill"}, Source: source, LineNum: 1},
			},
		},
		{
			name:  "alias directive is preserved with original kind",
			input: "alias eth0 e1000\n",
			want: []kernelmod.ConfDirective{
				{Kind: "alias", Module: "eth0", Args: []string{"e1000"}, Source: source, LineNum: 1},
			},
		},
		{
			name:  "multiple directives parse in order with correct line numbers",
			input: "install algif_aead /bin/false\nblacklist algif_aead\n",
			want: []kernelmod.ConfDirective{
				{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: source, LineNum: 1},
				{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: source, LineNum: 2},
			},
		},
		{
			name:  "tabs and multiple spaces between tokens are normalized",
			input: "install\talgif_aead\t\t/bin/false\n",
			want: []kernelmod.ConfDirective{
				{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: source, LineNum: 1},
			},
		},
		{
			name:    "directive with only one word aborts with wrapped ErrParse",
			input:   "blacklist\n",
			wantErr: kernelmod.ErrParse,
			want:    []kernelmod.ConfDirective{},
		},
		{
			name:    "abort returns directives parsed before the malformed line",
			input:   "blacklist algif_aead\nbroken\n",
			wantErr: kernelmod.ErrParse,
			want: []kernelmod.ConfDirective{
				{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: source, LineNum: 1},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			got, err := kernelmod.ParseConfReader(strings.NewReader(tc.input), source)

			switch {
			case tc.wantErr == nil && err != nil:
				subT.Fatalf("ParseConfReader() unexpected error: %v", err)
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				subT.Fatalf("ParseConfReader() error = %v, want errors.Is(_, %v)", err, tc.wantErr)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				subT.Errorf("ParseConfReader() result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestParseConfReader_MalformedErrorMessageIncludesContext pins the
// human-readable shape of the wrapped ErrParse: it MUST include the
// source path, 1-indexed line number, AND the raw line text so an
// operator reading the audit log can identify exactly which
// modprobe.d file is broken. Without this guarantee, "malformed
// directive" is useless for forensics across a fleet of hosts.
func TestParseConfReader_MalformedErrorMessageIncludesContext(t *testing.T) {
	t.Parallel()

	const (
		source = "/etc/modprobe.d/sample.conf"
		input  = "blacklist algif_aead\nblacklist\n"
	)
	_, err := kernelmod.ParseConfReader(strings.NewReader(input), source)
	if err == nil {
		t.Fatal("ParseConfReader() returned nil error; want wrapped ErrParse")
	}

	msg := err.Error()
	if !strings.Contains(msg, source) {
		t.Errorf("error message missing source path; got %q", msg)
	}
	if !strings.Contains(msg, ":2:") {
		t.Errorf("error message missing 1-indexed line number; got %q", msg)
	}
	if !strings.Contains(msg, "blacklist") {
		t.Errorf("error message missing offending raw text; got %q", msg)
	}
}

// TestParseConfFile_Happy parses the disable-algif-aead.conf testdata
// end-to-end so a regression in the file-IO wrapper (symlink resolution,
// open errors, defer-close ordering) becomes a failing test rather
// than a silent behavioral drift. Asserting the exact directives also
// pins the testdata file's contents — if someone "tidies" the fixture
// without updating expectations, this test catches it.
func TestParseConfFile_Happy(t *testing.T) {
	t.Parallel()

	path := filepath.Join("testdata", "disable-algif-aead.conf")
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("filepath.Abs(%s): %v", path, err)
	}

	directives, err := kernelmod.ParseConfFile(path)
	if err != nil {
		t.Fatalf("ParseConfFile(%s) error: %v", path, err)
	}

	want := []kernelmod.ConfDirective{
		{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: abs, LineNum: 3},
		{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: abs, LineNum: 4},
	}
	if diff := cmp.Diff(want, directives); diff != "" {
		t.Errorf("ParseConfFile() mismatch (-want +got):\n%s", diff)
	}
}

// TestParseConfFile_Symlink verifies the symlink-resolution behavior:
// when the input path is a symlink, the emitted directives' Source
// field records the RESOLVED target, not the symlink path. This is
// the audit hook the modprobe.conf_present check uses to detect a
// /etc/modprobe.d/foo.conf that has been redirected at /tmp/attacker.conf.
func TestParseConfFile_Symlink(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	target := filepath.Join(dir, "real.conf")
	if err := os.WriteFile(target, []byte("blacklist evil_module\n"), 0o600); err != nil {
		t.Fatalf("write real.conf: %v", err)
	}
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink not supported on this platform: %v", err)
	}

	directives, err := kernelmod.ParseConfFile(link)
	if err != nil {
		t.Fatalf("ParseConfFile(symlink) error: %v", err)
	}
	if len(directives) != 1 {
		t.Fatalf("expected 1 directive, got %d", len(directives))
	}

	// Resolve the target via EvalSymlinks ourselves so the comparison
	// matches what the parser does (handles /private prefix on macOS,
	// /tmp -> /var/folders symlinks, etc.).
	wantSource, err := filepath.EvalSymlinks(target)
	if err != nil {
		t.Fatalf("EvalSymlinks(%s): %v", target, err)
	}
	if directives[0].Source != wantSource {
		t.Errorf("Source = %q, want resolved target %q (NOT the symlink path %q)",
			directives[0].Source, wantSource, link)
	}
	if directives[0].Source == link {
		t.Errorf("Source equals the symlink path; want the resolved target")
	}
}

// TestParseConfFile_Nonexistent verifies the wrapped fs.ErrNotExist
// contract — a missing file produces an error matchable via
// errors.Is(_, fs.ErrNotExist) so callers can distinguish "no such
// file" (often: not installed) from "file exists but is malformed"
// (often: tampered).
func TestParseConfFile_Nonexistent(t *testing.T) {
	t.Parallel()

	_, err := kernelmod.ParseConfFile(filepath.Join(t.TempDir(), "does-not-exist.conf"))
	if err == nil {
		t.Fatal("ParseConfFile(nonexistent) returned nil error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error %v is not fs.ErrNotExist", err)
	}
}

// TestParseConfDir_Ordering pins the alphabetical-scan + later-wins
// behavior modprobe itself uses: 00-blacklist.conf is parsed first,
// 99-override.conf second, and the install target for algif_aead in
// the final concatenated slice should reflect the override. This is
// the contract the modprobe.dependency_chain check (Phase 5) is built
// on top of — if ParseConfDir ever sorts in a different order, the
// override-detection check would silently miss compromises.
func TestParseConfDir_Ordering(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	copyTestdata(t, dir, "00-blacklist.conf")
	copyTestdata(t, dir, "99-override.conf")

	directives, err := kernelmod.ParseConfDir(dir)
	if err != nil {
		t.Fatalf("ParseConfDir() error: %v", err)
	}

	// 00-blacklist.conf has 4 directives, 99-override.conf has 1 → 5 total.
	if got, want := len(directives), 5; got != want {
		t.Fatalf("got %d directives, want %d", got, want)
	}

	// First four must come from 00-blacklist.conf (alphabetical first).
	for i, d := range directives[:4] {
		if !strings.HasSuffix(d.Source, "00-blacklist.conf") {
			t.Errorf("directives[%d].Source = %q, want a 00-blacklist.conf file", i, d.Source)
		}
	}
	// Fifth must come from 99-override.conf.
	if !strings.HasSuffix(directives[4].Source, "99-override.conf") {
		t.Errorf("directives[4].Source = %q, want a 99-override.conf file", directives[4].Source)
	}

	// And the canonical "later wins" assertion on InstallTarget:
	// the override defeats the blocklist.
	target, found := kernelmod.InstallTarget(directives, "algif_aead")
	if !found {
		t.Fatal("InstallTarget(algif_aead) found=false; want found=true (override exists)")
	}
	if !strings.Contains(target, "modprobe") {
		t.Errorf("InstallTarget(algif_aead) = %q, want the override (containing 'modprobe'), not the blocklist", target)
	}
}

// TestParseConfDir_NonConfFileSkipped verifies that a file without
// the .conf suffix (a stray README, a backup file, etc.) is ignored
// by the scan. modprobe itself only reads *.conf files in
// /etc/modprobe.d; backup files like README, foo.conf.bak, or
// foo.conf.dpkg-old MUST NOT influence policy.
func TestParseConfDir_NonConfFileSkipped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	copyTestdata(t, dir, "disable-algif-aead.conf")
	if err := os.WriteFile(filepath.Join(dir, "README"), []byte("this is documentation, not policy\n"), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "backup.conf.bak"), []byte("install legitimate_module /bin/false\n"), 0o600); err != nil {
		t.Fatalf("write backup.conf.bak: %v", err)
	}

	directives, err := kernelmod.ParseConfDir(dir)
	if err != nil {
		t.Fatalf("ParseConfDir() error: %v", err)
	}

	// disable-algif-aead.conf has 2 directives; README and .conf.bak must be skipped.
	if got, want := len(directives), 2; got != want {
		t.Fatalf("got %d directives, want %d (README and .conf.bak must be skipped)", got, want)
	}
}

// TestParseConfDir_SubdirectorySkipped verifies that nested directories
// (e.g., a /etc/modprobe.d/legacy/ folder) are NOT recursed into.
// modprobe's own scan is non-recursive — recursing would double-count
// any conf file that the operator deliberately moved into a subfolder
// to disable.
func TestParseConfDir_SubdirectorySkipped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	copyTestdata(t, dir, "disable-algif-aead.conf")

	// Nested directory whose name ends in .conf — even the suffix
	// match must not promote a directory into the parse list.
	// Mode 0o750 is used over the more common 0o755 to keep gosec
	// G301 happy (the directory only needs to be readable by us
	// during the test, not by the world).
	nested := filepath.Join(dir, "legacy.conf")
	if err := os.Mkdir(nested, 0o750); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nested, "shadow.conf"), []byte("install evil /bin/sh\n"), 0o600); err != nil {
		t.Fatalf("write nested conf: %v", err)
	}

	directives, err := kernelmod.ParseConfDir(dir)
	if err != nil {
		t.Fatalf("ParseConfDir() error: %v", err)
	}

	if got, want := len(directives), 2; got != want {
		t.Fatalf("got %d directives, want %d (nested directory must be skipped)", got, want)
	}
	for _, d := range directives {
		if strings.Contains(d.Source, "legacy.conf") {
			t.Errorf("directive Source %q came from nested directory; nested scan must be skipped", d.Source)
		}
	}
}

// TestParseConfDir_EmptyDir verifies the empty-dir contract: zero
// .conf files in, zero directives out, no error. The slice MUST NOT
// be nil — see the package contract on slice shape stability.
func TestParseConfDir_EmptyDir(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	directives, err := kernelmod.ParseConfDir(dir)
	if err != nil {
		t.Fatalf("ParseConfDir(empty) error: %v", err)
	}
	if directives == nil {
		t.Fatal("ParseConfDir(empty) returned nil slice; want non-nil empty slice")
	}
	if len(directives) != 0 {
		t.Errorf("ParseConfDir(empty) returned %d directives; want 0", len(directives))
	}
}

// TestParseConfDir_PartialSuccess verifies the partial-success
// contract: when ONE file in the directory is malformed and another
// is well-formed, ParseConfDir returns the good directives AND a
// non-nil error wrapping the bad file's failure. Audit-driving
// callers MUST handle this case — silently dropping the partial
// result on error would mask the well-formed policy that IS in
// effect, and silently dropping the error would mask the broken
// file that needs operator attention.
func TestParseConfDir_PartialSuccess(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	copyTestdata(t, dir, "disable-algif-aead.conf")
	if err := os.WriteFile(filepath.Join(dir, "zz-broken.conf"), []byte("blacklist\n"), 0o600); err != nil {
		t.Fatalf("write zz-broken.conf: %v", err)
	}

	directives, err := kernelmod.ParseConfDir(dir)
	if err == nil {
		t.Fatal("ParseConfDir() returned nil error; want wrapped ErrParse")
	}
	if !errors.Is(err, kernelmod.ErrParse) {
		t.Errorf("error %v is not ErrParse", err)
	}

	if got, want := len(directives), 2; got != want {
		t.Fatalf("got %d directives, want %d (the good file must still be parsed)", got, want)
	}
	for _, d := range directives {
		if strings.HasSuffix(d.Source, "zz-broken.conf") {
			t.Errorf("directive Source %q came from broken file; abort-on-bad parser should have skipped it", d.Source)
		}
	}
}

// TestParseConfDir_NonexistentDir verifies the wrapped error contract
// for a missing input directory. This is a likely real-world condition
// on a host where /etc/modprobe.d simply doesn't exist (some minimal
// containers); callers should be able to distinguish this from a parse
// error via errors.Is.
func TestParseConfDir_NonexistentDir(t *testing.T) {
	t.Parallel()

	directives, err := kernelmod.ParseConfDir(filepath.Join(t.TempDir(), "no-such-dir"))
	if err == nil {
		t.Fatal("ParseConfDir(nonexistent) returned nil error")
	}
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("error %v is not fs.ErrNotExist", err)
	}
	if directives == nil {
		t.Error("ParseConfDir(nonexistent) returned nil slice; want non-nil empty slice")
	}
}

// TestInstallTarget covers the modprobe "later wins" semantics, the
// missing-directive case, and the malformed empty-target case. Pinning
// "later wins" is critical: the modprobe.dependency_chain Phase-5 check
// relies on this exact behavior to decide whether a 99-override.conf
// has defeated a baseline 00-blacklist.conf install rule.
func TestInstallTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		module     string
		wantTarget string
		directives []kernelmod.ConfDirective
		wantFound  bool
	}{
		{
			name: "later install directive wins",
			directives: []kernelmod.ConfDirective{
				{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: "00-blacklist.conf", LineNum: 1},
				{Kind: "install", Module: "algif_aead", Args: []string{"/sbin/modprobe", "--ignore-install", "algif_aead"}, Source: "99-override.conf", LineNum: 1},
			},
			module:     "algif_aead",
			wantTarget: "/sbin/modprobe --ignore-install algif_aead",
			wantFound:  true,
		},
		{
			name: "no install directive returns empty/false",
			directives: []kernelmod.ConfDirective{
				{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: "00-blacklist.conf", LineNum: 1},
			},
			module:     "algif_aead",
			wantTarget: "",
			wantFound:  false,
		},
		{
			name: "install with empty target returns empty/true (malformed but possible)",
			directives: []kernelmod.ConfDirective{
				{Kind: "install", Module: "algif_aead", Args: []string{}, Source: "weird.conf", LineNum: 1},
			},
			module:     "algif_aead",
			wantTarget: "",
			wantFound:  true,
		},
		{
			name: "install for a different module is ignored",
			directives: []kernelmod.ConfDirective{
				{Kind: "install", Module: "other_mod", Args: []string{"/bin/true"}, Source: "00.conf", LineNum: 1},
			},
			module:     "algif_aead",
			wantTarget: "",
			wantFound:  false,
		},
		{
			name:       "empty directives slice returns empty/false",
			directives: nil,
			module:     "algif_aead",
			wantTarget: "",
			wantFound:  false,
		},
		{
			name: "blacklist directive does not contribute to InstallTarget",
			directives: []kernelmod.ConfDirective{
				{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: "00.conf", LineNum: 1},
				{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: "00.conf", LineNum: 2},
			},
			module:     "algif_aead",
			wantTarget: "/bin/false",
			wantFound:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			gotTarget, gotFound := kernelmod.InstallTarget(tc.directives, tc.module)
			if gotFound != tc.wantFound {
				subT.Errorf("InstallTarget(_, %q) found = %v, want %v", tc.module, gotFound, tc.wantFound)
			}
			if gotTarget != tc.wantTarget {
				subT.Errorf("InstallTarget(_, %q) target = %q, want %q", tc.module, gotTarget, tc.wantTarget)
			}
		})
	}
}

// TestIsBlacklisted covers the monotonic blacklist semantics: any
// blacklist line for the module makes the module blacklisted, and
// duplicate blacklist lines are idempotent. Case-sensitivity is pinned
// because kernel module names are themselves case-sensitive, and any
// future "convenience" addition of strings.EqualFold would silently
// mask configs that name modules with different casings.
func TestIsBlacklisted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		module     string
		directives []kernelmod.ConfDirective
		want       bool
	}{
		{
			name: "single blacklist directive returns true",
			directives: []kernelmod.ConfDirective{
				{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: "x.conf", LineNum: 1},
			},
			module: "algif_aead",
			want:   true,
		},
		{
			name: "no blacklist directive returns false",
			directives: []kernelmod.ConfDirective{
				{Kind: "install", Module: "algif_aead", Args: []string{"/bin/false"}, Source: "x.conf", LineNum: 1},
			},
			module: "algif_aead",
			want:   false,
		},
		{
			name: "multiple blacklist directives still return true (idempotent)",
			directives: []kernelmod.ConfDirective{
				{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: "00.conf", LineNum: 1},
				{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: "99.conf", LineNum: 1},
			},
			module: "algif_aead",
			want:   true,
		},
		{
			name: "blacklist for different module returns false",
			directives: []kernelmod.ConfDirective{
				{Kind: "blacklist", Module: "other_mod", Args: []string{}, Source: "x.conf", LineNum: 1},
			},
			module: "algif_aead",
			want:   false,
		},
		{
			name: "case-sensitive: capitalized variant does NOT match",
			directives: []kernelmod.ConfDirective{
				{Kind: "blacklist", Module: "algif_aead", Args: []string{}, Source: "x.conf", LineNum: 1},
			},
			module: "Algif_Aead",
			want:   false,
		},
		{
			name:       "empty directives slice returns false",
			directives: nil,
			module:     "algif_aead",
			want:       false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(subT *testing.T) {
			subT.Parallel()
			if got := kernelmod.IsBlacklisted(tc.directives, tc.module); got != tc.want {
				subT.Errorf("IsBlacklisted(_, %q) = %v, want %v", tc.module, got, tc.want)
			}
		})
	}
}

// copyTestdata copies a committed testdata fixture into dir under its
// original basename. Centralized here so individual subtests stay focused
// on the assertion (and so a future "use embed.FS" refactor only touches
// one place).
func copyTestdata(t *testing.T, dir, name string) {
	t.Helper()

	src := filepath.Join("testdata", name)
	data, err := os.ReadFile(src) // #nosec G304 -- src is a fixed testdata path
	if err != nil {
		t.Fatalf("read testdata %s: %v", src, err)
	}
	dst := filepath.Join(dir, name)
	// dst is t.TempDir() + a hardcoded fixture basename — no taint
	// flow from external input. The G703 nosec annotation documents
	// that the linter's path-traversal warning is a false positive
	// here, not a tolerated risk.
	if err := os.WriteFile(dst, data, 0o600); err != nil { // #nosec G304,G703 -- dst = t.TempDir() + caller-fixed basename
		t.Fatalf("write %s: %v", dst, err)
	}
}
