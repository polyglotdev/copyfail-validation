// Copyright 2026 Dom Hallan
// SPDX-License-Identifier: Apache-2.0

package kernelmod

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ErrParse is returned for /etc/modprobe.d parsing failures. The wrapped
// error includes the source path, the 1-indexed line number, and the
// raw line text so an operator reading the audit log can identify
// exactly which conf file is malformed. Match with errors.Is — the
// surrounding message text is not part of the package contract and may
// change between minor releases.
var ErrParse = errors.New("kernelmod: malformed modprobe.d directive")

// confFileSuffix is the only filename suffix ParseConfDir recognizes.
// modprobe itself only reads files with this exact suffix in
// /etc/modprobe.d (and /lib/modprobe.d, /run/modprobe.d, /usr/lib/modprobe.d
// under the systemd-style search path) — files like ".conf.bak" or
// ".conf.dpkg-old" are deliberately ignored by modprobe and we mirror
// that behavior so a backup file does not get treated as policy.
const confFileSuffix = ".conf"

// confDirectiveMinFields is the minimum number of whitespace-separated
// tokens a directive line must have AFTER continuation joining and
// inline-comment stripping. Every supported directive (install,
// blacklist, options, alias, softdep, remove) requires at least
// "<kind> <module>" — two tokens. A line with one token is malformed
// and produces ErrParse; a line with zero tokens (e.g., only a comment)
// is skipped silently.
const confDirectiveMinFields = 2

// ConfDirective is one parsed directive from a /etc/modprobe.d/*.conf
// file. The package preserves the original Source path and 1-indexed
// LineNum so audit logs can point operators at the exact file:line that
// produced a particular policy decision — critical when ParseConfDir
// returns dozens of directives spanning multiple files.
//
// Field order is laid out for govet's fieldalignment pass (string and
// slice headers first, fixed-width integer last). The wire-format
// column order is "kind module args…" but that is not the in-memory
// order.
type ConfDirective struct {
	// Field order is laid out for govet's fieldalignment pass: the
	// 16-byte string headers (Source, Module, Kind) come first so all
	// their data-pointers sit in the prefix [0..48), then the 24-byte
	// slice header (Args) places its data-pointer at offset 48, then
	// the 8-byte int (LineNum) tail. This gives a 56-byte pointer
	// prefix instead of 64 — the GC scans 8 fewer bytes per directive.
	// The wire-format column order on disk is "kind module args…"
	// which is NOT the in-memory order; renderers that re-emit
	// directives must reconstruct the wire order explicitly.

	// Source is the path the directive was read from. ParseConfFile
	// records the absolute path of the resolved symlink target (so
	// audit can detect a /etc/modprobe.d/foo.conf -> /tmp/attacker.conf
	// redirect). ParseConfReader records whatever string the caller
	// passed for source; callers reading from a real file should pass
	// the absolute path.
	Source string

	// Module is the kernel module name the directive applies to.
	// Comparison should be case-sensitive — kernel module names are
	// themselves case-sensitive.
	Module string

	// Kind is the directive verb as written in the conf file.
	// Documented kinds (install, blacklist, options, alias, softdep,
	// remove) are stored verbatim; unknown verbs are tolerated and
	// stored as the raw string so a future modprobe directive does
	// not silently get dropped on the floor.
	Kind string

	// Args is the list of whitespace-separated tokens that followed
	// Module on the directive line (after continuation joining and
	// inline-comment stripping). For "install foo /bin/false" Args is
	// []string{"/bin/false"}. For "blacklist foo" Args is []string{}.
	// The empty case is the empty slice (NOT nil) so callers can
	// range over it without a length check.
	Args []string

	// LineNum is the 1-indexed line number within Source where the
	// directive started. For directives joined via line continuation
	// (a trailing backslash on the previous line), LineNum points at
	// the FIRST line of the joined block — that is where an operator
	// would edit to change the directive.
	LineNum int
}

// ParseConfFile parses one .conf file at path. Symlinks are followed
// (modprobe follows them) but the resolved ABSOLUTE path of the target
// is recorded in the emitted directives' Source field — an audit can
// then detect symlink redirection by comparing the requested path
// against the recorded Source. If symlink resolution or absolutization
// fails the original input path is used as a fallback so a broken
// symlink still produces a useful error message.
//
// The Source field is always absolute when the input path resolves
// successfully; callers passing relative paths (e.g., "testdata/foo.conf"
// in unit tests) get the absolute equivalent in the recorded Source.
// This matters for forensic audits where the relative working directory
// at parse time would otherwise be lost.
//
// Returns a wrapped fs.ErrNotExist for a missing file (use errors.Is
// to match), and a wrapped ErrParse for a malformed directive.
func ParseConfFile(path string) ([]ConfDirective, error) {
	// Resolve symlinks first so we follow whatever modprobe would
	// actually read. EvalSymlinks returns a path that is absolute IFF
	// the input was absolute — for relative inputs we still need
	// filepath.Abs to canonicalize for the Source field.
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		resolved = path
	}
	if abs, absErr := filepath.Abs(resolved); absErr == nil {
		resolved = abs
	}

	f, err := os.Open(resolved) // #nosec G304 -- caller-controlled path; this is the parser entry point
	if err != nil {
		return []ConfDirective{}, fmt.Errorf("kernelmod: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	return ParseConfReader(f, resolved)
}

// ParseConfReader parses an already-opened conf file from r. The source
// argument is used verbatim as the Source field on emitted directives;
// callers reading from a real file should pass the absolute path so
// downstream audit logs can identify which file produced a directive.
//
// The returned slice is never nil: empty input yields an empty slice
// with a nil error. Comment lines and blank lines are skipped without
// emitting a ConfDirective. A line with a trailing unescaped backslash
// is joined with the next line (modprobe.d continuation syntax); the
// joined directive's LineNum is the line number of the FIRST line.
//
// On the first malformed directive the parser aborts and returns the
// directives parsed so far PLUS a wrapped ErrParse that includes the
// source, 1-indexed line number, and raw line text. Aborting (rather
// than skipping) is deliberate: a malformed conf file usually indicates
// either a deployment bug or a tampered file — both conditions the
// caller must surface, not silently mask.
func ParseConfReader(r io.Reader, source string) ([]ConfDirective, error) {
	directives := make([]ConfDirective, 0)
	scanner := bufio.NewScanner(r)

	// Default 64KiB scanner buffer is more than enough for modprobe.d
	// files, which are typically <1KiB. We do not raise it because
	// doing so would invite OOM if a hostile io.Reader streams an
	// arbitrarily long single "line" — bufio.Scanner caps at
	// MaxScanTokenSize by default, returning bufio.ErrTooLong, which
	// we surface as a scanner.Err() below.

	var (
		pending      strings.Builder
		pendingStart int // 1-indexed line number where the joined block started
		lineNum      int
	)

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()

		// Strip inline comments and trailing whitespace BEFORE
		// continuation handling. modprobe ignores everything from
		// `#` to end-of-line, including any continuation backslash
		// that lives inside the comment region.
		stripped := stripInlineComment(raw)
		stripped = strings.TrimRight(stripped, " \t")

		// A line that contains nothing but whitespace and/or a
		// comment is a no-op IF we are not currently building a
		// continuation block. If we ARE inside a continuation block
		// the blank line still counts as a line for numbering but
		// does not contribute content (matching modprobe behavior:
		// the previous line's trailing `\` joined with empty content).
		if strings.TrimSpace(stripped) == "" {
			if pending.Len() > 0 {
				// In-continuation blank line: the previous line
				// promised "more content" via `\` but delivered
				// nothing on this line. Keep waiting for the next
				// line — modprobe also tolerates this.
				continue
			}
			continue
		}

		// Continuation: a trailing `\` (after inline-comment and
		// trailing-whitespace stripping) means "join with next line".
		if strings.HasSuffix(stripped, `\`) {
			content := strings.TrimSuffix(stripped, `\`)
			if pending.Len() == 0 {
				pendingStart = lineNum
			} else {
				pending.WriteByte(' ')
			}
			pending.WriteString(strings.TrimRight(content, " \t"))
			continue
		}

		// Non-continuation line: flush any pending block + this line.
		var (
			joined    string
			startLine int
		)
		if pending.Len() > 0 {
			pending.WriteByte(' ')
			pending.WriteString(strings.TrimLeft(stripped, " \t"))
			joined = pending.String()
			startLine = pendingStart
			pending.Reset()
			pendingStart = 0
		} else {
			joined = stripped
			startLine = lineNum
		}

		directive, err := parseConfDirectiveLine(joined, source, startLine)
		if err != nil {
			return directives, fmt.Errorf("%w: %s:%d: %q: %w", ErrParse, source, startLine, joined, err)
		}
		directives = append(directives, directive)
	}

	if err := scanner.Err(); err != nil {
		return directives, fmt.Errorf("kernelmod: read %s: %w", source, err)
	}

	// A trailing continuation (file ends with `\` and no following
	// line) collapses to whatever content accumulated. If the
	// accumulated content is non-empty we still try to parse it; if
	// it is empty we silently drop it (modprobe is similarly lenient).
	if pending.Len() > 0 {
		joined := strings.TrimSpace(pending.String())
		if joined != "" {
			directive, err := parseConfDirectiveLine(joined, source, pendingStart)
			if err != nil {
				return directives, fmt.Errorf("%w: %s:%d: %q: %w", ErrParse, source, pendingStart, joined, err)
			}
			directives = append(directives, directive)
		}
	}

	return directives, nil
}

// stripInlineComment removes a `#`-introduced comment from line.
// Only an UNQUOTED `#` introduces a comment; modprobe.d does not
// support quoted strings (no shell-style "..." or '...' grouping), so
// every `#` outside the leading-whitespace region is a comment marker.
// We deliberately do NOT trim leading whitespace here — the caller
// needs the original indentation to detect "fully blank" lines.
func stripInlineComment(line string) string {
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		return line[:idx]
	}
	return line
}

// parseConfDirectiveLine parses one already-joined, comment-stripped
// directive line into a ConfDirective. The source and lineNum are
// passed through unchanged into the returned record. Returns a
// non-nil error if the directive has fewer than two tokens (which
// would mean a kind with no module, e.g., "install" by itself).
func parseConfDirectiveLine(line, source string, lineNum int) (ConfDirective, error) {
	fields := strings.Fields(line)
	if len(fields) < confDirectiveMinFields {
		return ConfDirective{}, fmt.Errorf("expected at least %d fields, got %d", confDirectiveMinFields, len(fields))
	}

	args := make([]string, 0, len(fields)-2)
	if len(fields) > 2 {
		args = append(args, fields[2:]...)
	}

	return ConfDirective{
		Kind:    fields[0],
		Module:  fields[1],
		Args:    args,
		Source:  source,
		LineNum: lineNum,
	}, nil
}

// ParseConfDir scans dir for *.conf files (NOT *.conf.d/, NOT recursive),
// parses each in alphabetical order, and returns the concatenated list
// of directives. modprobe's "later wins" semantics mean that a directive
// in a file with a higher-sorting name overrides an earlier directive
// for the same module; callers comparing the list against an expected
// state should iterate in order and let later directives shadow earlier
// ones (see InstallTarget below for the canonical implementation).
//
// Files that are NOT regular files (sockets, FIFOs, char devices,
// directories) and files that fail to open are skipped with a
// non-fatal warning recorded in the returned error chain via
// errors.Join. The returned directives slice is the successfully-parsed
// subset; callers MUST handle a non-nil error AND a non-empty slice as
// the partial-success case.
func ParseConfDir(dir string) ([]ConfDirective, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []ConfDirective{}, fmt.Errorf("kernelmod: read dir %s: %w", dir, err)
	}

	// Sort alphabetically by raw filename (byte comparison) to match
	// what `ls -1` shows and what modprobe itself does. This is the
	// sort order that determines "later wins" — 99-override.conf
	// shadows 00-blacklist.conf because '9' > '0' in ASCII.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	directives := make([]ConfDirective, 0)
	var errs []error

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, confFileSuffix) {
			continue
		}

		// Use entry.Info() rather than os.Lstat to avoid an extra
		// syscall — ReadDir already populated the stat info. The
		// IsRegular() check rejects directories, sockets, FIFOs,
		// char devices, and block devices; a symlink TO a regular
		// file passes (Info() follows the link by default on
		// most filesystems, but we treat both shapes the same).
		info, infoErr := entry.Info()
		if infoErr != nil {
			errs = append(errs, fmt.Errorf("kernelmod: stat %s: %w", filepath.Join(dir, name), infoErr))
			continue
		}
		// Resolve symlinks: ReadDir's Info() returns Lstat-style
		// info on most filesystems, so a symlink-to-regular-file
		// would fail IsRegular(). os.Stat follows the link.
		if info.Mode()&os.ModeSymlink != 0 {
			info, infoErr = os.Stat(filepath.Join(dir, name))
			if infoErr != nil {
				errs = append(errs, fmt.Errorf("kernelmod: stat symlink target %s: %w", filepath.Join(dir, name), infoErr))
				continue
			}
		}
		if !info.Mode().IsRegular() {
			continue
		}

		path := filepath.Join(dir, name)
		fileDirectives, parseErr := ParseConfFile(path)
		// Append whatever directives were parsed before any error
		// (parser is abort-on-bad, so this is the prefix that
		// parsed cleanly). This preserves the partial-success
		// contract documented above.
		directives = append(directives, fileDirectives...)
		if parseErr != nil {
			errs = append(errs, parseErr)
			// Do NOT abort the whole dir scan — keep parsing
			// remaining files so an operator running an audit
			// gets the full picture, not just the first failure.
			continue
		}
	}

	if len(errs) > 0 {
		return directives, errors.Join(errs...)
	}
	return directives, nil
}

// InstallTarget walks directives in order and returns the LAST install
// target for module (matching modprobe's "later wins" semantics). The
// found bool distinguishes "no install directive" from "install …
// (empty target)" — though the latter is a malformed conf in practice.
//
// Args of an install directive are joined with spaces because the
// install command itself may contain arguments (e.g.,
// "install algif_aead /sbin/modprobe --ignore-install algif_aead"
// has a 4-token Args list that should be presented as a single
// command string for comparison against expected policy).
func InstallTarget(directives []ConfDirective, module string) (target string, found bool) {
	for _, d := range directives {
		if d.Kind != "install" || d.Module != module {
			continue
		}
		// "Later wins": keep overwriting until we exhaust the slice.
		target = strings.Join(d.Args, " ")
		found = true
	}
	return target, found
}

// IsBlacklisted reports whether ANY blacklist directive for module
// appears in directives. Unlike InstallTarget, blacklisting is
// monotonic — a single blacklist line anywhere in any file makes the
// module blacklisted; there is no "un-blacklist" directive in the
// modprobe.d format.
//
// Returns false for an empty directives slice and for a module name
// that matches no blacklist entry. Comparison is case-sensitive.
func IsBlacklisted(directives []ConfDirective, module string) bool {
	for _, d := range directives {
		if d.Kind == "blacklist" && d.Module == module {
			return true
		}
	}
	return false
}
