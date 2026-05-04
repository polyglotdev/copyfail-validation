# Check catalog

This catalog lists every check shipped (or planned) by `copyfail-validation`'s
day-one preset (`preset/copyfail`). Each entry documents the stable check ID,
its severity, when it is applicable, what the implementation does, the
state-mapping rules (Pass / Fail / Skip / Error), the shape of the
machine-readable Evidence map, and the SARIF rule ID emitted in the SARIF
output format.

## How to read this catalog

- **ID** is the stable, machine-readable string emitted in
  `Result.CheckID`, the SARIF `ruleId`, and the Prometheus
  `copyfail_check_state{check_id=…}` label. IDs are frozen at v1.0.0; see
  spec §10's semver table for the consequences of renaming one.
- **Severity** controls the exit-code contract (spec §6). A `required`
  check that returns `StateFail` flips the process exit code to 2; an
  `advisory` check never affects the exit code.
- **Applicability** (`Applicable() (bool, string)`) is checked before
  `Run()`. A non-applicable check produces a `StateSkip` result with the
  returned string in `Detail`.
- **State semantics** map the four `report.State` values
  (`Pass`/`Fail`/`Skip`/`Error`) to the conditions under which each fires.
  `Error` is reserved for "could not validate" — distinct from `Fail`
  ("validated, posture is wrong").
- **Evidence shape** is the JSON object emitted under `result.evidence`.
  Keys are stable across patch releases of the same minor version.

## Quick reference

| ID                              | Severity | Status                |
| ------------------------------- | -------- | --------------------- |
| `modprobe.conf_present`         | required | Implemented (v0.1.0)  |
| `modprobe.conf_correct`         | required | Implemented (v0.1.0)  |
| `modprobe.dry_run`              | required | Implemented (v0.1.0)  |
| `modprobe.dependency_chain`     | required | Implemented (v0.1.0)  |
| `module.not_loaded`             | required | Implemented (v0.1.0)  |
| `kernel.version`                | advisory | Planned for v0.1.x    |
| `hostinfo.os_release`           | advisory | Planned for v0.1.x    |
| `afalg.no_active_users`         | advisory | Planned for v0.1.x    |
| `integrity.su_binary`           | advisory | Planned for v0.1.x    |

## Implemented checks

### `modprobe.conf_present`

- **ID:** `modprobe.conf_present`
- **Title:** Modprobe blocklist file present
- **Severity:** required
- **SARIF rule ID:** `modprobe.conf_present`
- **Applicability:** always applicable (the blocklist file must exist on
  every host the preset runs on, regardless of distribution).

**Run logic.** Calls `os.Stat(opts.ConfPath)` (default
`/etc/modprobe.d/disable-algif-aead.conf`). The check is the cheapest of
the four `modprobe.*` checks and acts as the "is the configuration deployed
at all?" gate before the more expensive content checks run.

**State semantics:**

| Result                                          | State        |
| ----------------------------------------------- | ------------ |
| File exists and is a regular file               | `StatePass`  |
| File does not exist (`fs.ErrNotExist`)          | `StateFail`  |
| File exists but is not a regular file           | `StateFail`  |
| `os.Stat` returns any other error               | `StateError` |

**Evidence shape:**

```json
{
  "path": "/etc/modprobe.d/disable-algif-aead.conf",
  "exists": true,
  "is_regular": true,
  "size_bytes": 84
}
```

### `modprobe.conf_correct`

- **ID:** `modprobe.conf_correct`
- **Title:** Modprobe blocklist contents are correct
- **Severity:** required
- **SARIF rule ID:** `modprobe.conf_correct`
- **Applicability:** always applicable.

**Run logic.** Reads the configured blocklist file and verifies that BOTH
required directives are present:

- `install <module> /bin/false` (forces a no-op when something tries to
  load the module by name);
- `blacklist <module>` (prevents the module from being auto-loaded as a
  dependency of another module).

Both directives are required because each blocks a distinct load path. A
blocklist that has only one is a partial mitigation and is reported as a
failure with `Detail` naming the missing directive.

**State semantics:**

| Result                                                        | State        |
| ------------------------------------------------------------- | ------------ |
| Both directives present                                       | `StatePass`  |
| File missing or unreadable                                    | `StateError` |
| File readable but one or both directives missing or malformed | `StateFail`  |

**Evidence shape:**

```json
{
  "path": "/etc/modprobe.d/disable-algif-aead.conf",
  "module": "algif_aead",
  "has_install_directive": true,
  "has_blacklist_directive": true,
  "matched_lines": [
    "install algif_aead /bin/false",
    "blacklist algif_aead"
  ]
}
```

### `modprobe.dry_run`

- **ID:** `modprobe.dry_run`
- **Title:** modprobe -n -v resolves the module to /bin/false
- **Severity:** required
- **SARIF rule ID:** `modprobe.dry_run`
- **Applicability:** requires the `modprobe` binary on `$PATH`. When the
  binary is not found (resolved via `internal/exec`'s allowlist /
  `LookPath`), the check returns `StateSkip` with `skipped_reason="modprobe
  not found"`.

**Run logic.** Invokes `modprobe -n -v <module>` through `internal/exec`
with a 5-second timeout, captured stdout/stderr bounded to 1 MiB. The
output is parsed in Go (no shell). A correctly-blocklisted module produces
`install /bin/false` on stdout; anything else (loading the kmod from
`/lib/modules`, an `install … /bin/true` override) is a fail.

**State semantics:**

| Result                                                    | State        |
| --------------------------------------------------------- | ------------ |
| stdout contains `install /bin/false` (case-sensitive)     | `StatePass`  |
| `modprobe` binary not found                               | `StateSkip`  |
| stdout shows any other resolution                         | `StateFail`  |
| Subprocess errored (timeout, non-zero exit, write failure) | `StateError` |

**Evidence shape:**

```json
{
  "module": "algif_aead",
  "resolved_command": "/usr/sbin/modprobe",
  "argv": ["modprobe", "-n", "-v", "algif_aead"],
  "exit_code": 0,
  "stdout": "install /bin/false ",
  "duration_ms": 18
}
```

### `modprobe.dependency_chain`

- **ID:** `modprobe.dependency_chain`
- **Title:** No override directive in any /etc/modprobe.d/*.conf
- **Severity:** required
- **SARIF rule ID:** `modprobe.dependency_chain`
- **Applicability:** always applicable.

**Run logic.** Defense-in-depth check. modprobe processes files in
`/etc/modprobe.d/` in lexicographic order; a later-sorting file can
override the blocklist with a permissive directive (`install algif_aead
/bin/true`, `install algif_aead modprobe --allow-unsupported algif_aead`,
or any non-`/bin/false` install line). The check enumerates every
`*.conf` under `opts.ModprobeDir`, parses it, and flags any directive that
re-enables the module.

**State semantics:**

| Result                                              | State        |
| --------------------------------------------------- | ------------ |
| No override directive found in any scanned file     | `StatePass`  |
| ≥1 override directive found                         | `StateFail`  |
| Directory unreadable / unrecoverable parse error    | `StateError` |

**Evidence shape:**

```json
{
  "scanned_dir": "/etc/modprobe.d",
  "scanned_files": 12,
  "module": "algif_aead",
  "overrides": [
    {
      "file": "/etc/modprobe.d/99-vendor-override.conf",
      "line_number": 3,
      "directive": "install algif_aead /bin/true"
    }
  ]
}
```

### `module.not_loaded`

- **ID:** `module.not_loaded`
- **Title:** Target module absent from /proc/modules
- **Severity:** required
- **SARIF rule ID:** `module.not_loaded`
- **Applicability:** always applicable.

**Run logic.** Reads `/proc/modules` directly with `os.ReadFile` (no
shell, no `lsmod` subprocess). Each line of `/proc/modules` begins with
the module's canonical name; the check tokenises on whitespace and
compares the first field against `opts.Module`. The module is considered
"not loaded" when no line matches.

**State semantics:**

| Result                                          | State        |
| ----------------------------------------------- | ------------ |
| Module name not present in `/proc/modules`      | `StatePass`  |
| Module name present                             | `StateFail`  |
| `/proc/modules` not readable                    | `StateError` |

**Evidence shape:**

```json
{
  "module": "algif_aead",
  "loaded": false,
  "proc_modules_lines": 142
}
```

## Planned checks (v0.1.x)

The four advisory checks below are part of the day-one design (spec §11)
but have not landed yet. They will appear at the tail of `copyfail.All()`
once implemented; severity is `advisory` so they will not change the exit
code when they error or fail.

### `kernel.version`

- **Status:** planned for v0.1.x — see issue #N (placeholder).
- **Severity:** advisory.
- **Purpose:** populate `host.kernel_release` with the running kernel
  version (`uname -r` parsed in Go from `/proc/sys/kernel/osrelease`),
  giving operators a single field to bucket reports against.

### `hostinfo.os_release`

- **Status:** planned for v0.1.x — see issue #N (placeholder).
- **Severity:** advisory.
- **Purpose:** parse `/etc/os-release` and populate `host.os_release` /
  `host.os_version_id`. Reuses `internal/hostinfo`'s parser so the
  check itself is a thin wrapper.

### `afalg.no_active_users`

- **Status:** planned for v0.1.x — see issue #N (placeholder).
- **Severity:** advisory.
- **Purpose:** flag any process that has an AF_ALG-family kernel module
  mapped into its address space. Implemented in `internal/procscan`
  using `/proc/<pid>/maps` (no `lsof`, no shell). Skipped when EUID is
  not 0 (cannot read other processes' maps).

### `integrity.su_binary`

- **Status:** planned for v0.1.x — see issue #N (placeholder).
- **Severity:** advisory.
- **Purpose:** compare `/usr/bin/su` against the package manager's
  recorded checksum (rpm or dpkg, auto-selected via
  `internal/integrity.Detect()`). Single check, single result row;
  backend identity (`rpm` vs. `dpkg`) recorded in `Evidence["backend"]`.
  Skipped when neither package manager is present.
