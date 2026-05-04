# Security Policy

`copyfail-validation` is a defensive validator for Linux hosts against the
AF_ALG-family kernel-crypto vulnerabilities, starting with CVE-2026-31431
("copyfail"). The tool is **read-only**: it never modifies host state, never
attempts exploitation, and never executes shell pipelines. Subprocess
invocations go through an allowlisted, argument-validated wrapper
(`internal/exec`) with bounded stdout/stderr capture, hard timeouts, and
SIGTERM-then-SIGKILL teardown. Builds are reproducible (`-trimpath`,
`CGO_ENABLED=0`), the dependency graph is kept minimal, and supply-chain
controls (signed releases, SBOMs, SLSA provenance) are tracked in the v0.1.x
roadmap.

This document explains how to report a vulnerability, what versions receive
fixes, and what is explicitly out of scope.

## Supported versions

| Version | Status                       |
| ------- | ---------------------------- |
| v0.1.x  | Supported until v1.0.0 ships |
| < v0.1  | Unsupported (pre-release)    |

Once v1.0.0 ships, the `v0.x` line moves to end-of-life and only the
current `v1.x` line will receive security fixes. Backport policy for older
v1.x minors will be documented at that time.

## Reporting a vulnerability

Please report suspected security issues through one of the following
channels, in order of preference:

1. **GitHub Security Advisory** — open a private advisory at
   <https://github.com/polyglotdev/copyfail-validation/security/advisories/new>.
   This is the recommended channel: it gives maintainers a private workspace
   to coordinate the fix and produces a CVE-ready advisory once published.
2. **Signed email** — send an encrypted or signed message to
   `dom@domhallan.com`. Plaintext email is acceptable for low-sensitivity
   reports; please avoid pasting working exploits into plaintext.

When reporting, please include:

- The affected version(s) and OS / kernel.
- A clear description of the issue and the security impact.
- Reproduction steps, ideally as a minimal test case.
- Any suggested fix or mitigation, if you have one.

We follow a **90-day coordinated-disclosure window** consistent with
[CERT/CC's vulnerability disclosure guidelines][certcc-disclose]. We will
acknowledge receipt within 3 business days and aim to ship a fix (or a
detailed mitigation) before the 90-day deadline. If the report involves a
third-party dependency, we will coordinate with that project's maintainers
and may extend the window with the reporter's agreement.

[certcc-disclose]: https://insights.sei.cmu.edu/library/the-cert-guide-to-coordinated-vulnerability-disclosure/

## PGP key

PGP key publication is **planned for v0.2.0**. Until then, please use the
GitHub Security Advisory channel above (which is end-to-end encrypted to the
maintainer team) or signed email.

## Out of scope

The following threats are explicitly out of scope and are documented in the
project's threat model (spec §7):

- **Root attacker on the host.** This tool is a compliance reporter, not an
  EDR. A root attacker can defeat any userspace check by editing
  `/proc/modules` reads, swapping `modprobe`, or live-patching the kernel.
- **Kernel-level evasion.** Same reasoning — the validator runs in userspace
  and trusts the kernel's view of `/proc`, module state, and process
  metadata.
- **Adversarial local users.** The tool is designed to run as root or under
  an SSM Agent / cron context. It is not hardened against unprivileged
  users invoking it with crafted environment variables.
- **Bugs in third-party dependencies that do not affect the validator's
  behavior.** We do track and update dependencies via `govulncheck` in CI,
  and will issue advisories when a downstream CVE materially affects the
  tool's posture, but a CVE in an unused code path of a dependency is not
  itself a vulnerability in this project.

For everything else — including the full set of in-scope threats and their
mitigations (shell-injection, path-traversal, argument-injection,
`$PATH`-hijack, TOCTOU, resource exhaustion, output-truncation,
sensitive-data leakage) — see spec §7 in
`docs/superpowers/specs/2026-05-04-copyfail-validation-design.md`.
