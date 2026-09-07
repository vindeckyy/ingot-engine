# Security Policy

## Threat Model

Ingot runs containers with Linux namespace isolation, cgroups v2 resource limits, and capability confinement. It is designed for a single-operator host where the daemon runs as root and trusted users invoke the CLI.

Ingot is **not** a multi-tenant platform. It does not implement user-to-user isolation, RBAC, or quota enforcement across tenants. Do not expose the `/run/ingot/ingot.sock` to untrusted users or networks.

Ingot has not received a security audit.

## What Is In Scope

- Privilege escalation through the daemon or CLI.
- Container escape via namespace, cgroup, overlayfs, or capability handling.
- Image unpack vulnerabilities (path traversal, symlink attacks, whiteout handling).
- Registry client vulnerabilities (TLS, authentication, digest verification).
- Firewall or NAT rule leakage across container lifecycles.
- Secret leakage into logs, inspect output, or cache keys.

## What Is Out Of Scope

- Multi-tenant isolation between untrusted users sharing one daemon.
- Attacks requiring physical access or a compromised kernel.
- Vulnerabilities in dependencies that are already tracked by upstream CVEs (report those upstream).

## Reporting A Vulnerability

Do not file a public issue for security vulnerabilities.

Email the maintainer with a description and reproduction steps. You will receive an acknowledgment within 72 hours. Coordinated disclosure timelines are negotiated per report.

Include in your report:

- Affected version or commit
- Reproduction steps
- Impact assessment
- Suggested fix if you have one

## Hardening Notes

- The daemon runs as root. Restrict socket access to trusted users.
- Capability confinement uses Docker's default set plus bounding/effective/permitted/inheritable drops. Privileged mode grants all capabilities and is opt-in only.
- Read-only rootfs, masked paths, and no-new-privileges are supported per container.
- Image unpack validates tar entries and rejects path traversal. Whiteout markers are applied before the layer is committed.
- Registry downloads verify digests against the manifest before blobs are committed to CAS.

## Audit-Scope Brief (Pre-Audit)

Status: no external audit has been performed. The surfaces below are
the audit scope when one is scheduled; the evidence column names the
in-tree proof that exists today.

Trust boundaries:

- Unix socket (`/run/ingot/ingot.sock`) → effective root. Socket file
  permissions/group are the only gate. Evidence: `serve.rs` bind,
  `--socket-group`, `SECURITY.md` threat model.
- Container → host: namespaces, pivot-root, capability drops,
  no-new-privs, seccomp allowlist, masked/readonly `/proc`+`/sys`.
  Evidence: `crates/runtime/src/child.rs`, `seccomp.rs`, matrix tests
  in `crates/runtime/src/error.rs`.
- Registry → daemon: TLS, Bearer [REDACTED] negotiation, manifest
  digest pinning, blob hash verification, platform-digest checks.
  Evidence: `crates/registry/src/client.rs`, `crates/image/src/pull.rs`.
- Build secrets → image: values materialized outside the diff dir,
  excluded from cache keys and history rows. Evidence:
  `history_rendering_and_secret_hygiene` test in
  `crates/builder/src/build.rs`.

Privileged surfaces requiring review:

- `crates/runtime/src/child.rs` `unsafe` blocks (~27 syscall-scoped
  sites): namespace setup, pivot-root, capability and user switching.
- `crates/runtime/src/seccomp.rs`: allowlist completeness vs
  default-deny intent; per-syscall rationale comments.
- Archive extraction (`crates/image/src/unpack.rs`): symlink/hardlink
  escape, device nodes, setuid, `/proc`+`/sys` writes; covered by
  `fuzz_archive_unpack` plus unit tests.
- Firewall/NAT programming (`crates/network/src/lib.rs`): rule
  lifecycle, orphan cleanup, boot reconciliation.
- API validation (`crates/runtime/src/error.rs`,
  `crates/server/src/handlers/`): every accepted option enforced or
  explicitly rejected; negative-option matrix tests.

Pre-audit checklist: close the open hardening items (device plumbing
is reject-only; `push`/Swarm/plugins absent by design), run the
Tier-2 suites on a host that permits nsfs bind mounts, and execute a
longer fuzz campaign over the five `fuzz/` targets before engaging
reviewers.
