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
