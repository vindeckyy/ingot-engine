# Contributing to Ingot

## Build and Test Gates

Before opening a PR, run the strict gate locally:

```bash
./scripts/check.sh --strict
```

This runs `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`. All three must pass.

If you add a new crate or change dependencies, also run:

```bash
cargo build -p ingotd -p ingot-cli
```

## Test Tiers

### Tier 1: Rootless Unit Tests

`cargo test --workspace` runs anywhere, no root required. This is what CI runs on every push and PR.

Rules for Tier 1 tests:

- No namespaces, mounts, cgroups, netlink, or privileged sockets.
- No daemon process, no Unix socket at `/run/ingot`.
- Filesystem tests use `std::env::temp_dir()` and clean up after themselves.
- Tests that need a `DataPaths` or `DaemonState` construct them under a temp directory, not `/var/lib/ingot`.

If your test needs root or a running daemon, it belongs in Tier 2, not here.

### Tier 2: Root Integration Tests

Tier 2 tests require root, a running `ingotd`, and host networking/firewall access. They run on a disposable host or VM, not in CI.

```bash
sudo ./target/debug/ingotd --debug &
export DOCKER_HOST=unix:///run/ingot/ingot.sock
./scripts/test_interop.sh
./scripts/test_network.sh
```

If you add Tier 2 coverage, extend `scripts/test_interop.sh` or `scripts/test_network.sh` rather than gating a unit test on root.

## Code Conventions

- Follow existing style. `cargo fmt` is the authority.
- No new mandatory runtime dependencies. If a dependency is needed, prefer one already in `Cargo.toml`.
- Every accepted API option must be enforced or explicitly rejected. Do not silently ignore options.
- Error responses use Docker-shaped bodies: `{"message": "..."}`.
- Keep firewall, cgroup, and mount teardown idempotent.
- Preserve `/var/lib/ingot` on-disk migration discipline. Do not break existing state directories.
- Do not leak secrets into logs, inspect/history output, or cache keys.

## Pull Request Checklist

- [ ] `./scripts/check.sh --strict` passes
- [ ] New logic has a runnable check (unit test or assert-based self-check)
- [ ] No new mandatory runtime dependency
- [ ] No silently ignored API options
- [ ] Error bodies are Docker-shaped
- [ ] Tier 1 tests stay rootless-safe

## Reporting Issues

Use the GitHub issue templates. For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead of filing a public issue.
