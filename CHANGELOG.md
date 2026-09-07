# Changelog

## Versioning Policy

- Versions are `0.major.minor` until the API and on-disk format stabilize;
  `ENGINE_VERSION` (reported by `/version`) tracks the release.
- A **minor** bump may add endpoints/options (always additive) and tighten
  validation, but only through the deprecation path below.
- A **major** bump may change on-disk layout (with migrate-or-refuse) or
  remove a previously deprecated behavior.
- Every release records its passing commit, `check.sh --strict` status,
  and Tier-1/Tier-2 suite results.

## Deprecation Policy

Behavior tightening (a previously accepted input becomes a `400`/`501`,
or a default changes) ships in three steps:

1. Release N: the old behavior keeps working; the response or daemon log
   carries a `Deprecated:` warning naming the replacement.
2. Release N+1: the matrix (`docs/DOCKER_MATRIX.md`) marks it deprecated
   with the removal release.
3. Release N+2: the new behavior lands with an explicit Docker-shaped
   error, a matrix entry, and a changelog line.

Silent changes are never acceptable: warn first, document always.

## Unreleased (working tree)

Implemented on top of `113796b`, uncommitted, verified by
`./scripts/check.sh --strict` plus the crate suites named per item.

### Security sweep (container-escape hardening)

- Containers now join a private cgroup namespace (`CLONE_NEWCGROUP`),
  so `/proc/self/cgroup` and `/sys/fs/cgroup` no longer reveal the
  host cgroup layout (the matrix already claimed `cgroup` isolation;
  the code now matches).
- `--user uid:gid,gid2,...` multi-gid specs are parsed end to end:
  the daemon fast path splits primary and supplementary gids, and the
  in-container resolver handles named/numeric lists. Previously
  `1000:100,200` silently ran with gid 0 (root group); unresolvable
  specs now fail closed. Unit tests in `crates/runtime` cover both
  layers.
- `--tmpfs` destinations stay writable under `--read-only`: their
  directories are created before the recursive read-only remount and
  the tmpfs mounts land after it (previously the remount sealed them).

### Enforced-or-rejected closure

- `HostConfig.CpuQuota`/`CpuPeriod` are now enforced via cgroup v2
  `cpu.max` (quota/period, kernel default period when unset); negatives
  are `400` (`crates/runtime`: `error.rs`, `cgroup.rs`; matrix updated).
- New `HostConfig.MemorySwap` field enforced as `memory.swap.max`
  (`-1` unlimited, `0` daemon default, positive caps must cover
  `Memory`); below-memory caps are `400`.
- Negative `Memory`/`NanoCpus`/`CpuShares` are `400` (no silent
  clamp to unlimited); malformed `CpusetCpus` is `400` at create time.
- `LogConfig` honors `max-size`/`max-file` (json-file rotation,
  `crates/runtime/src/stdio.rs`); any other log-opt key is `400`.
- `docs/DOCKER_MATRIX.md` corrected: `Devices` rejected even when
  privileged; `SecurityOpt` accepted spellings fixed; rejected-field
  rollup row added.

### API surface

- The router serves every API minor from `1.24` to `1.44` (was 1.44
  only); out-of-range versions keep the explicit `501`
  (`crates/server/src/router.rs`, `crates/api/src/lib.rs`).
- `die` events carry `exitCode`; new `health_status` container events;
  new `network` (`create`/`destroy`/`connect`/`disconnect`), `volume`
  (`create`/`destroy`), and `image` (`pull`/`tag`) events.
- Image history is recorded for built images (base history inherited,
  one row per applied instruction); pulled images already carried OCI
  history (`crates/builder/src/build.rs`).
- `ingot push` and `POST /images/{name}/push`: single-platform OCI
  manifest push (config + layers, HEAD skip, `pull,push` bearer scope,
  Docker-shaped progress stream); manifest lists are not pushed
  (`crates/registry/src/client.rs`, `crates/image/src/push.rs`,
  `crates/server/src/handlers/images.rs`, `crates/ingot-cli`).

### Operability

- `ingotd --config` JSON config file with flag > file > default
  precedence; unknown keys fail the boot (`crates/ingotd/src/main.rs`,
  `README.md` "Config File").
- New `docs/OPERATIONS.md`: service lifecycle, backup/restore and
  schema-migration discipline, log rotation policy, troubleshooting
  matrix, leak checks.
- `scripts/test_crash_recovery.sh` fixed: correct `--socket` flag and a
  docker wrapper that actually points at the test socket.

### Gated scope (user-approved 2026-09-07)

- IPv6 dual-stack, opt-in via `ingotd --ipv6` (off by default, docker
  parity): ULA `/64` per network from `--fixed-cidr-v6` (default
  `fd00:dead:beef::/48`), `ip6tables` MASQUERADE/FORWARD rules,
  DNS AAAA records; per-network `EnableIPv6` stays `400`
  (`crates/network`, `crates/ingotd`).
- New `docs/ROOTLESS_STUDY.md`: rootless-daemon feasibility grounded in
  the actual privileged code paths (study only, no code).
- Compose `profiles` (`--profile`/`COMPOSE_PROFILES`), `extends`
  (local-file, shallow merge), `deploy.resources` limits, and
  `configs`/`secrets` short+long syntax wired to the secrets mount
  flow (`crates/ingot-cli/src/compose.rs`, README "Compose" section).

### Compose / CLI

- Compose `pull_policy` (`always`, `missing`, `never`, `build`) with
  fail-fast validation; health/completion gates for `depends_on`
  (`service_healthy` waits up to 60s, `service_completed_successfully`
  requires exit 0) (`crates/ingot-cli/src/compose.rs`).
- `ingot ps` / `ingot images` accept `--format table|json`
  (newline-delimited raw objects); Go templates are rejected with the
  accepted values named.

### Testing / fuzz

- New unit suites: resource validation matrix, cgroup value builders,
  log parsing/rotation (incl. file-cap pressure test), config merge,
  compose policy/condition/topology, history rendering + secret hygiene,
  manifest index selection, filter parsing.
- New fuzz targets: `fuzz_manifest_index`, `fuzz_api_filters`
  (`fuzz/`; `cargo check` clean). `fuzz_archive_unpack` already covers
  tar/whiteout traversal. Campaigns, all crash-free: filters 3.66M,
  manifest 2.94M, dockerfile 2.65M, archive-unpack 2.81M,
  registry-ref 5.47M execs.
- Secret values proven absent from cache keys, history rows, and mount
  keys (declarations only).

### Known environment limitation

Container *start* cannot run on hosts whose kernel refuses `mount(2)`
bind-mounts of mount-namespace files onto regular files (observed:
`EINVAL` on this machine, verified with a direct `mount` syscall and
the `mount(8)` CLI) — not by Ingot code. Everything else was validated
live against a release daemon on such a host: version negotiation
across `/v1.24`–`/v1.44`, pull/tag/untag/history, create-time
validation (negative memory, log opts), resource-field round-trip,
network and volume CRUD, `system/df`, 501s, and a filtered volume
`create`/`destroy` event stream. Full lifecycle e2e
(`test_interop.sh`, `test_network.sh`, crash recovery past pull) still
needs a host that permits nsfs bind mounts.
