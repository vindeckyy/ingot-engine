# Ingot — Project Handoff & Completion Report

**Date:** 2026-09-06  
**Goal:** Docker-compatible container engine written completely from scratch in Rust ("ingot"): root daemon (`ingotd`) + CLI (`ingot`), real `docker` CLI interop via Docker Engine API over Unix socket (`/run/ingot/ingot.sock`), implemented entirely in-repo without external container runtimes (no `runc`, `youki`, `crun`, or `libcontainer`).

---

## 1. Milestone Status & Verification Matrix

All planned milestones (M0 through M7) have been **100% implemented, verified, and passing**.

| Milestone | Scope | Status | Verification Evidence |
|---|---|---|---|
| **M0** | Daemon scaffold + ping/version/info | ✅ Done | Real Docker CLI 27.5.1 runs `docker version`, `docker info`, and engine `_ping` |
| **M1** | Registry v2 client + image store (CAS) | ✅ Done | Pulled `busybox`, `alpine:3.19`, `nginx:alpine` with sha256 verify; `docker images`, `docker inspect`, `docker tag`, `docker rmi` |
| **M2** | Container runtime core | ✅ Done | `docker run --rm`, `create`, `start`, `exec`, `logs`, `stop`, `rm`; 101 upgrade multiplexed stdio hijacking; process exit code propagation |
| **M3** | Networking & DNS | ✅ Done | Bridge `ingot0` + NAT; `-p` port publishing + host loopback proxy (`curl 127.0.0.1:port`); user-defined networks (`docker network create`) + embedded DNS resolution between containers |
| **M4** | Dockerfile Build Engine | ✅ Done | `docker build` multi-stage builds (`COPY --from`), layer caching (`---> Using cache`), `ENV`, `WORKDIR`, `CMD`, `RUN` step execution |
| **M5** | Volumes, Healthchecks & Observability | ✅ Done | Named & anonymous volumes, persistence across runs, `--health-cmd` exec probe loop & status reporting, `docker top`, `docker stats --no-stream` |
| **M6** | Ingot Compose | ✅ Done | `ingot compose up -d`, `ps`, `logs`, `down -v` with multi-service dependencies, networks, and named volume mounting |
| **M7** | Docker CLI Polish & Interop | ✅ Done | `docker cp` (running & stopped containers), `docker container prune`, `docker image prune`, `docker save` & `docker load` (with POSIX hard link preservation) |

- **Unit Tests:** All 21 workspace tests pass (`cargo test --workspace`).
- **End-to-End Interop Suite:** Automated test suite (`scripts/test_interop.sh`) executes end-to-end tests for Milestones M0–M7 against the real Docker CLI and Ingot CLI with 100% pass rate.

---

## 2. Repository Layout

```
.
├── Cargo.toml                  # Workspace manifest
├── README.md                   # Comprehensive documentation and architecture overview
├── HANDOFF.md                  # Project completion handoff report
├── scripts/
│   └── test_interop.sh         # End-to-end integration test suite (M0–M7)
└── crates/
    ├── api/                    # Engine API DTOs (PascalCase wire-format JSON)
    ├── builder/                # Dockerfile parser, multi-stage step runner, build cache
    ├── image/                  # CAS blobs, layer unpack, whiteout handling, chain IDs
    ├── ingotd/                 # Root daemon binary entrypoint
    ├── ingot-cli/              # Ingot CLI binary + Compose orchestrator
    ├── network/                # Bridges, IPAM, veth pairs, NAT, userland proxy, DNS
    ├── registry/               # Registry v2 client, bearer auth, blob streaming
    ├── runtime/                # Container lifecycle, namespaces, cgroup v2, overlayfs, stdio
    ├── server/                 # Axum HTTP/1.1 API server, routes, hijack upgrades
    ├── store/                  # Path conventions under /var/lib/ingot, atomic writes
    ├── util/                   # SHA256 helpers, container names, ID generation
    └── volume/                 # Named volume lifecycle
```

---

## 3. How to Operate

### Daemon Lifecycle

Always use absolute paths when managing the daemon:

```bash
# Build daemon and CLI
cargo build -p ingotd
cargo build -p ingot-cli

# Start daemon in background (as root)
sudo /home/hayden/.zcode/workspace/default/ingot/target/debug/ingotd --debug

# Stop daemon cleanly
sudo pkill -x ingotd
```

### Running Commands

```bash
# Using real Docker CLI 27.5.1 pointing to Ingot's socket:
DOCKER_HOST=unix:///run/ingot/ingot.sock docker <subcommand>

# Or using the preconfigured wrapper:
/tmp/dk <subcommand>

# Using the Ingot CLI:
/home/hayden/.zcode/workspace/default/ingot/target/debug/ingot <subcommand>
# Or wrapper:
/tmp/ig <subcommand>
```

### Running the End-to-End Test Suite

```bash
./scripts/test_interop.sh
```

---

## 4. Key Architectural & Implementation Solutions

1. **Docker Engine API Compatibility & Axum Routing:**
   - Docker CLI sends API requests prefixed with versions (`/v1.24` through `/v1.44`) or unversioned. Ingot nests the router across supported version prefixes to ensure seamless routing without URI rewriting conflicts.
   - Axum's default 2MB request body limit was disabled (`DefaultBodyLimit::disable()`) on the router to allow streaming multi-megabyte layer archives during `docker build`, `docker load`, and `docker cp`.
2. **Hard Link Preservation in Tar Generation:**
   - In standard utility images (like `busybox`), hundreds of binaries in `/bin` are hard links to a single executable. Rust's `tar::Builder` defaults to following links and duplicating files, which previously bloated a 2.2MB image into 414MB.
   - Implemented `tar_dir_recursive` tracking `(dev, ino)` pairs across directories. The first occurrence writes the file data, and subsequent occurrences write zero-sized `tar::EntryType::Link` entries, keeping archives compact (~4.5MB).
3. **Container Filesystem Archive Copy (`docker cp`):**
   - Implemented `GET /containers/{id}/archive` and `PUT /containers/{id}/archive`.
   - For stopped containers whose overlayfs is unmounted, introduced `OverlayGuard` which temporarily mounts the container's overlayfs layers, performs the copy/extraction, and automatically unmounts upon drop.
4. **Network Gateway Derivation:**
   - When creating user networks with `--subnet` (e.g. `172.30.0.0/16`) without an explicit `--gateway`, Ingot derives the default gateway as the first host IP (`.1`) in the subnet, matching Docker standard behavior.
5. **Multi-Stage Build Engine:**
   - The builder parses `AS <stage>` declarations, executes intermediate steps inside temporary container overlays, computes content-addressable cache keys (`chain_id + instruction_hash`), and transfers artifacts across stages using `COPY --from=<stage>`.
6. **Healthcheck Loop:**
   - Containers created with `HealthConfig` launch a background probe task executing the probe command via `exec` inside the container's namespaces at the configured interval, updating `State.Health.Status` (`starting` -> `healthy` / `unhealthy`).
7. **Compose Orchestration:**
   - Built directly into `ingot compose`, resolving dependency graphs (`depends_on`), generating isolated project networks (`<project>_default`), provisioning named volumes, and providing unified logs and status commands.
