# Ingot

A Docker-compatible container engine written from scratch in Rust. It runs a root daemon (`ingotd`) that serves the Docker Engine API over a Unix domain socket (`/run/ingot/ingot.sock`) and ships a CLI (`ingot`) that speaks the same protocol. The official Docker CLI (`docker` v27+) works unmodified against it.

Ingot has no external runtime dependency on `runc`, `crun`, `youki`, or `libcontainer`. Namespace isolation, cgroups v2 resource control, overlayfs storage, bridge networking, embedded DNS, json-file logging, multiplexed stream hijacking, Dockerfile building, and Compose orchestration are all implemented in-repo.

## Status

Ingot is a from-scratch engine intended for learning and hardening. It runs real containers on a disposable Linux host with cgroups v2. It is not production-hardened and has not received a security audit. See [SECURITY.md](SECURITY.md) for the threat model and reporting.

## Table of Contents

- [Architecture](#architecture)
- [Feature Matrix](#feature-matrix)
- [Crates](#crates)
- [Getting Started](#getting-started)
- [Compose](#compose)
- [Testing](#testing)
- [Technical Notes](#technical-notes)
- [Contributing](#contributing)
- [License](#license)

## Architecture

```
                    +----------------------------+
                    | Official Docker CLI (v27+) |
                    |     or `ingot` CLI         |
                    +--------------+-------------+
                                   |
                                   | Unix Domain Socket (/run/ingot/ingot.sock)
                                   | Docker Engine API (v1.24 - v1.44)
                                   v
                 +----------------------------------+
                 |         Ingotd Daemon            |
                 |  (Axum + Hyper HTTP/1.1 Server)  |
                 +-----------------+----------------+
                                   |
    +---------------+--------------+--------------+---------------+
    |               |              |              |               |
    v               v              v              v               v
+-----------+  +------------+  +-----------+  +-----------+  +------------+
|  Image    |  | Container  |  |  Network  |  |  Builder  |  |   Volume   |
|  Store &  |  |  Runtime   |  |  Manager  |  |  Engine   |  |  Manager   |
| Registry  |  | (Linux NS, |  | (Bridge,  |  | (Classic, |  | (Named,    |
| (OCI/CAS) |  | cgroups v2)|  | DNS, NAT) |  | Multi-stg)|  | Anon, Pre) |
+-----------+  +------------+  +-----------+  +-----------+  +------------+
```

1. **Server (`ingot-server`, `ingot-api`):** Serves the Docker Engine API over `/run/ingot/ingot.sock`. Supports HTTP/1.1 upgrade hijacking (101 Switching Protocols) for raw interactive and multiplexed stdio streams.
2. **Container Runtime (`ingot-runtime`):** Manages process lifecycles via direct `clone(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS)` calls, `pivot_root`, `/proc` and `/sys` isolation, cgroups v2 limits (CPU quota/shares, memory), overlayfs upper/lower layering, and multiplexed stdio logging.
3. **Network (`ingot-network`):** Manages Linux network namespaces, veth pairs, software bridges (`ingot0` and user bridges), iptables MASQUERADE/DNAT rules, userland TCP proxies for loopback binding, and an embedded DNS resolver for container-to-container name resolution.
4. **Image and Registry (`ingot-image`, `ingot-registry`):** OCI/Docker Registry v2 HTTP client with token authentication, digest verification, parallel blob streaming, content-addressable storage, layer unpack with OCI whiteout handling (`.wh.<name>`, `.wh..wh..opq`), and diffID/chainID tracking.
5. **Builder (`ingot-builder`):** Multi-stage classic build engine supporting `FROM`, `RUN`, `COPY`, `ADD`, `ENV`, `WORKDIR`, `LABEL`, `CMD`, `ENTRYPOINT`, `HEALTHCHECK`, and content-addressable layer caching.
6. **Compose (`ingot-cli`):** Multi-container orchestration parsing `compose.yaml` / `docker-compose.yml`, resolving service dependencies, creating dedicated bridge networks and named volumes, and managing startup/shutdown ordering.

## Feature Matrix

| Milestone | Description | Status |
|---|---|---|
| **M0** | Daemon scaffold, `/_ping`, `/version`, `/info` | Done |
| **M1** | Registry v2 client, CAS image store, pull | Done |
| **M2** | Container runtime, exec, logs, hijack | Done |
| **M3** | Linux bridge, port forwarding, embedded DNS | Done |
| **M4** | Multi-stage Dockerfile builder and caching | Done |
| **M5** | Volumes, healthchecks, top, stats | Done |
| **M6** | Compose engine | Done |
| **M7** | Docker CLI interop polish (`cp`, `save`/`load`, prune) | Done |

API version coverage: `/v1.24` through `/v1.44` plus bare routes. Unknown routes return HTTP 501 with a Docker-shaped `{"message": ...}` body. See `crates/server/src/router.rs` for the version-prefix contract tests.

## Crates

| Crate | Role |
|---|---|
| `crates/ingotd` | Daemon binary: boot checks, cgroup setup, stale bridge/NAT cleanup, server start. |
| `crates/ingot-cli` | CLI binary (`ingot`): Docker-compatible subcommands and Compose engine. |
| `crates/server` | Axum HTTP server exposing Engine API routes. |
| `crates/runtime` | Container runtime core: `ChildContext`, namespaces, cgroup v2, overlayfs, stdio multiplexing, `setns` exec. |
| `crates/network` | Bridge creation, IPAM, veth pairing, iptables NAT/DNAT, userland proxy, embedded DNS. |
| `crates/builder` | Dockerfile parser, variable expansion, step executor, build cache. |
| `crates/image` | Layer unpack, whiteout markers, CAS blobs, image metadata, diffID/chainID. |
| `crates/registry` | OCI and Docker Registry v2 client, bearer token negotiation, verifying downloads. |
| `crates/volume` | Named and anonymous volume lifecycle. |
| `crates/store` | Filesystem path conventions under `/var/lib/ingot` and event bus pub/sub. |
| `crates/api` | PascalCase Docker Engine API request/response DTOs and deserialization adapters. |
| `crates/util` | Crypto helpers, random container name generator, IDs. |

## Getting Started

### Prerequisites

- **OS:** Linux, kernel 5.4+ with cgroups v2, user namespaces, overlayfs.
- **Tools:** `iptables`, `iproute2` (`ip`), `curl`, `rustc` / `cargo` (1.75+, tested on 1.96).
- **Permissions:** Root (required for namespaces, overlayfs mounts, iptables, bridge creation).

### Build

```bash
cargo build --workspace
```

Binaries land at `target/debug/ingotd` and `target/debug/ingot`.

### Run the Daemon

```bash
sudo ./target/debug/ingotd --debug
```

Defaults:
- State: `/var/lib/ingot`
- Socket: `/run/ingot/ingot.sock`
- Default bridge: `ingot0` (172.17.0.1/16)

### Use the Docker CLI

Point `DOCKER_HOST` at the Ingot socket:

```bash
export DOCKER_HOST=unix:///run/ingot/ingot.sock

docker version
docker info

docker pull busybox:latest
docker run --rm busybox echo "Hello from Ingot"

docker run -d --name my-web -p 8080:80 nginx:alpine
curl http://127.0.0.1:8080

docker exec my-web ls -la /usr/share/nginx/html

docker stop my-web
docker rm my-web
```

### Use the Ingot CLI

```bash
./target/debug/ingot version
./target/debug/ingot images
./target/debug/ingot run --rm busybox uname -a
./target/debug/ingot ps -a
```

## Compose

Ingot includes a built-in Compose engine compatible with `compose.yaml` and `docker-compose.yml`.

```yaml
services:
  web:
    image: busybox:latest
    command: nc -ll -p 8080 -e echo -e "HTTP/1.1 200 OK\r\n\r\nHello from Compose"
    ports:
      - "8080:8080"
  worker:
    image: busybox:latest
    command: sleep 3600
    depends_on:
      - web
```

```bash
./target/debug/ingot compose -f compose.yaml up -d
./target/debug/ingot compose -f compose.yaml ps
./target/debug/ingot compose -f compose.yaml logs
./target/debug/ingot compose -f compose.yaml down -v
```

## Testing

Quality gates run through one wrapper:

```bash
./scripts/check.sh           # fmt --check, clippy, cargo test --workspace
./scripts/check.sh --strict  # additionally denies all clippy warnings
```

### Tier 1: Unit (rootless-safe, default)

`cargo test --workspace` runs anywhere. No test in this tier touches namespaces, mounts, cgroups, netlink, or the daemon socket. This is what CI runs.

### Tier 2: Integration (needs root and a disposable host)

End-to-end interop against the real Docker CLI:

```bash
sudo ./target/debug/ingotd --debug &
export DOCKER_HOST=unix:///run/ingot/ingot.sock
./scripts/test_interop.sh
./scripts/test_network.sh
```

The interop suite covers M0 through M7: ping/version/info, image pull/list/inspect/tag/rmi, container run/create/start/exec/logs/stop/rm, user bridges and port mapping, DNS resolution, multi-stage builds with layer caching, volumes and healthchecks, `top` and `stats`, Compose up/ps/logs/down, `cp`, `save`/`load`, and prune.

Tier 2 requires root, a running `ingotd`, and host networking/firewall access. Run it on a disposable host or VM.

## Technical Notes

1. **Direct syscall isolation:** Container creation uses `clone(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS)` without external binaries. The child sets up a private `/proc`, unshares mounts, and calls `pivot_root` into the overlayfs root.
2. **Hard link preservation in tar:** Standard tar building duplicates hard-linked files (Busybox applets). Ingot tracks `(dev, ino)` pairs to emit POSIX `EntryType::Link` entries, reducing archive size for utility images from hundreds of megabytes to a few.
3. **Protocol upgrade hijacking:** Interactive `run` and `exec` use HTTP 101 Switching Protocols. Ingot captures Hyper's `OnUpgrade` future, emits 8-byte multiplexed frames (`[stream_id, 0, 0, 0, payload_len_be, payload...]`), and streams bidirectionally.
4. **Dual port publishing:** External traffic forwards to containers via iptables DNAT. Localhost loopback connections go through an integrated userland TCP proxy, so `127.0.0.1` port maps work without special setup.
5. **Embedded DNS:** Every user-defined network runs an embedded UDP DNS resolver on port 53 of the bridge IP. Containers query the bridge IP to resolve sibling names and aliases; unknown domains forward to the host's upstream resolvers.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build gates, test tiers, and the rootless-safe test rules. Run `./scripts/check.sh --strict` before opening a PR.

## License

Apache-2.0. See [LICENSE](LICENSE).
