# Ingot 🦀📦

**Ingot** is a Docker-compatible container engine written completely from scratch in Rust. It provides a root daemon (`ingotd`) exposing the Docker Engine API over a Unix domain socket (`/run/ingot/ingot.sock`) and an accompanying CLI (`ingot`), allowing seamless drop-in interoperability with the official Docker CLI (`docker`).

Ingot is implemented entirely in-repo with no external runtime dependencies like `runc`, `crun`, `youki`, or `libcontainer`. All namespace isolation, cgroups v2 resource control, overlayfs storage, bridge networking, embedded DNS, container logs, multiplexed stream hijacking, Dockerfile builder, and Compose orchestration are built from scratch.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Milestones & Feature Matrix](#milestones--feature-matrix)
- [Crates Structure](#crates-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building](#building)
  - [Running the Daemon](#running-the-daemon)
  - [Using the Real Docker CLI](#using-the-real-docker-cli)
  - [Using the Ingot CLI](#using-the-ingot-cli)
- [Ingot Compose](#ingot-compose)
- [Testing & Verification](#testing--verification)
- [Technical Highlights & Engineering Notes](#technical-highlights--engineering-notes)

---

## Architecture Overview

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

1. **Server Layer (`ingot-server`, `ingot-api`):** Serves the Docker Engine API over `/run/ingot/ingot.sock`. Supports HTTP/1.1 upgrade hijacking (101 Switching Protocols) for raw interactive/multiplexed standard input, output, and error streams.
2. **Container Runtime (`ingot-runtime`):** Manages process lifecycles via direct Linux system calls (`clone` with `CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_NEWNET`, `CLONE_NEWIPC`, `CLONE_NEWUTS`), pivot_root/chroot, `/proc` and `/sys` isolation, cgroups v2 limits (CPU quota/shares, memory limits), overlayfs upper/lower layering, and multiplexed stdio logging.
3. **Network Engine (`ingot-network`):** Manages Linux network namespaces, virtual ethernet (`veth`) pairs, Linux software bridges (`ingot0` and user bridges), iptables MASQUERADE/DNAT rules, userland TCP proxies for loopback binding, and an embedded DNS resolver for container-to-container name resolution.
4. **Image & Registry (`ingot-image`, `ingot-registry`):** Implements OCI/Docker Registry v2 HTTP client with token authentication (`auth.docker.io`), digest verification, parallel blob streaming, content-addressable storage (CAS), layer unpack with OCI whiteout deletion handling (`.wh.<name>`, `.wh..wh..opq`), and diffID/chainID tracking.
5. **Dockerfile Builder (`ingot-builder`):** Multi-stage classic build engine supporting `FROM`, `RUN`, `COPY`, `ADD`, `ENV`, `WORKDIR`, `LABEL`, `CMD`, `ENTRYPOINT`, `HEALTHCHECK`, and content-addressable layer caching.
6. **Compose Orchestrator (`ingot-cli`):** Top-level multi-container orchestration parsing Compose files (`compose.yaml` / `docker-compose.yml`), resolving service dependencies, spinning up dedicated bridge networks, creating named volumes, and managing startup/shutdown ordering.

---

## Milestones & Feature Matrix

| Milestone | Description | Status | Verification Evidence |
|---|---|---|---|
| **M0** | Daemon scaffold, Ping, Version, Info | ✅ Complete | Real `docker version`, `docker info`, `curl /_ping` |
| **M1** | Registry v2 client, CAS Image Store, Pull | ✅ Complete | Pulled `busybox`, `alpine:3.19`, `nginx:alpine`; digest verified; `docker images`, `docker inspect`, `docker tag`, `docker rmi` |
| **M2** | Container Runtime, Exec, Logs, Hijack | ✅ Complete | `docker run --rm`, `create`, `start`, `exec`, `logs`, `stop`, `rm`; 101 upgrade multiplexing |
| **M3** | Linux Bridge, Port Forwarding, Embedded DNS | ✅ Complete | User bridges, `-p` port mapping with host `curl`, container-to-container DNS name resolution |
| **M4** | Multi-stage Dockerfile Builder & Caching | ✅ Complete | `docker build` multi-stage builds (`COPY --from`), layer caching (`---> Using cache`), `ENV`, `CMD` execution |
| **M5** | Volumes, Healthchecks, Top, Stats | ✅ Complete | Named & anonymous volumes, persistence across runs, `--health-cmd` exec probe loop & status reporting, `docker top`, `docker stats --no-stream` |
| **M6** | Ingot Compose Engine | ✅ Complete | `ingot compose up -d`, `ps`, `logs`, `down -v` with multi-service dependencies & volumes |
| **M7** | Docker CLI Polish & Interop | ✅ Complete | `docker cp` (running & stopped), `docker container prune`, `docker image prune`, `docker save` & `docker load` (with hard link preservation) |

---

## Crates Structure

- **`crates/ingotd`**: The daemon binary entrypoint; performs boot environment checks, cgroup setup, stale bridge/NAT cleanup, and starts the server.
- **`crates/ingot-cli`**: The user-facing CLI binary (`ingot`); provides Docker-compatible subcommands and the Compose orchestration engine.
- **`crates/server`**: Axum-based HTTP server exposing Engine API routes (`/containers/*`, `/images/*`, `/networks/*`, `/volumes/*`, `/build`, `/events`, etc.).
- **`crates/runtime`**: Container runtime core (`ChildContext`, namespaces, cgroup v2, overlayfs mounts, stdio multiplexing, `setns` exec-dance).
- **`crates/network`**: Bridge interface creation, IPAM allocations, veth pairing, iptables NAT/DNAT, userland proxy, and embedded DNS server.
- **`crates/builder`**: Dockerfile lexical parser, variable expansion, step executor (`runtime::step`), and build cache manager.
- **`crates/image`**: Layer unpacking, whiteout markers, CAS blobs, image record metadata, diffID/chainID calculation.
- **`crates/registry`**: OCI & Docker Registry v2 API client, bearer token negotiation, and verifying streaming downloads.
- **`crates/volume`**: Named and anonymous volume lifecycle management.
- **`crates/store`**: Filesystem path conventions under `/var/lib/ingot` and event bus pub/sub.
- **`crates/api`**: PascalCase Docker Engine API request/response DTOs and custom deserialization adapters.
- **`crates/util`**: Cryptographic helpers, random container name generator, and IDs.

---

## Getting Started

### Prerequisites

- **Operating System:** Linux (Kernel 5.4+ with cgroups v2, user namespaces, and overlayfs support).
- **Tools:** `iptables`, `iproute2` (`ip`), `curl`, `rustc` / `cargo` (1.75+).
- **Permissions:** Root privileges (required for namespaces, mounting overlayfs, iptables, and bridge creation).

### Building

To build all workspace crates in debug mode:

```bash
cargo build --workspace
```

The resulting binaries will be:
- Daemon: `target/debug/ingotd`
- CLI: `target/debug/ingot`

To run all unit tests:

```bash
cargo test --workspace
```

### Running the Daemon

Run the daemon with root privileges:

```bash
sudo ./target/debug/ingotd --debug
```

By default, the daemon:
- Stores state at `/var/lib/ingot`
- Listens on `/run/ingot/ingot.sock`
- Manages the default bridge `ingot0` (172.17.0.1/16)

### Using the Real Docker CLI

Configure your standard `docker` CLI to communicate with Ingot by pointing `DOCKER_HOST` to the Ingot Unix domain socket:

```bash
export DOCKER_HOST=unix:///run/ingot/ingot.sock

# Check daemon connectivity
docker version
docker info

# Pull and run containers
docker pull busybox:latest
docker run --rm busybox echo "Hello from Ingot!"

# Start a background container
docker run -d --name my-web -p 8080:80 nginx:alpine
curl http://127.0.0.1:8080

# Execute commands inside container
docker exec my-web ls -la /usr/share/nginx/html

# Stop and remove
docker stop my-web
docker rm my-web
```

### Using the Ingot CLI

The `ingot` CLI provides direct subcommands with native Unix domain socket client support:

```bash
./target/debug/ingot version
./target/debug/ingot images
./target/debug/ingot run --rm busybox uname -a
./target/debug/ingot ps -a
```

---

## Ingot Compose

Ingot includes a built-in Compose engine compatible with `compose.yaml` and `docker-compose.yml` specifications.

### Example Compose File (`compose.yaml`)

```yaml
services:
  web:
    image: busybox:latest
    command: nc -ll -p 8080 -e echo -e "HTTP/1.1 200 OK\r\n\r\nHello from Compose!"
    ports:
      - "8080:8080"
  worker:
    image: busybox:latest
    command: sleep 3600
    depends_on:
      - web
```

### Managing Compose Stacks

```bash
# Launch stack in background
./target/debug/ingot compose -f compose.yaml up -d

# View status
./target/debug/ingot compose -f compose.yaml ps

# View aggregate logs
./target/debug/ingot compose -f compose.yaml logs

# Tear down containers, networks, and volumes
./target/debug/ingot compose -f compose.yaml down -v
```

---

## Testing & Verification

Ingot comes with a comprehensive end-to-end integration test suite covering Milestones M0 through M7 against the real Docker CLI:

```bash
./scripts/test_interop.sh
```

### Verified Test Matrix:
- **M0:** Ping (`/_ping`), Docker version negotiation, Docker info metadata.
- **M1:** Image listing, inspection, tagging, and untagging.
- **M2:** Container execution (`run --rm`), create, start, detached run, exec, logs, stop, and rm.
- **M3:** User-defined bridge creation, host port mapping with loopback curl verification, container-to-container DNS resolution.
- **M4:** Multi-stage Dockerfile builds (`COPY --from`), layer caching on rebuilds, execution of built images.
- **M5:** Volume creation, persistence across container restarts, container healthcheck loop probes, `docker top`, `docker stats --no-stream`.
- **M6:** Compose stack creation (`up -d`), status reporting (`ps`), logs, and teardown (`down -v`).
- **M7:** Container archive copy (`docker cp` on running and stopped containers), `docker container prune`, `docker image prune`, `docker save` & `docker load` with hard link inode preservation.

---

## Technical Highlights & Engineering Notes

1. **Direct System Call Container Isolation:**
   Container creation leverages direct `clone(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS)` calls without invoking external binaries. The child process sets up a private `/proc`, unshares mounts, and uses `pivot_root` to transition into the overlayfs root filesystem.
2. **Hard Link Preservation in Tar Archives:**
   Standard tar building can inadvertently duplicate hard-linked files (such as Busybox applets). Ingot tracks filesystem inodes `(dev, ino)` to produce standard POSIX `EntryType::Link` entries, reducing archive size from ~400MB down to ~4MB for standard utility images.
3. **Protocol Upgrade Hijacking:**
   Interactive `docker run` and `docker exec` rely on HTTP 101 Switching Protocols. Ingot captures Hyper's `OnUpgrade` future, emits standard 8-byte multiplexed frames (`[stream_id, 0, 0, 0, payload_len_be, payload...]`), and streams bidirectionally.
4. **Dual Port Publishing (DNAT + Userland Proxy):**
   External traffic is forwarded to containers using iptables DNAT rules. Localhost loopback connections (`127.0.0.1`) are handled via an integrated userland TCP proxy, ensuring seamless host-to-container connectivity.
5. **Embedded DNS:**
   Every user-defined network runs an embedded UDP DNS resolver on port 53 of the bridge IP. Containers query the bridge IP to resolve sibling container names and aliases, while unknown domains are seamlessly forwarded to the host's upstream DNS nameservers.
