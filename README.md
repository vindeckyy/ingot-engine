<p align="center">
  <img src="docs/assets/logo/transparent/ingot-engine-primary-transparent.png" alt="Ingot" width="320">
</p>

<h3 align="center">A Docker-compatible container engine, written from scratch in Rust</h3>

<p align="center">
  <a href="https://github.com/vindeckyy/ingot-engine/actions"><img src="https://github.com/vindeckyy/ingot-engine/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/Rust-1.96-orange.svg" alt="Rust">
</p>

---

Ingot is a container engine that implements the Docker Engine API (v1.24 through v1.44) from scratch in Rust. It runs a root daemon (`ingotd`) that listens on a Unix domain socket (`/run/ingot/ingot.sock`) and ships a CLI (`ingot`) that speaks the same protocol. The official Docker CLI (`docker` v27+) works unmodified against it.

Ingot has no external runtime dependency on `runc`, `crun`, `youki`, or `libcontainer`. Namespace isolation, cgroups v2 resource control, overlayfs storage, bridge networking, embedded DNS, json-file logging, multiplexed stream hijacking, Dockerfile building, and Compose orchestration are all implemented in-repo.

## Status

Ingot is a from-scratch engine built for learning and hardening. It runs real containers on a disposable Linux host with cgroups v2. It is not production-hardened and has not received a security audit. See [SECURITY.md](SECURITY.md) for the threat model and reporting policy.

## Table of Contents

- [Architecture](#architecture)
- [API Coverage](#api-coverage)
- [Feature Matrix](#feature-matrix)
- [Crates](#crates)
- [On-Disk Layout](#on-disk-layout)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Container Runtime](#container-runtime)
- [Networking](#networking)
- [Image Storage and Registry](#image-storage-and-registry)
- [Builder](#builder)
- [Volumes](#volumes)
- [Observability](#observability)
- [Compose](#compose)
- [CLI Reference](#cli-reference)
- [Testing](#testing)
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

The server layer (`ingot-server`, `ingot-api`) serves the Docker Engine API over `/run/ingot/ingot.sock`. It supports HTTP/1.1 upgrade hijacking (101 Switching Protocols) for raw interactive and multiplexed stdio streams. The router nests the full API route set under every version prefix from `/v1.24` through `/v1.44` plus bare paths, because the Docker CLI always prefixes requests with the negotiated version and axum layers run after routing. Unknown routes return HTTP 501 with a Docker-shaped `{"message": "..."}` body.

The container runtime (`ingot-runtime`) manages process lifecycles via direct `clone(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | CLONE_NEWUTS)` calls, `pivot_root`, `/proc` and `/sys` isolation, cgroups v2 limits, overlayfs upper/lower layering, and multiplexed stdio logging.

The network engine (`ingot-network`) manages Linux network namespaces, veth pairs, software bridges (`ingot0` and user bridges), iptables MASQUERADE/DNAT rules, userland TCP proxies for loopback binding, and an embedded DNS resolver for container-to-container name resolution.

The image and registry layer (`ingot-image`, `ingot-registry`) implements an OCI/Docker Registry v2 HTTP client with token authentication, digest verification, resumable blob downloads, content-addressable storage, layer unpack with OCI whiteout handling, and diffID/chainID tracking.

The builder (`ingot-builder`) is a multi-stage classic build engine supporting `FROM`, `RUN`, `COPY`, `ADD`, `ENV`, `WORKDIR`, `LABEL`, `CMD`, `ENTRYPOINT`, `HEALTHCHECK`, and content-addressable layer caching.

The Compose engine (`ingot-cli`) parses `compose.yaml` / `docker-compose.yml`, resolves service dependencies, creates dedicated bridge networks and named volumes, and manages startup/shutdown ordering.

## API Coverage

### System

| Method | Path | Description |
|---|---|---|
| `ANY` | `/_ping` | Daemon health check |
| `GET` | `/version` | Daemon version and runtime info |
| `GET` | `/info` | Daemon state, storage driver, networking |
| `GET` | `/events` | Event stream with filtering |
| `GET` | `/system/df` | Disk usage (images, containers, volumes) |

### Containers

| Method | Path | Description |
|---|---|---|
| `GET` | `/containers/json` | List containers with filters |
| `POST` | `/containers/create` | Create a container |
| `GET` | `/containers/{id}/json` | Inspect a container |
| `POST` | `/containers/{id}/start` | Start a container |
| `POST` | `/containers/{id}/stop` | Stop with signal and timeout |
| `POST` | `/containers/{id}/kill` | Send a signal |
| `POST` | `/containers/{id}/wait` | Block until exit |
| `POST` | `/containers/{id}/pause` | Freeze cgroup |
| `POST` | `/containers/{id}/unpause` | Unfreeze cgroup |
| `POST` | `/containers/{id}/restart` | Stop then start |
| `GET` | `/containers/{id}/top` | Process list |
| `GET` | `/containers/{id}/stats` | Resource usage (streaming or one-shot) |
| `GET` | `/containers/{id}/logs` | Log retrieval with tail, since, until, timestamps |
| `POST` | `/containers/{id}/attach` | HTTP 101 hijack for interactive stdio |
| `POST` | `/containers/{id}/exec` | Create an exec session |
| `POST` | `/exec/{id}/start` | Start an exec session with hijack |
| `GET` | `/exec/{id}/json` | Inspect an exec session |
| `POST` | `/containers/prune` | Remove stopped containers |
| `GET` | `/containers/{id}/archive` | Download a tar path |
| `HEAD` | `/containers/{id}/archive` | Stat a path |
| `PUT` | `/containers/{id}/archive` | Upload a tar path |
| `DELETE` | `/containers/{id}` | Remove a container |

### Images

| Method | Path | Description |
|---|---|---|
| `GET` | `/images/json` | List images with filters |
| `POST` | `/images/create` | Pull from registry |
| `POST` | `/images/prune` | Remove unused images |
| `GET` | `/images/get` | Export all images as tar |
| `GET` | `/images/{name}/get` | Export one image as tar |
| `POST` | `/images/load` | Load tar into image store |
| `GET` | `/images/{name}/json` | Inspect an image |
| `GET` | `/images/{name}/history` | Image layer history |
| `POST` | `/images/{name}/tag` | Tag an image |
| `DELETE` | `/images/{name}` | Untag or remove an image |

### Networks

| Method | Path | Description |
|---|---|---|
| `GET` | `/networks` | List networks |
| `POST` | `/networks/create` | Create a user bridge |
| `POST` | `/networks/prune` | Remove unused networks |
| `GET` | `/networks/{id}` | Inspect a network |
| `DELETE` | `/networks/{id}` | Remove a network |
| `POST` | `/networks/{id}/connect` | Connect a container |
| `POST` | `/networks/{id}/disconnect` | Disconnect a container |

### Volumes

| Method | Path | Description |
|---|---|---|
| `GET` | `/volumes` | List volumes |
| `POST` | `/volumes/create` | Create a named volume |
| `POST` | `/volumes/prune` | Remove unused volumes with protection |
| `GET` | `/volumes/{name}` | Inspect a volume |
| `DELETE` | `/volumes/{name}` | Remove a volume |

### Build

| Method | Path | Description |
|---|---|---|
| `POST` | `/build` | Dockerfile build with context tar |
| `POST` | `/secrets` | Stage a build secret, returns a token |

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

## On-Disk Layout

All persistent state lives under `/var/lib/ingot` by default. Runtime state (socket, netns bind mounts, PID file) lives under `/run/ingot`.

| Path | Contents |
|---|---|
| `/var/lib/ingot/schema-version` | Schema version marker for migration discipline |
| `/var/lib/ingot/blobs/sha256/<hex>` | Content-addressed image blobs |
| `/var/lib/ingot/layers/<hex>` | Unpacked image layers |
| `/var/lib/ingot/images/<id>.json` | Image records (config, rootfs, history) |
| `/var/lib/ingot/tags.json` | Tag index |
| `/var/lib/ingot/containers/<id>/config.json` | Container config |
| `/var/lib/ingot/containers/<id>/hostconfig.json` | Host config (capabilities, mounts, resources) |
| `/var/lib/ingot/containers/<id>/state.json` | Container state (pid, status, exit code) |
| `/var/lib/ingot/containers/<id>/<id>-json.log` | json-file log driver output |
| `/var/lib/ingot/containers/<id>/resolv.conf` | Container resolv.conf |
| `/var/lib/ingot/containers/<id>/hosts` | Container hosts file |
| `/var/lib/ingot/containers/<id>/hostname` | Container hostname |
| `/var/lib/ingot/containers/<id>/netns` | Bind-mounted network namespace |
| `/var/lib/ingot/containers/<id>/mntns` | Bind-mounted mount namespace |
| `/var/lib/ingot/overlay/<id>/merged` | Overlayfs merged root |
| `/var/lib/ingot/overlay/<id>/diff` | Overlayfs upper (writable layer) |
| `/var/lib/ingot/overlay/<id>/work` | Overlayfs work directory |
| `/var/lib/ingot/networks/<id>.json` | Network records |
| `/var/lib/ingot/ipam-leases.json` | IPAM lease allocations |
| `/var/lib/ingot/volumes/<name>/` | Named volume contents and metadata |
| `/var/lib/ingot/builder/cache.json` | Build cache index |
| `/var/lib/ingot/builder/contexts/` | Build context scratch |
| `/var/lib/ingot/builder/steps/` | Per-build step scratch |
| `/run/ingot/ingot.sock` | Unix domain socket |
| `/run/ingot/netns/` | Runtime netns bind mounts |
| `/run/ingot/ingotd.pid` | Daemon PID file |

## Getting Started

### Prerequisites

- **OS:** Linux, kernel 5.4+ with cgroups v2, user namespaces, overlayfs.
- **Tools:** `iptables`, `iproute2` (`ip`), `curl`, `rustc` / `cargo` (1.96+).
- **Permissions:** Root (required for namespaces, overlayfs mounts, iptables, bridge creation).

### Installation

#### From source (release build)

```bash
git clone https://github.com/vindeckyy/ingot-engine.git
cd ingot-engine
make install
```

This builds release binaries and installs them to `/usr/local/bin`. It also installs the systemd unit and shell completions if the directories exist.

To install to a different prefix:

```bash
make install PREFIX=/opt/ingot
```

#### From source (debug build)

```bash
git clone https://github.com/vindeckyy/ingot-engine.git
cd ingot-engine
./scripts/install.sh --debug
```

#### Manual build

```bash
cargo build --release -p ingotd -p ingot-cli
sudo install -m 0755 target/release/ingotd /usr/local/bin/
sudo install -m 0755 target/release/ingot  /usr/local/bin/
```

### Shell Completions

```bash
ingot completions bash > /etc/bash_completion.d/ingot
ingot completions zsh  > /usr/share/zsh/site-functions/_ingot
ingot completions fish > ~/.config/fish/completions/ingot.fish
```

Or use the Makefile target:

```bash
make completions
```

### systemd Service

The install script copies `scripts/ingotd.service` to `/etc/systemd/system/`. To enable and start:

```bash
sudo systemctl enable --now ingotd
```

The service runs `ingotd` with default settings. Edit the unit file to pass custom flags (`--data-root`, `--bridge`, etc.).

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
- Default bridge: `ingot0` (172.17.0.0/16, gateway 172.17.0.1)

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

## Configuration

The daemon accepts the following flags:

| Flag | Default | Description |
|---|---|---|
| `--data-root` | `/var/lib/ingot` | Persistent state directory |
| `--run-root` | `/run/ingot` | Runtime state directory |
| `--socket` | `/run/ingot/ingot.sock` | Unix socket path |
| `--bridge` | `ingot0` | Default bridge name |
| `--debug` | off | Verbose logging |
| `--fsck` | off | Read-only image store consistency check |
| `--repair` | off | Reclaim stale partial downloads and unreferenced blobs |

### Boot Checks

The daemon verifies the following before accepting requests:
- Running as root.
- cgroups v2 mounted at `/sys/fs/cgroup` with `cgroup.controllers` present.
- overlayfs functional (attempts a test mount in a temp directory, tries `modprobe overlay` once on failure).

### Reconciliation

On restart, the daemon reconciles existing state:
- Containers recorded as `Running` or `Paused` are examined. `always` and `unless-stopped` restart policies are honored; others are marked `Exited` (exit code 255) and cleaned up.
- Stale overlay mounts under the overlay root are detached.
- Stale `ingot.slice/<id>` cgroups are removed.
- Builder scratch directories (`builder/steps/`, `builder/contexts/`) are swept, with any mounts beneath them detached.

## Container Runtime

### Namespace Isolation

Container creation uses `clone` with the following flags:

| Flag | Namespace |
|---|---|
| `CLONE_NEWNS` | Mount |
| `CLONE_NEWPID` | PID |
| `CLONE_NEWUTS` | Hostname / domain |
| `CLONE_NEWIPC` | IPC |
| `CLONE_NEWNET` | Network (unless `--network host`) |
| `SIGCHLD` | Waitable child |

The child process sets up a private `/proc`, unshares mounts, and calls `pivot_root` into the overlayfs merged root.

### Capability Confinement

The default capability set matches Docker's defaults:

`CHOWN`, `DAC_OVERRIDE`, `FSETID`, `FOWNER`, `MKNOD`, `NET_RAW`, `SETGID`, `SETUID`, `SETFCAP`, `SETPCAP`, `NET_BIND_SERVICE`, `SYS_CHROOT`, `KILL`, `AUDIT_WRITE`.

`--cap-add` and `--cap-drop` accept `CHOWN` or `CAP_CHOWN` (case-insensitive). `--cap-add ALL` grants the full set. `--cap-drop ALL` removes everything. The bounding set is dropped first, then effective, permitted, and inheritable are set to the computed keep set. Privileged mode (`--privileged`) skips confinement entirely and retains the daemon's full capabilities.

After a UID switch, `PR_SET_KEEPCAPS` is enabled and the effective set is re-asserted, so capabilities survive the identity change.

### Filesystem Isolation

- **Read-only rootfs:** Remounts `/` with `MS_RDONLY | MS_REMOUNT | MS_BIND | MS_REC` when `--read-only` is set.
- **Masked paths:** The following are bound over `/dev/null` or covered with empty read-only tmpfs: `/proc/asound`, `/proc/acpi`, `/proc/kcore`, `/proc/keys`, `/proc/timer_list`, `/proc/timer_stats`, `/proc/sched_debug`, `/proc/scsi`, `/sys/firmware`, `/sys/fs/selinux`.
- **No-new-privileges:** Set via `prctl(PR_SET_NO_NEW_PRIVS)` for all non-privileged containers.
- **tmpfs mounts:** `--tmpfs` destinations are mounted with `MS_NOSUID | MS_NODEV` and `mode=1777` by default.
- **`/dev/shm`:** Sized from `--shm-size` (default 64 MiB), mounted with `mode=1777`.

### User Resolution

User specifications (`--user`) accept `uid`, `uid:gid`, or `uid:gid,gid...`. Numeric values are fast-pathed. Named users are resolved against the container's own `/etc/passwd` and `/etc/group`. If an explicit user does not resolve, the container fails to start (fail-closed).

### Sysctl and Ulimits

- **Sysctl:** Only keys starting with `net.` are accepted at create time. Each is written to `/proc/sys/{key}` with `/` substituted for `.`.
- **Ulimits:** Supported rlimits: `core`, `nofile`, `nproc`, `stack`, `as`, `memlock`. Unknown names return an error. `-1` means unlimited.

### Lifecycle Supervision

#### Stop and Kill

`stop` sends the image's `STOPSIGNAL` (or the default), waits for the configured timeout (per-request, then `StopTimeout` from config, then 10 seconds), then escalates to `SIGKILL` with a final 5-second wait. `kill` sends the requested signal directly via `libc::kill`.

#### Restart Policies

| Policy | Behavior |
|---|---|
| `no` (default) | No restart |
| `always` | Restart on any exit |
| `unless-stopped` | Restart on any exit unless manually stopped |
| `on-failure` | Restart if exit code is non-zero, up to `MaximumRetryCount` |

A run of 10 seconds or longer resets the restart counter. Backoff doubles per consecutive failure (1s, 2s, 4s, 8s, 16s, 32s, 60s), capped at 60 seconds.

#### OOM Detection

The reaper records the cgroup's `oom_kills` counter at start. After `waitpid`, if the exit was `SIGKILL` and the counter increased, the container is marked `OOMKilled`.

#### Healthchecks

The healthcheck loop parses `CMD` or `CMD-SHELL` form from `HealthConfig.Test`. It uses `start_interval` during the `start_period`, then switches to `interval`. Status transitions from `starting` to `healthy` or `unhealthy` based on `retries`. The last 5 results are logged. Healthcheck status does not trigger restarts.

#### Autoremove

When `--rm` is set, the reaper unpublishes ports, releases IP leases, removes the container record, and publishes a `destroy` event after exit.

## Networking

### Default Bridge

The default bridge `ingot0` uses subnet `172.17.0.0/16` with gateway `172.17.0.1`. User-defined bridges are created on demand with `--subnet` and `--gateway`.

### Port Publishing

External traffic forwards to containers via iptables DNAT rules in the `INGOT-DNAT` chain. Localhost loopback connections (`127.0.0.1`) are handled by an integrated userland TCP proxy, so `127.0.0.1` port maps work without special host configuration.

### Embedded DNS

Every user-defined network runs an embedded UDP DNS resolver on port 53 of the bridge IP. Containers query the bridge IP to resolve sibling container names and aliases. Unknown domains are forwarded to the host's upstream resolvers.

### Boot-Time Reconciliation

On daemon start, the network manager performs the following:

1. **Stale bridge deletion:** Removes `br-*` and `ingot0` interfaces not backed by a persisted network record.
2. **Subnet validation:** Warns on invalid subnets, gateways outside subnets, and overlapping subnets among persisted networks.
3. **IPAM orphan sweep:** Drops lease buckets for unknown networks and releases IPs not referenced by any container record.
4. **DNS re-adoption:** Restarts embedded DNS servers for every non-default network.
5. **DNAT chain flush:** Creates and flushes the `INGOT-DNAT` chain in the `nat` table.
6. **Firewall rule cleanup:** Adds jumps from `PREROUTING` and `OUTPUT` (excluding `127.0.0.0/8`) to `INGOT-DNAT`, and sets up per-bridge `FORWARD` and `POSTROUTING` rules.

## Image Storage and Registry

### Registry Client

The registry client speaks OCI and Docker Registry v2. Authentication works as follows:

1. Send an unauthenticated request.
2. On `401`, parse the `WWW-Authenticate` header.
3. For `Bearer`, request a token from `realm?service=...&scope=repository:<repo>:pull`.
4. Cache tokens by `realm|service|scope|username`.
5. Retry the request with `Authorization: Bearer <token>`.
6. `Basic` auth is supported as a fallback.

Blob downloads support `Range` resume from `.part` files, transport-level retry with up to 4 attempts, and exponential backoff. Each blob is hashed with a `HashingWriter` and verified against the requested digest. On mismatch, the partial file is deleted and the download is retried.

Manifest digests are computed as `sha256:<hex>` of the response body and compared to the `Docker-Content-Digest` header. Pinned digest references (image@sha256:...) are verified against the computed top digest. Platform manifest digests are recomputed and compared to the digest from the index.

### Content-Addressable Storage

Image blobs are stored under `/var/lib/ingot/blobs/sha256/<hex>`, keyed by their SHA-256 digest. Unpacked layers live under `/var/lib/ingot/layers/<hex>`, keyed by their diffID. Image records (config, rootfs chain, history) are stored as JSON under `/var/lib/ingot/images/<id>.json`. Tags are indexed in `/var/lib/ingot/tags.json`.

### Layer Unpack

Layer unpack handles OCI whiteout markers:

- `.wh..wh..opq` sets the `trusted.overlay.opaque` / `user.overlay.opaque` xattr on the parent directory, marking it as opaque for overlayfs.
- `.wh.<name>` removes the target file or directory and creates a char device `0:0` marker.

Path traversal is rejected: tar entries with `..` components, absolute paths, or symlink targets escaping the unpack root are refused.

## Builder

The builder is a classic (non-BuildKit) multi-stage Dockerfile engine.

### Supported Instructions

`FROM`, `RUN`, `COPY`, `ADD`, `ENV`, `WORKDIR`, `LABEL`, `CMD`, `ENTRYPOINT`, `HEALTHCHECK`, `EXPOSE`, `VOLUME`, `USER`, `ARG`, `SHELL`, `STOPSIGNAL`.

`COPY --from` and `FROM ... AS ...` support multi-stage builds.

### Build Cache

Cache entries are stored in `/var/lib/ingot/builder/cache.json`, keyed by SHA-256. Cache keys incorporate:

- `RUN`: parent chain, args, env, shell, workdir, user, mount declarations.
- `COPY`/`ADD`: args, `--from`, source content hashes, ownership, mode.

Tamper detection compares path, size, mtime, mode, and symlink targets via `layer_fingerprint()`. `--no-cache` bypasses cache lookup entirely. `--no-cache-filter` bypasses cache for specified stages.

### Build Secrets

Secrets are staged via `POST /secrets`, which returns a token. The token is passed to `POST /build` in a header, and the builder mounts the secret into the build container.

## Volumes

Named and anonymous volumes are stored under `/var/lib/ingot/volumes/<name>/` with a `metadata.json` sidecar.

### Prune Protection

`POST /volumes/prune` accepts `until` (Unix timestamp) and `label` filters. Volumes referenced by any container record's mounts are protected and never pruned. Label filters require all key/value pairs to match; an empty value means the key must exist.

## Observability

### Events

`GET /events` streams daemon events as JSON objects. Supported filters:

| Filter | Description |
|---|---|
| `since` | Unix timestamp or RFC 3339; exclude events before |
| `until` | Unix timestamp or RFC 3339; stop after |
| `filters.type` | Event type (`container`, `image`, `network`, `volume`) |
| `filters.event` | Action (`create`, `start`, `die`, etc.) |
| `filters.label` | `key=value` or `key` (existence match) |

Unknown filter keys return HTTP 400.

### Logs

`GET /containers/{id}/logs` supports:

| Parameter | Description |
|---|---|
| `follow` | Stream new output after historical lines |
| `stdout` | Include stdout |
| `stderr` | Include stderr |
| `tail` | `all` or numeric N (last N lines) |
| `since` | RFC 3339 timestamp; exclude lines before |
| `until` | RFC 3339 timestamp; exclude lines after |
| `timestamps` | Prepend RFC 3339 timestamp to each line |

Non-TTY containers return `application/vnd.docker.multiplexed-stream` with 8-byte frames. TTY containers return raw bytes.

### Stats

`GET /containers/{id}/stats` supports `stream` (default true) and `stream=false` for a single sample. Each sample reads from cgroups v2:

- `memory.current`, `memory.max`
- `pids.current`
- `cpu.stat` (`usage_usec`, `user_usec`, `system_usec`)
- `/proc/stat` for system CPU usage
- `/proc/<pid>/net/dev` for per-interface network counters (loopback excluded)

The `precpu_stats` and `preread` fields carry the previous sample so consumers can compute CPU deltas correctly.

### Multiplexed Stream Framing

Non-TTY container stdio uses Docker's 8-byte multiplexed frame format:

```
[stream_id, 0, 0, 0, payload_len_be_u32, payload...]
```

`stream_id` is `0` for stdin, `1` for stdout, `2` for stderr. The `frame()` function encodes, `demux()` decodes.

### json-file Log Format

The json-file log driver writes one JSON object per line:

```json
{"log": "<text>", "stream": "stdout", "time": "<RFC 3339 timestamp>"}
```

The `StdioHub` broadcasts live `(stream, bytes)` to subscribers, writes to the log file atomically line-by-line, and fans in stdin via an async mpsc channel.

### HTTP 101 Hijacking

Interactive `docker run` and `docker exec` use HTTP 101 Switching Protocols. The handler captures Hyper's `OnUpgrade` future, returns `101 UPGRADED` with `Connection: Upgrade`, `Upgrade: tcp`, and `Content-Type: application/vnd.docker.raw-stream`, then spawns a task that:

- Replays historical logs if `logs=true` (for attach).
- Splits the upgraded socket with `tokio::io::split`.
- Writes hub output to the client, framing with `frame()` for non-TTY or raw bytes for TTY.
- Reads client bytes and forwards to `StdioHub.send_stdin()` if `stdin=true` and `stream=true`.
- Exits when the container or exec session exits.

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

The Compose engine resolves service dependencies, creates dedicated bridge networks, creates named volumes, and manages startup and shutdown ordering.

## CLI Reference

### Global Flag

| Flag | Description |
|---|---|
| `--host` | Unix socket path (default: `$DOCKER_HOST` or `/run/ingot/ingot.sock`) |

### Subcommands

| Command | Description |
|---|---|
| `version` | Print version |
| `ping` | Check daemon connectivity |
| `info` | Print daemon info |
| `run` | Create and start a container |
| `pull` | Pull an image |
| `push` | Push an image |
| `login` | Authenticate to a registry |
| `logout` | Clear registry credentials |
| `ps` | List containers |
| `images` | List images |
| `stop` | Stop a container |
| `kill` | Signal a container |
| `rm` | Remove a container |
| `rmi` | Remove an image |
| `tag` | Tag an image |
| `logs` | Fetch container logs |
| `exec` | Execute a command in a container |
| `build` | Build an image from a Dockerfile |
| `cp` | Copy files between host and container |
| `compose` | Manage a Compose stack |
| `network` | Manage networks (`ls`, `create`, `rm`, `inspect`, `connect`, `disconnect`, `prune`) |
| `volume` | Manage volumes (`ls`, `create`, `rm`, `inspect`, `prune`) |
| `system` | System commands (`df`, `prune`) |
| `completions` | Generate shell completions (`bash`, `zsh`, `fish`, `elvish`, `powershell`) |

### `run` Flags

| Flag | Description |
|---|---|
| `-d` / `--detach` | Run in background |
| `--name` | Container name |
| `-p` / `--publish` | Port mapping (`host:container`) |
| `-e` / `--env` | Environment variable |
| `-v` / `--volume` | Bind mount or named volume |
| `--network` | Network to connect (default: `default`) |
| `-t` / `--tty` | Allocate a TTY |
| `-i` / `--interactive` | Keep stdin open |
| `--rm` | Remove on exit |
| `-w` / `--workdir` | Working directory |
| `--dns` | DNS server |
| `--dns-search` | DNS search domain |
| `--dns-opt` | DNS option |

### `build` Flags

| Flag | Description |
|---|---|
| `-t` / `--tag` | Tag the result |
| `-f` / `--file` | Dockerfile path (default: `Dockerfile`) |
| `--no-cache` | Bypass all cache |
| `--no-cache-filter` | Bypass cache for specified stages |
| `--secret` | Build secret (`id=...,src=...`) |
| `-q` / `--quiet` | Suppress build output |

### `ps` and `images` Flags

| Flag | Description |
|---|---|
| `-a` / `--all` | Show all (not just running) |
| `-q` / `--quiet` | IDs only |
| `--no-trunc` | Do not truncate output |
| `-f` / `--filter` | Filter results |

## Testing

Quality gates run through one wrapper:

```bash
./scripts/check.sh           # fmt --check, clippy, cargo test --workspace
./scripts/check.sh --strict  # additionally denies all clippy warnings
```

### Tier 1: Unit (rootless-safe, default)

`cargo test --workspace` runs anywhere, no root required. This is what CI runs on every push and PR.

Rules for Tier 1 tests:
- No namespaces, mounts, cgroups, netlink, or privileged sockets.
- No daemon process, no Unix socket at `/run/ingot`.
- Filesystem tests use `std::env::temp_dir()` and clean up after themselves.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build gates, test tiers, and the rootless-safe test rules. Run `./scripts/check.sh --strict` before opening a PR.

## License

Apache-2.0. See [LICENSE](LICENSE).
