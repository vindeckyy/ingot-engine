# Ingot Docker Compatibility Matrix

This document defines the contract between the Ingot Container Engine and the Docker ecosystem.
Ingot targets **Docker Engine API v1.44** for Linux amd64. Rather than silently ignoring unsupported flags or configurations, Ingot distinguishes:
- **Supported / Tested**: Implemented, tested in the automated suites, and actively maintained.
- **Explicitly Rejected**: Deserialized and rejected with an explicit `HTTP 400 Bad Request` or `HTTP 501 Not Implemented` error to prevent unexpected security or runtime behavior.
- **Absent**: Not served or implemented.

---

## 1. CLI Commands

| Command | Status | Notes / Tested Flags |
|---|---|---|
| `run` | Supported | `-d`, `-i`, `-t`, `--name`, `-p`/`--publish`, `-e`/`--env`, `-v`/`--volume`, `--network`, `--rm`, `-w`/`--workdir`, `--dns`, `--dns-search`, `--dns-opt`, `--restart`, `--memory`, `--cpus`, `--pids-limit`, `--cap-add`, `--cap-drop`, `--privileged`, `--user` |
| `exec` | Supported | `-i`, `-t`, `-d`, `-e`, `-w`, `--user`. PTY allocation and multiplexed streaming via hijacked connection. |
| `ps` | Supported | `-a`, `-q`, `--no-trunc`, `--format table|json`, `-f` (`id`, `name`, `status`, `ancestor`, `label`). |
| `images` | Supported | `-a`, `-q`, `--no-trunc`, `--format table|json`, `-f` (`dangling`, `label`, `reference`, `before`, `since`). |
| `pull` | Supported | OCI & Docker v2 registries, digests, multi-architecture manifests, bearer/basic auth. |
| `build` | Supported | `-t`, `-f`, `--no-cache`, `--no-cache-filter`, `--secret`, `-q`. Multi-stage Dockerfile parser and layer cache. |
| `stop` | Supported | `-t`/`--time`, custom stop signals. Escalates `SIGTERM` → `SIGKILL` on timeout. |
| `kill` | Supported | `-s`/`--signal`. Direct `pidfd_send_signal` with fallback. |
| `restart` | Supported | `-t`/`--time`. Safe state transitions and atomic persistence. |
| `pause` / `unpause` | Supported | cgroups v2 freezer subsystem. |
| `rm` | Supported | `-f`/`--force`, `-v`/`--volumes` (deletes anonymous volumes created with container). |
| `rmi` | Supported | Untags reference; removes unreferenced layers and metadata. |
| `tag` | Supported | Content-addressed reference aliasing. |
| `logs` | Supported | `-f`/`--follow`, `-t`/`--timestamps`, `--tail`, `--since`, `--until`. Multiplexed stream framing. |
| `cp` | Supported | Host ↔ running container and host ↔ stopped container with path confinement. |
| `container prune` | Supported | `-f`/`--force`, filters. |
| `image prune` | Supported | `-a`/`--all`, `-f`/`--force`. |
| `network create/ls/rm/inspect` | Supported | Bridge driver (`--subnet`, `--gateway`, `--internal`). Returns `201 Created`. |
| `volume create/ls/rm/inspect` | Supported | Local driver (`--label`). Returns `201 Created`. |
| `compose` | Supported | `up`, `down`, `ps`, `logs` for basic services, networks, and volumes. |
| `doctor` | Supported | Ingot-specific diagnosis of socket, cgroups v2, overlayfs, network tools, and security profiles. |
| `push` | Supported | Single-platform OCI manifest push; bearer/basic auth via stored credentials, `Layer already exists` skip, Docker-shaped progress stream. Manifest lists are not pushed. |
| `swarm` | Absent | Not implemented. |
| `plugin` | Absent | Not implemented. |

---

## 2. Container Configuration Options (`ContainerConfig` / `HostConfig`)

### Resource Controls & Security Options
| Option | Status | Engine Behavior |
|---|---|---|
| `Memory` | Supported | Enforced via cgroup v2 `memory.max`. |
| `MemorySwap` | Supported | Enforced via cgroup v2 `memory.swap.max`. |
| `NanoCpus` / `CpuQuota` | Supported | Enforced via cgroup v2 `cpu.max`. |
| `CpuShares` | Supported | Converted and enforced via cgroup v2 `cpu.weight`. |
| `CpusetCpus` | Supported | Enforced via cgroup v2 `cpuset.cpus`. |
| `PidsLimit` | Supported | Enforced via cgroup v2 `pids.max`. |
| `CapAdd` / `CapDrop` | Supported | Enforced at clone/exec via Linux `cap_set_proc`. |
| `Privileged` | Supported | Grants all capabilities, disables seccomp, keeps host devices. |
| `SecurityOpt` | Supported / Rejected | `seccomp=default` (or `seccomp:default`) and `seccomp=unconfined` (or `seccomp:unconfined`) accepted; all other values (including `apparmor=*` and custom seccomp profile paths) rejected with `400 Bad Request`. |
| `Devices` | Rejected | Non-empty device lists rejected with `400 Bad Request`, including for privileged containers (no device plumbing yet). |
| `CgroupParent` | Rejected | Custom cgroup parents rejected with `400 Bad Request`. |
| `IpcMode` | Supported / Rejected | `private` and `shareable` accepted; non-empty others rejected. |
| `UTSMode` | Supported / Rejected | `private` accepted; others rejected. |
| `UsernsMode` | Rejected | Custom user namespace modes rejected with `400 Bad Request`. |
| `VolumeDriver` | Supported / Rejected | Only `local` accepted; other volume drivers rejected with `400 Bad Request`. |
| `LogConfig` | Supported / Rejected | Only `json-file` accepted; others rejected with `400 Bad Request`. Honored opts: `max-size` (bytes or `k`/`m`/`g`, `-1` unlimited), `max-file` (≥ 1, total files kept); any other opt key is rejected with `400 Bad Request`. Unset means unbounded (docker default). |
| `CpuPeriod` | Supported | Honored via cgroup v2 `cpu.max` quota/period (kernel default period when unset); negative values rejected. |
| `CpusetMems`, `BlkioWeight`, `VolumesFrom`, `GroupAdd`, `ContainerIDFile`, `Cgroup`, `Links`, `OomScoreAdj`, `CgroupParent`, `Init`, `Domainname`, `ArgsEscaped`, `OnBuild`, `Shell` | Rejected | Each rejected with `400 Bad Request` when set (covered by the negative-option matrix tests in `crates/runtime/src/error.rs`). |

---

## 3. Network Configuration Options

| Option | Status | Engine Behavior |
|---|---|---|
| `bridge` driver | Supported | Linux bridge (`ingot0` or user-defined) with iptables NAT; dual-stack with a ULA `/64` per network when the daemon runs with `--ipv6`. |
| `none` driver | Supported | Isolated loopback-only container network. |
| `host` driver | Supported | Container shares host network namespace. |
| `--internal` | Supported | Disables default gateway route and outbound NAT (v4 and v6: no v6 default route, no v6 MASQUERADE). |
| Port bindings (`-p`) | Supported | IPv4 TCP/UDP port mapping via iptables DNAT + userland proxy. IPv6 publishing is not yet supported. |
| DNS (`--dns`, `--dns-search`) | Supported | Written to container `/etc/resolv.conf` (unchanged by dual-stack) with embedded DNS fallback; the embedded server answers `A` and `AAAA` from container leases (`AAAA` for the wrong family is `NODATA`, never forwarded). |
| IPv6 dual-stack (daemon `--ipv6`, `--fixed-cidr-v6`) | Supported (opt-in) | `ingotd --ipv6` carves a ULA `/64` per network from `--fixed-cidr-v6` (default `fd00:dead:beef::/48`), assigns the `::1` gateway to the bridge, installs `ip6tables` `MASQUERADE`/`FORWARD` rules (new `INGOT6-DNAT` chain shape), and leases each container a v6 address with a v6 default route on `eth0`. Linux-only; disabled by default (docker parity). |
| IPv6 (`EnableIPv6` per-network API) | Rejected | Rejected with `400 Bad Request`; enable dual-stack at the daemon level (`ingotd --ipv6`) instead. |
| Custom IPAM drivers | Rejected | Only `default` IPAM accepted; others rejected with `400 Bad Request`. |
| Overlay / Macvlan drivers | Rejected | Non-bridge drivers rejected with `400 Bad Request`. |

---

## 4. Volume Configuration Options

| Option | Status | Engine Behavior |
|---|---|---|
| Named volumes | Supported | Created under `/var/lib/ingot/volumes/<name>/_data`. |
| Anonymous volumes | Supported | Created automatically for `VOLUME` declarations; deleted on `rm -v` or `--rm`. |
| Bind mounts | Supported | Host path mounted read-write or read-only (`:ro`). Path traversal confined. |
| Tmpfs mounts | Supported | Mounted under target destination with configurable size and mode. |
| Remote / Cloud volume plugins | Rejected | Non-local volume drivers rejected with `400 Bad Request`. |

---

## 5. Trust Boundaries & Isolation

1. **Host Isolation:**
   - Ingot uses Linux namespaces (`pid`, `net`, `mnt`, `ipc`, `uts`, `cgroup`), cgroups v2, and a pure-Rust default seccomp allowlist filter.
   - For multi-tenant or untrusted workloads, Ingot is designed to run inside disposable microVMs (e.g., Firecracker). Containers inside a single kernel are not marketed as multi-tenant boundaries.
2. **Daemon Access:**
   - The Unix domain socket (`/run/ingot/ingot.sock`) defaults to permissions `0600`. Access to the socket grants root control of the host.

---

## 6. Endpoint Coverage (Plan Phase 12, unit 12.1)

Every route below is served bare and under each `/v1.24`–`/v1.44`
prefix (see `supported_minors()` in `crates/server/src/router.rs`).
Anything else returns an explicit `501 Not Implemented` JSON error
(`unknown_routes_are_explicit_501` test).

| Group | Served | Notes |
|---|---|---|
| `/_ping`, `/version`, `/info`, `/events`, `/system/df` | Yes | `df` reports images/containers/volumes/build-cache accounting |
| Containers: `json`, `create`, `{id}/json`, `start/stop/kill/wait/restart/pause/unpause`, `top`, `stats`, `logs`, `attach`, `{id}/exec`, `{id}/archive` (GET/HEAD/PUT), `prune`, `DELETE {id}` | Yes | |
| Exec: `{id}/start`, `{id}/json` | Yes | 101 hijack with log replay and exit-gated teardown |
| Images: `json`, `create` (pull), `{name}/json`, `{name}/history`, `{name}/tag`, `{name}/push`, `{name}`, `get`, `{name}/get`, `load`, `prune` | Yes | Import (`fromSrc`) is an explicit `501` |
| Networks: ` ` (list), `create`, `{id}`, `{id}/connect`, `{id}/disconnect`, `prune` | Yes | |
| Volumes: ` ` (list/create), `create`, `{name}`, `prune` | Yes | |
| `/build`, `/secrets` | Yes | Classic builder; secret tokens never touch layers/history |
| `/auth`, `/commit`, `/distribution/*` | Absent | `ingot login` stores credentials client-side; pulls and pushes authenticate per-registry |
| `/containers/{id}/rename`, `/update`, `/resize`, `/checkpoint`, `/plugins/*`, `/swarm/*`, `/session`, `/grpc` | Absent | Explicit `501` via the fallback; no silent success |

Events published (visible on `/events`): container `create/start/die/destroy/restart/pause/unpause/health_status` (`die` carries `exitCode`); network `create/destroy/connect/disconnect`; volume `create/destroy`; image `pull/tag/untag/delete`.
