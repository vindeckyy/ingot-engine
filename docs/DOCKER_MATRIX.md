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
| `ps` | Supported | `-a`, `-q`, `--no-trunc`, `-f` (`id`, `name`, `status`, `ancestor`, `label`). |
| `images` | Supported | `-a`, `-q`, `--no-trunc`, `-f` (`dangling`, `label`, `reference`, `before`, `since`). |
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
| `push` | Absent | Explicitly deferred until validated registry design partner requirement. |
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
| `SecurityOpt` | Supported | `name=seccomp,profile=default` or `seccomp=unconfined`. Unsupported profiles rejected. |
| `Devices` | Rejected | Non-empty device lists rejected with `400 Bad Request` unless privileged. |
| `CgroupParent` | Rejected | Custom cgroup parents rejected with `400 Bad Request`. |
| `IpcMode` | Supported / Rejected | `private` and `shareable` accepted; non-empty others rejected. |
| `UTSMode` | Supported / Rejected | `private` accepted; others rejected. |
| `UsernsMode` | Rejected | Custom user namespace modes rejected with `400 Bad Request`. |
| `VolumeDriver` | Supported / Rejected | Only `local` accepted; other volume drivers rejected with `400 Bad Request`. |
| `LogConfig` | Supported / Rejected | Only `json-file` accepted; others rejected with `400 Bad Request`. |

---

## 3. Network Configuration Options

| Option | Status | Engine Behavior |
|---|---|---|
| `bridge` driver | Supported | Linux bridge (`ingot0` or user-defined) with iptables NAT. |
| `none` driver | Supported | Isolated loopback-only container network. |
| `host` driver | Supported | Container shares host network namespace. |
| `--internal` | Supported | Disables default gateway route and outbound NAT. |
| Port bindings (`-p`) | Supported | IPv4 TCP/UDP port mapping via iptables DNAT + userland proxy. |
| DNS (`--dns`, `--dns-search`) | Supported | Written to container `/etc/resolv.conf` with embedded DNS fallback. |
| IPv6 (`EnableIPv6`) | Rejected | Rejected with `400 Bad Request` (IPv4-only data plane). |
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
