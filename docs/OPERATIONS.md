# Ingot Operations Guide

Runbook companion to `README.md` (engine behavior) and
`docs/DOCKER_MATRIX.md` (compat contract). Defaults below assume stock
paths; replace `/var/lib/ingot` and `/run/ingot/ingot.sock` with your
`--data-root` / `--socket` when customized.

## Service Lifecycle

- Enable/start via the unit in `scripts/ingotd.service`; pass flags with
  `systemctl edit ingotd` (e.g. `--config /etc/ingot/daemon.json`,
  `--bridge`, `--socket-group`). See `README.md` "Configuration".
- Upgrade: stop the daemon, replace the `ingotd`/`ingot` binaries, start
  again. Boot reconciliation marks containers that were `Running`/`Paused`
  as `Exited(255)` with `OOMKilled=false` and cleans their mounts,
  cgroups, veth pairs, DNS registrations, and firewall rules
  (see `scripts/test_crash_recovery.sh`).
- `unless-stopped` restart-policy containers are restarted after a
  reboot; `always` containers are restarted too. Everything else stays
  stopped until you start it.
- Never run two daemons against one data root: `DaemonLock` refuses the
  second one. `--repair` also refuses while the daemon is live.

## Health And Diagnostics

- `ingot doctor` checks socket reachability, cgroup v2, overlayfs,
  iptables/ip availability, seccomp, and the data-root schema, and prints
  stale-resource counts.
- `curl --unix-socket /run/ingot/ingot.sock http://localhost/_ping`
  must print `OK`.
- Daemon log: run `ingotd --debug` in the foreground for startup and
  reconcile messages (`reconcile: ...`, `boot-leak audit: ...`).
- Per-container trouble state lives in `inspect`: `State.Error` (truncated
  last error), `State.OOMKilled`, `State.Health` (last 5 probe results).

## Backup, Restore, Migration

Back up while the daemon is stopped (or accept a crash-consistent copy;
boot reconciliation repairs it the same way it repairs a kill -9):

1. `systemctl stop ingotd` (or `kill` the daemon).
2. Copy `/var/lib/ingot` (images, containers, volumes, networks/IPAM,
   builder cache) and, if customized, the config file.
3. Restore by copying the tree back and starting the daemon.

On-disk schema is versioned (`DataPaths::check_schema_version`): a newer
data root on an older binary refuses to boot with an explicit error
instead of reinterpreting state. There is no downgrade path — restore
the matching backup or upgrade the binary.

## Log Rotation Policy

Container logs use the `json-file` driver
(`/var/lib/ingot/containers/<id>/<id>-json.log`). Unset log opts mean
unbounded growth (the docker default). Set per container at create time:

```json
{"LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "5"}}}
```

- `max-size`: bytes or `k`/`m`/`g` suffix (`-1` = unlimited).
- `max-file`: total files kept including the active one (≥ 1); the
  oldest rotated file is dropped past the cap.
- Any other log-opt key is rejected at create with `400 Bad Request`.

`/logs?follow=1` readers survive rotation: the hub reopens the active
file under the same lock that appends.

## Troubleshooting Matrix

| Symptom | Check | Fix |
|---|---|---|
| `Cannot connect ... ingot.sock` | `ls -l /run/ingot/ingot.sock`; `systemctl status ingotd` | Start the daemon; check `--socket` and directory permissions |
| `permission denied` on the socket | Socket mode/group (`--socket-group`) | Add the user to the group or run via sudo; anyone with socket access has effective root |
| `ingotd must run as root` | `id -u` | Start with `sudo ingotd` |
| `cannot acquire daemon lock` / repair refuses | `ps -C ingotd` | Stop the live daemon first; never force two daemons on one data root |
| `data-root schema` newer-than-binary error | Backup version vs binary | Upgrade the binary or restore the matching backup |
| Container `Error` / start failure mentioning cgroup | `cat /sys/fs/cgroup/cgroup.controllers`; v1 vs v2 | Boot a cgroup v2 host; `ingot doctor` reports controller state |
| Container `Error` mentioning overlay | `grep overlay /proc/filesystems` | Load the `overlay` module (`modprobe overlay`) |
| No outbound network from containers | `ip link show ingot0`; `iptables -t nat -L INGOT-DNAT -n` | Restart the daemon (boot reconciliation rebuilds the bridge, IPAM orphans, DNS, and NAT); check for foreign `ingot0` clashes |
| Port publish conflict | `docker ps` / inspect `HostConfig.PortBindings` | A 409 names the holder; republish on a free host port |
| `network has active endpoints` on remove | Inspect container `NetworkSettings.Networks` | Stop/remove the attached containers first |
| Pull stalls or digest mismatch | Registry reachability; pinned digest vs tag | Retry (4 attempts with backoff are built in); verify the digest; check `INGOT_REGISTRY_MIRRORS` |
| `image not found` after pull cancel | Re-pull | Cancelled pulls commit nothing by design |
| Daemon reports stale mounts/cgroups/rules at boot | `ingotd --debug` boot lines | Informational: reconciliation already cleaned them; investigate repeats |
| `ingot.slice` cgroups left after `rm -f` | `systemd-cgls` / `/sys/fs/cgroup/ingot.slice` | Report a bug with the daemon log; cleanup is idempotent and retried at next boot |
| Disk pressure from logs | Container `*-json.log` sizes | Set `max-size`/`max-file` log opts |
| Disk pressure from images | `docker system df` | `docker image prune` semantics per `DOCKER_MATRIX.md`; `--repair` reclaims stale partials offline |

## Leak Checks (Leak-Proofing After Incidents)

Run after a crash, a failed upgrade, or any incident report:

```sh
# mounts: no container overlay mounts outside live containers
mount | grep '/var/lib/ingot/containers' || echo "no stale mounts"
# cgroups: ingot.slice holds only running containers
ls /sys/fs/cgroup/ingot.slice
# firewall: DNAT chain has one rule set per published port
sudo iptables -t nat -L INGOT-DNAT -n --line-numbers
# bridge + IPAM: daemon boot log reconciles orphans automatically
sudo journalctl -u ingotd | grep -i -E "reconcil|leak|orphan|stale" | tail
```

Counts must be stable across create/remove storms; boot reconciliation
removes or re-adopts orphans and never duplicates rules.
