# Ingot rootless-daemon feasibility study (Q3, doc only)

Scope: can `ingotd` run as a non-root user? Grounded in the code paths
listed below. No code was changed for this study.

Files read:

- `crates/ingotd/src/main.rs` — boot gate, env checks, data-root init
- `crates/runtime/src/child.rs` — container init after `clone()`
- `crates/runtime/src/manager.rs` — start sequence, `clone()` flags,
  cgroup/netns setup, volume bind-mounts
- `crates/runtime/src/cgroup.rs` — cgroup v2 writes
- `crates/runtime/src/overlay.rs` — overlayfs mounts
- `crates/runtime/src/exec.rs`, `crates/runtime/src/step.rs` — exec setns,
  builder-step clone
- `crates/network/src/lib.rs`, `crates/network/src/dns.rs`,
  `crates/network/src/proxy.rs` — bridge/iptables/veth, DNS, userland proxy
- `crates/store/src/paths.rs` — data-root layout
- `crates/image/src/unpack.rs` — layer unpack (whiteouts, xattrs)
- `crates/server/src/serve.rs` — socket bind/permissions

No existing rootless/userns plumbing was found: a repo-wide search for
`subuid|subgid|newuidmap|CLONE_NEWUSER|rootless|userns|idmap|slirp|pasta`
matches only README/CONTRIBUTING prose ("root-only daemon",
"rootless-safe test rules") — there is no `CLONE_NEWUSER` use in
`crates/` today.

## 1. What works unprivileged today vs what needs root

### 1a. Works unprivileged already (or with only path changes)

- Config resolution, logging, schema-marker check, record persistence.
  `resolve_config` (`crates/ingotd/src/main.rs:91-120`),
  `DataPaths::check_schema_version` (`crates/store/src/paths.rs:33-58`),
  `create_all` (`crates/store/src/paths.rs:179-196`) are plain file I/O —
  they only need a user-owned data root (see §2/§3 for relocation).
- Image fetch/unpack, mostly. `unpack_entries`
  (`crates/image/src/unpack.rs:120-166`) uses `tar::Archive` with
  `preserve_permissions`/`preserve_mtime`; the two historically privileged
  operations already degrade gracefully: whiteout `mknod` falls back to a
  regular file on `EPERM` (`crates/image/src/unpack.rs:168-182`), and the
  opaque-dir `setxattr` is best-effort on `EPERM`/`ENOTSUP`
  (`crates/image/src/unpack.rs:184-211`). Caveat: entries owned by
  non-root uids unpack as the invoking user (ownership is *not* preserved),
  which §2 must address via shifting.
- The userland port proxy. `publish_port` spawns
  `proxy::run_proxy` (`crates/network/src/lib.rs:1172-1186`), a plain
  userspace TCP/UDP relay. Binding host ports ≥1024 works unprivileged;
  ports <1024 do not (no `CAP_NET_BIND_SERVICE` outside a userns).
- `docker exec` plumbing, in principle. The fork1→setns→fork2 dance
  (`crates/runtime/src/exec.rs:306-337`) joins namespaces the daemon owns;
  a rootless daemon owns its userns, so setns into container namespaces
  stays permitted for the same euid. The hard-coded
  `/sys/fs/cgroup/ingot.slice/...` open (`crates/runtime/src/exec.rs:212-217`)
  is the part that must move to the delegated subtree (§3).
- `--network none` containers. The child brings loopback up itself via an
  `SIOCSIFFLAGS` ioctl (`crates/runtime/src/child.rs:900-919`), which
  succeeds inside a userns-owned netns — no host network privilege needed.

### 1b. Needs root today (enumerated privileged op inventory)

Boot / environment:

1. Hard euid==0 gate. `crates/ingotd/src/main.rs:142-148` bails unless
   root. First thing to gate behind a `--rootless` mode.
2. `check_environment` (`crates/ingotd/src/main.rs:377-403`): requires
   `/sys/fs/cgroup` + cgroup-v2 controllers (read-only, fine unprivileged),
   but also `ip`/`iptables`/`modprobe` binaries and a trial overlay mount
   with a `modprobe overlay` retry (`crates/ingotd/src/main.rs:407-448`).
   `modprobe` cannot succeed unprivileged; the retry must be skipped in
   rootless mode and the overlay probe moved inside the userns (§2).
3. Boot-leak audit (`crates/ingotd/src/main.rs:283-327`): `umount2` of stale
   overlay mounts and `remove_dir` of `/sys/fs/cgroup/ingot.slice/<id>`.
   Rootless equivalent operates on the user-owned overlay root and the
   delegated cgroup subtree only.

Mount / rootfs (the largest group):

4. Daemon-side overlay mount of the container rootfs,
   `crates/runtime/src/overlay.rs:10-36` via `do_mount`
   (`crates/runtime/src/overlay.rs:75-98`, `mount(2)` with `MS_NOSUID`).
   Outside a userns this needs `CAP_SYS_ADMIN` in the initial ns.
   Inside a userns it is allowed on kernels ≥5.11 subject to ownership
   rules (§2). Same for builder mounts (`crates/runtime/src/step.rs:211-215`
   unmount path, `mount_overlay` at `crates/runtime/src/overlay.rs:48-65`).
5. Daemon-side volume/bind/tmpfs mounts before clone,
   `apply_mounts` (`crates/runtime/src/manager.rs:1947-2048`): `MS_BIND`
   mounts plus the `MS_RDONLY|MS_REMOUNT` second pass
   (`crates/runtime/src/manager.rs:2023-2042`) and tmpfs mounts
   (`crates/runtime/src/manager.rs:1959`, helper at `2074-2095`). Bind
   mounts are permitted in a userns; the read-only remount of a bind the
   daemon does not own is the sharp edge (works when source is
   user-owned; host-owned read-only sources need the userns owner to hold
   them — constrains bind-mount sources in rootless mode).
6. Child-side mount program (`crates/runtime/src/child.rs:178-326`):
   `MS_PRIVATE|MS_REC` remount of `/` (`:179-180`), bind mounts of
   resolv.conf/hosts/hostname (`:185-199`), tmpfs+devpts+shm for `/dev`
   (`:208-218`), `proc`/`sysfs`/`cgroup2` mounts (`:239-263`), masked-path
   binds/tmpfs (`mask_paths`, `:824-868`), self-bind + `pivot_root` +
   `umount2("/oldroot")` (`:277-297`), read-only recursive remount
   (`:310-318`), `--tmpfs` mounts (`:319-326`). All of these are legal
   inside a userns the daemon created (the child holds `CAP_SYS_ADMIN`
   over that userns), *provided* the daemon first creates a userns —
   today `clone()` requests no `CLONE_NEWUSER`
   (`crates/runtime/src/manager.rs:692-702`, builder steps at
   `crates/runtime/src/step.rs:160-165`).
7. `mknod` of the six standard `/dev` nodes
   (`crates/runtime/src/child.rs:219-229`, helper `:870-879`). Needs
   `CAP_MKNOD`; held inside a daemon-owned userns, so it survives — but
   note the deliberate default-cap exclusion has no device-cgroup backstop
   either way (`crates/runtime/src/child.rs:12-18`; worse in rootless, §5).
8. `pivot_root` syscall (`crates/runtime/src/child.rs:285`) and the
   fail-closed oldroot detach (`:293-297`): fine in a userns+mountns.
   Chroot-adjacent helpers (`chdir` into merged, `mask_paths` binds) ride
   along with the same requirement: userns + mountns, no host root.

Namespaces / identity:

9. `clone(2)` with `NEWNS|NEWPID|NEWUTS|NEWIPC|NEWNET|NEWCGROUP`
   (`crates/runtime/src/manager.rs:692-702`, stack helper at
   `crates/runtime/src/child.rs:658-685`). Unprivileged `clone` of these
   namespaces requires `CLONE_NEWUSER` in the same call (or an ancestor
   userns). This is *the* gating change: add `CLONE_NEWUSER` + uid/gid map
   setup (§2). `NEWCGROUP` is kept. Builder steps
   (`crates/runtime/src/step.rs:160-165`) need the identical treatment.
10. `sethostname` (`crates/runtime/src/child.rs:329-331`): needs the UTS ns
    — already created at clone; fine in userns.
11. `setgroups`/`setresgid`/`setresuid` + `PR_SET_KEEPCAPS`
    (`crates/runtime/src/child.rs:360-366`): in a userns, `setgroups` is
    denied unless the gid map allows it (kernel locks `setgroups` after
    writing a single-line `gid_map` without `newgidmap`); container `--user`
    with supplementary groups needs the multi-line map path (§2).
12. Capability confinement (`confine_caps`, `crates/runtime/src/child.rs:623-646`)
    and rlimit raising (`apply_rlimit`, `:689-716`, called pre-uid-switch at
    `:342-347`): operate on the userns-local bounding set; semantics hold,
    but the contained caps no longer imply any host privilege.
13. Net-namespace sysctls (`/proc/sys/net/...` writes,
    `crates/runtime/src/child.rs:334-340`): namespaced keys stay writable in
    a userns netns; host-wide keys were already rejected at create and must
    stay rejected.

Cgroups:

14. `Cgroup::create` (`crates/runtime/src/cgroup.rs:37-46`): `mkdir` under
    `/sys/fs/cgroup/ingot.slice` (constants `:7-8`) — root-owned, `EPERM`
    unprivileged. `enable_controllers` writes `cgroup.subtree_control`
    (`:170-183`), which requires ownership of the parent cgroup (§3).
15. Limit/placement writes: `memory.max`, `memory.swap.max`, `cpu.max`,
    `cpu.weight`, `pids.max`, `cpuset.cpus` (`:61-90`), `cgroup.procs`
    (`:92-94`), freezer/kill switches (`:96-103`). All need a delegated
    cgroup; `cpuset.cpus` additionally needs partitioned CPUs on many
    hosts and is the likeliest per-controller failure (§3, §7).

Network / firewall (host side, all require host net privilege today):

16. `enable_ip_forward` writes `/proc/sys/net/ipv4/ip_forward`
    (`crates/network/src/lib.rs:223-227`) — host-wide sysctl, impossible
    rootless. Must be skipped (document degraded forwarding).
17. Bridge lifecycle: `ip link add type bridge`, `ip addr add`, `ip link set up`
    (`crates/network/src/lib.rs:500-511`), stale-bridge sweep at boot
    (`:339-356`). Needs `CAP_NET_ADMIN` in the *initial* netns — impossible
    inside a userns (a userns child gets its own netns, not host bridges).
18. iptables NAT/filter rules: `INGOT-DNAT` chain setup
    (`:423-460`), per-bridge MASQUERADE + FORWARD ACCEPTs (`:518-585`),
    per-port DNAT + FORWARD (`:1136-1171`). Same verdict: host netfilter is
    out of reach; the existing bridge driver cannot be kept for rootless (§4).
19. Veth attach: `ip link add veth`, enslavement to bridge, move peer into
    container netns, `nsenter`-based addressing/routes
    (`crates/network/src/lib.rs:955-1000`). The peer-move + in-netns config
    works between two userns-owned netns; enslavement to a *host* bridge
    does not. The veth *primitive* is reusable only under a userns-local
    bridge (§4).
20. Netns bind-mounts for bookkeeping (`/proc/<pid>/ns/net` → run-root file,
    `crates/runtime/src/manager.rs:768-784`, `bind_mount` helper
    `:2097-2116`; same for mntns `:785-803`). Bind-mounting nsfs fds is
    allowed in a userns; the target dir must relocate from `/run/ingot`
    to `$XDG_RUNTIME_DIR` (§2).
21. Embedded DNS bind to `(gateway, 53)`
    (`crates/network/src/dns.rs:10-15`). Port 53 < 1024 needs
    `CAP_NET_BIND_SERVICE`; a userns root holds it *within the userns*, but
    binding a host bridge gateway IP is out of scope rootless. Under §4's
    recommendation the gateway/DNS model changes (DNS on a userns-local
    address, or host-loopback forwarding).

Socket / paths:

22. Default paths are root-owned: data root `/var/lib/ingot`, run root
    `/run/ingot`, socket `/run/ingot/ingot.sock`
    (`crates/ingotd/src/main.rs:11-13`, `crates/store/src/paths.rs:1-10`).
    Rootless needs `~/.local/share/ingot` (data) + `$XDG_RUNTIME_DIR/ingot`
    (socket, netns binds at `crates/store/src/paths.rs:171-176`).
23. Socket-group `chown 0:gid` (`crates/server/src/serve.rs:67-92`) cannot
    `chown` to root unprivileged; rootless mode must use owning-group/user
    perms only.

## 2. User-namespace design

Required change: the daemon creates a userns it owns, then keeps every
existing mount/pivot/mknod/cap step (child.rs §1b.6-8) running *inside* it.

Clone + map setup. Add `CLONE_NEWUSER` to both clone sites
(`crates/runtime/src/manager.rs:692-702`,
`crates/runtime/src/step.rs:160-165`). After `clone()` the parent writes
the maps before signalling `g` on the ready pipe
(`crates/runtime/src/manager.rs` start flow; child blocks at
`crates/runtime/src/child.rs:170-176`), with the standard ordering:
write `uid_map`/`gid_map`, write `setgroups`=`deny` first for the
single-line path. Two map schemes:

- Scheme A — single-entry identity map (`0 <euid> 1`, `setgroups deny`).
  Writable directly to `/proc/self/{uid,gid}_map` by an unprivileged
  process; needs no `/etc/subuid`, no helpers. Limitation: every container
  uid maps to the same host uid, so (a) multi-user images lose on-disk uid
  separation inside volumes, and (b) `setgroups(2)` + supplementary-group
  `--user uid:gid,gid...` (`crates/runtime/src/child.rs:514-528`) fails —
  daemon must reject `group_add`-style specs under Scheme A.
- Scheme B — ranged map via `/etc/subuid` + `/etc/subgid`
  (`0 1 65536` plus `<euid> <subid-base> 65536`, written through the
  setuid-root `newuidmap`/`newgidmap` helpers). Gives 64k container uids
  the Docker-rootless default shape, keeps per-uid separation, allows
  `setgroups`. Cost: depends on host-plumbed subordinate ranges and the
  two helpers (present on Debian/Fedora/Arch `shadow`/`uidmap` packages,
  but not guaranteed — must be a *detected capability*, not an assumption).

Recommendation: implement A first (zero host prerequisites beyond a ≥5.11
kernel), detect B at boot (`/etc/subuid` contains the invoking user AND
`newuidmap`/`newgidmap` execute), prefer B when available. Both schemes
leave the in-container `resolve_user` against `/etc/passwd`
(`crates/runtime/src/child.rs:483-529`) untouched — numeric uids just map
through the wider/narrower range.

`/etc/subuid` alignment. Under B, validate at boot: parse `/etc/subuid`
and `/etc/subgid` for the invoking user, require a contiguous range ≥65536
for faithful 1:1 image uids, else warn + clamp (container uids above the
range fail at `setresuid` — must surface as a start error, not a hang).
Under A, explicitly document that `chown 0:0`-style image content appears
owned by the invoking user on the host.

Overlayfs in userns. Native unprivileged overlay mounts require kernel
≥5.11 *and* all lower/upper/work dirs to be owned (as seen through the
userns) by the userns owner. Consequences for
`crates/runtime/src/overlay.rs:10-36`: layer dirs, `diff`, `work`, `merged`
must be `chown`ed to the mapped root at first use; a data root shared
between a rootful and a rootless daemon on the same layers will *not* work
(lowerdirs owned by host root are rejected as unprivileged lower layers on
some kernel versions — rootless gets its own data root, §1b.22). Kernels
<5.11 cannot do native unprivileged overlay at all; the only fallback is
`fuse-overlayfs`, which the "no new mandatory deps" constraint forbids —
so gate rootless mode on kernel ≥5.11 and fail fast with the version in
the error. `trusted.overlay.*` xattrs are unavailable unprivileged; the
unpack path already tries `user.overlay.opaque` second
(`crates/image/src/unpack.rs:187-200`) — verify on the floor kernel that
the user-xattr whiteout path actually hides entries, else deleted-file
semantics silently break (test per phase, §6).

File-ownership shifting for volumes/image layers. Three consumers move
across the boundary: image layers (unpacked once, shared), container
`diff` dirs (per-container), and volumes/binds (user data). Without
shifting, a `USER 1000` image's files land owned by the invoker under
Scheme A and by `subid-base+1000` under B. Options: (a) `chown -R` the
container `diff`/`merged` view at start (simple, but O(tree) per start and
corrupts shared layer dirs if applied there — restrict to `diff` + volume
copy-up at `crates/runtime/src/manager.rs:1990-1999`); (b) kernel idmapped
mounts (≥5.12, `mount_setattr(AT_RECURSIVE)` per-mount idmap — the clean
answer for volumes/binds, no tree walk, but needs capability detection and
a mount-attr helper that does not exist in the codebase); (c) share layers
read-only and shift only at the upper layer (overlayfs already presents
lower layers through the userns mapping — no per-file work for image
content, only for volume seed copy-up). Recommended: (c) + (a)-on-`diff`
under Scheme A, (c) + (b) for volumes when idmapped mounts probe
available, with (a) as fallback. Bind mounts of host paths the user owns
need no shifting; binds of paths the user cannot `chown` must be mounted
read-only or refused (fail closed, mirroring the oldroot-detach posture at
`crates/runtime/src/child.rs:293-297`).

## 3. Cgroup v2 delegation requirements

Today the daemon assumes root: hard-coded `/sys/fs/cgroup/ingot.slice`
(`crates/runtime/src/cgroup.rs:7-8`), boot warmup of `subtree_control` on
the *host root and slice* (`crates/ingotd/src/main.rs:194`,
`crates/runtime/src/cgroup.rs:50-59`, `170-183`), and `mkdir` that is fatal
on failure (`:37-46`). Unprivileged, every one of these returns `EPERM`/
`EROFS` on a stock host.

What rootless needs from the host (all standard systemd cgroup-v2
delegation, no kernel patches):

1. A delegated subtree owned by the invoking user, i.e. the daemon runs
   inside `user.slice/user-$(id -u).slice/...` (systemd user session) or
   the admin pre-creates `/sys/fs/cgroup/ingot-<user>.slice` with
   `chown <user>` + `+cpu +memory +pids +cpuset +io` in
   `cgroup.subtree_control`, plus `cgroup.procs` write access. systemd
   units express this as `Delegate=cpu cpuset io memory pids`.
2. The daemon must *discover*, not hard-code, its cgroup home: read
   `/proc/self/cgroup`, create `ingot.slice/<id>` equivalents beneath it,
   and treat "cannot enable controller X" as degrade-to-unlimited for X
   (today non-fatal per controller at `:30-36`, keep that) while "cannot
   `mkdir` my leaf" stays fatal.
3. `cpuset.cpus` deserves special handling: on many distros the delegated
   subtree ships with an empty `cpuset.cpus` and writes fail until the
   parent's set propagates. The `--cpuset-cpus` path
   (`crates/runtime/src/cgroup.rs:86-88`) must probe once at boot and, on
   failure, reject `--cpuset-cpus` with an actionable error rather than
   failing every start (§7 records the explicit non-recommendation).
4. Freezer/kill/stats (`cgroup.freeze`, `cgroup.kill`, `memory.current`,
   `cpu.stat`, `pids.current`, `memory.events` at `:96-150`) all function
   inside a delegated subtree — pause/unpause, stop-escalation, stats, and
   the OOM-vs-SIGKILL discriminator keep working. No redesign, only the
   path prefix changes.
5. systemd user lingering (`loginctl enable-linger`) or equivalent is an
   operational prerequisite, else the delegated subtree (and containers)
   die at logout — document, do not code around.

Test hooks per phase in §6 cover: no-delegation (clear error), partial
controllers (degrade), cpuset-unavailable (refuse flag).

## 4. Network options (recommend one, no new mandatory deps)

Constraints from the code: the entire current dataplane — host bridge,
`ip`/`iptables` fork/execs, veth-into-host-bridge, MASQUERADE, DNAT port
publishing, gateway-bound DNS — requires host `NET_ADMIN`/netfilter
(§1b.16-19). None of it survives unprivileged. Three options:

- Option 1 — no-net (+ loopback). The `network_mode == "none"` path
  already exists end to end: skip attach
  (`crates/runtime/src/manager.rs:807-811`), set `bring_lo_up`
  (`:684`), child raises `lo` itself (`crates/runtime/src/child.rs:266-268`
  + `:900-919`). Zero new code paths, zero deps, works on every kernel
  that does userns+netns. What is lost: DNS, inter-container networking,
  egress, `-p` publishing.
- Option 2 — slirp-like userland networking. Full TAP-based slirp needs a
  helper (`slirp4netns`, `pasta`) or a TAP device (`/dev/net/tun` +
  `NET_ADMIN` in the *outer* ns to create it) — both violate "no new
  mandatory deps" as stated. A from-scratch in-process TCP/IP stack is out
  of scope for a gated study. Partial reuse exists (the `proxy.rs`
  relay), but relay ≠ connectivity: without a packet path there is nothing
  to relay *from*.
- Option 3 — existing bridge driver. Technically impossible unprivileged
  (host bridge + iptables + `ip_forward`, §1b.16-18). A userns-*local*
  bridge variant (bridge inside the daemon's netns, veth pairs between it
  and containers, daemon-side NAT via its own netns) is a real design but
  is a second network driver, needs dynamic per-user subnet allocation to
  avoid colliding with the rootful `172.17.0.0/16` default
  (`crates/network/src/lib.rs:357-367`), and still cannot do host-port DNAT
  without help. Not a Phase-1 item.

Recommendation: **Option 1 (no-net + loopback) as the rootless Phase-1
network**, with two non-mandatory follow-ups sequenced after it: (a) an
*optional* `slirp4netns`/`pasta` external-helper mode, auto-detected and
never required ( PATH probe, clear "install X for egress" error); (b) the
userland proxy (`proxy.rs`) reused for explicit `-p` localhost-only
forwards, which works without DNAT. Explicitly do **not** port the bridge
driver to rootless: it cannot function, and a half-working bridge (no NAT,
no DNS, colliding subnets) is worse than an honest no-net mode. The
embedded DNS server (`crates/network/src/dns.rs:10-15`) is out of scope
for Phase 1 — no gateway exists to bind it to; container `resolv.conf`
generation (`crates/runtime/src/manager.rs:290`, builder at
`crates/image/src/unpack.rs`-adjacent etc paths) should emit host
resolvers or a loopback stub with documentation of the leak trade-off.

## 5. Security delta vs root daemon

What gets better:

- Daemon compromise blast radius. Today the socket warning is literal:
  socket access = host root (`crates/server/src/serve.rs:3-9`,
  `crates/ingotd/src/main.rs:33-39`). A rootless daemon holds no host
  capabilities; container escape yields the invoking user's privileges,
  not uid 0. The `chown 0:gid` socket path (`serve.rs:74`) disappears with
  it — the socket lives in `$XDG_RUNTIME_DIR` under user ownership.
- Privileged-flag containment. `--privileged` today keeps "everything the
  daemon has" (`crates/runtime/src/child.rs:718-726`, `compute_keep`
  `:570-578`) = host root caps. Rootless, it keeps userns-local caps only.
  Host device access via `--privileged` bind of `/dev` (`child.rs:204-206`)
  becomes useless-or-refused instead of a block-device backdoor (the exact
  hole the `MKNOD` default-exclusion at `:12-18` exists to narrow).
- Mount-table and cgroup isolation are structural rather than
  permission-based: stale-mount/cgroup cleanup can only touch the user's
  own subtree.

What gets worse or needs active mitigation:

- Userns kernel attack surface. Unprivileged userns creation exposes
  historically bug-prone kernel paths (overlayfs-in-userns, idmapped
  mounts, keyrings). This is the standard Docker-rootless trade-off, but
  several distros disable unprivileged userns by default (Debian
  `kernel.unprivileged_userns_clone`, RHEL's historical stance) — on those
  hosts rootless Ingot does not run at all. Failure must be a clear boot
  error naming the sysctl.
- No device-cgroup backstop, unchanged and slightly more load-bearing.
  The codebase already notes cgroup v2 removed the device controller
  (`child.rs:12-18`); mknod inside a userns is still gated by userns-local
  `CAP_MKNOD`, and the default seccomp profile blocks `mknod(2)`
  (`crates/runtime/src/seccomp.rs:151,241,374-377`) — keep both denials in
  rootless mode and refuse `--cap-add MKNOD` (or gate it behind Scheme B +
  explicit opt-in), since a userns-root container creating device nodes for
  host majors is one mount mistake from host disk access.
- UID-range confusion. Under Scheme A all container uids are one host uid:
  containers can read each other's volume contents through the host
  filesystem, and a container writing `0600 root` files locks the *user*
  out of their own volume on the host. Under B, stale `subid-base+uid`
  ownership after range reassignment misattributes files. Mitigations:
  per-daemon data root with `0700`, documented backup semantics (host-side
  tools see shifted uids), never mix rootful/rootless data roots (§2).
- Weaker network isolation story. No-net is honest but pushes users toward
  `--network host`-equivalents or manual forwards; if a userns-local bridge
  (Option 3 variant) is later added, its "isolation" is software-only
  (no host netfilter enforcement) and must be documented as such. The
  `internal`-network DROP rules (`crates/network/src/lib.rs:512-562`) have
  no rootless counterpart in Phase 1.
- Setuid-helper trust (Scheme B only): `newuidmap`/`newgidmap` are
  setuid-root binaries parsing daemon-supplied ranges — constrain range
  inputs, never pass user-controlled strings through, prefer direct
  `/proc` map writes for Scheme A.

Net assessment: strictly better containment of the daemon and of routine
container workloads; *narrower* functionality with a few sharper edges
(uid aliasing, no device backstop, userns kernel surface) that the phased
plan below contains by refusing the dangerous flags rather than emulating
them.

## 6. Phased work breakdown (tests per phase, not implemented)

Phase 0 — mode plumbing + path relocation (no privilege changes).

- Add `--rootless` (or auto-detect euid≠0 → rootless-or-die) that: skips
  the root gate (`main.rs:142-148`), relocates defaults to
  `~/.local/share/ingot` + `$XDG_RUNTIME_DIR/ingot`, replaces the
  `chown 0:gid` socket path with user-only perms (`serve.rs:67-92`),
  skips `modprobe`/host-bridge boot steps.
- Tests: unit — config resolution prefers env/XDG roots; `serve::`
  perm tests extended with rootless expectations; integration — daemon
  boots as non-root with `--network none` and runs `echo hi` (the only
  container test in this phase).

Phase 1 — userns container execution, no-net.

- `CLONE_NEWUSER` + Scheme A maps at both clone sites
  (`manager.rs:692-702`, `step.rs:160-165`); ready-pipe ordering (maps
  before `g`); kernel ≥5.11 gate; overlay dirs user-owned; keep the full
  child mount/pivot/cap program unchanged inside the userns; force
  `NetworkMode=none`, refuse `-p`/bridge/`--privileged`/host-path binds
  outside the user's tree with docker-shaped errors.
- Tests: unit — map-writing helper (order: `setgroups deny`→`gid_map`;
  parse/validate `/etc/subuid` probe); integration (run as non-root on a
  ≥5.11 host) — start/exec/stop/logs of a no-net container, `/dev` node
  presence, masked paths present, read-only rootfs honored, `id -u`
  inside == 0 mapped to invoker outside; negative — privileged/publish/
  foreign-bind each fail with the documented message; kernel <5.11 →
  clean boot refusal.

Phase 2 — cgroup delegation.

- Discover cgroup home from `/proc/self/cgroup`; replace `CGROUP_ROOT`/
  `SLICE` constants' host paths with the delegated subtree; keep
  degrade-per-controller, fatal-on-leaf-mkdir; wire `Delegate=` systemd
  user-unit docs + linger note.
- Tests: unit — existing conversion tests stay; new — subtree discovery
  parsing, degrade matrix (missing cpu → unlimited, missing cpuset →
  flag refused); integration — memory/pids limits enforced
  (`stress`-free: allocate-to-limit + OOM-counter check via
  `memory.events`), freeze/thaw round-trip, stats fields non-zero.

Phase 3 — identity: Scheme B + ownership shifting.

- `newuidmap`/`newgidmap` (or direct multi-line writes where permitted)
  ranged maps; `/etc/subuid` validation + clamp errors; ownership policy
  (c)-plus-(a)/(b) from §2; idmapped-mount probe with chown fallback.
- Tests: unit — subuid parsing/validation, clamp math; integration —
  `USER 1000` image files read correctly inside, host-side ownership in
  the subordinate range, volume seed copy-up ownership, supplementary
  groups functional, Scheme-A rejection of group specs preserved.

Phase 4 — network, optional and explicitly non-mandatory.

- (a) host-resolver `resolv.conf` + docs; (b) localhost-only `-p` via the
  existing userland proxy for high ports (integration: connect from host
  loopback, confirm no DNAT chain touched); (c) *optional* external
  slirp/pasta helper behind a PATH probe (integration skipped when the
  helper is absent — never a hard failure).
- Tests: unit — proxy bind-permission expectations by port; integration —
  egress test gated on helper presence; negative — bridge create/join in
  rootless mode returns the documented refusal.

Phase 5 — hardening + parity audit.

- Re-run the full Tier-1 suite as non-root; seccomp default stays on;
  `--cap-add MKNOD` refused in rootless; adversarial unpack tests
  (symlink-escape cases already in `unpack.rs:254+`) re-run under Scheme A
  uids; data-root cross-mode (rootful vs rootless) mixing test proves
  refusal-or-separation.
- Exit gate: every §1b op either works in the userns, is rehomed
  (delegated cgroup, XDG paths), has an optional-helper path, or fails
  with a named error covered by a test.

## 7. Explicit non-recommendations (infeasible — do not build)

1. **Host bridge networking for rootless: do not build.** Requires host
   `NET_ADMIN`, host netfilter, and host-wide `ip_forward`
   (`lib.rs:223-227,500-511,518-585,1136-1171`). There is no unprivileged
   path to any of them. Ship no-net; consider only the optional-helper
   (§4.2) or a future userns-local driver.
2. **`--privileged` with host effects: refuse, do not emulate.**
   Privileged bind of `/dev` (`child.rs:204-206`), `ALL_CAPS`
   (`child.rs:36-78`), and host device access cannot be granted without
   host caps. Rootless `--privileged` must at most mean "all
   userns-local caps", and host-path/device requests under it must error.
3. **`--cpuset-cpus` without delegated cpuset: refuse the flag.**
   Delegation frequently ships empty/unwritable `cpuset.cpus`; faking
   success (silently ignoring pinning) violates the fail-closed posture
   used for oldroot detach (`child.rs:293-297`).
4. **Low ports (<1024), host `ip_forward`, `modprobe`, host-wide sysctls,
   `chown 0:*` socket groups: refuse or skip with a message**, per §1b
   items 2, 16, 23. None has an unprivileged equivalent.
5. **Shared rootful/rootless data root or layer dirs: forbid.**
   Ownership and overlay-lowerdir rules (§2) make sharing corrupt or
   unmountable; schema marker (`paths.rs:33-58`) should gain a mode tag or
   the daemon must refuse a root-owned data root in rootless mode.
6. **In-process NAT/slirp stack or `fuse-overlayfs` fallback as mandatory:
   do not build.** The first is a second network stack to secure; the
   second violates the no-new-mandatory-deps constraint. Kernel ≥5.11 is
   the floor; older kernels get a clear refusal, not a FUSE shim.
7. **Do not weaken the existing guards to "make rootless fit":** keep the
   `MKNOD`-minus-defaults set (`child.rs:19-33`), the seccomp
   mknod/pivot/umount denials (`seccomp.rs:151,241,374-377`), masked paths
   (`child.rs:270-301`), and fail-closed oldroot detach. A rootless mode
   that drops these to pass tests would be less safe than the root daemon
   it replaces.

## Verdict

Feasible with reduced scope: **Scheme-A userns + native overlay (≥5.11) +
delegated cgroup subtree + no-net/loopback + user-owned data/socket roots
is a coherent, shippable rootless Phase 1**, reusing the child mount/pivot/
cap program, the image unpack fallbacks, the exec setns dance, and the
userland proxy nearly unchanged. Everything host-network-shaped (bridge,
iptables, DNAT, gateway DNS), host-cgroup-shaped (fixed `ingot.slice`,
subtree_control on host root), and host-identity-shaped (`chown 0:*`,
low ports, cpusets without delegation, `--privileged`-as-host-root) is
infeasible and must be refused with named errors, not emulated. The
phasing above keeps each refusal covered by a test and never trades an
existing hardening control for rootless convenience.
