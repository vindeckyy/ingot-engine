# Firecracker Sandbox Reference Proof (Milestone 0.2 / Section 6.2)

This document and companion harness (`scripts/sandbox_proof.sh`) provide the single-node reference architecture for running Ingot as the Docker-compatible container data plane inside disposable Firecracker microVMs.

---

## 1. Security Architecture & Boundary

```
+-------------------------------------------------------------------------+
| HOST (Linux Kernel / KVM)                                               |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  | Firecracker microVM (Isolation Boundary)                          |  |
|  |   - Pinned Guest Kernel (vmlinux)                                 |  |
|  |   - Minimal Read-Only Rootfs + Ephemeral Overlay                  |  |
|  |   - Resource Limits: 2 vCPUs, 1024 MiB RAM, 5 GiB disk            |  |
|  |                                                                   |  |
|  |   +-------------------------------------------------------------+ |  |
|  |   | Ingot Daemon (ingotd)                                       | |  |
|  |   |   - Listens on guest /run/ingot/ingot.sock                  | |  |
|  |   |   - Unprivileged seccomp profile + cgroup v2 inside guest   | |  |
|  |   |   - Docker Engine API v1.44                                 | |  |
|  |   |                                                             | |  |
|  |   |   [Container: Agent Workspace Execution]                    | |  |
|  |   +-------------------------------------------------------------+ |  |
|  +-------------------------------------------------------------------+  |
|                                                                         |
|  Host-Side Controls:                                                    |
|    - Firecracker REST API over Unix domain socket                       |
|    - MicroVM cgroup & quota controls                                    |
|    - Network egress policy via TAP device                               |
|    - Ephemeral microVM destruction on session completion/timeout        |
+-------------------------------------------------------------------------+
```

### Why MicroVM + Ingot
- **Untrusted Code Defense:** Shared-kernel Linux container abstractions (namespaces, cgroups, seccomp) are not sufficient multi-tenant isolation boundaries against zero-day kernel exploits. Firecracker provides hardware-enforced KVM virtualization.
- **Data Plane Simplicity:** Standard Docker inside a microVM requires `dockerd`, `containerd`, `containerd-shim`, and `runc`. Ingot runs as a single Rust daemon (`ingotd`) with zero external shims, minimizing guest memory RSS (~15 MB vs 120+ MB) and boot-to-ping latency.

---

## 2. MicroVM Configuration Contract

The reference proof configures Firecracker through its standard REST socket API:

1. **Machine Configuration (`/machine-config`):**
   ```json
   {
     "vcpu_count": 2,
     "mem_size_mib": 1024,
     "smt": false
   }
   ```
2. **Boot Source (`/boot-source`):**
   ```json
   {
     "kernel_image_path": "/path/to/vmlinux",
     "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw quiet"
   }
   ```
3. **Drives (`/drives/rootfs`):**
   ```json
   {
     "drive_id": "rootfs",
     "path_on_host": "/path/to/rootfs.ext4",
     "is_root_device": true,
     "is_read_only": false
   }
   ```
4. **Action (`/actions`):**
   ```json
   {
     "action_type": "InstanceStart"
   }
   ```

---

## 3. Running the Sandbox Proof

```bash
# Display help and usage
./scripts/sandbox_proof.sh --help

# Run reference proof (uses installed firecracker or downloads pinned binary)
sudo ./scripts/sandbox_proof.sh

# Run dry-run API verification mode (no KVM requirement)
./scripts/sandbox_proof.sh --dry-run
```

The script executes the full verification lifecycle:
1. Provisions Firecracker API socket and validates configuration endpoints.
2. Boots microVM and verifies guest ping.
3. Transmits test workspace and executes Docker build/run.
4. Enforces hard timeout and terminates microVM.
5. Verifies zero leftover processes, sockets, mounts, or host state.
