//! ingotd — the Ingot daemon (dockerd equivalent).

use anyhow::{Context, Result};
use clap::Parser;
use ingot_server::{DaemonConfig, DaemonState};
use ingot_store::{paths::DataPaths, DaemonLock};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(name = "ingotd", about = "Ingot container engine daemon", version)]
struct Args {
    /// Data root (docker's --data-root).
    #[arg(long, default_value = "/var/lib/ingot")]
    data_root: PathBuf,
    /// Runtime state root (exec-root).
    #[arg(long, default_value = "/run/ingot")]
    run_root: PathBuf,
    /// Socket path (docker's --host unix://...).
    #[arg(long, default_value = "/run/ingot/ingot.sock")]
    socket: PathBuf,
    #[arg(long)]
    debug: bool,
    /// Default bridge interface name.
    #[arg(long, default_value = "ingot0")]
    bridge: String,
    /// Group owner for the Unix socket (e.g. "docker" or "ingot"). Defaults to
    /// root-only access (mode 0600).
    ///
    /// WARNING: Any user with access to the Ingot socket has effective root
    /// privileges on the host.
    #[arg(long)]
    socket_group: Option<String>,
    /// Verify image-store consistency (read-only) and exit.
    #[arg(long)]
    fsck: bool,
    /// Verify and repair the image store (removes stale partial downloads
    /// and unreferenced blobs; refuses while the daemon is live), then exit.
    #[arg(long)]
    repair: bool,
}

fn init_logging(debug: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if debug {
            "debug".into()
        } else {
            "info,hyper=warn,reqwest=warn".into()
        }
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_logging(args.debug);

    // The daemon manipulates mounts, namespaces, cgroups, netlink and iptables.
    if !nix::unistd::Uid::effective().is_root() {
        anyhow::bail!(
            "ingotd must run as root (namespace/cgroup/mount setup requires it). \
             Start it with: sudo ingotd"
        );
    }

    let paths = DataPaths::new(&args.data_root, &args.run_root);
    if args.fsck || args.repair {
        let _lock = if args.repair {
            // Image repair modifies the store; refuse if daemon is live
            Some(
                DaemonLock::acquire(&args.data_root, &args.run_root)
                    .context("cannot repair image store while ingotd is running")?,
            )
        } else {
            None
        };
        let report = if args.repair {
            ingot_image::fsck::repair(&paths, &args.run_root)?
        } else {
            ingot_image::fsck::check(&paths)?
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        if report.clean() {
            println!("fsck: store is clean");
            return Ok(());
        }
        anyhow::bail!("fsck: {} problem(s) found", report.errors.len());
    }

    // Acquire exclusive daemon lock on data_root and run_root before proceeding
    let _daemon_lock = DaemonLock::acquire(&args.data_root, &args.run_root)?;

    paths.create_all().context("initialise data root")?;
    paths
        .check_schema_version()
        .context("data-root schema check")?;

    let config = DaemonConfig {
        debug: args.debug,
        default_bridge_name: args.bridge.clone(),
        ..Default::default()
    };
    let mut daemon = DaemonState::new(paths.clone(), config)?;

    // Boot self-check: fail fast with actionable errors.
    check_environment(&paths)?;

    // Container manager (M2) — networking attaches in M3.
    let containers = Arc::new(ingot_runtime::ContainerManager::new(
        paths.clone(),
        daemon.events.clone(),
        daemon.images.clone(),
    )?);
    *containers.self_ref.write().unwrap() = Some(Arc::downgrade(&containers));
    // Network manager (M3) — bridge, IPAM, NAT, DNS.
    let networks = Arc::new(ingot_network::NetworkManager::new(paths.clone())?);
    networks.boot().await?;
    *containers.net.write().unwrap() = Some(networks.clone());
    daemon.networks = Some(networks);
    // Volume manager (M5).
    let volumes = Arc::new(ingot_volume::VolumeManager::new(paths.clone())?);
    daemon.volumes = Some(volumes);

    // Crash recovery: any container recorded as running died with the daemon.
    reconcile(&paths, &containers).await;
    audit_boot_leaks(&paths);

    daemon.containers = Some(containers);
    let state = Arc::new(daemon);

    tracing::info!(
        "ingotd {} starting: data-root={} socket={}",
        ingot_api::ENGINE_VERSION,
        paths.root.display(),
        args.socket.display()
    );

    ingot_server::serve::serve(state, &args.socket, args.socket_group.as_deref()).await
}

/// On boot: stale "running" containers died with the daemon. Supervised
/// policies (`always`, `unless-stopped`) are restarted (Plan Phase 2, unit
/// 2.3); everything else is marked exited and cleaned up.
async fn reconcile(paths: &DataPaths, containers: &Arc<ingot_runtime::ContainerManager>) {
    {
        for record in containers.list_records().await {
            let state_path = paths.container_state(&record.id);
            let Ok(raw) = std::fs::read(&state_path) else {
                continue;
            };
            let Ok(mut st) = serde_json::from_slice::<ingot_runtime::record::ContainerState>(&raw)
            else {
                continue;
            };
            if st.status == ingot_runtime::record::StateStatus::Running
                || st.status == ingot_runtime::record::StateStatus::Paused
            {
                let short = &record.id[..12.min(record.id.len())];
                // Persisted restart intent survives the daemon (unless-stopped
                // means "keep running across reboots until explicitly stopped").
                let policy = record.hostconfig.RestartPolicy.Name.as_str();
                if matches!(policy, "always" | "unless-stopped") {
                    tracing::warn!(
                        "reconcile: restarting supervised container {short} (policy {policy})"
                    );
                    st.status = ingot_runtime::record::StateStatus::Exited;
                    st.exit_code = 255;
                    st.finished_at = ingot_util::now_rfc3339();
                    st.pid = 0;
                    let _ = ingot_store::write_json_atomic(&state_path, &st);
                    let _ = ingot_runtime::manager::cleanup_runtime_state(paths, &record.id);
                    if let Err(e) = containers.start(&record.id).await {
                        tracing::warn!("reconcile: restart of {short} failed: {e:#}");
                    }
                    continue;
                }
                tracing::warn!("reconcile: container {short} was running at boot — marking exited");
                st.status = ingot_runtime::record::StateStatus::Exited;
                st.exit_code = 255;
                st.finished_at = ingot_util::now_rfc3339();
                st.pid = 0;
                let _ = ingot_store::write_json_atomic(&state_path, &st);
                // Runtime state only: the record stays so the container
                // shows up Exited (docker semantics across restarts).
                let _ = ingot_runtime::manager::cleanup_runtime_state(paths, &record.id);
            }
        }
    }
}

/// Boot-leak audit (Plan Phase 2, unit 2.7): after reconcile, no live
/// container exists, so any overlay mount under our overlay root or any
/// leftover `ingot.slice/<id>` cgroup is stale. Detach-unmount stale
/// mounts, drop empty stale cgroups, and warn with counts.
fn audit_boot_leaks(paths: &DataPaths) {
    let overlay_root = paths.overlay();
    let mut stale_mounts = 0;
    let mut unmounted = 0;
    if let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") {
        for line in mountinfo.lines() {
            // mount point is field 5 (after " - " separator accounting:
            // fields are id parent maj:min root mountpoint opts...).
            let pre = line.split(" - ").next().unwrap_or("");
            let mountpoint = pre.split_whitespace().nth(4).unwrap_or("");
            if !mountpoint.is_empty() && std::path::Path::new(mountpoint).starts_with(&overlay_root)
            {
                stale_mounts += 1;
                let cpoint = std::ffi::CString::new(mountpoint.as_bytes().to_vec()).unwrap();
                let rc = unsafe { libc::umount2(cpoint.as_ptr(), libc::MNT_DETACH) };
                if rc == 0 {
                    unmounted += 1;
                }
            }
        }
    }
    if stale_mounts > 0 {
        tracing::warn!(
            "boot audit: found {stale_mounts} stale overlay mount(s), detached {unmounted}"
        );
    }
    let slice = std::path::Path::new("/sys/fs/cgroup/ingot.slice");
    let mut stale_cgroups = 0;
    if let Ok(rd) = std::fs::read_dir(slice) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stale_cgroups += 1;
                // Succeeds only when the cgroup is drained; anything live
                // is left alone and reported.
                let _ = std::fs::remove_dir(&p);
            }
        }
    }
    if stale_cgroups > 0 {
        let remaining = std::fs::read_dir(slice).map(|r| r.count()).unwrap_or(0);
        tracing::warn!("boot audit: found {stale_cgroups} stale cgroup(s), {remaining} remaining");
    }
    sweep_builder_scratch(paths);
}

/// Boot sweep for builder scratch: a SIGTERM/SIGKILL mid-build (or a
/// step failure before cleanup) strands `builder/steps/<id>` work roots
/// — which may hold bind-mounted secret files — and `build_contexts`
/// uploads. No live build exists at boot, so detach any mounts beneath
/// each entry and remove it. Best-effort: failures only warn.
fn sweep_builder_scratch(paths: &DataPaths) {
    for root in [paths.builder().join("steps"), paths.build_contexts()] {
        let Ok(rd) = std::fs::read_dir(&root) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if let Ok(mountinfo) = std::fs::read_to_string("/proc/self/mountinfo") {
                for line in mountinfo.lines() {
                    let pre = line.split(" - ").next().unwrap_or("");
                    let mountpoint = pre.split_whitespace().nth(4).unwrap_or("");
                    if !mountpoint.is_empty() && std::path::Path::new(mountpoint).starts_with(&p) {
                        let cpoint =
                            std::ffi::CString::new(mountpoint.as_bytes().to_vec()).unwrap();
                        unsafe {
                            libc::umount2(cpoint.as_ptr(), libc::MNT_DETACH);
                        }
                    }
                }
            }
            if std::fs::remove_dir_all(&p).is_ok() {
                tracing::warn!("boot audit: removed stale builder scratch {}", p.display());
            }
        }
    }
}

fn check_binary(bin: &str) -> Result<()> {
    let paths = std::env::var_os("PATH").unwrap_or_default();
    for p in std::env::split_paths(&paths) {
        let cand = p.join(bin);
        if cand.is_file() {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = cand.metadata() {
                if meta.permissions().mode() & 0o111 != 0 {
                    return Ok(());
                }
            }
        }
    }
    anyhow::bail!("required host utility '{bin}' not found in PATH");
}

fn check_environment(paths: &DataPaths) -> Result<()> {
    if std::fs::metadata("/sys/fs/cgroup").is_err() {
        anyhow::bail!("/sys/fs/cgroup is not mounted; cannot manage containers");
    }
    let cgroup_v2 = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers")
        .map(|s| !s.trim().is_empty())
        .unwrap_or(false);
    if !cgroup_v2 {
        anyhow::bail!(
            "cgroup v2 is required but not available on /sys/fs/cgroup \
             (Ingot requires cgroup v2 unified hierarchy)"
        );
    }

    for bin in ["ip", "iptables", "modprobe"] {
        check_binary(bin)?;
    }

    if !overlay_works() {
        anyhow::bail!(
            "overlayfs test mount failed; the kernel overlay module is required \
             (try: modprobe overlay)"
        );
    }
    let _ = paths;
    Ok(())
}

/// Verify overlayfs by actually mounting one in a throwaway dir — the module
/// may need loading first (it does not appear in /proc/filesystems unloaded).
fn overlay_works() -> bool {
    let tmp = std::env::temp_dir().join(format!("ingot-overlay-check-{}", std::process::id()));
    for sub in ["lower", "upper", "work", "merged"] {
        let _ = std::fs::create_dir_all(tmp.join(sub));
    }
    let ok = try_overlay_mount(&tmp);
    let _ = nix::mount::umount2(&tmp.join("merged"), nix::mount::MntFlags::MNT_DETACH);
    let _ = std::fs::remove_dir_all(&tmp);
    ok
}

fn try_overlay_mount(tmp: &std::path::Path) -> bool {
    let opts = format!(
        "lowerdir={},upperdir={},workdir={}",
        tmp.join("lower").display(),
        tmp.join("upper").display(),
        tmp.join("work").display()
    );
    let mount_overlay = |data: &str| unsafe {
        let null = std::ffi::CString::new("").unwrap();
        let fs = std::ffi::CString::new("overlay").unwrap();
        let dir =
            std::ffi::CString::new(tmp.join("merged").as_os_str().as_encoded_bytes().to_vec())
                .unwrap();
        let data = std::ffi::CString::new(data).unwrap();
        libc::mount(
            null.as_ptr(),
            dir.as_ptr(),
            fs.as_ptr(),
            libc::MS_NOSUID,
            data.as_ptr() as *const libc::c_void,
        )
    };
    if mount_overlay(&opts) == 0 {
        return true;
    }
    // Try to autoload the module, retry once.
    let _ = std::process::Command::new("modprobe")
        .arg("overlay")
        .status();
    mount_overlay(&opts) == 0
}
