//! ingotd — the Ingot daemon (dockerd equivalent).

use anyhow::{Context, Result};
use clap::Parser;
use ingot_server::{DaemonConfig, DaemonState};
use ingot_store::paths::DataPaths;
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
}

fn init_logging(debug: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
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
    paths.create_all().context("initialise data root")?;

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

    daemon.containers = Some(containers);
    let state = Arc::new(daemon);

    tracing::info!(
        "ingotd {} starting: data-root={} socket={}",
        ingot_api::ENGINE_VERSION,
        paths.root.display(),
        args.socket.display()
    );

    ingot_server::serve::serve(state, &args.socket).await
}

/// On boot, mark stale "running" containers as exited and clean their mounts.
async fn reconcile(paths: &DataPaths, containers: &Arc<ingot_runtime::ContainerManager>) {
    {
        for record in containers.list_records().await {
            let state_path = paths.container_state(&record.id);
            let Ok(raw) = std::fs::read(&state_path) else { continue };
            let Ok(mut st) = serde_json::from_slice::<ingot_runtime::record::ContainerState>(&raw)
            else {
                continue;
            };
            if st.status == ingot_runtime::record::StateStatus::Running
                || st.status == ingot_runtime::record::StateStatus::Paused
            {
                tracing::warn!("reconcile: container {} was running at boot — marking exited", &record.id[..12.min(record.id.len())]);
                st.status = ingot_runtime::record::StateStatus::Exited;
                st.exit_code = 255;
                st.finished_at = ingot_util::now_rfc3339();
                st.pid = 0;
                let _ = ingot_store::write_json_atomic(&state_path, &st);
                let _ = ingot_runtime::manager::cleanup_container(paths, &record.id);
            }
        }
    }
}

fn check_environment(paths: &DataPaths) -> Result<()> {
    let cgroup_v2 = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").is_ok();
    if !cgroup_v2 {
        tracing::warn!("cgroup v2 not detected — container resource limits will be unavailable");
    }
    if !overlay_works() {
        anyhow::bail!(
            "overlayfs test mount failed; the kernel overlay module is required \
             (try: modprobe overlay)"
        );
    }
    if std::fs::metadata("/sys/fs/cgroup").is_err() {
        anyhow::bail!("/sys/fs/cgroup is not mounted; cannot manage containers");
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
        let dir = std::ffi::CString::new(
            tmp.join("merged").as_os_str().as_encoded_bytes().to_vec(),
        )
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
    let _ = std::process::Command::new("modprobe").arg("overlay").status();
    mount_overlay(&opts) == 0
}
