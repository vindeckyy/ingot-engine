//! `/_ping`, `/version`, `/info`, `/events`, `/system/df`.

use crate::state::SharedState;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use ingot_api::{Info, Version, VersionComponent, VersionPlatform};

pub async fn ping() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert("Api-Version", ingot_api::API_VERSION.parse().unwrap());
    headers.insert("MinAPIVersion", ingot_api::MIN_API_VERSION.parse().unwrap());
    headers.insert("Docker-Experimental", "false".parse().unwrap());
    headers.insert("Ostype", "linux".parse().unwrap());
    headers.insert("Builder-Version", "1".parse().unwrap());
    headers.insert("Swarm", "inactive".parse().unwrap());
    headers.insert(header::CACHE_CONTROL, "no-cache".parse().unwrap());
    headers.insert(header::PRAGMA, "no-cache".parse().unwrap());
    (StatusCode::OK, headers, "OK").into_response()
}

pub async fn version(State(_state): State<SharedState>) -> Response {
    let uname = uname_info();
    let v = Version {
        Platform: VersionPlatform {
            Name: format!("Ingot Engine ({} {})", uname.0, uname.2),
        },
        Version: ingot_api::ENGINE_VERSION.into(),
        ApiVersion: ingot_api::API_VERSION.into(),
        MinAPIVersion: ingot_api::MIN_API_VERSION.into(),
        GitCommit: ingot_api::GIT_COMMIT.into(),
        GoVersion: "rustc".into(),
        Os: "linux".into(),
        Arch: std::env::consts::ARCH.into(),
        KernelVersion: uname.2.clone(),
        BuildTime: ingot_api::BUILD_TIME.into(),
        Components: Some(vec![VersionComponent {
            Name: "Engine".into(),
            Version: ingot_api::ENGINE_VERSION.into(),
            Details: Some(
                [
                    ("ApiVersion".to_string(), ingot_api::API_VERSION.to_string()),
                    (
                        "MinAPIVersion".to_string(),
                        ingot_api::MIN_API_VERSION.to_string(),
                    ),
                    ("Arch".to_string(), std::env::consts::ARCH.to_string()),
                    ("Os".to_string(), "linux".to_string()),
                    ("Experimental".to_string(), "false".to_string()),
                    ("GitCommit".to_string(), ingot_api::GIT_COMMIT.to_string()),
                    ("GoVersion".to_string(), "rustc".to_string()),
                    ("KernelVersion".to_string(), uname.2.clone()),
                    ("BuildTime".to_string(), ingot_api::BUILD_TIME.to_string()),
                ]
                .into_iter()
                .collect(),
            ),
        }]),
    };
    axum::Json(v).into_response()
}

#[derive(Clone)]
struct HostCapabilities {
    cgroup_v2: bool,
    memory_limit: bool,
    swap_limit: bool,
    kernel_memory_tcp: bool,
    cpu_cfs_period: bool,
    cpu_cfs_quota: bool,
    cpu_shares: bool,
    cpuset: bool,
    pids_limit: bool,
    oom_kill_disable: bool,
    ipv4_forwarding: bool,
    bridge_nf_iptables: bool,
    bridge_nf_ip6tables: bool,
    security_options: Vec<String>,
    warnings: Vec<String>,
}

static HOST_CAPS_CACHE: std::sync::OnceLock<
    std::sync::Mutex<(std::time::Instant, HostCapabilities)>,
> = std::sync::OnceLock::new();

fn cached_host_capabilities() -> HostCapabilities {
    let cell = HOST_CAPS_CACHE.get_or_init(|| {
        std::sync::Mutex::new((
            std::time::Instant::now() - std::time::Duration::from_secs(10),
            host_caps_inner(),
        ))
    });
    {
        let guard = cell.lock().unwrap();
        if guard.0.elapsed() < std::time::Duration::from_secs(5) {
            return guard.1.clone();
        }
    }
    let fresh = host_caps_inner();
    *cell.lock().unwrap() = (std::time::Instant::now(), fresh.clone());
    fresh
}

fn detect_host_capabilities() -> HostCapabilities {
    cached_host_capabilities()
}

fn host_caps_inner() -> HostCapabilities {
    let controllers =
        std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").unwrap_or_default();
    let controller_list: Vec<&str> = controllers.split_whitespace().collect();
    let cgroup_v2 = !controllers.is_empty();

    let has_memory = controller_list.contains(&"memory");
    let has_cpu = controller_list.contains(&"cpu");
    let has_cpuset = controller_list.contains(&"cpuset");
    let has_pids = controller_list.contains(&"pids");

    let swap_limit = has_memory && std::path::Path::new("/sys/fs/cgroup/memory.swap.max").exists();

    // IPv4 forwarding
    let ipv4_forwarding = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|s| s.trim() == "1")
        .unwrap_or(false);

    // Bridge netfilter iptables calls
    let bridge_nf_iptables =
        std::fs::read_to_string("/proc/sys/net/bridge/bridge-nf-call-iptables")
            .map(|s| s.trim() == "1")
            .unwrap_or(false);

    let bridge_nf_ip6tables =
        std::fs::read_to_string("/proc/sys/net/bridge/bridge-nf-call-ip6tables")
            .map(|s| s.trim() == "1")
            .unwrap_or(false);

    let mut warnings = Vec::new();
    if !ipv4_forwarding {
        warnings.push("WARNING: IPv4 forwarding is disabled".into());
    }
    if !bridge_nf_iptables {
        warnings.push("WARNING: bridge-nf-call-iptables is disabled".into());
    }
    if !bridge_nf_ip6tables {
        warnings.push("WARNING: bridge-nf-call-ip6tables is disabled".into());
    }
    if !cgroup_v2 {
        warnings.push("WARNING: cgroup v2 is not mounted or available".into());
    }

    // Security options: default seccomp profile is enforced
    let security_options = vec!["name=seccomp,profile=default".into()];

    HostCapabilities {
        cgroup_v2,
        memory_limit: has_memory,
        swap_limit,
        kernel_memory_tcp: has_memory,
        cpu_cfs_period: has_cpu,
        cpu_cfs_quota: has_cpu,
        cpu_shares: has_cpu,
        cpuset: has_cpuset,
        pids_limit: has_pids,
        oom_kill_disable: false,
        ipv4_forwarding,
        bridge_nf_iptables,
        bridge_nf_ip6tables,
        security_options,
        warnings,
    }
}

pub async fn info(State(state): State<SharedState>) -> Response {
    let uname = uname_info();
    let (nproc, memtotal) = sys_info();
    let caps = detect_host_capabilities();
    let (n_containers, n_running, n_paused, n_images) = census(&state).await;
    let info = Info {
        ID: daemon_id(&state),
        Containers: n_containers,
        ContainersRunning: n_running,
        ContainersPaused: n_paused,
        ContainersStopped: n_containers - n_running - n_paused,
        Images: n_images,
        Driver: "overlay2".into(),
        DriverStatus: vec![
            vec!["Backing Filesystem".into(), "extfs".into()],
            vec!["Supports d_type".into(), "true".into()],
        ],
        DockerRootDir: state.paths.root.display().to_string(),
        MemoryLimit: caps.memory_limit,
        SwapLimit: caps.swap_limit,
        KernelMemoryTCP: caps.kernel_memory_tcp,
        CpuCfsPeriod: caps.cpu_cfs_period,
        CpuCfsQuota: caps.cpu_cfs_quota,
        CPUShares: caps.cpu_shares,
        CPUSet: caps.cpuset,
        PidsLimit: caps.pids_limit,
        OomKillDisable: caps.oom_kill_disable,
        IPv4Forwarding: caps.ipv4_forwarding,
        BridgeNfIptables: caps.bridge_nf_iptables,
        BridgeNfIp6tables: caps.bridge_nf_ip6tables,
        Debug: state.config.debug,
        NFd: 0,
        NGoroutines: 0,
        LoggingDriver: "json-file".into(),
        CgroupDriver: "cgroupfs".into(),
        CgroupVersion: if caps.cgroup_v2 {
            "2".into()
        } else {
            "1".into()
        },
        NEventsListener: state
            .event_listeners
            .load(std::sync::atomic::Ordering::Relaxed),
        KernelVersion: uname.2,
        OperatingSystem: uname.0,
        OSVersion: uname.1,
        OSType: "linux".into(),
        Architecture: std::env::consts::ARCH.into(),
        NCPU: nproc,
        MemTotal: memtotal,
        IndexServerAddress: "https://index.docker.io/v1/".into(),
        Name: hostname(),
        ServerVersion: ingot_api::ENGINE_VERSION.into(),
        Labels: vec![],
        ExperimentalBuild: false,
        RuntimesMap: serde_json::json!({"ingot": {"path": "ingot"}}),
        DefaultRuntime: "ingot".into(),
        SecurityOptions: caps.security_options,
        CDISpecDirs: vec![],
        Warnings: caps.warnings,
    };
    axum::Json(info).into_response()
}

/// Recursive directory size in bytes (symlinks not followed).
fn dir_size(path: &std::path::Path) -> i64 {
    let mut total: i64 = 0;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&p) else {
                continue;
            };
            if meta.is_dir() && !meta.file_type().is_symlink() {
                stack.push(p);
            } else if meta.is_file() {
                total = total.saturating_add(meta.len() as i64);
            }
        }
    }
    total
}

/// Builder-cache rollup for /system/df: entry count, bytes still on
/// disk (blobs referenced by live entries), and how many entries root
/// layers still referenced by an image (the rest is all reclaimable).
fn build_cache_summary(
    state: &SharedState,
    images: &[ingot_image::ImageRecord],
) -> serde_json::Value {
    use serde_json::json;
    let empty =
        || json!({"Type": "regular", "TotalCount": 0, "Size": 0, "InUse": 0, "Shareable": 0});
    let data = match std::fs::read(state.paths.build_cache()) {
        Ok(d) => d,
        Err(_) => return empty(),
    };
    let entries: std::collections::HashMap<String, serde_json::Value> =
        serde_json::from_slice(&data).unwrap_or_default();
    if entries.is_empty() {
        return empty();
    }
    let used_layers: std::collections::HashSet<&str> = images
        .iter()
        .flat_map(|r| r.diff_ids.iter().map(String::as_str))
        .collect();
    let mut size: i64 = 0;
    let mut in_use: i64 = 0;
    for e in entries.values() {
        let diff = e.get("diff_id").and_then(|v| v.as_str()).unwrap_or("");
        let blob = e
            .get("blob_digest")
            .and_then(|v| v.as_str())
            .unwrap_or(diff);
        if !blob.is_empty() {
            size += std::fs::metadata(state.paths.blob(blob))
                .map(|m| m.len() as i64)
                .unwrap_or(0);
        }
        if used_layers.contains(diff) {
            in_use += 1;
        }
    }
    json!({
        "Type": "regular",
        "TotalCount": entries.len(),
        "Size": size,
        "InUse": in_use,
        "Shareable": size,
    })
}

/// GET /system/df — real disk-usage accounting (Plan Phase 1, unit 1.5).
/// `SizeRw` is the container writable-layer (overlay diff) size;
/// `SizeRootFs` approximates writable + image size. BuildCache carries
/// the builder-cache rollup (Plan Phase 5, unit 5.4).
pub async fn df(State(state): State<SharedState>) -> Response {
    use serde_json::json;
    let images = state.images.list_effective().await.unwrap_or_default();
    let containers = match state.containers.as_ref() {
        Some(m) => m.list_records().await,
        None => Vec::new(),
    };
    let usage: std::collections::HashMap<String, i64> = {
        let mut m = std::collections::HashMap::new();
        for c in &containers {
            *m.entry(c.image_id.trim_start_matches("sha256:").to_string())
                .or_default() += 1;
        }
        m
    };
    let image_items: Vec<serde_json::Value> = images
        .iter()
        .map(|r| {
            json!({
                "Id": format!("sha256:{}", r.id),
                "RepoTags": r.repo_tags,
                "RepoDigests": r.repo_digests,
                "Created": r.created_unix,
                "Size": r.size,
                "SharedSize": -1,
                "Containers": usage.get(&r.id).copied().unwrap_or(0),
            })
        })
        .collect();
    let container_items: Vec<serde_json::Value> = containers
        .iter()
        .map(|c| {
            let size_rw = dir_size(&state.paths.overlay_diff(&c.id));
            let img_size = images
                .iter()
                .find(|i| i.id == c.image_id.trim_start_matches("sha256:"))
                .map(|i| i.size)
                .unwrap_or(0);
            json!({
                "Id": c.id,
                "Names": [format!("/{}", c.name)],
                "Image": c.image_name,
                "ImageID": c.image_id,
                "Command": c.cmd_display,
                "Created": chrono::DateTime::parse_from_rfc3339(&c.created)
                    .map(|d| d.timestamp())
                    .unwrap_or(0),
                "State": "created",
                "Status": "",
                "SizeRw": size_rw,
                "SizeRootFs": size_rw.saturating_add(img_size),
            })
        })
        .collect();
    let volume_items: Vec<serde_json::Value> = match state.volumes.as_ref() {
        Some(vm) => vm
            .list()
            .unwrap_or_default()
            .into_iter()
            .map(|v| {
                let dir = state.paths.volumes().join(&v.Name);
                let refs = containers
                    .iter()
                    .flat_map(|c| c.mounts.iter())
                    .filter(|m| m.name == v.Name || m.source == dir.to_string_lossy())
                    .count() as i64;
                json!({
                    "Name": v.Name,
                    "Driver": "local",
                    "Mountpoint": dir,
                    "Labels": v.Labels,
                    "Scope": "local",
                    "Options": {},
                    "UsageData": {"Size": dir_size(&dir), "RefCount": refs},
                })
            })
            .collect(),
        None => Vec::new(),
    };
    let layers_size: i64 = images.iter().map(|r| r.size).sum();
    let cache = build_cache_summary(&state, &images);
    axum::Json(ingot_api::SystemDFResponse {
        LayersSize: Some(layers_size),
        Images: Some(image_items),
        Containers: Some(container_items),
        Volumes: Some(volume_items),
        BuildCache: Some(vec![cache]),
    })
    .into_response()
}

/// Live container/image census for `/info` (Plan Phase 1, unit 1.5).
/// States come from live handles when present, else the persisted state
/// file — the same source the list endpoint reads.
async fn census(state: &SharedState) -> (i64, i64, i64, i64) {
    let mut total = 0i64;
    let mut running = 0i64;
    let mut paused = 0i64;
    if let Some(mgr) = state.containers.as_ref() {
        for record in mgr.list_records().await {
            total += 1;
            let status = if let Ok(Some(h)) = mgr.get(&record.id).await {
                h.state.lock().unwrap().status
            } else {
                ingot_store::read_json(&state.paths.container_state(&record.id))
                    .map(|st: ingot_runtime::record::ContainerState| st.status)
                    .unwrap_or(ingot_runtime::record::StateStatus::Exited)
            };
            match status {
                ingot_runtime::record::StateStatus::Running => running += 1,
                ingot_runtime::record::StateStatus::Paused => paused += 1,
                _ => {}
            }
        }
    }
    let images = state
        .images
        .list()
        .await
        .map(|v| v.len() as i64)
        .unwrap_or(0);
    (total, running, paused, images)
}

fn daemon_id(state: &SharedState) -> String {
    use std::sync::OnceLock;
    static CACHED: OnceLock<String> = OnceLock::new();
    if let Some(id) = CACHED.get() {
        return id.clone();
    }
    // Stable per data-root id.
    let path = state.paths.root.join("engine-id");
    if let Ok(id) = std::fs::read_to_string(&path) {
        let id = id.trim().to_string();
        let _ = CACHED.set(id.clone());
        return id;
    }
    let id = ingot_util::new_id();
    let _ = std::fs::create_dir_all(&state.paths.root);
    let _ = std::fs::write(&path, &id);
    let _ = CACHED.set(id.clone());
    id
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "ingotd".into())
}

fn uname_info() -> (String, String, String) {
    // (OS name, version, kernel release)
    let mut utsname: libc::utsname = unsafe { std::mem::zeroed() };
    let _ = unsafe { libc::uname(&mut utsname) };
    let read = |f: &[i8]| {
        let bytes: Vec<u8> = f
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect();
        String::from_utf8_lossy(&bytes).to_string()
    };
    (
        read(&utsname.sysname),
        read(&utsname.version),
        read(&utsname.release),
    )
}

fn sys_info() -> (i64, i64) {
    let nproc = std::thread::available_parallelism()
        .map(|n| n.get() as i64)
        .unwrap_or(1);
    let memtotal = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|s| {
            s.lines().find_map(|l| {
                l.strip_prefix("MemTotal:").and_then(|rest| {
                    rest.trim()
                        .trim_end_matches(" kB")
                        .trim()
                        .parse::<i64>()
                        .ok()
                })
            })
        })
        .map(|kb| kb * 1024)
        .unwrap_or(0);
    (nproc, memtotal)
}

/// Allow Body::empty() usage elsewhere without dead-code warnings.
#[allow(dead_code)]
fn _touch(_b: &Body) {}
