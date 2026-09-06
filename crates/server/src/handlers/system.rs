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
        Platform: VersionPlatform { Name: format!("Ingot Engine ({} {})", uname.0, uname.2) },
        Version: ingot_api::ENGINE_VERSION.into(),
        ApiVersion: ingot_api::API_VERSION.into(),
        MinAPIVersion: ingot_api::MIN_API_VERSION.into(),
        GitCommit: "dev".into(),
        GoVersion: "rustc-1.96".into(),
        Os: "linux".into(),
        Arch: std::env::consts::ARCH.into(),
        KernelVersion: uname.2.clone(),
        BuildTime: chrono::Utc::now().to_rfc3339(),
        Components: Some(vec![VersionComponent {
            Name: "Engine".into(),
            Version: ingot_api::ENGINE_VERSION.into(),
            Details: Some([
                ("ApiVersion".to_string(), ingot_api::API_VERSION.to_string()),
                ("MinAPIVersion".to_string(), ingot_api::MIN_API_VERSION.to_string()),
                ("Arch".to_string(), std::env::consts::ARCH.to_string()),
                ("Os".to_string(), "linux".to_string()),
                ("Experimental".to_string(), "false".to_string()),
                ("GitCommit".to_string(), "dev".to_string()),
                ("GoVersion".to_string(), "rustc".to_string()),
                ("KernelVersion".to_string(), uname.2.clone()),
                ("BuildTime".to_string(), chrono::Utc::now().to_rfc3339()),
            ].into_iter().collect()),
        }]),
    };
    axum::Json(v).into_response()
}

pub async fn info(State(state): State<SharedState>) -> Response {
    let uname = uname_info();
    let (nproc, memtotal) = sys_info();
    let cgroup_v2 = std::fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").is_ok();
    let info = Info {
        ID: daemon_id(&state),
        Containers: 0,
        ContainersRunning: 0,
        ContainersPaused: 0,
        ContainersStopped: 0,
        Images: 0,
        Driver: "overlay2".into(),
        DriverStatus: vec![
            vec!["Backing Filesystem".into(), "extfs".into()],
            vec!["Supports d_type".into(), "true".into()],
        ],
        DockerRootDir: state.paths.root.display().to_string(),
        MemoryLimit: true,
        SwapLimit: true,
        KernelMemoryTCP: true,
        CpuCfsPeriod: true,
        CpuCfsQuota: true,
        CPUShares: true,
        CPUSet: true,
        PidsLimit: true,
        OomKillDisable: true,
        IPv4Forwarding: true,
        BridgeNfIptables: true,
        BridgeNfIp6tables: true,
        Debug: state.config.debug,
        NFd: 0,
        NGoroutines: 0,
        LoggingDriver: "json-file".into(),
        CgroupDriver: "cgroupfs".into(),
        CgroupVersion: if cgroup_v2 { "2".into() } else { "1".into() },
        NEventsListener: state.event_listeners.load(std::sync::atomic::Ordering::Relaxed),
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
        SecurityOptions: vec!["name=seccomp,profile=default".into()],
        CDISpecDirs: vec![],
        Warnings: vec![],
    };
    axum::Json(info).into_response()
}

fn daemon_id(state: &SharedState) -> String {
    // Stable per data-root id.
    let path = state.paths.root.join("engine-id");
    if let Ok(id) = std::fs::read_to_string(&path) {
        return id.trim().to_string();
    }
    let id = ingot_util::new_id();
    let _ = std::fs::create_dir_all(&state.paths.root);
    let _ = std::fs::write(&path, &id);
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
        let bytes: Vec<u8> = f.iter().take_while(|&&c| c != 0).map(|&c| c as u8).collect();
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
                l.strip_prefix("MemTotal:")
                    .map(|rest| rest.trim().trim_end_matches(" kB").trim().parse::<i64>().ok())
                    .flatten()
            })
        })
        .map(|kb| kb * 1024)
        .unwrap_or(0);
    (nproc, memtotal)
}

/// Allow Body::empty() usage elsewhere without dead-code warnings.
#[allow(dead_code)]
fn _touch(_b: &Body) {}
