//! Create-time validation and typed errors (Plan Phase 1, unit 1.1).
//!
//! Every option the Engine API accepts is either enforced by the runtime
//! or rejected here with a precise error — never silently ignored. The
//! server maps each variant to its HTTP status (see the taxonomy in
//! `ingot_server::handlers`).

use ingot_api::{ContainerCreateBody, HostConfig};

/// Typed container-create failure. The server maps variants to statuses:
/// `Conflict` → 409, `NotFound` → 404, `BadRequest`/`Unsupported` → 400,
/// `Internal` → 500.
#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("Conflict. The container name \"/{0}\" is already in use")]
    Conflict(String),
    #[error("No such image: {0}")]
    NotFound(String),
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("{0}")]
    Internal(#[from] anyhow::Error),
    #[error("daemon storage error: {0}")]
    Io(#[from] std::io::Error),
}

impl CreateError {
    pub fn bad(op: impl std::fmt::Display, why: impl std::fmt::Display) -> Self {
        CreateError::BadRequest(format!("invalid {op}: {why}"))
    }

    pub fn unsupported(what: impl std::fmt::Display) -> Self {
        CreateError::Unsupported(format!(
            "{what} is not supported by ingot yet (see `ingot` docs for the supported subset)"
        ))
    }
}

/// Docker container-name rules: `/` prefix optional, then
/// `[a-zA-Z0-9][a-zA-Z0-9_.-]*`.
pub fn valid_name(name: &str) -> bool {
    ingot_util::validate_container_name(name).is_ok()
}

/// Validate everything checkable before allocating container state.
/// Image existence and name-taken races are checked by the caller
/// (they need the store); pure option validation lives here so it is
/// unit-testable without root (Tier 1).
pub fn validate_create(
    body: &ContainerCreateBody,
    name: Option<&str>,
    platform: Option<&str>,
) -> Result<(), CreateError> {
    if let Some(p) = platform {
        let p_clean = p.trim().to_lowercase();
        if !p_clean.is_empty() && p_clean != "linux/amd64" && p_clean != "linux" {
            return Err(CreateError::bad(
                "platform",
                format!("unsupported platform {p:?}; only linux/amd64 is supported"),
            ));
        }
    }
    if let Some(n) = name {
        if !valid_name(n) {
            return Err(CreateError::bad(
                "container name",
                format!("{n:?} must match /?[a-zA-Z0-9][a-zA-Z0-9_.-]*"),
            ));
        }
    }
    if body.Image.trim().is_empty() {
        return Err(CreateError::bad("image", "no command specified"));
    }
    validate_hostconfig(&body.HostConfig)?;
    validate_networking_config(body)?;
    validate_config(body)?;
    Ok(())
}

/// NetworkingConfig validation (Plan Phase 6.3): create-time static IPs
/// must parse as IPv4 (fail at create, not at first start), and the
/// none/host modes cannot carry endpoints.
fn validate_networking_config(body: &ContainerCreateBody) -> Result<(), CreateError> {
    let Some(nc) = body.NetworkingConfig.as_ref() else {
        return Ok(());
    };
    if nc.EndpointsConfig.is_empty() {
        return Ok(());
    }
    let mode = body.HostConfig.NetworkMode.as_str();
    if mode == "none" || mode == "host" {
        return Err(CreateError::bad(
            "networking config",
            format!("network mode {mode:?} cannot have endpoints"),
        ));
    }
    for (net, ep) in &nc.EndpointsConfig {
        if let Some(ipam) = ep.IPAMConfig.as_ref() {
            if !ipam.IPv4Address.is_empty()
                && ipam.IPv4Address.parse::<std::net::Ipv4Addr>().is_err()
            {
                return Err(CreateError::bad(
                    "IPAMConfig.IPv4Address",
                    format!(
                        "{:?} on network {net:?} is not an IPv4 address",
                        ipam.IPv4Address
                    ),
                ));
            }
        }
    }
    Ok(())
}

/// Split a `"port[/proto]"` key for exposed-port validation. Returns the
/// (port, proto) with the docker default proto.
fn split_exposed_key(k: &str) -> Option<(u16, &str)> {
    let (port_str, proto) = match k.split_once('/') {
        Some((p, t)) => (p, t),
        None => (k, "tcp"),
    };
    if proto != "tcp" && proto != "udp" {
        return None;
    }
    port_str
        .parse::<u16>()
        .ok()
        .filter(|p| *p != 0)
        .map(|p| (p, proto))
}

/// Create-body validation, unit 2.1: user/workdir shape, stop
/// signal/timeout ranges, port bindings, binds/mounts, DNS/hosts.
fn validate_config(body: &ContainerCreateBody) -> Result<(), CreateError> {
    if body.User.contains('\0') {
        return Err(CreateError::bad("user", "must not contain NUL bytes"));
    }
    if !body.WorkingDir.is_empty() && !body.WorkingDir.starts_with('/') {
        return Err(CreateError::bad(
            "working directory",
            format!("{:?} must be an absolute path", body.WorkingDir),
        ));
    }
    if !body.StopSignal.is_empty() && !valid_signal(&body.StopSignal) {
        return Err(CreateError::bad(
            "stop signal",
            format!("{:?} is not a known signal name or number", body.StopSignal),
        ));
    }
    if let Some(t) = body.StopTimeout {
        if t < 0 {
            return Err(CreateError::bad("stop timeout", "must not be negative"));
        }
    }
    validate_ports(&body.HostConfig)?;
    validate_binds(&body.HostConfig)?;
    validate_mounts(&body.HostConfig)?;
    validate_net_opts(&body.HostConfig)?;
    if let Some(exposed) = body.ExposedPorts.as_ref() {
        for k in exposed.keys() {
            if split_exposed_key(k).is_none() {
                return Err(CreateError::bad(
                    "exposed ports",
                    format!("{k:?} is not a port[/tcp|/udp]"),
                ));
            }
        }
    }
    if !body.Domainname.is_empty() {
        return Err(CreateError::unsupported("Domainname"));
    }
    if body.ArgsEscaped {
        return Err(CreateError::unsupported("ArgsEscaped"));
    }
    if body.OnBuild.as_ref().is_some_and(|v| !v.is_empty()) {
        return Err(CreateError::unsupported("OnBuild"));
    }
    if body.Shell.as_ref().is_some_and(|v| !v.is_empty()) {
        return Err(CreateError::unsupported("Shell"));
    }
    Ok(())
}

/// Ulimit resource names the daemon enforces (Plan Phase 3, unit 3.4).
/// Anything else is an explicit 400, never a silent ignore.
pub const SUPPORTED_RLIMITS: &[&str] = &["core", "nofile", "nproc", "stack", "as", "memlock"];

/// Parse `HostConfig.Ulimits` (`[{Name, Soft, Hard}]`, `-1` = unlimited).
pub fn parse_ulimits(hc: &HostConfig) -> Result<Vec<(String, i64, i64)>, CreateError> {
    let mut out = Vec::with_capacity(hc.Ulimits.len());
    for v in &hc.Ulimits {
        let name = v
            .get("Name")
            .or_else(|| v.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("");
        if !SUPPORTED_RLIMITS.contains(&name) {
            return Err(CreateError::unsupported(format!("ulimit {name:?}")));
        }
        let num = |k: &str| {
            v.get(k).and_then(|x| x.as_i64()).ok_or_else(|| {
                CreateError::bad("ulimit", format!("{name}: {k} must be an integer"))
            })
        };
        let soft = num("Soft")?;
        let hard = num("Hard")?;
        if soft < -1 || hard < -1 {
            return Err(CreateError::bad(
                "ulimit",
                format!("{name}: values must be >= -1 (-1 = unlimited)"),
            ));
        }
        if hard != -1 && soft > hard {
            return Err(CreateError::bad(
                "ulimit",
                format!("{name}: soft limit exceeds hard limit"),
            ));
        }
        out.push((name.to_string(), soft, hard));
    }
    Ok(out)
}

fn valid_signal(s: &str) -> bool {
    parse_signal(s).is_ok()
}

/// Parse a Docker-style signal: number 1-64, short name, or SIG-prefixed
/// name (Plan Phase 2, unit 2.2). Used for `kill ?signal=` and
/// `stop ?signal=`; unknown values are 400s, never silent SIGTERM.
pub fn parse_signal(s: &str) -> Result<i32, String> {
    if let Ok(n) = s.trim().parse::<i32>() {
        if (1..=64).contains(&n) {
            return Ok(n);
        }
        return Err(format!("signal number {n} out of range 1-64"));
    }
    let upper = s.trim().to_uppercase();
    let name = upper.strip_prefix("SIG").unwrap_or(&upper);
    // Linux signal numbers (asm-generic).
    let num = match name {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "ILL" => 4,
        "TRAP" => 5,
        "ABRT" => 6,
        "BUS" => 7,
        "FPE" => 8,
        "KILL" => 9,
        "USR1" => 10,
        "SEGV" => 11,
        "USR2" => 12,
        "PIPE" => 13,
        "ALRM" => 14,
        "TERM" => 15,
        "STKFLT" => 16,
        "CHLD" => 17,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "TTIN" => 21,
        "TTOU" => 22,
        "URG" => 23,
        "XCPU" => 24,
        "XFSZ" => 25,
        "VTALRM" => 26,
        "PROF" => 27,
        "WINCH" => 28,
        "IO" => 29,
        "PWR" => 30,
        "SYS" => 31,
        _ => return Err(format!("unknown signal {s:?}")),
    };
    Ok(num)
}

fn valid_port(p: &str) -> bool {
    p.parse::<u16>().is_ok_and(|n| n > 0)
}

fn validate_ports(hc: &HostConfig) -> Result<(), CreateError> {
    for (key, bindings) in &hc.PortBindings {
        let (port, proto) = match key.split_once('/') {
            Some((p, t)) => (p, t),
            None => (key.as_str(), "tcp"),
        };
        if !valid_port(port) {
            return Err(CreateError::bad(
                "port binding",
                format!("{key:?} is not port[/proto]"),
            ));
        }
        // The userland proxy relays TCP and UDP only: accepting sctp
        // would silently mistarget it as TCP (Plan Phase 6.4).
        if !matches!(proto, "tcp" | "udp") {
            return Err(CreateError::bad(
                "port binding",
                format!("protocol {proto:?} must be tcp or udp"),
            ));
        }
        for b in bindings {
            if !b.HostPort.is_empty() && !valid_port(&b.HostPort) {
                return Err(CreateError::bad(
                    "port binding",
                    format!("host port {:?} out of range 1-65535", b.HostPort),
                ));
            }
            if !b.HostIp.is_empty() {
                match b.HostIp.parse::<std::net::IpAddr>() {
                    Ok(std::net::IpAddr::V4(_)) => {}
                    // Dual-stack-ready schema, v4-only dataplane: an
                    // explicit 400, never a silent no-publish.
                    Ok(_) => {
                        return Err(CreateError::bad(
                            "port binding",
                            format!(
                                "IPv6 address {:?} is not supported for publishing yet",
                                b.HostIp
                            ),
                        ));
                    }
                    Err(_) => {
                        return Err(CreateError::bad(
                            "port binding",
                            format!("host IP {:?} is not a valid IP address", b.HostIp),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_binds(hc: &HostConfig) -> Result<(), CreateError> {
    for bind in &hc.Binds {
        let parts: Vec<&str> = bind.split(':').collect();
        // Single segment = anonymous volume destination (e.g. `-v /data`).
        if parts.len() == 1 {
            let dst = parts[0];
            if !dst.starts_with('/') {
                return Err(CreateError::bad(
                    "bind",
                    format!("{bind:?} must be an absolute container path or src:dst[:ro|rw]"),
                ));
            }
            if dst.split('/').any(|p| p == "..") {
                return Err(CreateError::bad(
                    "bind",
                    format!("{bind:?} destination contains '..' traversal"),
                ));
            }
            continue;
        }
        if parts.len() > 3 || parts[1].is_empty() {
            return Err(CreateError::bad(
                "bind",
                format!("{bind:?} must be src:dst[:ro|rw]"),
            ));
        }
        let src = parts[0];
        let dst = parts[1];
        if !dst.starts_with('/') || dst.split('/').any(|p| p == "..") {
            return Err(CreateError::bad(
                "bind",
                format!("{bind:?} destination must be an absolute container path without '..'"),
            ));
        }
        // If src is a named volume (not an absolute path)
        if !src.starts_with('/') {
            if let Err(e) = ingot_util::validate_resource_name(src) {
                return Err(CreateError::bad("volume name", format!("{src:?}: {e}")));
            }
        }
        if parts.len() == 3 && !matches!(parts[2].to_lowercase().as_str(), "ro" | "rw") {
            return Err(CreateError::bad(
                "bind",
                format!("mode {:?} must be ro or rw", parts[2]),
            ));
        }
    }
    Ok(())
}

fn validate_mounts(hc: &HostConfig) -> Result<(), CreateError> {
    for m in &hc.Mounts {
        let typ = if m.typ.is_empty() {
            "volume"
        } else {
            m.typ.as_str()
        };
        if !matches!(typ, "bind" | "volume" | "tmpfs") {
            return Err(CreateError::unsupported(format!("mount type {typ:?}")));
        }
        if m.Target.is_empty()
            || !m.Target.starts_with('/')
            || m.Target.split('/').any(|p| p == "..")
        {
            return Err(CreateError::bad(
                "mount",
                "Target must be a non-empty absolute path without '..'",
            ));
        }
        if typ == "bind" && !m.Source.starts_with('/') {
            return Err(CreateError::bad(
                "mount",
                "bind Source must be an absolute host path",
            ));
        }
        if typ == "volume" && !m.Source.is_empty() && !m.Source.starts_with('/') {
            if let Err(e) = ingot_util::validate_resource_name(&m.Source) {
                return Err(CreateError::bad(
                    "volume name",
                    format!("{:?}: {e}", m.Source),
                ));
            }
        }
    }
    Ok(())
}

/// resolv.conf line safety: no whitespace or control characters (line
/// injection), printable ASCII, bounded length.
fn valid_resolv_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && s.bytes()
            .all(|b| b.is_ascii_graphic() && !b.is_ascii_whitespace())
}

fn validate_net_opts(hc: &HostConfig) -> Result<(), CreateError> {
    for dns in &hc.Dns {
        if dns.parse::<std::net::IpAddr>().is_err() {
            return Err(CreateError::bad(
                "DNS server",
                format!("{dns:?} is not a valid IP address"),
            ));
        }
    }
    // Search domains and resolver options render verbatim into
    // resolv.conf: reject anything that could break the line structure
    // (Plan Phase 6.5). Unknown-but-well-formed options pass through
    // like docker (glibc ignores what it doesn't know).
    for domain in &hc.DnsSearch {
        if !valid_resolv_token(domain) {
            return Err(CreateError::bad(
                "DNS search domain",
                format!("{domain:?} is not a valid search domain"),
            ));
        }
    }
    for opt in &hc.DnsOptions {
        if !valid_resolv_token(opt) {
            return Err(CreateError::bad(
                "DNS option",
                format!("{opt:?} is not a valid resolver option"),
            ));
        }
    }
    for entry in &hc.ExtraHosts {
        match entry.split_once(':') {
            Some((host, ip)) if !host.is_empty() && ip.parse::<std::net::IpAddr>().is_ok() => {}
            _ => {
                return Err(CreateError::bad(
                    "extra host",
                    format!("{entry:?} must be hostname:IP"),
                ));
            }
        }
    }
    Ok(())
}

/// Enforced-or-rejected matrix, unit 1.1 scope:
///
/// | option | status |
/// |---|---|
/// | Devices (non-empty) | 400 rejected (Phase 3 implements) |
/// | CapAdd/CapDrop unknown names | 400 rejected |
/// | CapAdd/CapDrop known names | enforced by child |
/// | Privileged | enforced by child |
/// | ReadonlyRootfs | enforced by child |
/// | User | enforced by child (fail-closed on unknown, unit 1.1b) |
/// | RestartPolicy name/count | 400 on invalid; supervision in Phase 2 |
/// | ShmSize | enforced (/dev/shm sizing); 400 when negative |
/// | Tmpfs | enforced (tmpfs mounts); 400 on relative dest |
/// | Sysctls | `net.*` enforced; others 400 rejected |
/// | Ulimits | core/nofile/nproc/stack/as/memlock enforced; others 400 |
pub fn validate_hostconfig(hc: &HostConfig) -> Result<(), CreateError> {
    // Devices: no device-cgroup/plumbing yet (Plan Phase 3) — reject
    // loudly instead of silently running without the device.
    if !hc.Devices.is_empty() {
        return Err(CreateError::unsupported("HostConfig.Devices"));
    }
    // Unknown capability names were silently dropped by the child
    // (Plan Phase 3 hardens the rest); fail fast at create instead.
    // `ALL` is the docker spelling for the full set.
    let mut unknown = Vec::new();
    for name in hc.CapAdd.iter().chain(hc.CapDrop.iter()) {
        if !name.eq_ignore_ascii_case("ALL") && crate::child::cap_name_to_bit(name).is_none() {
            unknown.push(name.clone());
        }
    }
    if !unknown.is_empty() {
        return Err(CreateError::bad(
            "capability",
            format!("unknown capability name(s): {}", unknown.join(", ")),
        ));
    }
    // ShmSize: bytes, 0 means the daemon default (64MiB, docker parity).
    if hc.ShmSize < 0 {
        return Err(CreateError::bad("shm size", "must not be negative"));
    }
    // Tmpfs: keys are absolute container paths.
    for dest in hc.Tmpfs.keys() {
        if !dest.starts_with('/') {
            return Err(CreateError::bad(
                "tmpfs",
                format!("mount point {dest:?} must be an absolute path"),
            ));
        }
    }
    // Sysctls: namespaced `net.*` only (documented subset, Plan Phase 3).
    for key in hc.Sysctls.keys() {
        if !key.starts_with("net.") {
            return Err(CreateError::unsupported(format!("sysctl {key:?}")));
        }
    }
    // Ulimits: parsed strictly (names + ranges) here and in start().
    parse_ulimits(hc).map(|_| ())?;
    // Restart policy names are validated now; supervision lands in Phase 2.
    match hc.RestartPolicy.Name.as_str() {
        "" | "no" | "always" | "unless-stopped" | "on-failure" => {}
        other => {
            return Err(CreateError::bad(
                "restart policy",
                format!("{other:?} must be one of: no, always, unless-stopped, on-failure"),
            ));
        }
    }
    if hc.RestartPolicy.MaximumRetryCount < 0 {
        return Err(CreateError::bad(
            "restart policy",
            "MaximumRetryCount must not be negative",
        ));
    }
    for opt in &hc.SecurityOpt {
        if opt != "seccomp=unconfined"
            && opt != "seccomp:unconfined"
            && opt != "seccomp=default"
            && opt != "seccomp:default"
        {
            return Err(CreateError::unsupported(format!("SecurityOpt {opt:?}")));
        }
    }
    if !hc.VolumeDriver.is_empty() && hc.VolumeDriver != "local" {
        return Err(CreateError::unsupported(format!(
            "volume driver {:?}",
            hc.VolumeDriver
        )));
    }
    if !hc.VolumesFrom.is_empty() {
        return Err(CreateError::unsupported("HostConfig.VolumesFrom"));
    }
    if !hc.GroupAdd.is_empty() {
        return Err(CreateError::unsupported("HostConfig.GroupAdd"));
    }
    if !hc.ContainerIDFile.is_empty() {
        return Err(CreateError::unsupported("HostConfig.ContainerIDFile"));
    }
    if !hc.LogConfig.typ.is_empty() && hc.LogConfig.typ != "json-file" {
        return Err(CreateError::unsupported(format!(
            "log driver {:?}",
            hc.LogConfig.typ
        )));
    }
    if !hc.IpcMode.is_empty() && hc.IpcMode != "private" && hc.IpcMode != "shareable" {
        return Err(CreateError::unsupported(format!(
            "IpcMode {:?}",
            hc.IpcMode
        )));
    }
    if !hc.Cgroup.is_empty() {
        return Err(CreateError::unsupported("HostConfig.Cgroup"));
    }
    if !hc.Links.is_empty() {
        return Err(CreateError::unsupported("HostConfig.Links"));
    }
    if hc.OomScoreAdj != 0 {
        return Err(CreateError::unsupported("HostConfig.OomScoreAdj"));
    }
    if !hc.UTSMode.is_empty() && hc.UTSMode != "private" {
        return Err(CreateError::unsupported(format!(
            "UTSMode {:?}",
            hc.UTSMode
        )));
    }
    if !hc.UsernsMode.is_empty() {
        return Err(CreateError::unsupported("HostConfig.UsernsMode"));
    }
    if !hc.Runtime.is_empty() && hc.Runtime != "runc" {
        return Err(CreateError::unsupported(format!(
            "Runtime {:?}",
            hc.Runtime
        )));
    }
    if !hc.Isolation.is_empty() && hc.Isolation != "default" {
        return Err(CreateError::unsupported(format!(
            "Isolation {:?}",
            hc.Isolation
        )));
    }
    if !hc.CgroupParent.is_empty() {
        return Err(CreateError::unsupported("HostConfig.CgroupParent"));
    }
    if hc.BlkioWeight != 0 {
        return Err(CreateError::unsupported("HostConfig.BlkioWeight"));
    }
    if hc.CpuPeriod != 0 {
        return Err(CreateError::unsupported("HostConfig.CpuPeriod"));
    }
    if hc.CpuQuota != 0 {
        return Err(CreateError::unsupported("HostConfig.CpuQuota"));
    }
    if !hc.CpusetMems.is_empty() {
        return Err(CreateError::unsupported("HostConfig.CpusetMems"));
    }
    if hc.Init.is_some_and(|v| v) {
        return Err(CreateError::unsupported("HostConfig.Init"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body() -> ContainerCreateBody {
        ContainerCreateBody {
            Image: "busybox:latest".to_string(),
            ..Default::default()
        }
    }

    fn validate_create(body: &ContainerCreateBody, name: Option<&str>) -> Result<(), CreateError> {
        super::validate_create(body, name, None)
    }

    #[test]
    fn matrix_names() {
        assert!(valid_name("web"));
        assert!(valid_name("/web"));
        assert!(valid_name("my-web_1.2"));
        assert!(!valid_name(""));
        assert!(!valid_name("/"));
        assert!(!valid_name("has space"));
        assert!(!valid_name("semi;colon"));
        assert!(validate_create(&body(), Some("ok-name_1")).is_ok());
        assert!(validate_create(&body(), Some("bad name")).is_err());
    }

    #[test]
    fn matrix_devices_rejected() {
        let mut b = body();
        b.HostConfig.Devices = vec![serde_json::json!({"PathOnHost": "/dev/fuse"})];
        let err = validate_create(&b, None).unwrap_err().to_string();
        assert!(err.contains("Devices"), "unexpected: {err}");
    }

    #[test]
    fn matrix_cap_names() {
        let mut b = body();
        b.HostConfig.CapAdd = vec!["NET_ADMIN".into(), "CAP_SYS_PTRACE".into()];
        b.HostConfig.CapDrop = vec!["MKNOD".into(), "ALL".into()];
        assert!(validate_create(&b, None).is_ok());

        let mut b = body();
        b.HostConfig.CapAdd = vec!["NOT_A_CAP".into()];
        let err = validate_create(&b, None).unwrap_err().to_string();
        assert!(err.contains("NOT_A_CAP"), "unexpected: {err}");
    }

    #[test]
    fn matrix_restart_policy() {
        for good in ["", "no", "always", "unless-stopped", "on-failure"] {
            let mut b = body();
            b.HostConfig.RestartPolicy.Name = good.to_string();
            assert!(validate_create(&b, None).is_ok(), "policy {good:?}");
        }
        let mut b = body();
        b.HostConfig.RestartPolicy.Name = "sometimes".to_string();
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.HostConfig.RestartPolicy.Name = "on-failure".to_string();
        b.HostConfig.RestartPolicy.MaximumRetryCount = -1;
        assert!(validate_create(&b, None).is_err());
    }

    #[test]
    fn matrix_enforced_options_accepted() {
        // Privileged, CapAdd/CapDrop (known), ReadonlyRootfs, User are
        // enforced by the child — create must accept them.
        let mut b = body();
        b.HostConfig.Privileged = true;
        b.HostConfig.ReadonlyRootfs = true;
        b.HostConfig.CapAdd = vec!["SYS_PTRACE".into()];
        b.User = "1000:1000".to_string();
        assert!(validate_create(&b, None).is_ok());
    }

    #[test]
    fn matrix_resources_validated() {
        // Supported subset passes validation.
        let mut b = body();
        b.HostConfig.ShmSize = 128 * 1024 * 1024;
        b.HostConfig.Tmpfs = [("/run".to_string(), "size=100m".to_string())]
            .into_iter()
            .collect();
        b.HostConfig.Sysctls = [("net.ipv4.ip_forward".to_string(), "0".to_string())]
            .into_iter()
            .collect();
        b.HostConfig.Ulimits =
            vec![serde_json::json!({"Name": "nofile", "Soft": 1024, "Hard": 2048})];
        assert!(validate_create(&b, None).is_ok());

        let mut b = body();
        b.HostConfig.ShmSize = -1;
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.HostConfig.Tmpfs = [("relative".to_string(), String::new())]
            .into_iter()
            .collect();
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.HostConfig.Sysctls = [("kernel.hostname".to_string(), "x".to_string())]
            .into_iter()
            .collect();
        let err = validate_create(&b, None).unwrap_err().to_string();
        assert!(err.contains("sysctl"), "unexpected: {err}");
        let mut b = body();
        b.HostConfig.Ulimits = vec![serde_json::json!({"Name": "rtprio", "Soft": 0, "Hard": 0})];
        let err = validate_create(&b, None).unwrap_err().to_string();
        assert!(err.contains("ulimit"), "unexpected: {err}");
        let mut b = body();
        b.HostConfig.Ulimits =
            vec![serde_json::json!({"Name": "nofile", "Soft": 4096, "Hard": 1024})];
        assert!(validate_create(&b, None).is_err());
    }

    #[test]
    fn matrix_empty_image_rejected() {
        let b = ContainerCreateBody::default();
        assert!(validate_create(&b, None).is_err());
    }

    #[test]
    fn create_ports_validated() {
        use std::collections::HashMap;
        let mut b = body();
        b.HostConfig.PortBindings = HashMap::from([(
            "80/tcp".to_string(),
            vec![ingot_api::PortBinding {
                HostIp: "127.0.0.1".into(),
                HostPort: "8080".into(),
            }],
        )]);
        assert!(validate_create(&b, None).is_ok());

        for bad_key in ["0/tcp", "99999/tcp", "abc", "80/gre"] {
            let mut b = body();
            b.HostConfig.PortBindings =
                HashMap::from([(bad_key.to_string(), vec![ingot_api::PortBinding::default()])]);
            assert!(validate_create(&b, None).is_err(), "key {bad_key:?}");
        }
        let mut b = body();
        b.HostConfig.PortBindings = HashMap::from([(
            "80/tcp".to_string(),
            vec![ingot_api::PortBinding {
                HostIp: "not-an-ip".into(),
                HostPort: String::new(),
            }],
        )]);
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.HostConfig.PortBindings = HashMap::from([(
            "80/tcp".to_string(),
            vec![ingot_api::PortBinding {
                HostIp: String::new(),
                HostPort: "0".into(),
            }],
        )]);
        assert!(validate_create(&b, None).is_err());
        // IPv6 and sctp are explicit 400s (schema carries v6, dataplane
        // is v4 TCP/UDP; the proxy would mistarget sctp as TCP).
        for (key, ip) in [("80/tcp", "::1"), ("80/udp", "::"), ("80/sctp", "")] {
            let mut b = body();
            b.HostConfig.PortBindings = HashMap::from([(
                key.to_string(),
                vec![ingot_api::PortBinding {
                    HostIp: ip.into(),
                    HostPort: "8080".into(),
                }],
            )]);
            let err = validate_create(&b, None).unwrap_err().to_string();
            assert!(
                err.contains("not supported") || err.contains("must be tcp or udp"),
                "unexpected: {err}"
            );
        }
        // Malformed request ExposedPorts fail closed too.
        let mut b = body();
        b.ExposedPorts = Some(HashMap::from([(
            "abc".to_string(),
            serde_json::Value::Null,
        )]));
        assert!(validate_create(&b, None).is_err());
    }

    #[test]
    fn create_binds_mounts_validated() {
        let mut b = body();
        b.HostConfig.Binds = vec![
            "/host:/data:ro".into(),
            "named:/data".into(),
            "/anon-dest".into(),
        ];
        assert!(validate_create(&b, None).is_ok());

        for bad in ["", "nodest", "/src:", "/src:/dst:z", "a:b:c:d"] {
            let mut b = body();
            b.HostConfig.Binds = vec![bad.to_string()];
            assert!(validate_create(&b, None).is_err(), "bind {bad:?}");
        }
        let mut b = body();
        b.HostConfig.Mounts = vec![ingot_api::MountRequest {
            typ: "npipe".into(),
            Source: String::new(),
            Target: "/data".into(),
            ..Default::default()
        }];
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.HostConfig.Mounts = vec![ingot_api::MountRequest {
            typ: "bind".into(),
            Source: "relative".into(),
            Target: "/data".into(),
            ..Default::default()
        }];
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.HostConfig.Mounts = vec![ingot_api::MountRequest {
            typ: "volume".into(),
            Source: "data".into(),
            Target: "relative".into(),
            ..Default::default()
        }];
        assert!(validate_create(&b, None).is_err());

        // Traversal rejection tests
        let mut b = body();
        b.HostConfig.Binds = vec!["/host:/data/../../etc".into()];
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.Binds = vec!["../evil:/data".into()];
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.Mounts = vec![ingot_api::MountRequest {
            typ: "bind".into(),
            Source: "/host".into(),
            Target: "/data/../../etc".into(),
            ..Default::default()
        }];
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.Mounts = vec![ingot_api::MountRequest {
            typ: "volume".into(),
            Source: "my/evil/volume".into(),
            Target: "/data".into(),
            ..Default::default()
        }];
        assert!(validate_create(&b, None).is_err());
    }

    #[test]
    fn signals_parse_strictly() {
        assert_eq!(parse_signal("TERM").unwrap(), 15);
        assert_eq!(parse_signal("SIGTERM").unwrap(), 15);
        assert_eq!(parse_signal("sigkill").unwrap(), 9);
        assert_eq!(parse_signal("9").unwrap(), 9);
        assert_eq!(parse_signal("CONT").unwrap(), 18);
        assert!(parse_signal("BOGUS").is_err());
        assert!(parse_signal("0").is_err());
        assert!(parse_signal("65").is_err());
        assert!(parse_signal("").is_err());
    }

    #[test]
    fn create_net_and_stop_validated() {
        let mut b = body();
        b.HostConfig.Dns = vec!["8.8.8.8".into(), "::1".into()];
        b.HostConfig.ExtraHosts = vec!["db:10.0.0.2".into()];
        b.WorkingDir = "/app".into();
        b.StopSignal = "SIGTERM".into();
        b.StopTimeout = Some(10);
        assert!(validate_create(&b, None).is_ok());

        let mut b = body();
        b.HostConfig.Dns = vec!["not-an-ip".into()];
        assert!(validate_create(&b, None).is_err());
        // Search domains and options render into resolv.conf: line
        // breaks and blanks are rejected, well-formed values pass.
        let mut b = body();
        b.HostConfig.DnsSearch = vec!["svc".into(), "example.com.".into()];
        b.HostConfig.DnsOptions = vec!["ndots:2".into(), "single-request".into()];
        assert!(validate_create(&b, None).is_ok());
        let mut b = body();
        b.HostConfig.DnsSearch = vec!["has space".into()];
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.HostConfig.DnsSearch = vec!["line\nbreak".into()];
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.HostConfig.DnsOptions = vec!["".into()];
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.HostConfig.ExtraHosts = vec!["no-ip-here".into()];
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.WorkingDir = "relative".into();
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.StopSignal = "SIGNOPE".into();
        assert!(validate_create(&b, None).is_err());
        let mut b = body();
        b.StopTimeout = Some(-1);
        assert!(validate_create(&b, None).is_err());
    }

    #[test]
    fn platform_validation() {
        let b = body();
        assert!(super::validate_create(&b, None, None).is_ok());
        assert!(super::validate_create(&b, None, Some("linux/amd64")).is_ok());
        assert!(super::validate_create(&b, None, Some("linux")).is_ok());
        assert!(super::validate_create(&b, None, Some("windows/amd64")).is_err());
        assert!(super::validate_create(&b, None, Some("darwin/arm64")).is_err());
    }

    #[test]
    fn security_opts_validation() {
        let mut b = body();
        b.HostConfig.SecurityOpt = vec!["seccomp=unconfined".into()];
        assert!(validate_create(&b, None).is_ok());

        let mut b = body();
        b.HostConfig.SecurityOpt = vec!["seccomp:unconfined".into()];
        assert!(validate_create(&b, None).is_ok());

        let mut b = body();
        b.HostConfig.SecurityOpt = vec!["seccomp=default".into()];
        assert!(validate_create(&b, None).is_ok());

        let mut b = body();
        b.HostConfig.SecurityOpt = vec!["apparmor=unconfined".into()];
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.SecurityOpt = vec!["seccomp=/path/profile.json".into()];
        assert!(validate_create(&b, None).is_err());
    }

    #[test]
    fn unsupported_options_rejected() {
        let mut b = body();
        b.HostConfig.VolumeDriver = "nfs".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.VolumesFrom = vec!["other".into()];
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.GroupAdd = vec!["wheel".into()];
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.ContainerIDFile = "/tmp/cid".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.LogConfig.typ = "syslog".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.IpcMode = "host".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.Cgroup = "parent".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.Links = vec!["redis:db".into()];
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.OomScoreAdj = 500;
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.UTSMode = "host".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.UsernsMode = "host".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.Runtime = "kata".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.Isolation = "hyperv".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.CgroupParent = "slice".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.BlkioWeight = 500;
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.CpuPeriod = 100000;
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.CpuQuota = 50000;
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.CpusetMems = "0".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.HostConfig.Init = Some(true);
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.Domainname = "example.com".into();
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.ArgsEscaped = true;
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.OnBuild = Some(vec!["RUN echo hi".into()]);
        assert!(validate_create(&b, None).is_err());

        let mut b = body();
        b.Shell = Some(vec!["/bin/sh".into()]);
        assert!(validate_create(&b, None).is_err());
    }
}
