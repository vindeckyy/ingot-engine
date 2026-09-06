use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// GET /containers/json
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerSummary {
    pub Id: String,
    pub Names: Vec<String>,
    pub Image: String,
    pub ImageID: String,
    pub Command: String,
    pub Created: i64,
    pub Ports: Vec<Port>,
    pub Labels: HashMap<String, String>,
    pub State: String,
    pub Status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub HostConfig: Option<SummaryHostConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub NetworkSettings: Option<SummaryNetworkSettings>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Mounts: Option<Vec<MountPoint>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SummaryHostConfig {
    pub NetworkMode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SummaryNetworkSettings {
    pub Networks: HashMap<String, EndpointSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Port {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub IP: String,
    pub PrivatePort: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub PublicPort: Option<u16>,
    pub Type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortBinding {
    #[serde(default)]
    pub HostIp: String,
    #[serde(default)]
    pub HostPort: String,
}

/// The `Config` block of a container / image (OCI-ish container runtime config).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerConfig {
    pub Hostname: String,
    pub Domainname: String,
    pub User: String,
    pub AttachStdin: bool,
    pub AttachStdout: bool,
    pub AttachStderr: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ExposedPorts: Option<HashMap<String, serde_json::Value>>,
    pub Tty: bool,
    pub OpenStdin: bool,
    pub StdinOnce: bool,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Env: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Cmd: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Healthcheck: Option<HealthConfig>,
    pub ArgsEscaped: bool,
    pub Image: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Volumes: Option<HashMap<String, serde_json::Value>>,
    pub WorkingDir: String,
    pub Entrypoint: Option<Vec<String>>,
    pub OnBuild: Option<Vec<String>>,
    pub Labels: HashMap<String, String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub StopSignal: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub StopTimeout: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Shell: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HealthConfig {
    pub Test: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Interval: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Timeout: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Retries: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub StartPeriod: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub StartInterval: Option<i64>,
}

/// Full HostConfig — we accept everything, act on the fields marked used.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HostConfig {
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Binds: Vec<String>,
    pub ContainerIDFile: String,
    pub LogConfig: LogConfig,
    pub NetworkMode: String,
    #[serde(default, deserialize_with = "crate::de::null_to_map")]
    pub PortBindings: HashMap<String, Vec<PortBinding>>,
    pub RestartPolicy: RestartPolicy,
    pub AutoRemove: bool,
    pub VolumeDriver: String,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub VolumesFrom: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub CapAdd: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub CapDrop: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Dns: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub DnsOptions: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub DnsSearch: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub ExtraHosts: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub GroupAdd: Vec<String>,
    pub IpcMode: String,
    pub Cgroup: String,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Links: Vec<String>,
    pub OomScoreAdj: i64,
    pub Privileged: bool,
    pub PublishAllPorts: bool,
    pub ReadonlyRootfs: bool,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub SecurityOpt: Vec<String>,
    pub UTSMode: String,
    pub UsernsMode: String,
    pub ShmSize: i64,
    pub Runtime: String,
    pub Isolation: String,
    pub CpuShares: i64,
    pub Memory: i64,
    pub NanoCpus: i64,
    pub CgroupParent: String,
    pub BlkioWeight: u16,
    pub CpuPeriod: i64,
    pub CpuQuota: i64,
    pub CpusetCpus: String,
    pub CpusetMems: String,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Devices: Vec<serde_json::Value>,
    pub PidsLimit: i64,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Ulimits: Vec<serde_json::Value>,
    #[serde(default, deserialize_with = "crate::de::null_to_map")]
    pub Tmpfs: HashMap<String, String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Mounts: Vec<MountRequest>,
    pub Init: Option<bool>,
    #[serde(default, deserialize_with = "crate::de::null_to_map")]
    pub Sysctls: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct LogConfig {
    #[serde(rename = "Type")]
    pub typ: String,
    #[serde(rename = "Config")]
    pub config: HashMap<String, String>,
}

impl Default for RestartPolicy {
    fn default() -> Self {
        RestartPolicy { Name: "".into(), MaximumRetryCount: 0 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RestartPolicy {
    pub Name: String, // "", "always", "unless-stopped", "on-failure", "no"
    pub MaximumRetryCount: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MountRequest {
    #[serde(rename = "Type")]
    pub typ: String, // bind | volume | tmpfs
    pub Source: String,
    pub Target: String,
    #[serde(rename = "ReadOnly")]
    pub read_only: bool,
    #[serde(rename = "Bind", skip_serializing_if = "Option::is_none")]
    pub bind: Option<serde_json::Value>,
    #[serde(rename = "VolumeOptions", skip_serializing_if = "Option::is_none")]
    pub volume_options: Option<serde_json::Value>,
    #[serde(rename = "TmpfsOptions", skip_serializing_if = "Option::is_none")]
    pub tmpfs_options: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MountPoint {
    #[serde(rename = "Type")]
    pub typ: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub Name: String,
    pub Source: String,
    pub Destination: String,
    pub Driver: String,
    pub Mode: String,
    pub RW: bool,
    pub Propagation: String,
}

/// POST /containers/create request body.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerCreateBody {
    pub Hostname: String,
    pub Domainname: String,
    pub User: String,
    pub AttachStdin: bool,
    pub AttachStdout: bool,
    pub AttachStderr: bool,
    pub ExposedPorts: Option<HashMap<String, serde_json::Value>>,
    pub Tty: bool,
    pub OpenStdin: bool,
    pub StdinOnce: bool,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Env: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Cmd: Vec<String>,
    pub Healthcheck: Option<HealthConfig>,
    pub ArgsEscaped: bool,
    pub Image: String,
    pub Volumes: Option<HashMap<String, serde_json::Value>>,
    pub WorkingDir: String,
    pub Entrypoint: Option<Vec<String>>,
    pub OnBuild: Option<Vec<String>>,
    pub Labels: HashMap<String, String>,
    pub StopSignal: String,
    pub StopTimeout: Option<i64>,
    pub Shell: Option<Vec<String>>,
    pub HostConfig: HostConfig,
    pub NetworkingConfig: Option<NetworkingConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkingConfig {
    pub EndpointsConfig: HashMap<String, EndpointSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EndpointSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub IPAMConfig: Option<EndpointIpamConfig>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec", skip_serializing_if = "Vec::is_empty")]
    pub Links: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec", skip_serializing_if = "Vec::is_empty")]
    pub Aliases: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub NetworkID: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub EndpointID: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub Gateway: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub IPAddress: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub IPPrefixLen: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub MacAddress: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub DriverOpts: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EndpointIpamConfig {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub IPv4Address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerState {
    pub Status: String,
    pub Running: bool,
    pub Paused: bool,
    pub Restarting: bool,
    pub OOMKilled: bool,
    pub Dead: bool,
    pub Pid: i64,
    pub ExitCode: i64,
    pub Error: String,
    pub StartedAt: String,
    pub FinishedAt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Health: Option<HealthState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HealthState {
    pub Status: String, // none|starting|healthy|unhealthy
    pub FailingStreak: i64,
    pub Log: Vec<HealthLogEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HealthLogEntry {
    pub Start: String,
    pub End: String,
    pub ExitCode: i64,
    pub Output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct GraphDriverData {
    pub Name: String,
    pub Data: HashMap<String, String>,
}

/// GET /containers/{id}/json
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerInspect {
    pub Id: String,
    pub Created: String,
    pub Path: String,
    pub Args: Vec<String>,
    pub State: ContainerState,
    pub Image: String,
    pub ResolvConfPath: String,
    pub HostnamePath: String,
    pub HostsPath: String,
    pub LogPath: String,
    pub Name: String,
    pub RestartCount: i64,
    pub Driver: String,
    pub Platform: String,
    pub MountLabel: String,
    pub ProcessLabel: String,
    pub AppArmorProfile: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ExecIDs: Option<Vec<String>>,
    pub HostConfig: HostConfig,
    pub GraphDriver: GraphDriverData,
    pub Mounts: Vec<MountPoint>,
    pub Config: ContainerConfig,
    pub NetworkSettings: NetworkSettingsInspect,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkSettingsInspect {
    pub Bridge: String,
    pub SandboxID: String,
    pub HairpinMode: bool,
    pub LinkLocalIPv6Address: String,
    pub LinkLocalIPv6PrefixLen: i64,
    pub Ports: HashMap<String, Option<Vec<PortMapping>>>,
    pub SandboxKey: String,
    pub SecondaryIPAddresses: Option<Vec<serde_json::Value>>,
    pub EndpointID: String,
    pub Gateway: String,
    pub GlobalIPv6Address: String,
    pub GlobalIPv6PrefixLen: i64,
    pub IPAddress: String,
    pub IPPrefixLen: i64,
    pub IPv6Gateway: String,
    pub MacAddress: String,
    pub Networks: HashMap<String, EndpointSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PortMapping {
    pub HostIp: String,
    pub HostPort: String,
}

/// GET /containers/{id}/wait
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WaitResponse {
    #[serde(default)]
    pub StatusCode: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Error: Option<WaitError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WaitError {
    pub Message: String,
}

/// POST /containers/{id}/exec create body.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ExecCreateBody {
    pub Detach: bool,
    pub Tty: bool,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Env: Vec<String>,
    #[serde(default, deserialize_with = "crate::de::null_to_vec")]
    pub Cmd: Vec<String>,
    pub AttachStdin: bool,
    pub AttachStdout: bool,
    pub AttachStderr: bool,
    pub Privileged: bool,
    pub User: String,
    pub WorkingDir: String,
}

/// GET /exec/{id}/json
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ExecInspect {
    pub CanRemove: bool,
    pub ContainerID: String,
    pub DetachKeys: String,
    pub ExitCode: i64,
    pub ID: String,
    pub OpenStderr: bool,
    pub OpenStdin: bool,
    pub OpenStdout: bool,
    pub ProcessConfig: ExecProcessConfig,
    pub Running: bool,
    pub Pid: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ExecProcessConfig {
    pub arguments: Vec<String>,
    pub entrypoint: String,
    pub privileged: bool,
    pub tty: bool,
    pub user: String,
}

/// GET /containers/{id}/top
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerTop {
    pub Titles: Vec<String>,
    pub Processes: Vec<Vec<String>>,
}

/// GET /containers/{id}/stats one-shot (stream=0)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerStats {
    pub id: String,
    pub name: String,
    pub read: String,
    pub preread: String,
    pub pids_stats: PidsStats,
    pub networks: HashMap<String, NetworkStats>,
    pub memory_stats: MemoryStats,
    pub cpu_stats: CpuStats,
    pub precpu_stats: CpuStats,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PidsStats {
    pub current: u64,
    pub limit: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkStats {
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errors: u64,
    pub rx_dropped: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errors: u64,
    pub tx_dropped: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MemoryStats {
    pub usage: u64,
    pub max_usage: u64,
    pub limit: u64,
    pub stats: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CpuStats {
    pub cpu_usage: CpuUsage,
    pub system_cpu_usage: u64,
    pub online_cpus: u64,
    pub throttling_data: ThrottlingData,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CpuUsage {
    pub total_usage: u64,
    pub percpu_usage: Vec<u64>,
    pub usage_in_kernelmode: u64,
    pub usage_in_usermode: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ThrottlingData {
    pub periods: u64,
    pub throttled_periods: u64,
    pub throttled_time: u64,
}

/// POST /containers/{id}/update
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerUpdateBody {
    pub Memory: i64,
    pub NanoCpus: i64,
    pub CpuShares: i64,
    pub PidsLimit: i64,
    pub CpusetCpus: String,
    pub RestartPolicy: Option<RestartPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerUpdateOKBody {
    pub Warnings: Vec<String>,
}

impl ContainerCreateBody {
    pub fn into_container_config(self) -> ContainerConfig {
        ContainerConfig {
            Hostname: self.Hostname,
            Domainname: self.Domainname,
            User: self.User,
            AttachStdin: self.AttachStdin,
            AttachStdout: self.AttachStdout,
            AttachStderr: self.AttachStderr,
            ExposedPorts: self.ExposedPorts,
            Tty: self.Tty,
            OpenStdin: self.OpenStdin,
            StdinOnce: self.StdinOnce,
            Env: self.Env,
            Cmd: self.Cmd,
            Healthcheck: self.Healthcheck,
            ArgsEscaped: self.ArgsEscaped,
            Image: self.Image,
            Volumes: self.Volumes,
            WorkingDir: self.WorkingDir,
            Entrypoint: self.Entrypoint,
            OnBuild: self.OnBuild,
            Labels: self.Labels,
            StopSignal: self.StopSignal,
            StopTimeout: self.StopTimeout,
            Shell: self.Shell,
        }
    }
}

/// POST /containers/prune
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainersPruneReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ContainersDeleted: Option<Vec<String>>,
    pub SpaceReclaimed: u64,
}

/// GET/HEAD /containers/{id}/archive stat header
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ContainerPathStat {
    pub name: String,
    pub size: i64,
    pub mode: u32,
    pub mtime: String,
    #[serde(rename = "linkTarget")]
    pub link_target: String,
}

