use serde::{Deserialize, Serialize};

/// GET /version
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Version {
    pub Platform: VersionPlatform,
    pub Version: String,
    pub ApiVersion: String,
    pub MinAPIVersion: String,
    pub GitCommit: String,
    pub GoVersion: String,
    pub Os: String,
    pub Arch: String,
    pub KernelVersion: String,
    pub BuildTime: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Components: Option<Vec<VersionComponent>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct VersionPlatform {
    pub Name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionComponent {
    pub Name: String,
    pub Version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Details: Option<std::collections::HashMap<String, String>>,
}

/// GET /info — the fields `docker info` renders, plus a few the CLI probes.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Info {
    pub ID: String,
    pub Containers: i64,
    pub ContainersRunning: i64,
    pub ContainersPaused: i64,
    pub ContainersStopped: i64,
    pub Images: i64,
    pub Driver: String,
    pub DriverStatus: Vec<Vec<String>>,
    pub DockerRootDir: String,
    pub MemoryLimit: bool,
    pub SwapLimit: bool,
    pub KernelMemoryTCP: bool,
    pub CpuCfsPeriod: bool,
    pub CpuCfsQuota: bool,
    pub CPUShares: bool,
    pub CPUSet: bool,
    pub PidsLimit: bool,
    pub OomKillDisable: bool,
    pub IPv4Forwarding: bool,
    pub BridgeNfIptables: bool,
    pub BridgeNfIp6tables: bool,
    pub Debug: bool,
    pub NFd: i64,
    pub NGoroutines: i64,
    pub LoggingDriver: String,
    pub CgroupDriver: String,
    pub CgroupVersion: String,
    pub NEventsListener: i64,
    pub KernelVersion: String,
    pub OperatingSystem: String,
    pub OSVersion: String,
    pub OSType: String,
    pub Architecture: String,
    pub NCPU: i64,
    pub MemTotal: i64,
    pub IndexServerAddress: String,
    pub Name: String,
    pub ServerVersion: String,
    pub Labels: Vec<String>,
    pub ExperimentalBuild: bool,
    #[serde(rename = "Runtimes")]
    pub RuntimesMap: serde_json::Value,
    pub DefaultRuntime: String,
    pub SecurityOptions: Vec<String>,
    pub CDISpecDirs: Vec<String>,
    pub Warnings: Vec<String>,
}

/// GET /events — modern event schema the docker CLI understands.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EventMessage {
    pub Type: String,
    pub Action: String,
    pub Actor: EventActor,
    pub scope: String,
    pub time: i64,
    pub timeNano: i64,
    // legacy fields, still read by some tooling
    pub status: String,
    pub id: String,
    pub from: String,
}

impl Default for EventMessage {
    fn default() -> Self {
        Self {
            Type: String::new(),
            Action: String::new(),
            Actor: EventActor::default(),
            scope: "local".into(),
            time: 0,
            timeNano: 0,
            status: String::new(),
            id: String::new(),
            from: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EventActor {
    pub ID: String,
    pub Attributes: std::collections::HashMap<String, String>,
}

impl EventMessage {
    pub fn new(typ: &str, action: &str, id: &str, attrs: std::collections::HashMap<String, String>) -> Self {
        let now = chrono::Utc::now();
        let from = attrs.get("image").cloned().unwrap_or_default();
        EventMessage {
            Type: typ.into(),
            Action: action.into(),
            Actor: EventActor { ID: id.into(), Attributes: attrs },
            scope: "local".into(),
            time: now.timestamp(),
            timeNano: now.timestamp_nanos_opt().unwrap_or_default(),
            status: action.into(),
            id: id.into(),
            from,
        }
    }
}

/// GET /system/df
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SystemDFResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub LayersSize: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Images: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Containers: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Volumes: Option<Vec<serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub BuildCache: Option<Vec<serde_json::Value>>,
}

/// X-Registry-Auth header payload (base64 of this JSON).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AuthConfig {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub username: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub password: String,
    #[serde(rename = "serveraddress", skip_serializing_if = "String::is_empty")]
    pub server_address: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub auth: String,
    #[serde(rename = "identitytoken", skip_serializing_if = "String::is_empty")]
    pub identity_token: String,
}
