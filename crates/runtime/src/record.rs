//! Container on-disk record + runtime state.

use ingot_api::{ContainerConfig, HostConfig};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerRecord {
    pub id: String,
    pub name: String,
    pub created: String,
    pub image_id: String,
    /// Ref the user asked for (e.g. `busybox:latest`).
    pub image_name: String,
    pub config: ContainerConfig,
    pub hostconfig: HostConfig,
    /// Entry command for `docker ps` display.
    pub cmd_display: String,
    /// Network endpoints allocated at create time: network → endpoint.
    pub endpoints: Vec<EndpointRecord>,
    /// Volume/bind mounts resolved at create time.
    pub mounts: Vec<MountRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EndpointRecord {
    pub network_id: String,
    pub network_name: String,
    pub ip: String,
    pub gateway: String,
    pub mac: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct MountRecord {
    #[serde(rename = "type")]
    pub typ: String, // bind | volume | tmpfs
    pub name: String,
    pub source: String,
    pub destination: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ContainerState {
    pub status: StateStatus,
    pub pid: i64,
    pub exit_code: i64,
    pub error: String,
    pub oom_killed: bool,
    pub started_at: String,
    pub finished_at: String,
    pub restart_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<ingot_api::HealthState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StateStatus {
    #[serde(rename = "created")]
    Created,
    #[serde(rename = "running")]
    Running,
    #[serde(rename = "paused")]
    Paused,
    #[serde(rename = "restarting")]
    Restarting,
    #[serde(rename = "removing")]
    Removing,
    #[serde(rename = "exited")]
    Exited,
    #[serde(rename = "dead")]
    Dead,
}

impl Default for StateStatus {
    fn default() -> Self {
        StateStatus::Created
    }
}

impl StateStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            StateStatus::Created => "created",
            StateStatus::Running => "running",
            StateStatus::Paused => "paused",
            StateStatus::Restarting => "restarting",
            StateStatus::Removing => "removing",
            StateStatus::Exited => "exited",
            StateStatus::Dead => "dead",
        }
    }
}

impl ContainerRecord {
    /// Entrypoint + Cmd resolution exactly like docker: when the request
    /// overrides Entrypoint, Cmd is the args; when only Cmd is set, it
    /// replaces the image Cmd.
    pub fn argv(&self) -> Vec<String> {
        let ep = self.config.Entrypoint.clone().unwrap_or_default();
        let cmd = self.config.Cmd.clone();
        if ep.is_empty() {
            cmd
        } else {
            [ep, cmd].concat()
        }
    }

    /// The docker stop signal (default SIGTERM) and timeout (default 10s).
    pub fn stop_signal(&self) -> nix::sys::signal::Signal {
        use nix::sys::signal::Signal;
        match self.config.StopSignal.as_str() {
            "SIGINT" | "INT" => Signal::SIGINT,
            "SIGKILL" | "KILL" => Signal::SIGKILL,
            "SIGHUP" | "HUP" => Signal::SIGHUP,
            "SIGQUIT" | "QUIT" => Signal::SIGQUIT,
            "SIGUSR1" | "USR1" => Signal::SIGUSR1,
            "SIGUSR2" | "USR2" => Signal::SIGUSR2,
            _ => Signal::SIGTERM,
        }
    }

    pub fn stop_timeout(&self) -> i64 {
        self.config.StopTimeout.unwrap_or(10)
    }
}
