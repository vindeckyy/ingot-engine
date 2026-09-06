//! Daemon-wide state shared by all request handlers.

use ingot_registry::RegistryClient;
use ingot_store::paths::DataPaths;
use ingot_store::EventBus;
use std::sync::atomic::AtomicI64;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DaemonConfig {
    pub debug: bool,
    pub default_bridge_name: String,
    pub default_bridge_subnet: String,
    pub default_bridge_gateway: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            debug: false,
            default_bridge_name: "ingot0".into(),
            default_bridge_subnet: "172.17.0.0/16".into(),
            default_bridge_gateway: "172.17.0.1".into(),
        }
    }
}

pub struct DaemonState {
    pub paths: DataPaths,
    pub events: EventBus,
    pub config: DaemonConfig,
    pub started_at: chrono::DateTime<chrono::Utc>,
    /// Monotonic count of open event streams (for /info).
    pub event_listeners: AtomicI64,
    pub images: Arc<ingot_image::ImageStore>,
    pub registry: Arc<RegistryClient>,
    /// Container manager (M2).
    pub containers: Option<Arc<ingot_runtime::ContainerManager>>,
    /// Network manager (M3).
    pub networks: Option<Arc<ingot_network::NetworkManager>>,
    /// Volume manager (M5).
    pub volumes: Option<Arc<ingot_volume::VolumeManager>>,
}

pub type SharedState = Arc<DaemonState>;

impl DaemonState {
    pub fn new(paths: DataPaths, config: DaemonConfig) -> anyhow::Result<Self> {
        let images = Arc::new(ingot_image::ImageStore::new(paths.clone())?);
        Ok(DaemonState {
            paths,
            events: EventBus::new(4096),
            config,
            started_at: chrono::Utc::now(),
            event_listeners: AtomicI64::new(0),
            images,
            registry: Arc::new(RegistryClient::new()),
            containers: None,
            networks: None,
            volumes: None,
        })
    }
}
