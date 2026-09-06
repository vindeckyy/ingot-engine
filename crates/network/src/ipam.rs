//! Sequential IPv4 lease allocator per network, persisted under the data root.

use ingot_store::paths::DataPaths;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct IpamLeases {
    /// network id → allocated ips (u32, host order)
    pub allocated: HashMap<String, Vec<u32>>,
}

pub struct Ipam {
    path: std::path::PathBuf,
    state: tokio::sync::Mutex<IpamLeases>,
}

impl Ipam {
    pub fn new(paths: &DataPaths) -> Self {
        let path = paths.ipam_leases();
        let state = std::fs::read(&path)
            .ok()
            .and_then(|d| serde_json::from_slice(&d).ok())
            .unwrap_or_default();
        Ipam { path, state: tokio::sync::Mutex::new(state) }
    }

    /// Allocate the lowest free address above the gateway (gateway + 2 …).
    pub async fn allocate(&self, network_id: &str, gateway: &str) -> anyhow::Result<Ipv4Addr> {
        let mut state = self.state.lock().await;
        let gw: u32 = gateway
            .parse::<Ipv4Addr>()
            .map_err(|e| anyhow::anyhow!("bad gateway {gateway}: {e}"))?
            .into();
        let used = state.allocated.entry(network_id.to_string()).or_default();
        let candidate = (gw + 2)..=(gw + 60000);
        for c in candidate {
            if !used.contains(&c) {
                used.push(c);
                let _ = ingot_store::write_json_atomic(&self.path, &*state);
                return Ok(Ipv4Addr::from(c));
            }
        }
        Err(anyhow::anyhow!("address pool exhausted"))
    }

    pub async fn release(&self, network_id: &str, ip: &str) {
        if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
            let mut state = self.state.lock().await;
            if let Some(used) = state.allocated.get_mut(network_id) {
                let v: u32 = parsed.into();
                used.retain(|x| *x != v);
            }
            let _ = ingot_store::write_json_atomic(&self.path, &*state);
        }
    }
}
