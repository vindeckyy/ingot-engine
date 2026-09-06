use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Volume {
    pub CreatedAt: String,
    pub Driver: String,
    pub Labels: HashMap<String, String>,
    pub Mountpoint: String,
    pub Name: String,
    pub Options: HashMap<String, String>,
    pub Scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct VolumeCreateBody {
    pub Name: String,
    pub Driver: String,
    pub Labels: HashMap<String, String>,
    pub DriverOpts: HashMap<String, String>,
    #[serde(rename = "ClusterVolume", skip_serializing_if = "Option::is_none")]
    pub cluster_volume: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct VolumeListInfo {
    pub Volumes: Vec<Volume>,
    pub Warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct VolumePruneResponse {
    pub VolumesDeleted: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Reclaimable: Option<u64>,
}
