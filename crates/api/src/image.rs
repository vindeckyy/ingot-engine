use crate::container::ContainerConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// GET /images/json
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ImageSummary {
    pub Id: String,
    pub ParentId: String,
    pub RepoTags: Vec<String>,
    pub RepoDigests: Vec<String>,
    pub Created: i64,
    pub Size: i64,
    pub SharedSize: i64,
    pub VirtualSize: i64,
    pub Labels: HashMap<String, String>,
    pub Containers: i64,
}

/// GET /images/{name}/json
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ImageInspect {
    pub Id: String,
    pub RepoTags: Vec<String>,
    pub RepoDigests: Vec<String>,
    pub Parent: String,
    pub Comment: String,
    pub Created: String,
    pub Container: String,
    pub ContainerConfig: ContainerConfig,
    pub DockerVersion: String,
    pub Author: String,
    pub Config: ContainerConfig,
    pub Architecture: String,
    pub Variant: String,
    pub Os: String,
    pub Size: i64,
    pub VirtualSize: i64,
    pub GraphDriver: crate::container::GraphDriverData,
    pub RootFS: RootFs,
    pub Metadata: ImageMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RootFs {
    #[serde(rename = "Type")]
    pub typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Layers: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub FsLayers: Option<Vec<BlobSummary>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobSummary {
    pub BlobSum: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ImageMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub LastTagTime: Option<String>,
}

/// GET /images/{name}/history
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct HistoryResponseItem {
    pub Comment: String,
    pub Created: i64,
    pub CreatedBy: String,
    pub Id: String,
    pub Size: i64,
    pub Tags: Option<Vec<String>>,
}

/// DELETE /images/{name}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ImageDeleteResponseItem {
    pub Untagged: String,
    pub Deleted: String,
}

/// POST /images/{name}/push or /images/create auth body (X-Registry-Auth).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PushOptions {
    pub Tag: String,
}

/// Progress/status JSON messages streamed by /images/create, /build, /push.
/// Docker uses newline-delimited JSON with per-message `stream`/`status`/`progress` keys.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ProgressMessage {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progressDetail: Option<ProgressDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errorDetail: Option<ErrorDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aux: Option<serde_json::Value>,
}

impl ProgressMessage {
    pub fn stream(s: impl Into<String>) -> Self {
        ProgressMessage {
            stream: Some(s.into()),
            ..Default::default()
        }
    }
    pub fn status(s: impl Into<String>) -> Self {
        ProgressMessage {
            status: Some(s.into()),
            ..Default::default()
        }
    }
    pub fn error(s: impl Into<String>) -> Self {
        let msg: String = s.into();
        ProgressMessage {
            error: Some(msg.clone()),
            errorDetail: Some(ErrorDetail { message: msg }),
            ..Default::default()
        }
    }
    pub fn to_line(&self) -> String {
        let mut s = serde_json::to_string(self).unwrap_or_default();
        s.push('\n');
        s
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ProgressDetail {
    pub current: i64,
    pub total: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ErrorDetail {
    pub message: String,
}

/// POST /images/{name}/tag
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct TagRequest {
    pub repo: String,
    pub tag: String,
}

/// GET /images/search
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SearchResultItem {
    pub description: String,
    pub is_official: bool,
    pub name: String,
    pub star_count: i64,
    pub is_automated: bool,
}

/// POST /images/prune
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ImagesPruneReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ImagesDeleted: Option<Vec<ImageDeleteResponseItem>>,
    pub SpaceReclaimed: u64,
}
