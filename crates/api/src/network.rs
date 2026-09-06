use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// GET /networks
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkSummary {
    pub Name: String,
    pub Id: String,
    pub Created: String,
    pub Scope: String,
    pub Driver: String,
    pub EnableIPv6: bool,
    pub Internal: bool,
    pub Attachable: bool,
    pub Ingress: bool,
    pub IPAM: Ipam,
    pub Options: HashMap<String, String>,
    pub Labels: HashMap<String, String>,
}

/// GET /networks/{id}
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkInspect {
    pub Name: String,
    pub Id: String,
    pub Created: String,
    pub Scope: String,
    pub Driver: String,
    pub EnableIPv6: bool,
    pub IPAM: Ipam,
    pub Internal: bool,
    pub Attachable: bool,
    pub Ingress: bool,
    pub ConfigFrom: ConfigFrom,
    pub ConfigOnly: bool,
    pub Containers: HashMap<String, EndpointContainer>,
    pub Options: HashMap<String, String>,
    pub Labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ConfigFrom {
    pub Network: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Ipam {
    pub Driver: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub Config: Option<Vec<IpamConfig>>,
    pub Options: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct IpamConfig {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub Subnet: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub IPRange: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub Gateway: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub AuxAddress: Option<HashMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EndpointContainer {
    pub Name: String,
    pub EndpointID: String,
    pub MacAddress: String,
    pub IPv4Address: String,
    pub IPv6Address: String,
}

/// POST /networks/create
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkCreateBody {
    pub Name: String,
    pub Driver: String,
    pub CheckDuplicate: Option<bool>,
    pub Internal: bool,
    pub Attachable: bool,
    pub Ingress: bool,
    pub IPAM: Ipam,
    pub EnableIPv6: bool,
    pub Options: HashMap<String, String>,
    pub Labels: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkCreateResponse {
    pub Id: String,
    pub Warning: String,
}

/// POST /networks/{id}/connect | /disconnect
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkConnectBody {
    pub Container: String,
    pub EndpointConfig: Option<crate::container::EndpointSettings>,
    pub Force: bool,
}

/// GET /networks/prune response
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkPruneResponse {
    pub NetworksDeleted: Vec<String>,
}
