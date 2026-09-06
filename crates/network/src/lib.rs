//! Container networking: bridge creation, veth attach, IPAM, iptables NAT,
//! port publishing and an embedded DNS forwarder for user-defined networks.
//!
//! Link/route operations shell out to iproute2 (`ip`) and netfilter to
//! `iptables` — the same binaries dockerd drives — keeping the data path
//! identical to docker's default bridge.

pub mod dns;
pub mod ipam;
pub mod proxy;

pub use dns::spawn_dns_server;
pub use ipam::IpamLeases;

use anyhow::{anyhow, Context, Result};
use ingot_store::paths::DataPaths;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::process::Command;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkRecord {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub bridge: String,
    pub subnet: String,
    pub gateway: String,
    pub created: String,
    pub internal: bool,
    pub attachable: bool,
    pub options: HashMap<String, String>,
    pub labels: HashMap<String, String>,
}

/// What the runtime asks the network manager for when starting a container.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AttachRequest {
    pub container_id: String,
    pub container_name: String,
    pub hostname: String,
    /// Network name or id ("bridge" = default bridge).
    pub network: String,
    /// Host PID of the container init (used to enter its netns).
    pub pid: i64,
    /// Path of the bind-mounted netns file.
    pub netns_path: String,
    pub aliases: Vec<String>,
    /// This container's resolver search domains (--dns-search): stored
    /// per endpoint IP so the embedded server can expand queries from
    /// stub resolvers without client-side search support.
    pub dns_search: Vec<String>,
    /// Requested static IP (connect --ip / EndpointIPAMConfig). None
    /// means dynamic allocation.
    pub requested_ip: Option<String>,
    /// Index of this endpoint on the container: the in-container
    /// interface is named eth{if_index}, and only eth0 installs the
    /// default route. A second endpoint sharing eth0 would collide on
    /// rename and fight over the default route.
    pub if_index: usize,
}

/// The allocated endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct EndpointAllocation {
    pub network_id: String,
    pub network_name: String,
    pub ip: String,
    pub gateway: String,
    pub mac: String,
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PortRule {
    pub container_id: String,
    pub host_ip: String,
    pub host_port: u16,
    pub container_ip: String,
    pub container_port: u16,
    pub proto: String,
}

fn proxy_key(rule: &PortRule) -> String {
    format!(
        "{}|{}|{}:{}",
        rule.container_id, rule.proto, rule.host_ip, rule.host_port
    )
}

/// A host (ip, port, proto) binding collision. Carried inside anyhow so
/// the caller can downcast, resolve the occupier's name, and report a
/// docker-shaped 409.
#[derive(Debug)]
pub struct PortConflict {
    pub proto: String,
    pub host_ip: String,
    pub host_port: u16,
    /// Owning container id; None when held by a non-ingot process.
    pub occupier: Option<String>,
}

impl std::fmt::Display for PortConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ip = if self.host_ip.is_empty() {
            "0.0.0.0"
        } else {
            &self.host_ip
        };
        match &self.occupier {
            Some(id) => write!(
                f,
                "port {}:{}/{} is already allocated by container {}",
                ip,
                self.host_port,
                self.proto,
                &id[..12.min(id.len())]
            ),
            None => write!(
                f,
                "port {}:{}/{} is already in use",
                ip, self.host_port, self.proto
            ),
        }
    }
}

impl std::error::Error for PortConflict {}

/// Host-IP wildcard test for overlap checks ("" and zero addresses bind
/// every interface).
fn publish_ip_wild(ip: &str) -> bool {
    ip.is_empty() || ip == "0.0.0.0" || ip == "::"
}

/// Do two published bindings collide? Same proto+port with overlapping
/// host IPs (a wildcard collides with every specific IP).
fn publish_overlaps(proto: &str, ip: &str, port: u16, other: &PortRule) -> bool {
    other.proto == proto
        && other.host_port == port
        && (publish_ip_wild(ip) || publish_ip_wild(&other.host_ip) || ip == other.host_ip)
}

/// True when no process on this host currently holds (ip, port, proto).
/// Catches bindings owned outside ingot (whose proxy bind would
/// otherwise die silently inside its task).
fn host_port_free(host_ip: &str, port: u16, proto: &str) -> bool {
    if port == 0 {
        return false;
    }
    let ip: std::net::IpAddr = if host_ip.is_empty() {
        std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        let Ok(ip) = host_ip.parse() else {
            return false;
        };
        ip
    };
    if proto == "udp" {
        std::net::UdpSocket::bind((ip, port)).is_ok()
    } else {
        std::net::TcpListener::bind((ip, port)).is_ok()
    }
}

/// Idempotent iptables rule: `-C` first, then `-I` (insert, for filters
/// that must precede generic ACCEPTs) or `-A` (append) on miss. Never
/// duplicates across re-ensures or daemon restarts.
fn iptables_ensure(table: Option<&str>, insert: bool, rule: &[&str]) {
    let mut check: Vec<&str> = Vec::new();
    if let Some(t) = table {
        check.extend(["-t", t]);
    }
    check.push("-C");
    check.extend(rule.iter());
    if sh("iptables", &check).is_err() {
        let mut add: Vec<&str> = Vec::new();
        if let Some(t) = table {
            add.extend(["-t", t]);
        }
        add.push(if insert { "-I" } else { "-A" });
        add.extend(rule.iter());
        let _ = sh("iptables", &add);
    }
}

pub fn sh(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("spawn {cmd} {args:?}"))?;
    if !out.status.success() {
        return Err(anyhow!(
            "{cmd} {:?} failed ({}): {}{}",
            args,
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

fn enable_ip_forward() {
    let _ = std::fs::write("/proc/sys/net/ipv4/ip_forward", "1");
}

/// One network's name → ip registry, shared with its DNS server task.
/// Keys are lowercased on insert (DNS is case-insensitive; the server
/// lowercases queries before lookup).
type DnsRegistry = Arc<tokio::sync::RwLock<HashMap<String, String>>>;
/// Network id → per-network DNS registry.
type DnsRegistries = Arc<tokio::sync::RwLock<HashMap<String, DnsRegistry>>>;
/// One network's container-ip → resolver search domains, for server-side
/// search expansion of queriers whose stub resolver cannot expand
/// (musl-based images ignore resolv.conf `search`).
type DnsSearchMap = Arc<tokio::sync::RwLock<HashMap<String, Vec<String>>>>;
/// Network id → per-network search-domain map.
type DnsSearches = Arc<tokio::sync::RwLock<HashMap<String, DnsSearchMap>>>;
/// Network id → live DNS server task. Aborted on network removal so a
/// removed-then-recreated network never answers from a dead registry
/// (the ghost task would squat the gateway port and NXDOMAIN everything).
type DnsServers = Arc<tokio::sync::Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>;

pub struct NetworkManager {
    paths: DataPaths,
    /// Per-network name → ip registries, each consulted only by its own
    /// network's DNS server: names never leak across networks (docker
    /// parity, and required for `internal` containment to mean anything).
    dns: DnsRegistries,
    dns_search: DnsSearches,
    dns_tasks: DnsServers,
    networks: tokio::sync::RwLock<HashMap<String, NetworkRecord>>,
    ipam: ipam::Ipam,
    /// published port rules: (container_id, host_port, proto, target)
    pub published: tokio::sync::Mutex<Vec<PortRule>>,
    /// userland proxy shutdown senders keyed "container|proto|host:port"
    proxy_handles: tokio::sync::Mutex<HashMap<String, tokio::sync::watch::Sender<bool>>>,
}

impl NetworkManager {
    pub fn new(paths: DataPaths) -> Result<Self> {
        Ok(NetworkManager {
            ipam: ipam::Ipam::new(&paths),
            dns: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            dns_search: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            dns_tasks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            paths,
            networks: tokio::sync::RwLock::new(HashMap::new()),
            published: tokio::sync::Mutex::new(Vec::new()),
            proxy_handles: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Boot: load/create the default bridge network.
    pub async fn boot(&self) -> Result<()> {
        enable_ip_forward();
        if let Ok(rd) = std::fs::read_dir(self.paths.networks()) {
            for entry in rd.flatten() {
                if let Ok(data) = std::fs::read(entry.path()) {
                    if let Ok(rec) = serde_json::from_slice::<NetworkRecord>(&data) {
                        self.networks.write().await.insert(rec.id.clone(), rec);
                    }
                }
            }
        }
        // Conflict audit over persisted records: overlapping subnets on
        // two live bridges blackhole replies, so report every pair loudly
        // (records predate validation or were edited by hand).
        {
            let nets: Vec<NetworkRecord> = self.networks.read().await.values().cloned().collect();
            for (i, a) in nets.iter().enumerate() {
                let Ok(sa) = ipam::Subnet::parse(&a.subnet) else {
                    tracing::warn!("boot: network {} has invalid subnet {:?}", a.name, a.subnet);
                    continue;
                };
                if let Ok(gw) = a.gateway.parse::<std::net::Ipv4Addr>() {
                    let gu: u32 = gw.into();
                    if !sa.contains(gu) {
                        tracing::warn!(
                            "boot: network {} gateway {} is outside subnet {}",
                            a.name,
                            a.gateway,
                            a.subnet
                        );
                    }
                }
                for b in nets.iter().skip(i + 1) {
                    if let Ok(sb) = ipam::Subnet::parse(&b.subnet) {
                        if sa.overlaps(&sb) {
                            tracing::warn!(
                                "boot: network {} ({}) overlaps network {} ({}) — cross-bridge replies may blackhole",
                                a.name,
                                a.subnet,
                                b.name,
                                b.subnet
                            );
                        }
                    }
                }
            }
        }
        // Delete stale bridges left by previous runs (their network records
        // are gone) — duplicate subnets on two bridges blackhole replies.
        let mut keep: Vec<String> = self
            .networks
            .read()
            .await
            .values()
            .map(|n| n.bridge.clone())
            .collect();
        keep.push("lo".into());
        if let Ok(out) = sh("ip", &["-o", "link", "show"]) {
            for line in out.lines() {
                // "12: br-abc@None: <...>" — capture ifname
                let ifname = line
                    .split(':')
                    .nth(1)
                    .unwrap_or("")
                    .trim()
                    .split('@')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if (ifname.starts_with("br-") || ifname == "ingot0") && !keep.contains(&ifname) {
                    tracing::warn!("removing stale bridge {ifname}");
                    let _ = sh("ip", &["link", "del", &ifname]);
                }
            }
        }
        if self.by_name("bridge").await.is_none() {
            let rec = NetworkRecord {
                id: ingot_util::new_id(),
                name: "bridge".into(),
                driver: "bridge".into(),
                bridge: "ingot0".into(),
                subnet: "172.17.0.0/16".into(),
                gateway: "172.17.0.1".into(),
                created: ingot_util::now_rfc3339(),
                ..Default::default()
            };
            self.ensure_bridge(&rec).await?;
            self.save_network(&rec).await?;
        }
        // Re-adopt user-network DNS servers: they were spawned by the
        // dead daemon (create-time only), so without this no name on a
        // user network resolves after a restart. The default bridge
        // keeps host DNS (no embedded server), matching create-time
        // behavior.
        {
            let nets: Vec<NetworkRecord> = self.networks.read().await.values().cloned().collect();
            for rec in &nets {
                if rec.name != "bridge" {
                    self.ensure_dns(rec).await;
                }
            }
        }
        // IPAM orphan sweep: every live lease is referenced by a container
        // record's endpoints, so anything else is garbage from a crashed
        // daemon, a killed --rm reaper, or a deleted network. Runs at boot
        // only — no container is starting yet, so the record set is stable.
        {
            let known: std::collections::HashSet<String> =
                self.networks.read().await.keys().cloned().collect();
            let mut live: std::collections::HashSet<(String, u32)> =
                std::collections::HashSet::new();
            if let Ok(rd) = std::fs::read_dir(self.paths.containers()) {
                for entry in rd.flatten() {
                    let cfg = entry.path().join("config.json");
                    let Ok(data) = std::fs::read(&cfg) else {
                        continue;
                    };
                    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&data) else {
                        continue;
                    };
                    if let Some(eps) = v.get("endpoints").and_then(|e| e.as_array()) {
                        for ep in eps {
                            if let (Some(nid), Some(ip)) = (
                                ep.get("network_id").and_then(|n| n.as_str()),
                                ep.get("ip").and_then(|i| i.as_str()),
                            ) {
                                if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                                    live.insert((nid.to_string(), addr.into()));
                                }
                            }
                        }
                    }
                }
            }
            let (dropped, released) = self.ipam.sweep_orphans(&known, &live).await;
            if dropped > 0 || released > 0 {
                tracing::warn!(
                    "boot: reclaimed {released} orphan lease(s) in {dropped} stale bucket(s)"
                );
            }
        }
        // Base iptables state (idempotent).
        let _ = sh("iptables", &["-t", "nat", "-N", "INGOT-DNAT"]);
        // All containers died with the daemon — stale DNAT rules are garbage.
        let _ = sh("iptables", &["-t", "nat", "-F", "INGOT-DNAT"]);
        // Remove any OUTPUT jump that lacks the loopback exclusion: loopback
        // traffic must reach the userland proxy, not DNAT (docker parity).
        let _ = sh(
            "iptables",
            &[
                "-t",
                "nat",
                "-D",
                "OUTPUT",
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "-j",
                "INGOT-DNAT",
            ],
        );
        for chain in ["PREROUTING", "OUTPUT"] {
            let excl_loopback = chain == "OUTPUT";
            let mut rule: Vec<&str> = vec!["-t", "nat", "-C", chain];
            if excl_loopback {
                rule.extend(["!", "-d", "127.0.0.0/8"]);
            }
            rule.extend(["-m", "addrtype", "--dst-type", "LOCAL", "-j", "INGOT-DNAT"]);
            let add = rule.clone();
            let mut add_rule: Vec<String> = add.iter().map(|s| s.to_string()).collect();
            add_rule[2] = "-A".into();
            let add_refs: Vec<&str> = add_rule.iter().map(|s| s.as_str()).collect();
            let _ = sh("iptables", &rule).or_else(|_| sh("iptables", &add_refs));
        }
        Ok(())
    }

    async fn save_network(&self, rec: &NetworkRecord) -> Result<()> {
        self.networks
            .write()
            .await
            .insert(rec.id.clone(), rec.clone());
        ingot_store::write_json_atomic(&self.paths.network(&rec.id), rec)
    }

    async fn by_name(&self, name: &str) -> Option<NetworkRecord> {
        self.networks
            .read()
            .await
            .values()
            .find(|n| n.name == name)
            .cloned()
    }

    pub async fn get(&self, name_or_id: &str) -> Option<NetworkRecord> {
        let nets = self.networks.read().await;
        nets.values()
            .find(|n| n.id == name_or_id || n.name == name_or_id)
            .cloned()
    }

    pub async fn list(&self) -> Vec<NetworkRecord> {
        self.networks.read().await.values().cloned().collect()
    }

    async fn ensure_bridge(&self, rec: &NetworkRecord) -> Result<()> {
        let exists = sh("ip", &["link", "show", &rec.bridge]).is_ok();
        if !exists {
            sh("ip", &["link", "add", &rec.bridge, "type", "bridge"])?;
            // Mask the gateway with the subnet's own prefix: a hardcoded
            // /16 on a /24 bridge would swallow neighboring subnets.
            let prefix = ipam::Subnet::parse(&rec.subnet)
                .map(|s| s.prefix)
                .unwrap_or(16);
            sh(
                "ip",
                &[
                    "addr",
                    "add",
                    &format!("{}/{}", rec.gateway, prefix),
                    "dev",
                    &rec.bridge,
                ],
            )?;
        }
        sh("ip", &["link", "set", &rec.bridge, "up"])?;
        if rec.internal {
            // Internal network (docker parity): no MASQUERADE (no
            // external NAT) and no forwarding off the bridge in either
            // direction — traffic stays bridge-local. Inserts precede the
            // generic ACCEPTs below; each is -C guarded, so re-ensure
            // never duplicates.
            iptables_ensure(
                None,
                true,
                &[
                    "FORWARD",
                    "-i",
                    &rec.bridge,
                    "!",
                    "-o",
                    &rec.bridge,
                    "-j",
                    "DROP",
                ],
            );
            iptables_ensure(
                None,
                true,
                &[
                    "FORWARD",
                    "-o",
                    &rec.bridge,
                    "!",
                    "-i",
                    &rec.bridge,
                    "-j",
                    "DROP",
                ],
            );
            // Bridge-local hairpin still allowed (policy-independent).
            iptables_ensure(
                None,
                false,
                &[
                    "FORWARD",
                    "-i",
                    &rec.bridge,
                    "-o",
                    &rec.bridge,
                    "-j",
                    "ACCEPT",
                ],
            );
        } else {
            // NAT for this subnet.
            iptables_ensure(
                Some("nat"),
                false,
                &[
                    "POSTROUTING",
                    "-s",
                    &rec.subnet,
                    "!",
                    "-o",
                    &rec.bridge,
                    "-j",
                    "MASQUERADE",
                ],
            );
            // Allow forwarded traffic in/out of this bridge.
            iptables_ensure(None, false, &["FORWARD", "-i", &rec.bridge, "-j", "ACCEPT"]);
            iptables_ensure(None, false, &["FORWARD", "-o", &rec.bridge, "-j", "ACCEPT"]);
        }
        Ok(())
    }

    /// Best-effort removal of one bridge's iptables rules, mirroring
    /// ensure_bridge. Failures are ignored: a half-created network may
    /// never have installed them, and a missing rule is the goal state.
    fn drop_bridge_rules(rec: &NetworkRecord) {
        let drop_rule = |table: Option<&str>, rule: &[&str]| {
            let mut del: Vec<&str> = Vec::new();
            if let Some(t) = table {
                del.extend(["-t", t]);
            }
            del.push("-D");
            del.extend(rule.iter());
            let _ = sh("iptables", &del);
        };
        if rec.internal {
            drop_rule(
                None,
                &[
                    "FORWARD",
                    "-i",
                    &rec.bridge,
                    "!",
                    "-o",
                    &rec.bridge,
                    "-j",
                    "DROP",
                ],
            );
            drop_rule(
                None,
                &[
                    "FORWARD",
                    "-o",
                    &rec.bridge,
                    "!",
                    "-i",
                    &rec.bridge,
                    "-j",
                    "DROP",
                ],
            );
            drop_rule(
                None,
                &[
                    "FORWARD",
                    "-i",
                    &rec.bridge,
                    "-o",
                    &rec.bridge,
                    "-j",
                    "ACCEPT",
                ],
            );
        } else {
            drop_rule(
                Some("nat"),
                &[
                    "POSTROUTING",
                    "-s",
                    &rec.subnet,
                    "!",
                    "-o",
                    &rec.bridge,
                    "-j",
                    "MASQUERADE",
                ],
            );
            drop_rule(None, &["FORWARD", "-i", &rec.bridge, "-j", "ACCEPT"]);
            drop_rule(None, &["FORWARD", "-o", &rec.bridge, "-j", "ACCEPT"]);
        }
    }

    /// Derive the default gateway for a subnet: the first usable host
    /// address (the `.1` rule). Locked by unit test.
    pub fn derive_gateway(subnet: &ipam::Subnet) -> String {
        ipam::default_gateway(subnet).to_string()
    }

    /// Pure create-time validation: parses and normalizes the subnet,
    /// derives or checks the gateway (inside the subnet, never
    /// network/broadcast), and rejects overlaps with existing networks.
    /// Validation failures are phrased "invalid ..." (→ HTTP 400);
    /// overlaps are conflicts (→ HTTP 409).
    fn validate_create_params(
        subnet: &str,
        gateway: Option<&str>,
        existing: &[NetworkRecord],
    ) -> Result<(String, String)> {
        let parsed = ipam::Subnet::parse(subnet).map_err(|e| anyhow!("{e:#}"))?;
        let gw = match gateway {
            Some(g) => {
                let gip: u32 = g
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(|_| anyhow!("invalid gateway {g:?} (want an IPv4 address)"))?
                    .into();
                if !parsed.contains(gip) {
                    return Err(anyhow!(
                        "invalid gateway {g:?}: outside subnet {}",
                        parsed.cidr()
                    ));
                }
                g.to_string()
            }
            None => Self::derive_gateway(&parsed),
        };
        for other in existing {
            if let Ok(o) = ipam::Subnet::parse(&other.subnet) {
                if parsed.overlaps(&o) {
                    return Err(anyhow!(
                        "subnet {} overlaps with network {} ({})",
                        parsed.cidr(),
                        other.name,
                        other.subnet
                    ));
                }
            }
        }
        Ok((parsed.cidr(), gw))
    }

    /// docker network create
    // Seven create options by design; they map 1:1 to the Engine API
    // `POST /networks/create` body, so bundling them would add a type
    // without removing a parameter.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_network(
        &self,
        name: &str,
        driver: &str,
        internal: bool,
        subnet: Option<String>,
        gateway: Option<String>,
        labels: HashMap<String, String>,
        options: HashMap<String, String>,
    ) -> Result<NetworkRecord> {
        if driver != "bridge" && !driver.is_empty() {
            return Err(anyhow!("driver {driver} not supported (bridge only)"));
        }
        if self.by_name(name).await.is_some() {
            return Err(anyhow!("network with name {name} already exists"));
        }
        let (subnet, gateway, bridge) = match subnet {
            Some(s) => {
                let existing: Vec<NetworkRecord> =
                    self.networks.read().await.values().cloned().collect();
                let (subnet, gw) = Self::validate_create_params(&s, gateway.as_deref(), &existing)?;
                (subnet, gw, format!("br-{}", &ingot_util::new_id()[..12]))
            }
            None => {
                let mut chosen = None;
                'outer: for b in 18..=31u8 {
                    let candidate = format!("172.{b}.0.0/16");
                    let cand_parsed = ipam::Subnet::parse(&candidate)?;
                    let nets = self.networks.read().await;
                    let clash = nets.values().any(|n| {
                        ipam::Subnet::parse(&n.subnet)
                            .map(|o| cand_parsed.overlaps(&o))
                            .unwrap_or(false)
                    });
                    drop(nets);
                    if !clash {
                        chosen = Some((candidate, format!("172.{b}.0.1")));
                        break 'outer;
                    }
                }
                let (s, gw) = chosen.ok_or_else(|| {
                    anyhow!("all predefined address pools have been fully subnetted")
                })?;
                (s, gw, format!("br-{}", &ingot_util::new_id()[..12]))
            }
        };
        let rec = NetworkRecord {
            id: ingot_util::new_id(),
            name: name.into(),
            driver: "bridge".into(),
            bridge,
            subnet,
            gateway,
            created: ingot_util::now_rfc3339(),
            internal,
            attachable: false,
            options,
            labels,
        };
        self.ensure_bridge(&rec).await?;
        self.save_network(&rec).await?;
        self.ensure_dns(&rec).await;
        Ok(rec)
    }

    /// Per-network name → ip map, created on demand.
    async fn dns_map(&self, net_id: &str) -> DnsRegistry {
        self.dns
            .write()
            .await
            .entry(net_id.to_string())
            .or_default()
            .clone()
    }

    /// Per-network ip → search-domains map, created on demand.
    async fn dns_search_map(&self, net_id: &str) -> DnsSearchMap {
        self.dns_search
            .write()
            .await
            .entry(net_id.to_string())
            .or_default()
            .clone()
    }

    /// (Re)spawn the embedded DNS server on a network's gateway, serving
    /// only that network's names. Any previous server task for this
    /// network is aborted first (a removed-then-recreated network must
    /// not answer from a dead registry); a bind failure still only warns.
    async fn ensure_dns(&self, rec: &NetworkRecord) {
        if let Ok(gw) = rec.gateway.parse::<std::net::Ipv4Addr>() {
            if let Some(old) = self.dns_tasks.lock().await.remove(&rec.id) {
                old.abort();
            }
            let records = self.dns_map(&rec.id).await;
            let searches = self.dns_search_map(&rec.id).await;
            match dns::spawn_dns_server(gw, records, searches).await {
                Ok(handle) => {
                    self.dns_tasks.lock().await.insert(rec.id.clone(), handle);
                }
                Err(e) => tracing::warn!("DNS server for {} failed: {e}", rec.name),
            }
        }
    }

    pub async fn remove_network(&self, name_or_id: &str) -> Result<()> {
        let rec = self
            .get(name_or_id)
            .await
            .ok_or_else(|| anyhow!("network not found: {name_or_id}"))?;
        if rec.name == "bridge" {
            return Err(anyhow!(
                "bridge is a pre-defined network and cannot be removed"
            ));
        }
        let _ = sh("ip", &["link", "del", &rec.bridge]);
        // Drop this bridge's dataplane rules with it: FORWARD guards and
        // MASQUERADE otherwise accumulate forever (one pair per removed
        // network) and slow every future iptables invocation.
        Self::drop_bridge_rules(&rec);
        self.networks.write().await.remove(&rec.id);
        // Stop this network's DNS server and drop its registry: a ghost
        // task would squat the gateway port and answer from dead names.
        if let Some(task) = self.dns_tasks.lock().await.remove(&rec.id) {
            task.abort();
        }
        self.dns.write().await.remove(&rec.id);
        self.dns_search.write().await.remove(&rec.id);
        let _ = std::fs::remove_file(self.paths.network(&rec.id));
        // The bridge and its endpoints are gone: no lease in this
        // bucket can be live. Refusing removal while endpoints exist
        // is the API layer's guard; this stays unconditional.
        self.ipam.reset_bucket(&rec.id).await;
        Ok(())
    }

    /// Resolve a network name, id, or alias ("", "default", "bridge" →
    /// the default bridge) to its record. Fail-closed on unknown names.
    pub async fn resolve(&self, name_or_id: &str) -> Result<NetworkRecord> {
        match self.get(name_or_id).await {
            Some(n) => Ok(n),
            // Only the implicit default falls back to the bridge network.
            None if name_or_id.is_empty() || name_or_id == "default" || name_or_id == "bridge" => {
                self.by_name("bridge")
                    .await
                    .ok_or_else(|| anyhow!("bridge network missing"))
            }
            None => Err(anyhow!("no such network: {name_or_id}")),
        }
    }

    /// Attach a container's netns to its network (lease + veth +
    /// addressing).
    pub async fn attach(&self, req: &AttachRequest) -> Result<EndpointAllocation> {
        let net = self.resolve(&req.network).await?;
        self.ensure_bridge(&net).await?;
        let prefix = ipam::Subnet::parse(&net.subnet)
            .map(|s| s.prefix)
            .unwrap_or(16);
        let ip = match req.requested_ip.as_deref().filter(|s| !s.is_empty()) {
            Some(want) => {
                self.ipam
                    .reserve(&net.id, &net.subnet, &net.gateway, want)
                    .await?
            }
            None => {
                self.ipam
                    .allocate(&net.id, &net.subnet, &net.gateway)
                    .await?
            }
        };
        // Any setup failure past this point must hand the lease back (the
        // wire step drops its own half-built veth on error).
        match self.wire(&net, req, ip, prefix).await {
            Ok(ep) => Ok(ep),
            Err(e) => {
                self.ipam.release(&net.id, &ip.to_string()).await;
                Err(e)
            }
        }
    }

    /// Re-wire a recorded endpoint at (re)start: the lease is already
    /// held by the container record (stop never releases; remove and
    /// disconnect do), so this skips allocation and only rebuilds the
    /// veth + addressing + DNS for the recorded IP.
    pub async fn rewire(
        &self,
        network: &str,
        req: &AttachRequest,
        ip: std::net::Ipv4Addr,
    ) -> Result<EndpointAllocation> {
        let net = self.resolve(network).await?;
        self.ensure_bridge(&net).await?;
        let prefix = ipam::Subnet::parse(&net.subnet)
            .map(|s| s.prefix)
            .unwrap_or(16);
        self.wire(&net, req, ip, prefix).await
    }

    /// Build the veth pair and configure the container side; drops the
    /// half-built pair on error.
    async fn wire(
        &self,
        net: &NetworkRecord,
        req: &AttachRequest,
        ip: std::net::Ipv4Addr,
        prefix: u8,
    ) -> Result<EndpointAllocation> {
        let host_if = Self::endpoint_ifname(&req.container_id, &net.id);
        match self.attach_inner(net, req, ip, prefix).await {
            Ok(ep) => Ok(ep),
            Err(e) => {
                let _ = sh("ip", &["link", "del", &host_if]);
                Err(e)
            }
        }
    }

    /// Host-side veth name for one (container, network) endpoint. Scoped
    /// per endpoint — not per container — so a container on N networks
    /// gets N pairs (docker parity); a shared name would collide on the
    /// second connect. 13 chars, leaving room for the "-p" peer suffix
    /// under the 15-char ifname limit.
    fn endpoint_ifname(container_id: &str, net_id: &str) -> String {
        let c = &container_id[..4.min(container_id.len())];
        let n = &net_id[..4.min(net_id.len())];
        format!("veth-{c}{n}")
    }

    /// veth + addressing + DNS registration for an already-leased IP.
    async fn attach_inner(
        &self,
        net: &NetworkRecord,
        req: &AttachRequest,
        ip: std::net::Ipv4Addr,
        prefix: u8,
    ) -> Result<EndpointAllocation> {
        let host_if = Self::endpoint_ifname(&req.container_id, &net.id);
        let peer = format!("{host_if}-p");

        sh(
            "ip",
            &[
                "link", "add", &host_if, "type", "veth", "peer", "name", &peer,
            ],
        )?;
        sh("ip", &["link", "set", &host_if, "master", &net.bridge])?;
        sh("ip", &["link", "set", &host_if, "up"])?;
        sh("ip", &["link", "set", &peer, "netns", &req.pid.to_string()])?;

        // Configure inside the container's netns (via /proc — always valid).
        let proc_netns = format!("/proc/{}/ns/net", req.pid);
        let enter = |args: &[&str]| -> Result<String> {
            let net_arg = format!("--net={proc_netns}");
            let mut full: Vec<&str> = vec!["--net=&dummy", &net_arg];
            full[0] = "--net=__unused__"; // placeholder removed below
                                          // nsenter optional args require the '=' form; build explicitly.
            let mut cmd_args: Vec<String> = vec![net_arg];
            cmd_args.extend(args.iter().map(|s| s.to_string()));
            let refs: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
            sh("nsenter", &refs)
        };
        // One interface per endpoint (eth0, eth1, ...); only the first
        // installs the default route — a second `route add default`
        // would fail and two defaults would fight anyway.
        let ifname = format!("eth{}", req.if_index);
        enter(&["ip", "link", "set", &peer, "name", &ifname])?;
        enter(&[
            "ip",
            "addr",
            "add",
            &format!("{ip}/{prefix}"),
            "dev",
            &ifname,
        ])?;
        enter(&["ip", "link", "set", &ifname, "up"])?;
        enter(&["ip", "link", "set", "lo", "up"])?;
        if req.if_index == 0 {
            enter(&["ip", "route", "add", "default", "via", &net.gateway])?;
        }

        // Register DNS entries on this network only (container name +
        // hostname + aliases → ip), plus this endpoint's search domains
        // keyed by IP for server-side expansion.
        {
            let map = self.dns_map(&net.id).await;
            let mut reg = map.write().await;
            reg.insert(req.container_name.to_ascii_lowercase(), ip.to_string());
            reg.insert(req.hostname.to_ascii_lowercase(), ip.to_string());
            for a in &req.aliases {
                reg.insert(a.to_ascii_lowercase(), ip.to_string());
            }
        }
        if !req.dns_search.is_empty() {
            let smap = self.dns_search_map(&net.id).await;
            smap.write()
                .await
                .insert(ip.to_string(), req.dns_search.clone());
        }
        Ok(EndpointAllocation {
            network_id: net.id.clone(),
            network_name: net.name.clone(),
            ip: ip.to_string(),
            gateway: net.gateway.clone(),
            mac: String::new(),
            aliases: req.aliases.clone(),
        })
    }

    /// Drop one endpoint's host-side veth (new scoped name, with a
    /// legacy one-name-per-container fallback: the old scheme could only
    /// ever create a single endpoint per container, so the fallback
    /// cannot hit a sibling endpoint).
    fn drop_veth(container_id: &str, net_id: &str) {
        let host_if = Self::endpoint_ifname(container_id, net_id);
        if sh("ip", &["link", "show", &host_if]).is_ok() {
            let _ = sh("ip", &["link", "del", &host_if]);
        } else {
            let legacy = format!("veth-{}", &container_id[..8.min(container_id.len())]);
            let _ = sh("ip", &["link", "del", &legacy]);
        }
    }

    /// Undo a start-time wire without releasing the lease: the endpoint
    /// stays recorded (and leased), so a retried start re-wires cleanly
    /// instead of colliding with its own stranded veth.
    pub async fn unwire(&self, net_id: &str, container_id: &str) {
        Self::drop_veth(container_id, net_id);
    }

    /// (Re)register DNS names for a surviving endpoint on its own
    /// network (used after a disconnect when the shared container name
    /// needs to keep resolving on the remaining networks).
    pub async fn register_dns(&self, net_id: &str, keys: &[String], ip: &str) {
        let map = self.dns_map(net_id).await;
        let mut reg = map.write().await;
        for k in keys {
            reg.insert(k.to_ascii_lowercase(), ip.to_string());
        }
    }

    /// Detach (container removal / network disconnect): drop the veth,
    /// release the lease, and deregister this endpoint's DNS names from
    /// its own network's registry. A key is removed only when it still
    /// points at the released IP.
    pub async fn detach(&self, net_id: &str, ip: &str, container_id: &str, dns_keys: &[String]) {
        Self::drop_veth(container_id, net_id);
        self.ipam.release(net_id, ip).await;
        let dns = self.dns.read().await;
        if let Some(map) = dns.get(net_id) {
            let mut reg = map.write().await;
            for k in dns_keys {
                let kl = k.to_ascii_lowercase();
                if reg.get(&kl).is_some_and(|v| v == ip) {
                    reg.remove(&kl);
                }
            }
        }
        // The endpoint is gone and its lease released: its per-IP search
        // entry would only misdirect later queriers from a reused IP.
        if let Some(smap) = self.dns_search.read().await.get(net_id) {
            smap.write().await.remove(ip);
        }
    }

    /// Publish a port: userland proxy (127.x / host local reachability) +
    /// DNAT + FORWARD rule for external traffic (docker parity).
    ///
    /// Lock order is `published` → `proxy_handles` (matching
    /// unpublish_all): the conflict check, reservation, and proxy spawn
    /// are atomic, so two concurrent starts cannot double-allocate. An
    /// identical re-publish (restart) is a silent no-op; a clash with
    /// another container's binding fails with [`PortConflict`].
    pub async fn publish_port(&self, rule: PortRule) -> Result<()> {
        let mut all = self.published.lock().await;
        if all.iter().any(|r| {
            r.container_id == rule.container_id
                && r.proto == rule.proto
                && r.host_ip == rule.host_ip
                && r.host_port == rule.host_port
                && r.container_ip == rule.container_ip
                && r.container_port == rule.container_port
        }) {
            return Ok(());
        }
        if let Some(prior) = all.iter().find(|r| {
            r.container_id != rule.container_id
                && publish_overlaps(&rule.proto, &rule.host_ip, rule.host_port, r)
        }) {
            return Err(anyhow!(PortConflict {
                proto: rule.proto.clone(),
                host_ip: rule.host_ip.clone(),
                host_port: rule.host_port,
                occupier: Some(prior.container_id.clone()),
            }));
        }
        if !host_port_free(&rule.host_ip, rule.host_port, &rule.proto) {
            return Err(anyhow!(PortConflict {
                proto: rule.proto.clone(),
                host_ip: rule.host_ip.clone(),
                host_port: rule.host_port,
                occupier: None,
            }));
        }
        sh(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "INGOT-DNAT",
                "-p",
                &rule.proto,
                "-d",
                if publish_ip_wild(&rule.host_ip) {
                    "0.0.0.0/0"
                } else {
                    &rule.host_ip
                },
                "--dport",
                &rule.host_port.to_string(),
                "-j",
                "DNAT",
                "--to-destination",
                &format!("{}:{}", rule.container_ip, rule.container_port),
            ],
        )?;
        sh(
            "iptables",
            &[
                "-A",
                "FORWARD",
                "-p",
                &rule.proto,
                "-d",
                &rule.container_ip,
                "--dport",
                &rule.container_port.to_string(),
                "-j",
                "ACCEPT",
            ],
        )?;
        // Userland proxy: listen on the host port and relay to the container.
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let target: std::net::SocketAddr = format!("{}:{}", rule.container_ip, rule.container_port)
            .parse()
            .context("parse container addr")?;
        let bind_ip: std::net::IpAddr = if rule.host_ip.is_empty() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            rule.host_ip.parse().context("parse host ip")?
        };
        let proto = rule.proto.clone();
        let hp = rule.host_port;
        tokio::spawn(async move {
            let _ = crate::proxy::run_proxy(bind_ip, hp, target, &proto, shutdown_rx).await;
        });
        self.proxy_handles
            .lock()
            .await
            .insert(proxy_key(&rule), shutdown_tx);
        all.push(rule);
        Ok(())
    }

    /// Pick a free ephemeral host port for `-P` / empty HostPort: not in
    /// our published set and not bound by any host process right now.
    pub async fn allocate_ephemeral_port(&self, proto: &str) -> u16 {
        let used: Vec<u16> = self
            .published
            .lock()
            .await
            .iter()
            .filter(|r| r.proto == proto)
            .map(|r| r.host_port)
            .collect();
        for p in 32768..=60999u16 {
            if !used.contains(&p) && host_port_free("", p, proto) {
                return p;
            }
        }
        32768
    }

    /// Live published rules for one container (inspect/ps rendering of
    /// ephemeral and `-P` mappings, which exist only here).
    pub async fn published_for(&self, container_id: &str) -> Vec<PortRule> {
        self.published
            .lock()
            .await
            .iter()
            .filter(|r| r.container_id == container_id)
            .cloned()
            .collect()
    }

    /// Unpublish everything for a container. Lock order matches
    /// publish_port (`published` → `proxy_handles`).
    pub async fn unpublish_all(&self, container_id: &str) {
        let mut all = self.published.lock().await;
        {
            let mut handles = self.proxy_handles.lock().await;
            for (k, tx) in handles.iter() {
                if k.starts_with(&format!("{container_id}|")) {
                    let _ = tx.send(true);
                }
            }
            handles.retain(|k, _| !k.starts_with(&format!("{container_id}|")));
        }
        let mut kept = Vec::new();
        for r in all.drain(..) {
            if r.container_id == container_id {
                let _ = sh(
                    "iptables",
                    &[
                        "-t",
                        "nat",
                        "-D",
                        "INGOT-DNAT",
                        "-p",
                        &r.proto,
                        "-d",
                        if publish_ip_wild(&r.host_ip) {
                            "0.0.0.0/0"
                        } else {
                            &r.host_ip
                        },
                        "--dport",
                        &r.host_port.to_string(),
                        "-j",
                        "DNAT",
                        "--to-destination",
                        &format!("{}:{}", r.container_ip, r.container_port),
                    ],
                );
                let _ = sh(
                    "iptables",
                    &[
                        "-D",
                        "FORWARD",
                        "-p",
                        &r.proto,
                        "-d",
                        &r.container_ip,
                        "--dport",
                        &r.container_port.to_string(),
                        "-j",
                        "ACCEPT",
                    ],
                );
            } else {
                kept.push(r);
            }
        }
        *all = kept;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publish_overlap_matrix() {
        let rule = |ip: &str, port: u16, proto: &str| PortRule {
            container_id: "a".into(),
            host_ip: ip.into(),
            host_port: port,
            container_ip: "10.0.0.2".into(),
            container_port: 80,
            proto: proto.into(),
        };
        // Wildcard collides with everything on the same proto+port.
        assert!(publish_overlaps("tcp", "", 80, &rule("", 80, "tcp")));
        assert!(publish_overlaps(
            "tcp",
            "",
            80,
            &rule("127.0.0.1", 80, "tcp")
        ));
        assert!(publish_overlaps(
            "tcp",
            "127.0.0.1",
            80,
            &rule("", 80, "tcp")
        ));
        assert!(publish_overlaps(
            "tcp",
            "0.0.0.0",
            8080,
            &rule("10.0.0.9", 8080, "tcp")
        ));
        // Same specific IP collides; different ones don't.
        assert!(publish_overlaps(
            "tcp",
            "127.0.0.1",
            80,
            &rule("127.0.0.1", 80, "tcp")
        ));
        assert!(!publish_overlaps(
            "tcp",
            "127.0.0.1",
            80,
            &rule("10.0.0.9", 80, "tcp")
        ));
        // Different ports or protos never collide.
        assert!(!publish_overlaps("tcp", "", 80, &rule("", 81, "tcp")));
        assert!(!publish_overlaps("tcp", "", 80, &rule("", 80, "udp")));
        // Conflict message names the occupier (or says "in use").
        let named = PortConflict {
            proto: "tcp".into(),
            host_ip: "".into(),
            host_port: 8080,
            occupier: Some("abcdef1234567890".into()),
        };
        assert_eq!(
            named.to_string(),
            "port 0.0.0.0:8080/tcp is already allocated by container abcdef123456"
        );
        let anon = PortConflict {
            proto: "udp".into(),
            host_ip: "127.0.0.1".into(),
            host_port: 53,
            occupier: None,
        };
        assert_eq!(anon.to_string(), "port 127.0.0.1:53/udp is already in use");
    }

    #[test]
    fn endpoint_ifname_is_scoped_and_short() {
        let a = NetworkManager::endpoint_ifname("abcdef123456", "net111111");
        let b = NetworkManager::endpoint_ifname("abcdef123456", "net222222");
        assert_ne!(a, b);
        assert!(a.len() <= 13 && format!("{a}-p").len() <= 15);
        // Deterministic across calls (detach must recompute attach's name).
        assert_eq!(
            a,
            NetworkManager::endpoint_ifname("abcdef123456", "net111111")
        );
    }

    #[tokio::test]
    async fn detach_deregisters_only_its_own_dns_names() {
        let dir = std::env::temp_dir().join(format!("net-detach-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mgr = NetworkManager::new(DataPaths::new(dir.clone(), dir.clone())).unwrap();
        // Same name on two networks: each registry is independent.
        mgr.register_dns("net-a", &["web".to_string()], "10.0.0.5")
            .await;
        mgr.register_dns("net-b", &["web".to_string()], "10.0.1.5")
            .await;
        mgr.register_dns("net-a", &["other".to_string()], "10.0.0.5")
            .await;
        // Detaching net-a clears only net-a's entries.
        mgr.detach("net-a", "10.0.0.5", "cid", &["web".to_string()])
            .await;
        let dns = mgr.dns.read().await;
        let a = dns.get("net-a").unwrap().read().await;
        let b = dns.get("net-b").unwrap().read().await;
        assert!(a.get("web").is_none());
        assert_eq!(a.get("other").map(String::as_str), Some("10.0.0.5"));
        assert_eq!(b.get("web").map(String::as_str), Some("10.0.1.5"));
        drop(a);
        drop(b);
        drop(dns);
        // Detaching net-b removes the name there too.
        mgr.detach("net-b", "10.0.1.5", "cid", &["web".to_string()])
            .await;
        let dns = mgr.dns.read().await;
        assert!(dns.get("net-b").unwrap().read().await.get("web").is_none());
        drop(dns);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn dns_registry_is_case_insensitive_and_drops_search_on_detach() {
        let dir = std::env::temp_dir().join(format!("net-dnscase-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mgr = NetworkManager::new(DataPaths::new(dir.clone(), dir.clone())).unwrap();
        mgr.register_dns("net-a", &["WebApp".to_string()], "10.0.0.5")
            .await;
        mgr.dns_search_map("net-a")
            .await
            .write()
            .await
            .insert("10.0.0.5".to_string(), vec!["svc".to_string()]);
        {
            let dns = mgr.dns.read().await;
            let a = dns.get("net-a").unwrap().read().await;
            assert_eq!(a.get("webapp").map(String::as_str), Some("10.0.0.5"));
        }
        // Detach with original casing still deregisters, and the
        // endpoint's search entry dies with its lease.
        mgr.detach("net-a", "10.0.0.5", "cid", &["WebApp".to_string()])
            .await;
        {
            let dns = mgr.dns.read().await;
            assert!(dns
                .get("net-a")
                .unwrap()
                .read()
                .await
                .get("webapp")
                .is_none());
        }
        assert!(mgr
            .dns_search
            .read()
            .await
            .get("net-a")
            .unwrap()
            .read()
            .await
            .get("10.0.0.5")
            .is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn rec(name: &str, subnet: &str) -> NetworkRecord {
        NetworkRecord {
            id: format!("id-{name}"),
            name: name.into(),
            subnet: subnet.into(),
            gateway: "x".into(),
            ..Default::default()
        }
    }

    #[test]
    fn gateway_derivation_is_first_usable() {
        // The `.1` rule, locked: default gateway is always the first
        // usable host address of the subnet.
        for (cidr, gw) in [
            ("172.17.0.0/16", "172.17.0.1"),
            ("10.1.2.0/24", "10.1.2.1"),
            ("192.168.9.0/30", "192.168.9.1"),
            ("10.0.0.0/8", "10.0.0.1"),
        ] {
            let s = ipam::Subnet::parse(cidr).unwrap();
            assert_eq!(NetworkManager::derive_gateway(&s), gw, "{cidr}");
        }
    }

    #[test]
    fn create_validation() {
        let existing = vec![rec("prod", "172.18.0.0/16")];
        // Derives gateway, normalizes host bits.
        let (s, g) =
            NetworkManager::validate_create_params("172.20.5.99/24", None, &existing).unwrap();
        assert_eq!((s.as_str(), g.as_str()), ("172.20.5.0/24", "172.20.5.1"));
        // Explicit in-subnet gateway kept (even non-.1).
        let (_, g) = NetworkManager::validate_create_params(
            "172.20.0.0/16",
            Some("172.20.0.254"),
            &existing,
        )
        .unwrap();
        assert_eq!(g, "172.20.0.254");
        // Overlaps (exact, nested, gateway-outside, bad input) rejected.
        assert!(NetworkManager::validate_create_params("172.18.0.0/16", None, &existing).is_err());
        assert!(NetworkManager::validate_create_params("172.18.9.0/24", None, &existing).is_err());
        assert!(NetworkManager::validate_create_params(
            "172.20.0.0/16",
            Some("172.21.0.1"),
            &existing
        )
        .is_err());
        assert!(NetworkManager::validate_create_params(
            "172.20.0.0/16",
            Some("172.20.0.0"),
            &existing
        )
        .is_err());
        assert!(NetworkManager::validate_create_params("garbage", None, &existing).is_err());
        assert!(
            NetworkManager::validate_create_params("172.20.0.0/16", Some("nope"), &existing)
                .is_err()
        );
        // Non-overlapping passes.
        assert!(NetworkManager::validate_create_params("172.21.0.0/16", None, &existing).is_ok());
    }
}
