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

/// Default IPv6 ULA pool for per-network /64s (dockerd
/// `--fixed-cidr-v6` equivalent). ingotd's `--fixed-cidr-v6` overrides it.
pub const DEFAULT_FIXED_CIDR_V6: &str = "fd00:dead:beef::/48";
/// Prefix length carved per network out of the v6 pool.
pub const V6_SUBNET_PREFIX: u8 = 64;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct NetworkRecord {
    pub id: String,
    pub name: String,
    pub driver: String,
    pub bridge: String,
    pub subnet: String,
    pub gateway: String,
    /// Dual-stack ULA range (e.g. "fd00:dead:beef:3::/64"). Empty means
    /// v6 is off for this network; container `#[serde(default)]` migrates
    /// pre-dual-stack records to v6-disabled.
    pub subnet_v6: String,
    /// First usable address of `subnet_v6` (the ::1 rule). Empty = off.
    pub gateway_v6: String,
    pub created: String,
    pub internal: bool,
    pub attachable: bool,
    pub options: HashMap<String, String>,
    pub labels: HashMap<String, String>,
}

impl NetworkRecord {
    /// True when this network carries a dual-stack v6 range.
    pub fn has_ipv6(&self) -> bool {
        !self.subnet_v6.is_empty() && !self.gateway_v6.is_empty()
    }
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
    /// Dual-stack v6 address. Empty when the network has v6 disabled.
    pub ipv6: String,
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

/// One ip6tables rule for a dual-stack bridge, in ensure/delete form.
/// Pure data: [`v6_network_rules`] builds it, the async ensure/delete
/// fns execute it, and unit tests assert its shape without touching
/// netfilter (rootless-safe).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ip6Rule {
    /// nat table selector, e.g. Some("nat"); None = filter table.
    table: Option<&'static str>,
    /// true = `-I` (head, for DROP guards), false = `-A`.
    insert: bool,
    args: Vec<String>,
}

impl Ip6Rule {
    fn full_args(&self, op: &str) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(t) = self.table {
            out.push("-t".to_string());
            out.push(t.to_string());
        }
        out.push(op.to_string());
        out.extend(self.args.iter().cloned());
        out
    }
}

/// Pure: this network's v6 dataplane, mirroring the v4 MASQUERADE /
/// FORWARD / internal-DROP rules in [`NetworkManager::ensure_bridge`].
/// Empty when the network has v6 disabled. No side effects.
fn v6_network_rules(rec: &NetworkRecord) -> Vec<Ip6Rule> {
    if !rec.has_ipv6() {
        return Vec::new();
    }
    let b = rec.bridge.clone();
    let s = rec.subnet_v6.clone();
    if rec.internal {
        // No MASQUERADE and no forwarding off the bridge (docker
        // parity for internal): DROP both directions, ACCEPT hairpin.
        vec![
            Ip6Rule {
                table: None,
                insert: true,
                args: vec![
                    "FORWARD".into(),
                    "-i".into(),
                    b.clone(),
                    "!".into(),
                    "-o".into(),
                    b.clone(),
                    "-j".into(),
                    "DROP".into(),
                ],
            },
            Ip6Rule {
                table: None,
                insert: true,
                args: vec![
                    "FORWARD".into(),
                    "-o".into(),
                    b.clone(),
                    "!".into(),
                    "-i".into(),
                    b.clone(),
                    "-j".into(),
                    "DROP".into(),
                ],
            },
            Ip6Rule {
                table: None,
                insert: false,
                args: vec![
                    "FORWARD".into(),
                    "-i".into(),
                    b.clone(),
                    "-o".into(),
                    b,
                    "-j".into(),
                    "ACCEPT".into(),
                ],
            },
        ]
    } else {
        vec![
            Ip6Rule {
                table: Some("nat"),
                insert: false,
                args: vec![
                    "POSTROUTING".into(),
                    "-s".into(),
                    s,
                    "!".into(),
                    "-o".into(),
                    b.clone(),
                    "-j".into(),
                    "MASQUERADE".into(),
                ],
            },
            Ip6Rule {
                table: None,
                insert: false,
                args: vec![
                    "FORWARD".into(),
                    "-i".into(),
                    b.clone(),
                    "-j".into(),
                    "ACCEPT".into(),
                ],
            },
            Ip6Rule {
                table: None,
                insert: false,
                args: vec![
                    "FORWARD".into(),
                    "-o".into(),
                    b,
                    "-j".into(),
                    "ACCEPT".into(),
                ],
            },
        ]
    }
}

/// Pure: `ip -6 addr add` argument for the bridge's v6 gateway.
fn v6_bridge_addr(gateway_v6: &str, prefix: u8) -> String {
    format!("{gateway_v6}/{prefix}")
}

/// FNV-1a/64 (no new dependencies): stable hash so a network id
/// re-derives the same pool slot across restarts.
fn fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Pure: carve a /64 for `net_id` out of the ULA `pool`, probing forward
/// from a stable hash over colliding slots in `existing_v6`. Returns
/// (subnet_cidr, gateway). A full pool is a conflict-style error (→ 409),
/// bad pool input an "invalid ..." error (→ 400).
fn assign_v6_subnet(pool: &str, net_id: &str, existing_v6: &[String]) -> Result<(String, String)> {
    let pool_sub = ipam::V6Subnet::parse(pool)
        .map_err(|e| anyhow!("invalid fixed-cidr-v6 {pool:?}: {e:#}"))?;
    if pool_sub.prefix > V6_SUBNET_PREFIX {
        return Err(anyhow!(
            "invalid fixed-cidr-v6 {pool:?} (prefix must be /{} or shorter for /{}-per-network allocation)",
            V6_SUBNET_PREFIX,
            V6_SUBNET_PREFIX
        ));
    }
    let used: Vec<u128> = existing_v6
        .iter()
        .filter_map(|c| ipam::V6Subnet::parse(c).ok())
        .map(|s| s.network)
        .collect();
    // Number of /64s in the pool; the index occupies address bits
    // [pool_prefix, 64), i.e. u128 bits [64, 128-pool_prefix).
    let capacity: u128 = 1u128 << (V6_SUBNET_PREFIX - pool_sub.prefix);
    let start = u128::from(fnv1a64(net_id)) % capacity;
    let mut step: u128 = 0;
    loop {
        let idx = (start + step) % capacity;
        let network = pool_sub.network | (idx << (128 - V6_SUBNET_PREFIX));
        if !used.contains(&network) {
            let sub = ipam::V6Subnet {
                network,
                prefix: V6_SUBNET_PREFIX,
            };
            return Ok((sub.cidr(), ipam::default_gateway_v6(&sub).to_string()));
        }
        step += 1;
        if step >= capacity {
            break;
        }
    }
    Err(anyhow!("all IPv6 address pools have been fully subnetted"))
}

/// Async idempotent iptables rule (off-executor): `-C` first, then
/// `-I`/`-A` on miss. Sync callers use `sh` directly.
async fn iptables_ensure_async(table: Option<&str>, insert: bool, rule: &[&str]) -> Result<()> {
    let mut check: Vec<String> = Vec::new();
    if let Some(t) = table {
        check.extend(["-t".to_string(), t.to_string()]);
    }
    check.push("-C".to_string());
    check.extend(rule.iter().map(|s| s.to_string()));
    let check_refs: Vec<&str> = check.iter().map(|s| s.as_str()).collect();
    if sh_async("iptables", &check_refs).await.is_err() {
        let mut add: Vec<String> = Vec::new();
        if let Some(t) = table {
            add.extend(["-t".to_string(), t.to_string()]);
        }
        add.push(if insert { "-I" } else { "-A" }.to_string());
        add.extend(rule.iter().map(|s| s.to_string()));
        let add_refs: Vec<&str> = add.iter().map(|s| s.as_str()).collect();
        sh_async("iptables", &add_refs).await?;
    }
    Ok(())
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

/// Async idempotent ip6tables rule (off-executor), mirroring
/// [`iptables_ensure_async`]: `-C` first, then `-I`/`-A` on miss.
async fn ip6tables_ensure_async(rule: &Ip6Rule) -> Result<()> {
    let check = rule.full_args("-C");
    let check_refs: Vec<&str> = check.iter().map(|s| s.as_str()).collect();
    if sh_async("ip6tables", &check_refs).await.is_err() {
        let add = rule.full_args(if rule.insert { "-I" } else { "-A" });
        let add_refs: Vec<&str> = add.iter().map(|s| s.as_str()).collect();
        sh_async("ip6tables", &add_refs).await?;
    }
    Ok(())
}

/// Best-effort ip6tables delete of one [`Ip6Rule`] (rollback / removal).
async fn ip6tables_delete_async(rule: &Ip6Rule) {
    let del = rule.full_args("-D");
    let refs: Vec<&str> = del.iter().map(|s| s.as_str()).collect();
    let _ = sh_async("ip6tables", &refs).await;
}

/// Async wrapper that moves the blocking fork/exec off the Tokio executor.
/// All async network paths must use this instead of [`sh`] to avoid
/// stalling workers 5-20ms per iptables/ip invocation.
pub async fn sh_async(cmd: &str, args: &[&str]) -> Result<String> {
    let cmd = cmd.to_string();
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    tokio::task::spawn_blocking(move || {
        let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        sh(&cmd, &refs)
    })
    .await?
}

fn enable_ip_forward() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .context("failed to enable /proc/sys/net/ipv4/ip_forward")?;
    Ok(())
}

fn enable_ip6_forward() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", "1")
        .context("failed to enable /proc/sys/net/ipv6/conf/all/forwarding")?;
    Ok(())
}

/// Daemon-level IPv6 dual-stack switch (ingotd `--ipv6` /
/// `--fixed-cidr-v6`; dockerd `--ipv6` / `--fixed-cidr-v6` equivalent).
/// Off by default (docker parity): no v6 ranges, addresses, or rules
/// are created until enabled.
#[derive(Debug, Clone)]
struct Ipv6Config {
    enabled: bool,
    pool: String,
}

impl Default for Ipv6Config {
    fn default() -> Self {
        Ipv6Config {
            enabled: false,
            pool: DEFAULT_FIXED_CIDR_V6.to_string(),
        }
    }
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
    /// Per-network name → IPv6 registries, parallel to [`NetworkManager::dns`].
    dns6: DnsRegistries,
    dns_search: DnsSearches,
    dns_tasks: DnsServers,
    /// Daemon-level dual-stack switch (ingotd `--ipv6`).
    ipv6: tokio::sync::RwLock<Ipv6Config>,
    /// (network id, v4 ip) → v6 ip for live endpoints, so [`NetworkManager::detach`]
    /// can release the v6 lease and scrub v6 DNS without a signature
    /// change. In-memory only: v6 leases are dynamic per boot until the
    /// container record persists them (boot sweeps them, see
    /// [`ipam::Ipam::sweep_orphans_v6`]).
    v6_by_v4: tokio::sync::Mutex<HashMap<(String, String), String>>,
    networks: tokio::sync::RwLock<HashMap<String, NetworkRecord>>,
    ipam: ipam::Ipam,
    /// published port rules: (container_id, host_port, proto, target)
    pub published: tokio::sync::Mutex<Vec<PortRule>>,
    /// userland proxy shutdown senders keyed "container|proto|host:port"
    proxy_handles: tokio::sync::Mutex<HashMap<String, tokio::sync::watch::Sender<bool>>>,
    /// Bridges already ensured this boot (bridge name → ()). Makes
    /// `ensure_bridge` a no-op when warm, eliminating 6-10 iptables/ip
    /// execs per container start. Invalidated never (boot reconciles).
    bridges_ready: tokio::sync::Mutex<std::collections::HashSet<String>>,
}

impl NetworkManager {
    pub fn new(paths: DataPaths) -> Result<Self> {
        Ok(NetworkManager {
            ipam: ipam::Ipam::new(&paths),
            dns: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            dns6: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            dns_search: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            dns_tasks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            ipv6: tokio::sync::RwLock::new(Ipv6Config::default()),
            v6_by_v4: tokio::sync::Mutex::new(HashMap::new()),
            paths,
            networks: tokio::sync::RwLock::new(HashMap::new()),
            published: tokio::sync::Mutex::new(Vec::new()),
            proxy_handles: tokio::sync::Mutex::new(HashMap::new()),
            bridges_ready: tokio::sync::Mutex::new(std::collections::HashSet::new()),
        })
    }

    /// Enable daemon-level dual-stack and set the ULA pool (ingotd
    /// `--ipv6` / `--fixed-cidr-v6`). Must precede [`NetworkManager::boot`]:
    /// the default bridge is carved at boot. Bad pool input is a
    /// docker-shaped "invalid fixed-cidr-v6 ..." error. Clears the
    /// bridge-ready cache so a flip re-ensures every bridge.
    pub async fn set_ipv6_config(&self, enabled: bool, pool: &str) -> Result<()> {
        let normalized = ipam::V6Subnet::parse(pool)
            .map_err(|e| anyhow!("invalid fixed-cidr-v6 {pool:?}: {e:#}"))?;
        if normalized.prefix > V6_SUBNET_PREFIX {
            return Err(anyhow!(
                "invalid fixed-cidr-v6 {pool:?} (prefix must be /{} or shorter)",
                V6_SUBNET_PREFIX
            ));
        }
        *self.ipv6.write().await = Ipv6Config {
            enabled,
            pool: normalized.cidr(),
        };
        self.bridges_ready.lock().await.clear();
        Ok(())
    }

    async fn ipv6_snapshot(&self) -> Ipv6Config {
        self.ipv6.read().await.clone()
    }

    /// Boot: load/create the default bridge network.
    pub async fn boot(&self) -> Result<()> {
        enable_ip_forward()?;
        let v6cfg = self.ipv6_snapshot().await;
        if v6cfg.enabled {
            enable_ip6_forward()?;
        }
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
                    // Same audit for the dual-stack ULA ranges.
                    if let (Ok(sa6), Ok(sb6)) = (
                        ipam::V6Subnet::parse(&a.subnet_v6),
                        ipam::V6Subnet::parse(&b.subnet_v6),
                    ) {
                        if sa6.overlaps(&sb6) {
                            tracing::warn!(
                                "boot: network {} ({}) overlaps network {} ({}) — cross-bridge replies may blackhole",
                                a.name,
                                a.subnet_v6,
                                b.name,
                                b.subnet_v6
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
        if let Ok(out) = sh_async("ip", &["-o", "link", "show"]).await {
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
                    let _ = sh_async("ip", &["link", "del", &ifname]).await;
                }
            }
        }
        if self.by_name("bridge").await.is_none() {
            let id = ingot_util::new_id();
            // Dual-stack from birth when enabled: carve the default
            // bridge's /64 alongside the v4 /16.
            let (subnet_v6, gateway_v6) = if v6cfg.enabled {
                assign_v6_subnet(&v6cfg.pool, &id, &[])?
            } else {
                (String::new(), String::new())
            };
            let rec = NetworkRecord {
                id,
                name: "bridge".into(),
                driver: "bridge".into(),
                bridge: "ingot0".into(),
                subnet: "172.17.0.0/16".into(),
                gateway: "172.17.0.1".into(),
                subnet_v6,
                gateway_v6,
                created: ingot_util::now_rfc3339(),
                ..Default::default()
            };
            self.ensure_bridge(&rec).await?;
            self.save_network(&rec).await?;
        } else if v6cfg.enabled {
            // Migrate a pre-dual-stack default bridge: carve its /64,
            // re-ensure (adds the v6 gateway address + rules to the live
            // bridge), and persist.
            let migrate = self.by_name("bridge").await.filter(|r| !r.has_ipv6());
            if let Some(mut rec) = migrate {
                let existing: Vec<String> = self
                    .networks
                    .read()
                    .await
                    .values()
                    .map(|n| n.subnet_v6.clone())
                    .filter(|s| !s.is_empty())
                    .collect();
                let (subnet_v6, gateway_v6) = assign_v6_subnet(&v6cfg.pool, &rec.id, &existing)?;
                rec.subnet_v6 = subnet_v6;
                rec.gateway_v6 = gateway_v6;
                self.ensure_bridge(&rec).await?;
                self.save_network(&rec).await?;
            }
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
            // v6 leases are dynamic per boot (not yet in container
            // records), so the live set is empty: every surviving v6
            // lease belonged to a dead daemon's netns.
            let live6: std::collections::HashSet<(String, u128)> = std::collections::HashSet::new();
            let (dropped6, released6) = self.ipam.sweep_orphans_v6(&known, &live6).await;
            if dropped6 > 0 || released6 > 0 {
                tracing::warn!(
                    "boot: reclaimed {released6} orphan IPv6 lease(s) in {dropped6} stale bucket(s)"
                );
            }
        }
        // Base iptables state (idempotent). Off-executor via sh_async.
        let _ = sh_async("iptables", &["-t", "nat", "-N", "INGOT-DNAT"]).await;
        // All containers died with the daemon — stale DNAT rules are garbage.
        let _ = sh_async("iptables", &["-t", "nat", "-F", "INGOT-DNAT"]).await;
        // Remove any OUTPUT jump that lacks the loopback exclusion: loopback
        // traffic must reach the userland proxy, not DNAT (docker parity).
        let _ = sh_async(
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
        )
        .await;
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
            let _ = sh_async("iptables", &rule)
                .await
                .or_else(|_| sh("iptables", &add_refs));
        }
        // Base ip6tables state (idempotent), mirroring the v4 chains
        // above under new INGOT6 names. v6 port publishing is not yet
        // implemented, so INGOT6-DNAT starts empty; the jumps keep the
        // shape identical for when it lands.
        if v6cfg.enabled {
            let _ = sh_async("ip6tables", &["-t", "nat", "-N", "INGOT6-DNAT"]).await;
            let _ = sh_async("ip6tables", &["-t", "nat", "-F", "INGOT6-DNAT"]).await;
            let _ = sh_async(
                "ip6tables",
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
                    "INGOT6-DNAT",
                ],
            )
            .await;
            for chain in ["PREROUTING", "OUTPUT"] {
                let excl_loopback = chain == "OUTPUT";
                let mut rule: Vec<&str> = vec!["-t", "nat", "-C", chain];
                if excl_loopback {
                    rule.extend(["!", "-d", "::1/128"]);
                }
                rule.extend(["-m", "addrtype", "--dst-type", "LOCAL", "-j", "INGOT6-DNAT"]);
                let add = rule.clone();
                let mut add_rule: Vec<String> = add.iter().map(|s| s.to_string()).collect();
                add_rule[2] = "-A".into();
                let add_refs: Vec<&str> = add_rule.iter().map(|s| s.as_str()).collect();
                let _ = sh_async("ip6tables", &rule)
                    .await
                    .or_else(|_| sh("ip6tables", &add_refs));
            }
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
        // Fast path: already ensured this boot. Eliminates 6-10 fork/execs
        // per container start (attach calls ensure_bridge unconditionally).
        {
            let ready = self.bridges_ready.lock().await;
            if ready.contains(&rec.bridge) {
                return Ok(());
            }
        }
        let exists = sh_async("ip", &["link", "show", &rec.bridge]).await.is_ok();
        if !exists {
            sh_async("ip", &["link", "add", &rec.bridge, "type", "bridge"]).await?;
            // Mask the gateway with the subnet's own prefix: a hardcoded
            // /16 on a /24 bridge would swallow neighboring subnets.
            let prefix = ipam::Subnet::parse(&rec.subnet)
                .map(|s| s.prefix)
                .unwrap_or(16);
            let addr = format!("{}/{}", rec.gateway, prefix);
            sh_async("ip", &["addr", "add", &addr, "dev", &rec.bridge]).await?;
        }
        sh_async("ip", &["link", "set", &rec.bridge, "up"]).await?;
        if rec.internal {
            // Internal network (docker parity): no MASQUERADE (no
            // external NAT) and no forwarding off the bridge in either
            // direction — traffic stays bridge-local. Inserts precede the
            // generic ACCEPTs below; each is -C guarded, so re-ensure
            // never duplicates.
            iptables_ensure_async(
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
            )
            .await?;
            iptables_ensure_async(
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
            )
            .await?;
            // Bridge-local hairpin still allowed (policy-independent).
            iptables_ensure_async(
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
            )
            .await?;
        } else {
            // NAT for this subnet.
            iptables_ensure_async(
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
            )
            .await?;
            // Allow forwarded traffic in/out of this bridge.
            iptables_ensure_async(None, false, &["FORWARD", "-i", &rec.bridge, "-j", "ACCEPT"])
                .await?;
            iptables_ensure_async(None, false, &["FORWARD", "-o", &rec.bridge, "-j", "ACCEPT"])
                .await?;
        }
        // Dual-stack second half (v6 partial state is rolled back
        // inside): a failure fails the ensure so create/attach retry
        // idempotently; v4 state is untouched.
        self.ensure_bridge_v6(rec).await?;
        self.bridges_ready.lock().await.insert(rec.bridge.clone());
        Ok(())
    }

    /// Assign the v6 gateway address and install the ip6tables dataplane
    /// for one bridge. No-op when the network has v6 disabled. On partial
    /// failure every v6 step already applied is undone in reverse order.
    async fn ensure_bridge_v6(&self, rec: &NetworkRecord) -> Result<()> {
        if !rec.has_ipv6() {
            return Ok(());
        }
        let prefix = ipam::V6Subnet::parse(&rec.subnet_v6)
            .map(|s| s.prefix)
            .unwrap_or(V6_SUBNET_PREFIX);
        let addr = v6_bridge_addr(&rec.gateway_v6, prefix);
        // Idempotent: an existing address reports EEXIST ("exists").
        if let Err(e) = sh_async("ip", &["-6", "addr", "add", &addr, "dev", &rec.bridge]).await {
            if !format!("{e:#}").contains("exists") {
                return Err(e).with_context(|| {
                    format!("assign IPv6 gateway {addr} to bridge {}", rec.bridge)
                });
            }
        }
        let rules = v6_network_rules(rec);
        let mut applied: Vec<&Ip6Rule> = Vec::new();
        for rule in &rules {
            if let Err(e) = ip6tables_ensure_async(rule).await {
                for done in applied.iter().rev() {
                    ip6tables_delete_async(done).await;
                }
                let _ = sh_async("ip", &["-6", "addr", "del", &addr, "dev", &rec.bridge]).await;
                return Err(e)
                    .with_context(|| format!("install IPv6 rules for bridge {}", rec.bridge));
            }
            applied.push(rule);
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
        // Mirror for the v6 dataplane (no-op when v6 is disabled).
        // Failures ignored like the v4 drops above.
        for rule in v6_network_rules(rec) {
            let full = rule.full_args("-D");
            let refs: Vec<&str> = full.iter().map(|s| s.as_str()).collect();
            let _ = sh("ip6tables", &refs);
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
        // Dual-stack carve (before any side effect, so exhaustion fails
        // clean): a /64 out of the daemon pool, alongside the v4 subnet.
        let id = ingot_util::new_id();
        let v6cfg = self.ipv6_snapshot().await;
        let (subnet_v6, gateway_v6) = if v6cfg.enabled {
            let existing: Vec<String> = self
                .networks
                .read()
                .await
                .values()
                .map(|n| n.subnet_v6.clone())
                .filter(|s| !s.is_empty())
                .collect();
            assign_v6_subnet(&v6cfg.pool, &id, &existing)?
        } else {
            (String::new(), String::new())
        };
        let rec = NetworkRecord {
            id,
            name: name.into(),
            driver: "bridge".into(),
            bridge,
            subnet,
            gateway,
            subnet_v6,
            gateway_v6,
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

    /// Per-network name → IPv6 map, created on demand.
    async fn dns6_map(&self, net_id: &str) -> DnsRegistry {
        self.dns6
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
            let records_v6 = self.dns6_map(&rec.id).await;
            let searches = self.dns_search_map(&rec.id).await;
            match dns::spawn_dns_server(gw, records, records_v6, searches).await {
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
        self.dns6.write().await.remove(&rec.id);
        self.dns_search.write().await.remove(&rec.id);
        let _ = std::fs::remove_file(self.paths.network(&rec.id));
        // The bridge and its endpoints are gone: no lease in this
        // bucket can be live. Refusing removal while endpoints exist
        // is the API layer's guard; this stays unconditional.
        self.ipam.reset_bucket(&rec.id).await;
        self.v6_by_v4
            .lock()
            .await
            .retain(|(nid, _), _| *nid != rec.id);
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
        // Dual-stack lease alongside v4 (dynamic only: static --ip6
        // needs API/handler work, out of scope). A v6 failure fails the
        // whole attach so the endpoint never half-exists.
        let ipv6: Option<std::net::Ipv6Addr> = if net.has_ipv6() {
            Some(
                self.ipam
                    .allocate_v6(&net.id, &net.subnet_v6, &net.gateway_v6)
                    .await?,
            )
        } else {
            None
        };
        // Any setup failure past this point must hand the lease back (the
        // wire step drops its own half-built veth on error).
        match self.wire(&net, req, ip, prefix, ipv6).await {
            Ok(ep) => Ok(ep),
            Err(e) => {
                self.ipam.release(&net.id, &ip.to_string()).await;
                if let Some(v6) = ipv6 {
                    self.ipam.release_v6(&net.id, &v6.to_string()).await;
                }
                Err(e)
            }
        }
    }

    /// Re-wire a recorded endpoint at (re)start: the lease is already
    /// held by the container record (stop never releases; remove and
    /// disconnect do), so this skips allocation and only rebuilds the
    /// veth + addressing + DNS for the recorded IP. The v6 lease is
    /// dynamic per boot (not in the record yet), so a fresh one is
    /// drawn; the pre-stop v6 lease is reclaimed by the boot sweep.
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
        let ipv6: Option<std::net::Ipv6Addr> = if net.has_ipv6() {
            Some(
                self.ipam
                    .allocate_v6(&net.id, &net.subnet_v6, &net.gateway_v6)
                    .await?,
            )
        } else {
            None
        };
        match self.wire(&net, req, ip, prefix, ipv6).await {
            Ok(ep) => Ok(ep),
            Err(e) => {
                if let Some(v6) = ipv6 {
                    self.ipam.release_v6(&net.id, &v6.to_string()).await;
                }
                Err(e)
            }
        }
    }

    /// Build the veth pair and configure the container side; drops the
    /// half-built pair on error.
    async fn wire(
        &self,
        net: &NetworkRecord,
        req: &AttachRequest,
        ip: std::net::Ipv4Addr,
        prefix: u8,
        ipv6: Option<std::net::Ipv6Addr>,
    ) -> Result<EndpointAllocation> {
        let host_if = Self::endpoint_ifname(&req.container_id, &net.id);
        match self.attach_inner(net, req, ip, prefix, ipv6).await {
            Ok(ep) => Ok(ep),
            Err(e) => {
                let _ = sh_async("ip", &["link", "del", &host_if]).await;
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

    /// Pure: the `ip -6 ...` invocations configuring one endpoint's v6
    /// address (and, for eth0 on non-internal networks, its default
    /// route) inside the container netns. Each inner vec is the argv
    /// after `nsenter --net=...`. No side effects: unit tests assert the
    /// shape (rootless-safe) and [`NetworkManager::attach_inner`] runs it.
    fn v6_endpoint_cmds(
        ipv6: std::net::Ipv6Addr,
        prefix: u8,
        ifname: &str,
        gateway_v6: &str,
        if_index: usize,
        internal: bool,
    ) -> Vec<Vec<String>> {
        let mut cmds = vec![vec![
            "ip".to_string(),
            "-6".to_string(),
            "addr".to_string(),
            "add".to_string(),
            v6_bridge_addr(&ipv6.to_string(), prefix),
            "dev".to_string(),
            ifname.to_string(),
        ]];
        // eth0 alone carries the default route; internal networks get no
        // external route at all (v6 parity for `internal:true`).
        if if_index == 0 && !internal {
            cmds.push(vec![
                "ip".to_string(),
                "-6".to_string(),
                "route".to_string(),
                "add".to_string(),
                "default".to_string(),
                "via".to_string(),
                gateway_v6.to_string(),
            ]);
        }
        cmds
    }

    /// veth + addressing + DNS registration for an already-leased IP.
    async fn attach_inner(
        &self,
        net: &NetworkRecord,
        req: &AttachRequest,
        ip: std::net::Ipv4Addr,
        prefix: u8,
        ipv6: Option<std::net::Ipv6Addr>,
    ) -> Result<EndpointAllocation> {
        let host_if = Self::endpoint_ifname(&req.container_id, &net.id);
        let peer = format!("{host_if}-p");

        sh_async(
            "ip",
            &[
                "link", "add", &host_if, "type", "veth", "peer", "name", &peer,
            ],
        )
        .await?;
        sh_async("ip", &["link", "set", &host_if, "master", &net.bridge]).await?;
        sh_async("ip", &["link", "set", &host_if, "up"]).await?;
        sh_async("ip", &["link", "set", &peer, "netns", &req.pid.to_string()]).await?;

        // Configure inside the container's netns (via /proc — always valid).
        let proc_netns = format!("/proc/{}/ns/net", req.pid);
        let net_arg = format!("--net={proc_netns}");
        async fn enter(net_arg: &str, args: &[&str]) -> Result<String> {
            let mut cmd_args: Vec<String> = vec![net_arg.to_string()];
            cmd_args.extend(args.iter().map(|s| s.to_string()));
            let refs: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
            sh_async("nsenter", &refs).await
        }
        // One interface per endpoint (eth0, eth1, ...); only the first
        // installs the default route — a second `route add default`
        // would fail and two defaults would fight anyway.
        let ifname = format!("eth{}", req.if_index);
        enter(&net_arg, &["ip", "link", "set", &peer, "name", &ifname]).await?;
        enter(
            &net_arg,
            &[
                "ip",
                "addr",
                "add",
                &format!("{ip}/{prefix}"),
                "dev",
                &ifname,
            ],
        )
        .await?;
        enter(&net_arg, &["ip", "link", "set", &ifname, "up"]).await?;
        enter(&net_arg, &["ip", "link", "set", "lo", "up"]).await?;
        if req.if_index == 0 {
            enter(
                &net_arg,
                &["ip", "route", "add", "default", "via", &net.gateway],
            )
            .await?;
        }
        // Dual-stack addressing. resolv.conf is built by the runtime
        // crate and stays unchanged: the v4 gateway remains the
        // resolver, reachable over the dual-stack bridge.
        let ipv6_s = if let Some(v6) = ipv6 {
            let prefix6 = ipam::V6Subnet::parse(&net.subnet_v6)
                .map(|s| s.prefix)
                .unwrap_or(V6_SUBNET_PREFIX);
            for cmd in Self::v6_endpoint_cmds(
                v6,
                prefix6,
                &ifname,
                &net.gateway_v6,
                req.if_index,
                net.internal,
            ) {
                let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
                enter(&net_arg, &refs).await?;
            }
            v6.to_string()
        } else {
            String::new()
        };

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
        if !ipv6_s.is_empty() {
            // AAAA side of the same names, served by the same per-network
            // DNS task (see dns::decide).
            let map6 = self.dns6_map(&net.id).await;
            let mut reg6 = map6.write().await;
            reg6.insert(req.container_name.to_ascii_lowercase(), ipv6_s.clone());
            reg6.insert(req.hostname.to_ascii_lowercase(), ipv6_s.clone());
            for a in &req.aliases {
                reg6.insert(a.to_ascii_lowercase(), ipv6_s.clone());
            }
            self.v6_by_v4
                .lock()
                .await
                .insert((net.id.clone(), ip.to_string()), ipv6_s.clone());
        }
        if !req.dns_search.is_empty() {
            let smap = self.dns_search_map(&net.id).await;
            let mut sm = smap.write().await;
            sm.insert(ip.to_string(), req.dns_search.clone());
            if !ipv6_s.is_empty() {
                sm.insert(ipv6_s.clone(), req.dns_search.clone());
            }
        }
        Ok(EndpointAllocation {
            network_id: net.id.clone(),
            network_name: net.name.clone(),
            ip: ip.to_string(),
            gateway: net.gateway.clone(),
            ipv6: ipv6_s,
            mac: String::new(),
            aliases: req.aliases.clone(),
        })
    }

    /// Drop one endpoint's host-side veth (new scoped name, with a
    /// legacy one-name-per-container fallback: the old scheme could only
    /// ever create a single endpoint per container, so the fallback
    /// cannot hit a sibling endpoint).
    async fn drop_veth_async(container_id: &str, net_id: &str) {
        let host_if = Self::endpoint_ifname(container_id, net_id);
        if sh_async("ip", &["link", "show", &host_if]).await.is_ok() {
            let _ = sh_async("ip", &["link", "del", &host_if]).await;
        } else {
            let legacy = format!("veth-{}", &container_id[..8.min(container_id.len())]);
            let _ = sh_async("ip", &["link", "del", &legacy]).await;
        }
    }

    /// Undo a start-time wire without releasing the lease: the endpoint
    /// stays recorded (and leased), so a retried start re-wires cleanly
    /// instead of colliding with its own stranded veth.
    pub async fn unwire(&self, net_id: &str, container_id: &str) {
        Self::drop_veth_async(container_id, net_id).await;
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
    /// points at the released IP. The v6 lease (tracked in-memory per
    /// boot, see `v6_by_v4`) is released and scrubbed the same way.
    pub async fn detach(&self, net_id: &str, ip: &str, container_id: &str, dns_keys: &[String]) {
        Self::drop_veth_async(container_id, net_id).await;
        self.ipam.release(net_id, ip).await;
        let v6 = self
            .v6_by_v4
            .lock()
            .await
            .remove(&(net_id.to_string(), ip.to_string()));
        if let Some(ref v6ip) = v6 {
            self.ipam.release_v6(net_id, v6ip).await;
        }
        let scrub = |reg: &mut HashMap<String, String>, want: &str| {
            for k in dns_keys {
                let kl = k.to_ascii_lowercase();
                if reg.get(&kl).is_some_and(|v| v == want) {
                    reg.remove(&kl);
                }
            }
        };
        let dns = self.dns.read().await;
        if let Some(map) = dns.get(net_id) {
            let mut reg = map.write().await;
            scrub(&mut reg, ip);
        }
        drop(dns);
        if let Some(v6ip) = &v6 {
            let dns6 = self.dns6.read().await;
            if let Some(map) = dns6.get(net_id) {
                let mut reg = map.write().await;
                scrub(&mut reg, v6ip);
            }
        }
        // The endpoint is gone and its lease released: its per-IP search
        // entry would only misdirect later queriers from a reused IP.
        if let Some(smap) = self.dns_search.read().await.get(net_id) {
            let mut sm = smap.write().await;
            sm.remove(ip);
            if let Some(v6ip) = v6 {
                sm.remove(&v6ip);
            }
        }
    }

    /// Publish a port: userland proxy (127.x / host local reachability) +
    /// DNAT + FORWARD rule for external traffic (docker parity).
    ///
    /// Lock order is `published` → `proxy_handles` (matching
    /// unpublish_all): the conflict check is done under lock, iptables
    /// execs run WITHOUT holding the lock (off-executor via sh_async),
    /// then the reservation commits under lock with a re-check. An
    /// identical re-publish (restart) is a silent no-op; a clash with
    /// another container's binding fails with [`PortConflict`].
    pub async fn publish_port(&self, rule: PortRule) -> Result<()> {
        {
            let all = self.published.lock().await;
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
        }
        if !host_port_free(&rule.host_ip, rule.host_port, &rule.proto) {
            return Err(anyhow!(PortConflict {
                proto: rule.proto.clone(),
                host_ip: rule.host_ip.clone(),
                host_port: rule.host_port,
                occupier: None,
            }));
        }
        let dnat_dst = if publish_ip_wild(&rule.host_ip) {
            "0.0.0.0/0".to_string()
        } else {
            rule.host_ip.clone()
        };
        let host_port_s = rule.host_port.to_string();
        let to_dest = format!("{}:{}", rule.container_ip, rule.container_port);
        let cont_port_s = rule.container_port.to_string();
        sh_async(
            "iptables",
            &[
                "-t",
                "nat",
                "-A",
                "INGOT-DNAT",
                "-p",
                &rule.proto,
                "-d",
                &dnat_dst,
                "--dport",
                &host_port_s,
                "-j",
                "DNAT",
                "--to-destination",
                &to_dest,
            ],
        )
        .await?;
        sh_async(
            "iptables",
            &[
                "-A",
                "FORWARD",
                "-p",
                &rule.proto,
                "-d",
                &rule.container_ip,
                "--dport",
                &cont_port_s,
                "-j",
                "ACCEPT",
            ],
        )
        .await?;
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
        let mut all = self.published.lock().await;
        // Re-check under lock: another task may have won the race while we
        // were in iptables.
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
        self.proxy_handles
            .lock()
            .await
            .insert(proxy_key(&rule), shutdown_tx);
        all.push(rule);
        Ok(())
    }

    /// Pick a free ephemeral host port for `-P` / empty HostPort: not in
    /// our published set and not bound by any host process right now.
    /// Uses a kernel `bind(port 0)` pick instead of linearly probing
    /// 32768..60999 with a syscall per candidate (worst ~28k binds).
    pub async fn allocate_ephemeral_port(&self, proto: &str) -> u16 {
        let used: std::collections::HashSet<u16> = self
            .published
            .lock()
            .await
            .iter()
            .filter(|r| r.proto == proto)
            .map(|r| r.host_port)
            .collect();
        // Ask the kernel for a free port, retry if it collides with our
        // published set (tiny race window, loop bounded).
        for _ in 0..16 {
            let picked = if proto == "udp" {
                std::net::UdpSocket::bind(("0.0.0.0", 0))
                    .ok()
                    .and_then(|s| s.local_addr().ok().map(|a| a.port()))
            } else {
                std::net::TcpListener::bind(("0.0.0.0", 0))
                    .ok()
                    .and_then(|l| l.local_addr().ok().map(|a| a.port()))
            };
            if let Some(p) = picked {
                if p != 0 && !used.contains(&p) && host_port_free("", p, proto) {
                    return p;
                }
            }
        }
        // Fallback: linear scan (previous behavior) if kernel pick keeps
        // colliding.
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

    /// Unpublish everything for a container. Drains the rule set under
    /// lock, then runs iptables deletes WITHOUT holding the lock so
    /// concurrent starts/stops are not serialized behind N×2 fork/execs.
    pub async fn unpublish_all(&self, container_id: &str) {
        let mine: Vec<PortRule> = {
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
            let mut mine = Vec::new();
            for r in all.drain(..) {
                if r.container_id == container_id {
                    mine.push(r);
                } else {
                    kept.push(r);
                }
            }
            *all = kept;
            mine
        };
        for r in &mine {
            let dnat_dst = if publish_ip_wild(&r.host_ip) {
                "0.0.0.0/0".to_string()
            } else {
                r.host_ip.clone()
            };
            let host_port_s = r.host_port.to_string();
            let to_dest = format!("{}:{}", r.container_ip, r.container_port);
            let cont_port_s = r.container_port.to_string();
            let _ = sh_async(
                "iptables",
                &[
                    "-t",
                    "nat",
                    "-D",
                    "INGOT-DNAT",
                    "-p",
                    &r.proto,
                    "-d",
                    &dnat_dst,
                    "--dport",
                    &host_port_s,
                    "-j",
                    "DNAT",
                    "--to-destination",
                    &to_dest,
                ],
            )
            .await;
            let _ = sh_async(
                "iptables",
                &[
                    "-D",
                    "FORWARD",
                    "-p",
                    &r.proto,
                    "-d",
                    &r.container_ip,
                    "--dport",
                    &cont_port_s,
                    "-j",
                    "ACCEPT",
                ],
            )
            .await;
        }
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

    fn v6rec(bridge: &str, subnet_v6: &str, gateway_v6: &str, internal: bool) -> NetworkRecord {
        NetworkRecord {
            id: "id".into(),
            name: "n".into(),
            bridge: bridge.into(),
            subnet_v6: subnet_v6.into(),
            gateway_v6: gateway_v6.into(),
            internal,
            ..Default::default()
        }
    }

    #[test]
    fn assign_v6_subnet_is_stable_and_collision_free() {
        let pool = "fd00:dead:beef::/48";
        let (s1, g1) = assign_v6_subnet(pool, "net-a", &[]).unwrap();
        // Deterministic across calls (restart re-derives the same /64).
        assert_eq!(
            assign_v6_subnet(pool, "net-a", &[]).unwrap(),
            (s1.clone(), g1.clone())
        );
        assert!(
            s1.starts_with("fd00:dead:beef:") && s1.ends_with("::/64"),
            "{s1}"
        );
        // Gateway is the subnet's ::1.
        let sub = ipam::V6Subnet::parse(&s1).unwrap();
        assert_eq!(g1, ipam::default_gateway_v6(&sub).to_string());
        assert!(g1.ends_with("::1"));
        // A colliding slot probes forward to a distinct /64.
        let (s2, _) = assign_v6_subnet(pool, "net-b", std::slice::from_ref(&s1)).unwrap();
        assert_ne!(s1, s2);
        assert!(s2.ends_with("::/64"));
        // Bad pool input is docker-shaped ("invalid ..." → HTTP 400).
        for bad in ["garbage", "10.0.0.0/16", "fd00::/80", "fd00::/64/extra"] {
            let err = assign_v6_subnet(bad, "net-a", &[]).unwrap_err().to_string();
            assert!(err.starts_with("invalid "), "{bad}: {err}");
        }
    }

    #[test]
    fn assign_v6_subnet_exhausts_a_tiny_pool() {
        // A /64 pool holds exactly one /64: the second network conflicts.
        let pool = "fd00:dead:beef:1::/64";
        let (s1, _) = assign_v6_subnet(pool, "net-a", &[]).unwrap();
        assert_eq!(s1, "fd00:dead:beef:1::/64");
        let err = assign_v6_subnet(pool, "net-b", &[s1])
            .unwrap_err()
            .to_string();
        assert!(err.contains("fully subnetted"), "{err}");
        assert!(
            !err.starts_with("invalid "),
            "exhaustion is a conflict, not validation"
        );
    }

    #[test]
    fn v6_network_rules_mirror_v4_dataplane() {
        // Disabled network: no rules at all.
        assert!(v6_network_rules(&v6rec("br-x", "", "", false)).is_empty());
        // External: MASQUERADE + FORWARD both ways.
        let rules = v6_network_rules(&v6rec(
            "br-abc",
            "fd00:dead:beef:1::/64",
            "fd00:dead:beef:1::1",
            false,
        ));
        assert_eq!(rules.len(), 3);
        assert_eq!(
            rules[0],
            Ip6Rule {
                table: Some("nat"),
                insert: false,
                args: vec![
                    "POSTROUTING".into(),
                    "-s".into(),
                    "fd00:dead:beef:1::/64".into(),
                    "!".into(),
                    "-o".into(),
                    "br-abc".into(),
                    "-j".into(),
                    "MASQUERADE".into(),
                ],
            }
        );
        assert_eq!(rules[0].full_args("-A")[..3], vec!["-t", "nat", "-A"]);
        // Internal: DROP guards first (insert), hairpin ACCEPT, no NAT.
        let rules = v6_network_rules(&v6rec(
            "br-abc",
            "fd00:dead:beef:1::/64",
            "fd00:dead:beef:1::1",
            true,
        ));
        assert_eq!(rules.len(), 3);
        assert!(rules.iter().all(|r| r.table.is_none()));
        assert!(rules[0].insert && rules[1].insert && !rules[2].insert);
        assert!(rules
            .iter()
            .all(|r| !r.args.iter().any(|a| a == "MASQUERADE")));
        assert_eq!(
            rules[0].args[1..3],
            vec!["-i".to_string(), "br-abc".to_string()]
        );
    }

    #[test]
    fn v6_endpoint_cmds_shape() {
        let v6: std::net::Ipv6Addr = "fd00:dead:beef:1::5".parse().unwrap();
        // eth0 on an external network: address + default route.
        let cmds =
            NetworkManager::v6_endpoint_cmds(v6, 64, "eth0", "fd00:dead:beef:1::1", 0, false);
        assert_eq!(cmds.len(), 2);
        assert_eq!(
            cmds[0],
            vec![
                "ip",
                "-6",
                "addr",
                "add",
                "fd00:dead:beef:1::5/64",
                "dev",
                "eth0"
            ]
        );
        assert_eq!(
            cmds[1],
            vec![
                "ip",
                "-6",
                "route",
                "add",
                "default",
                "via",
                "fd00:dead:beef:1::1"
            ]
        );
        // Secondary interface: address only, no default route.
        let cmds =
            NetworkManager::v6_endpoint_cmds(v6, 64, "eth1", "fd00:dead:beef:1::1", 1, false);
        assert_eq!(cmds.len(), 1);
        // internal:true: no external route even on eth0.
        let cmds = NetworkManager::v6_endpoint_cmds(v6, 64, "eth0", "fd00:dead:beef:1::1", 0, true);
        assert_eq!(cmds.len(), 1);
        assert!(cmds[0].contains(&"add".to_string()));
    }

    #[tokio::test]
    async fn ipv6_config_validation_and_record_migration() {
        let dir = std::env::temp_dir().join(format!("net-v6cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mgr = NetworkManager::new(DataPaths::new(dir.clone(), dir.clone())).unwrap();
        // Disabled by default: no v6 anywhere.
        assert!(!mgr.ipv6_snapshot().await.enabled);
        // Bad pool input is docker-shaped.
        for bad in ["garbage", "10.0.0.0/16", "fd00::/80"] {
            let err = mgr
                .set_ipv6_config(true, bad)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.starts_with("invalid fixed-cidr-v6"), "{bad}: {err}");
        }
        // Host bits in the pool are masked like Docker normalizes.
        mgr.set_ipv6_config(true, "fd00:dead:beef:ffff::99/48")
            .await
            .unwrap();
        assert_eq!(mgr.ipv6_snapshot().await.pool, "fd00:dead:beef::/48");
        // Pre-dual-stack record deserializes with v6 disabled (migrate).
        let old: NetworkRecord = serde_json::from_str(
            r#"{"id":"x","name":"bridge","subnet":"172.17.0.0/16","gateway":"172.17.0.1"}"#,
        )
        .unwrap();
        assert!(!old.has_ipv6());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
