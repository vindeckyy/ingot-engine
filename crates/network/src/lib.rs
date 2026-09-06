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
use std::net::Ipv4Addr;
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
    format!("{}|{}|{}:{}", rule.container_id, rule.proto, rule.host_ip, rule.host_port)
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

pub struct NetworkManager {
    paths: DataPaths,
    /// Shared name → ip registry consulted by every per-network DNS server.
    dns_records: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
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
            dns_records: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            paths,
            networks: tokio::sync::RwLock::new(HashMap::new()),
            published: tokio::sync::Mutex::new(Vec::new()),
            proxy_handles: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Boot: load/create the default bridge network.
    pub async fn boot(&self) -> Result<()> {
        enable_ip_forward();
        if let Ok(mut rd) = std::fs::read_dir(self.paths.networks()) {
            for entry in rd.flatten() {
                if let Ok(data) = std::fs::read(entry.path()) {
                    if let Ok(rec) = serde_json::from_slice::<NetworkRecord>(&data) {
                        self.networks.write().await.insert(rec.id.clone(), rec);
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
                let ifname = line.split(':').nth(1).unwrap_or("").trim().split('@').next().unwrap_or("").to_string();
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
        // Base iptables state (idempotent).
        let _ = sh("iptables", &["-t", "nat", "-N", "INGOT-DNAT"]);
        // All containers died with the daemon — stale DNAT rules are garbage.
        let _ = sh("iptables", &["-t", "nat", "-F", "INGOT-DNAT"]);
        // Remove any OUTPUT jump that lacks the loopback exclusion: loopback
        // traffic must reach the userland proxy, not DNAT (docker parity).
        let _ = sh("iptables", &[
            "-t", "nat", "-D", "OUTPUT", "-m", "addrtype", "--dst-type", "LOCAL", "-j", "INGOT-DNAT",
        ]);
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
        self.networks.write().await.insert(rec.id.clone(), rec.clone());
        ingot_store::write_json_atomic(&self.paths.network(&rec.id), rec)
    }

    async fn by_name(&self, name: &str) -> Option<NetworkRecord> {
        self.networks.read().await.values().find(|n| n.name == name).cloned()
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
            sh("ip", &["addr", "add", &format!("{}/16", rec.gateway), "dev", &rec.bridge])?;
        }
        sh("ip", &["link", "set", &rec.bridge, "up"])?;
        // NAT for this subnet.
        let _ = sh("iptables", &[
            "-t", "nat", "-C", "POSTROUTING", "-s", &rec.subnet, "!", "-o", &rec.bridge, "-j", "MASQUERADE",
        ])
        .or_else(|_| {
            sh("iptables", &[
                "-t", "nat", "-A", "POSTROUTING", "-s", &rec.subnet, "!", "-o", &rec.bridge, "-j", "MASQUERADE",
            ])
        });
        // Allow forwarded traffic in/out of this bridge.
        let _ = sh("iptables", &["-C", "FORWARD", "-i", &rec.bridge, "-j", "ACCEPT"])
            .or_else(|_| sh("iptables", &["-A", "FORWARD", "-i", &rec.bridge, "-j", "ACCEPT"]));
        let _ = sh("iptables", &["-C", "FORWARD", "-o", &rec.bridge, "-j", "ACCEPT"])
            .or_else(|_| sh("iptables", &["-A", "FORWARD", "-o", &rec.bridge, "-j", "ACCEPT"]));
        Ok(())
    }

    /// docker network create
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
                let gw = match gateway {
                    Some(g) => g,
                    None => {
                        let ip_part = s.split('/').next().unwrap_or("");
                        let octets: Vec<&str> = ip_part.split('.').collect();
                        if octets.len() == 4 {
                            format!("{}.{}.{}.1", octets[0], octets[1], octets[2])
                        } else {
                            return Err(anyhow!("subnet without gateway not supported"));
                        }
                    }
                };
                (s, gw, format!("br-{}", &ingot_util::new_id()[..12]))
            }
            None => {
                let mut chosen = None;
                'outer: for b in 18..=31u8 {
                    let candidate = format!("172.{b}.0.0/16");
                    let taken = self.networks.read().await.values().any(|n| n.subnet == candidate);
                    if !taken {
                        chosen = Some((candidate, format!("172.{b}.0.1")));
                        break 'outer;
                    }
                }
                let (s, gw) = chosen.ok_or_else(|| anyhow!("all predefined address pools have been fully subnetted"))?;
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
        // Embedded DNS on the gateway (docker-style service discovery).
        if let Ok(gw) = rec.gateway.parse::<std::net::Ipv4Addr>() {
            let records = self.dns_records.clone();
            if let Err(e) = dns::spawn_dns_server(gw, records).await {
                tracing::warn!("DNS server for {} failed: {e}", rec.name);
            }
        }
        Ok(rec)
    }

    pub async fn remove_network(&self, name_or_id: &str) -> Result<()> {
        let rec = self
            .get(name_or_id)
            .await
            .ok_or_else(|| anyhow!("network not found: {name_or_id}"))?;
        if rec.name == "bridge" {
            return Err(anyhow!("bridge is a pre-defined network and cannot be removed"));
        }
        let _ = sh("ip", &["link", "del", &rec.bridge]);
        self.networks.write().await.remove(&rec.id);
        let _ = std::fs::remove_file(self.paths.network(&rec.id));
        Ok(())
    }

    /// Attach a container's netns to its network (veth + addressing).
    pub async fn attach(&self, req: &AttachRequest) -> Result<EndpointAllocation> {
        let net = match self.get(&req.network).await {
            Some(n) => n,
            // Only the implicit default falls back to the bridge network.
            None if req.network.is_empty() || req.network == "default" || req.network == "bridge" => self
                .by_name("bridge")
                .await
                .ok_or_else(|| anyhow!("bridge network missing"))?,
            None => return Err(anyhow!("no such network: {}", req.network)),
        };
        self.ensure_bridge(&net).await?;
        let ip = self.ipam.allocate(&net.id, &net.gateway).await?;

        let host_if = format!("veth-{}", &req.container_id[..8.min(req.container_id.len())]);
        let peer = format!("{host_if}-p");

        sh("ip", &["link", "add", &host_if, "type", "veth", "peer", "name", &peer])?;
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
        enter(&["ip", "link", "set", &peer, "name", "eth0"])?;
        enter(&["ip", "addr", "add", &format!("{ip}/16"), "dev", "eth0"])?;
        enter(&["ip", "link", "set", "eth0", "up"])?;
        enter(&["ip", "link", "set", "lo", "up"])?;
        enter(&["ip", "route", "add", "default", "via", &net.gateway])?;

        // Register DNS entries (container name + aliases → ip).
        {
            let mut reg = self.dns_records.write().await;
            reg.insert(req.container_name.clone(), ip.to_string());
            reg.insert(req.hostname.clone(), ip.to_string());
            for a in &req.aliases {
                reg.insert(a.clone(), ip.to_string());
            }
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

    /// Detach (container removal): drop the veth and release the lease.
    pub async fn detach(&self, net_id: &str, ip: &str, container_id: &str) {
        let host_if = format!("veth-{}", &container_id[..8.min(container_id.len())]);
        let _ = sh("ip", &["link", "del", &host_if]);
        self.ipam.release(net_id, ip).await;
    }

    /// Publish a port: userland proxy (127.x / host local reachability) +
    /// DNAT + FORWARD rule for external traffic (docker parity).
    pub async fn publish_port(&self, rule: PortRule) -> Result<()> {
        sh("iptables", &[
            "-t", "nat", "-A", "INGOT-DNAT", "-p", &rule.proto, "-d",
            if rule.host_ip.is_empty() { "0.0.0.0/0" } else { &rule.host_ip },
            "--dport", &rule.host_port.to_string(),
            "-j", "DNAT", "--to-destination",
            &format!("{}:{}", rule.container_ip, rule.container_port),
        ])?;
        sh("iptables", &[
            "-A", "FORWARD", "-p", &rule.proto, "-d", &rule.container_ip,
            "--dport", &rule.container_port.to_string(), "-j", "ACCEPT",
        ])?;
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
        all.push(rule.clone());
        self.proxy_handles
            .lock()
            .await
            .insert(proxy_key(&rule), shutdown_tx);
        Ok(())
    }

    /// Pick a free ephemeral host port for `-P` / empty HostPort.
    pub async fn allocate_ephemeral_port(&self) -> u16 {
        let used: Vec<u16> = self
            .published
            .lock()
            .await
            .iter()
            .map(|r| r.host_port)
            .collect();
        for p in 32768..=60999u16 {
            if !used.contains(&p) {
                return p;
            }
        }
        32768
    }

    /// Unpublish everything for a container.
    pub async fn unpublish_all(&self, container_id: &str) {
        {
            let mut handles = self.proxy_handles.lock().await;
            for (k, tx) in handles.iter() {
                if k.starts_with(&format!("{container_id}|")) {
                    let _ = tx.send(true);
                }
            }
            handles.retain(|k, _| !k.starts_with(&format!("{container_id}|")));
        }
        let mut all = self.published.lock().await;
        let mut kept = Vec::new();
        for r in all.drain(..) {
            if r.container_id == container_id {
                let _ = sh("iptables", &[
                    "-t", "nat", "-D", "INGOT-DNAT", "-p", &r.proto, "-d",
                    if r.host_ip.is_empty() { "0.0.0.0/0" } else { &r.host_ip },
                    "--dport", &r.host_port.to_string(),
                    "-j", "DNAT", "--to-destination",
                    &format!("{}:{}", r.container_ip, r.container_port),
                ]);
                let _ = sh("iptables", &[
                    "-D", "FORWARD", "-p", &r.proto, "-d", &r.container_ip,
                    "--dport", &r.container_port.to_string(), "-j", "ACCEPT",
                ]);
            } else {
                kept.push(r);
            }
        }
        *all = kept;
    }
}

