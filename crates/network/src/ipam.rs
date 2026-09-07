//! Sequential IPv4 lease allocator per network, persisted under the data root.
//!
//! Allocation is SUBNET-aware: leases come from the usable host range of
//! the network's CIDR (excluding network, broadcast, and gateway
//! addresses). Pre-CIDR callers cannot exist — every allocation names its
//! subnet, so out-of-subnet leases are unrepresentable.

use ingot_store::paths::DataPaths;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct IpamLeases {
    /// network id → allocated ips (u32, host order). HashSet for O(1)
    /// membership; serializes as a JSON array (back-compat with Vec).
    pub allocated: HashMap<String, std::collections::HashSet<u32>>,
    /// network id → allocated IPv6 addresses (u128). Absent in
    /// pre-dual-stack files: `default` migrates them to "none leased".
    /// Unknown-field tolerance keeps old binaries reading new files.
    #[serde(default)]
    pub allocated_v6: HashMap<String, std::collections::HashSet<u128>>,
}

/// A parsed IPv4 subnet with its usable host range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Subnet {
    /// Network address (masked).
    pub network: u32,
    /// Prefix length.
    pub prefix: u8,
}

impl Subnet {
    /// Parse "a.b.c.d/p". Rejects non-IPv4, bad prefixes, prefixes with
    /// no usable host addresses (/31, /32), and host bits set... no —
    /// host bits are masked off like Docker (which normalizes).
    pub fn parse(cidr: &str) -> anyhow::Result<Subnet> {
        let (addr, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("invalid subnet {cidr:?} (want a.b.c.d/p)"))?;
        let ip: u32 = addr
            .parse::<Ipv4Addr>()
            .map_err(|_| anyhow::anyhow!("invalid subnet address in {cidr:?}"))?
            .into();
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid subnet prefix in {cidr:?}"))?;
        if prefix > 30 {
            anyhow::bail!("invalid subnet {cidr:?} (prefix must leave host addresses)");
        }
        let mask = if prefix == 0 {
            0u32
        } else {
            u32::MAX << (32 - prefix)
        };
        Ok(Subnet {
            network: ip & mask,
            prefix,
        })
    }

    /// First and last usable host addresses (inclusive).
    pub fn usable_range(&self) -> (u32, u32) {
        let hosts = if self.prefix == 32 {
            1u32
        } else {
            (1u32 << (32 - self.prefix)) - 1
        };
        let broadcast = self.network | hosts;
        (self.network + 1, broadcast - 1)
    }

    pub fn contains(&self, ip: u32) -> bool {
        let (lo, hi) = self.usable_range();
        (lo..=hi).contains(&ip)
    }

    pub fn overlaps(&self, other: &Subnet) -> bool {
        let (a_lo, a_hi) = self.usable_range();
        let (b_lo, b_hi) = other.usable_range();
        // Overlap on usable ranges; shared network/broadcast edges alone
        // (adjacent subnets) do not count.
        a_lo <= b_hi && b_lo <= a_hi
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network), self.prefix)
    }
}

/// Default gateway for a subnet: first usable address (.1 rule).
pub fn default_gateway(subnet: &Subnet) -> Ipv4Addr {
    Ipv4Addr::from(subnet.usable_range().0)
}

/// A parsed IPv6 subnet (dual-stack ULA range, e.g. fd00:dead:beef:1::/64).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct V6Subnet {
    /// Network address (masked).
    pub network: u128,
    /// Prefix length.
    pub prefix: u8,
}

impl V6Subnet {
    /// Parse "a:b::/p". Docker-shaped errors ("invalid ...") so callers
    /// can map them to HTTP 400. Host bits are masked off like Docker.
    pub fn parse(cidr: &str) -> anyhow::Result<V6Subnet> {
        let (addr, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("invalid subnet {cidr:?} (want a:b::/p)"))?;
        let ip: u128 = addr
            .parse::<Ipv6Addr>()
            .map_err(|_| anyhow::anyhow!("invalid subnet address in {cidr:?} (want IPv6)"))?
            .into();
        // Reject IPv4-mapped input explicitly: "1.2.3.0/24" parses as an
        // IPv6 address (::ffff:1.2.3.0) but is never a valid v6 subnet.
        if addr.contains('.') {
            anyhow::bail!("invalid subnet address in {cidr:?} (want IPv6)");
        }
        let prefix: u8 = prefix
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid subnet prefix in {cidr:?}"))?;
        if prefix > 126 {
            anyhow::bail!("invalid subnet {cidr:?} (prefix must leave host addresses)");
        }
        let mask = if prefix == 0 {
            0u128
        } else {
            u128::MAX << (128 - prefix)
        };
        Ok(V6Subnet {
            network: ip & mask,
            prefix,
        })
    }

    /// First and last usable host addresses (inclusive). Mirrors the v4
    /// shape (network and last address excluded); v6 has no broadcast,
    /// but the last address stays reserved all the same.
    pub fn usable_range(&self) -> (u128, u128) {
        let mask = if self.prefix == 0 {
            0u128
        } else {
            u128::MAX << (128 - self.prefix)
        };
        let last = self.network | !mask;
        (self.network + 1, last - 1)
    }

    pub fn contains(&self, ip: u128) -> bool {
        let (lo, hi) = self.usable_range();
        (lo..=hi).contains(&ip)
    }

    pub fn overlaps(&self, other: &V6Subnet) -> bool {
        let (a_lo, a_hi) = self.usable_range();
        let (b_lo, b_hi) = other.usable_range();
        a_lo <= b_hi && b_lo <= a_hi
    }

    pub fn cidr(&self) -> String {
        format!("{}/{}", Ipv6Addr::from(self.network), self.prefix)
    }
}

/// Default v6 gateway for a subnet: first usable address (the ::1 rule).
pub fn default_gateway_v6(subnet: &V6Subnet) -> Ipv6Addr {
    Ipv6Addr::from(subnet.usable_range().0)
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
        Ipam {
            path,
            state: tokio::sync::Mutex::new(state),
        }
    }

    /// Allocate the lowest free usable address that is not the gateway.
    pub async fn allocate(
        &self,
        network_id: &str,
        subnet: &str,
        gateway: &str,
    ) -> anyhow::Result<Ipv4Addr> {
        let sub = Subnet::parse(subnet)?;
        let gw: u32 = gateway
            .parse::<Ipv4Addr>()
            .map_err(|e| anyhow::anyhow!("invalid gateway {gateway}: {e}"))?
            .into();
        if !sub.contains(gw) {
            anyhow::bail!("invalid gateway {gateway}: outside subnet {subnet}");
        }
        let mut state = self.state.lock().await;
        let used = state.allocated.entry(network_id.to_string()).or_default();
        let (lo, hi) = sub.usable_range();
        for c in lo..=hi {
            if c != gw && !used.contains(&c) {
                used.insert(c);
                let _ = ingot_store::write_json_atomic(&self.path, &*state);
                return Ok(Ipv4Addr::from(c));
            }
        }
        Err(anyhow::anyhow!(
            "could not find an available IPv4 address on network {network_id}"
        ))
    }

    /// Reserve one requested (static) address. Fails when the address is
    /// outside the subnet, is the network/gateway/broadcast address, or
    /// is already leased.
    pub async fn reserve(
        &self,
        network_id: &str,
        subnet: &str,
        gateway: &str,
        ip: &str,
    ) -> anyhow::Result<Ipv4Addr> {
        let sub = Subnet::parse(subnet)?;
        let gw: u32 = gateway
            .parse::<Ipv4Addr>()
            .map_err(|e| anyhow::anyhow!("invalid gateway {gateway}: {e}"))?
            .into();
        let want: u32 = ip
            .parse::<Ipv4Addr>()
            .map_err(|e| anyhow::anyhow!("invalid IP address {ip}: {e}"))?
            .into();
        if !sub.contains(want) {
            anyhow::bail!("requested IP {ip} is outside subnet {subnet}");
        }
        if want == gw {
            anyhow::bail!("requested IP {ip} is the gateway address");
        }
        let mut state = self.state.lock().await;
        let used = state.allocated.entry(network_id.to_string()).or_default();
        if used.contains(&want) {
            anyhow::bail!("requested IP {ip} is already allocated");
        }
        used.insert(want);
        let _ = ingot_store::write_json_atomic(&self.path, &*state);
        Ok(Ipv4Addr::from(want))
    }

    /// Allocate the lowest free usable v6 address that is not the gateway.
    pub async fn allocate_v6(
        &self,
        network_id: &str,
        subnet: &str,
        gateway: &str,
    ) -> anyhow::Result<Ipv6Addr> {
        let sub = V6Subnet::parse(subnet)?;
        let gw: u128 = gateway
            .parse::<Ipv6Addr>()
            .map_err(|e| anyhow::anyhow!("invalid gateway {gateway}: {e}"))?
            .into();
        if !sub.contains(gw) {
            anyhow::bail!("invalid gateway {gateway}: outside subnet {subnet}");
        }
        let mut state = self.state.lock().await;
        let used = state
            .allocated_v6
            .entry(network_id.to_string())
            .or_default();
        let (lo, hi) = sub.usable_range();
        let mut c = lo;
        loop {
            if c != gw && !used.contains(&c) {
                used.insert(c);
                let _ = ingot_store::write_json_atomic(&self.path, &*state);
                return Ok(Ipv6Addr::from(c));
            }
            if c == hi {
                break;
            }
            c += 1;
        }
        Err(anyhow::anyhow!(
            "could not find an available IPv6 address on network {network_id}"
        ))
    }

    /// Reserve one requested (static) v6 address. Fails when the address
    /// is outside the subnet, is the network/gateway/last address, or is
    /// already leased.
    pub async fn reserve_v6(
        &self,
        network_id: &str,
        subnet: &str,
        gateway: &str,
        ip: &str,
    ) -> anyhow::Result<Ipv6Addr> {
        let sub = V6Subnet::parse(subnet)?;
        let gw: u128 = gateway
            .parse::<Ipv6Addr>()
            .map_err(|e| anyhow::anyhow!("invalid gateway {gateway}: {e}"))?
            .into();
        let want: u128 = ip
            .parse::<Ipv6Addr>()
            .map_err(|e| anyhow::anyhow!("invalid IP address {ip}: {e}"))?
            .into();
        if !sub.contains(want) {
            anyhow::bail!("requested IP {ip} is outside subnet {subnet}");
        }
        if want == gw {
            anyhow::bail!("requested IP {ip} is the gateway address");
        }
        let mut state = self.state.lock().await;
        let used = state
            .allocated_v6
            .entry(network_id.to_string())
            .or_default();
        if used.contains(&want) {
            anyhow::bail!("requested IP {ip} is already allocated");
        }
        used.insert(want);
        let _ = ingot_store::write_json_atomic(&self.path, &*state);
        Ok(Ipv6Addr::from(want))
    }

    /// Drop a network's whole lease bucket (network removal: the bridge
    /// and all its endpoints are gone, so no lease can be live).
    pub async fn reset_bucket(&self, network_id: &str) {
        let mut state = self.state.lock().await;
        let drop4 = state.allocated.remove(network_id).is_some();
        let drop6 = state.allocated_v6.remove(network_id).is_some();
        if drop4 || drop6 {
            let _ = ingot_store::write_json_batched(&self.path, &*state);
        }
    }

    /// Boot sweep: drop buckets for networks that no longer exist and
    /// release leases no live container record references. Every live
    /// lease is recorded in its container's config endpoints (attach
    /// persists the record; remove/detach drops it), so a leased IP with
    /// no referencing record is garbage from a crashed daemon, a killed
    /// --rm reaper, or a deleted network. Returns (dropped_buckets,
    /// released_ips).
    pub async fn sweep_orphans(
        &self,
        known_net_ids: &std::collections::HashSet<String>,
        live: &std::collections::HashSet<(String, u32)>,
    ) -> (usize, usize) {
        let mut state = self.state.lock().await;
        let mut dropped = 0usize;
        let mut released = 0usize;
        state.allocated.retain(|net_id, ips| {
            if !known_net_ids.contains(net_id) {
                dropped += 1;
                released += ips.len();
                return false;
            }
            let before = ips.len();
            ips.retain(|ip| live.contains(&(net_id.clone(), *ip)));
            released += before - ips.len();
            true
        });
        if dropped > 0 || released > 0 {
            let _ = ingot_store::write_json_batched(&self.path, &*state);
        }
        (dropped, released)
    }

    pub async fn release(&self, network_id: &str, ip: &str) {
        if let Ok(parsed) = ip.parse::<Ipv4Addr>() {
            let mut state = self.state.lock().await;
            let mut removed = false;
            if let Some(used) = state.allocated.get_mut(network_id) {
                let v: u32 = parsed.into();
                removed = used.remove(&v);
            }
            // Skip the file rewrite when nothing changed (unknown network
            // or already-released IP): previously every release rewrote
            // ipam-leases.json even on miss.
            if removed {
                let _ = ingot_store::write_json_batched(&self.path, &*state);
            }
        }
    }

    pub async fn release_v6(&self, network_id: &str, ip: &str) {
        if let Ok(parsed) = ip.parse::<Ipv6Addr>() {
            let mut state = self.state.lock().await;
            let mut removed = false;
            if let Some(used) = state.allocated_v6.get_mut(network_id) {
                let v: u128 = parsed.into();
                removed = used.remove(&v);
            }
            if removed {
                let _ = ingot_store::write_json_batched(&self.path, &*state);
            }
        }
    }

    /// Boot sweep for v6 leases, mirroring [`Ipam::sweep_orphans`].
    /// v6 endpoints are not yet persisted in container records (dynamic
    /// per boot), so the daemon passes an empty live set until the
    /// record carries the v6 address — every v6 lease is then garbage
    /// from a dead daemon. Returns (dropped_buckets, released_ips).
    pub async fn sweep_orphans_v6(
        &self,
        known_net_ids: &std::collections::HashSet<String>,
        live: &std::collections::HashSet<(String, u128)>,
    ) -> (usize, usize) {
        let mut state = self.state.lock().await;
        let mut dropped = 0usize;
        let mut released = 0usize;
        state.allocated_v6.retain(|net_id, ips| {
            if !known_net_ids.contains(net_id) {
                dropped += 1;
                released += ips.len();
                return false;
            }
            let before = ips.len();
            ips.retain(|ip| live.contains(&(net_id.clone(), *ip)));
            released += before - ips.len();
            true
        });
        if dropped > 0 || released > 0 {
            let _ = ingot_store::write_json_batched(&self.path, &*state);
        }
        (dropped, released)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_parsing_and_range() {
        let s = Subnet::parse("10.1.2.0/24").unwrap();
        assert_eq!(s.usable_range(), (0x0A010201, 0x0A0102FE));
        assert_eq!(default_gateway(&s).to_string(), "10.1.2.1");
        // Host bits are masked like Docker normalizes.
        assert_eq!(Subnet::parse("10.1.2.99/24").unwrap(), s);
        assert!(Subnet::parse("10.0.0.0/31").is_err());
        assert!(Subnet::parse("10.0.0.0/32").is_err());
        assert!(Subnet::parse("nope").is_err());
        assert!(Subnet::parse("10.0.0.0/33").is_err());
        assert!(Subnet::parse("::1/128").is_err());
    }

    #[test]
    fn overlap_detection() {
        let a = Subnet::parse("172.18.0.0/16").unwrap();
        assert!(a.overlaps(&Subnet::parse("172.18.5.0/24").unwrap()));
        assert!(a.overlaps(&Subnet::parse("172.18.0.0/16").unwrap()));
        assert!(!a.overlaps(&Subnet::parse("172.19.0.0/16").unwrap()));
        // Adjacent /24s share an edge address but no usable hosts.
        assert!(!Subnet::parse("10.0.0.0/24")
            .unwrap()
            .overlaps(&Subnet::parse("10.0.1.0/24").unwrap()));
    }

    #[tokio::test]
    async fn allocate_skips_gateway_and_exhausts() {
        let dir = std::env::temp_dir().join(format!("ipam-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Point Ipam at a scratch file via a minimal DataPaths... DataPaths
        // is root-joined, so use a temp root.
        let paths = DataPaths::new(dir.clone(), dir.clone());
        let ipam = Ipam::new(&paths);
        // /30: usable .1 (gateway) + .2 only.
        let first = ipam
            .allocate("n", "192.168.9.0/30", "192.168.9.1")
            .await
            .unwrap();
        assert_eq!(first.to_string(), "192.168.9.2");
        let err = ipam
            .allocate("n", "192.168.9.0/30", "192.168.9.1")
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("no available") || err.contains("available IPv4"),
            "{err}"
        );
        // Static reservations conflict and validate.
        assert!(ipam
            .reserve("m", "192.168.9.0/30", "192.168.9.1", "192.168.9.2")
            .await
            .is_ok());
        assert!(ipam
            .reserve("m", "192.168.9.0/30", "192.168.9.1", "192.168.9.2")
            .await
            .is_err());
        assert!(ipam
            .reserve("m", "192.168.9.0/30", "192.168.9.1", "192.168.9.1")
            .await
            .is_err());
        assert!(ipam
            .reserve("m", "192.168.9.0/30", "192.168.9.1", "10.9.9.9")
            .await
            .is_err());
        ipam.release("m", "192.168.9.2").await;
        assert!(ipam
            .reserve("m", "192.168.9.0/30", "192.168.9.1", "192.168.9.2")
            .await
            .is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn v6_subnet_parsing_and_range() {
        let s = V6Subnet::parse("fd00:dead:beef:1::/64").unwrap();
        assert_eq!(s.prefix, 64);
        assert_eq!(
            Ipv6Addr::from(s.usable_range().0).to_string(),
            "fd00:dead:beef:1::1"
        );
        assert_eq!(default_gateway_v6(&s).to_string(), "fd00:dead:beef:1::1");
        // Host bits are masked like Docker normalizes.
        assert_eq!(V6Subnet::parse("fd00:dead:beef:1::99/64").unwrap(), s);
        assert_eq!(s.cidr(), "fd00:dead:beef:1::/64");
        // Docker-shaped errors for bad v6 input.
        for bad in [
            "nope",
            "10.0.0.0/24",
            "1.2.3.0/24",
            "fd00::/127",
            "fd00::/128",
            "fd00::/129",
            "fd00::",
        ] {
            let err = V6Subnet::parse(bad).unwrap_err().to_string();
            assert!(err.starts_with("invalid "), "{bad}: {err}");
        }
    }

    #[test]
    fn v6_overlap_detection() {
        let a = V6Subnet::parse("fd00:dead:beef::/48").unwrap();
        assert!(a.overlaps(&V6Subnet::parse("fd00:dead:beef:1::/64").unwrap()));
        assert!(!a.overlaps(&V6Subnet::parse("fd00:dead:beee::/48").unwrap()));
        assert!(!V6Subnet::parse("fd00::1:0:0:0/96")
            .unwrap()
            .overlaps(&V6Subnet::parse("fd00::2:0:0:0/96").unwrap()));
    }

    #[test]
    fn v6_store_schema_migrates_old_files() {
        // Pre-dual-stack ipam-leases.json has no allocated_v6 key.
        let leases: IpamLeases = serde_json::from_str(r#"{"allocated":{"n":[12345]}}"#).unwrap();
        assert!(leases.allocated_v6.is_empty());
        assert!(leases.allocated.contains_key("n"));
    }

    #[tokio::test]
    async fn allocate_v6_skips_gateway_and_exhausts() {
        let dir = std::env::temp_dir().join(format!("ipam-v6-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = DataPaths::new(dir.clone(), dir.clone());
        let ipam = Ipam::new(&paths);
        // /126: usable ::1 (gateway) + ::2 only.
        let first = ipam
            .allocate_v6("n", "fd00::/126", "fd00::1")
            .await
            .unwrap();
        assert_eq!(first.to_string(), "fd00::2");
        let err = ipam
            .allocate_v6("n", "fd00::/126", "fd00::1")
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("available IPv6"), "{err}");
        // Static reservations conflict and validate.
        assert!(ipam
            .reserve_v6("m", "fd00::/126", "fd00::1", "fd00::2")
            .await
            .is_ok());
        assert!(ipam
            .reserve_v6("m", "fd00::/126", "fd00::1", "fd00::2")
            .await
            .is_err());
        assert!(ipam
            .reserve_v6("m", "fd00::/126", "fd00::1", "fd00::1")
            .await
            .is_err());
        assert!(ipam
            .reserve_v6("m", "fd00::/126", "fd00::1", "fd01::2")
            .await
            .is_err());
        ipam.release_v6("m", "fd00::2").await;
        assert!(ipam
            .reserve_v6("m", "fd00::/126", "fd00::1", "fd00::2")
            .await
            .is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn sweep_orphans_v6_reclaims_dead_buckets_and_leases() {
        let dir = std::env::temp_dir().join(format!("ipam-v6sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = DataPaths::new(dir.clone(), dir.clone());
        let ipam = Ipam::new(&paths);
        let a = ipam
            .allocate_v6("n", "fd00::/120", "fd00::1")
            .await
            .unwrap();
        ipam.allocate_v6("n", "fd00::/120", "fd00::1")
            .await
            .unwrap();
        ipam.allocate_v6("gone", "fd01::/120", "fd01::1")
            .await
            .unwrap();
        let known: std::collections::HashSet<String> = ["n".to_string()].into_iter().collect();
        let au: u128 = a.into();
        let live: std::collections::HashSet<(String, u128)> =
            [("n".to_string(), au)].into_iter().collect();
        let (dropped, released) = ipam.sweep_orphans_v6(&known, &live).await;
        assert_eq!((dropped, released), (1, 2));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn sweep_orphans_reclaims_dead_buckets_and_leases() {
        let dir = std::env::temp_dir().join(format!("ipam-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = DataPaths::new(dir.clone(), dir.clone());
        let ipam = Ipam::new(&paths);
        // Live network "n" with two leases; dead network "gone" with one.
        let a = ipam
            .allocate("n", "192.168.9.0/29", "192.168.9.1")
            .await
            .unwrap();
        let b = ipam
            .allocate("n", "192.168.9.0/29", "192.168.9.1")
            .await
            .unwrap();
        ipam.allocate("gone", "10.10.0.0/29", "10.10.0.1")
            .await
            .unwrap();
        // Only lease `a` on "n" is referenced by a container record.
        let known: std::collections::HashSet<String> = ["n".to_string()].into_iter().collect();
        let au: u32 = a.into();
        let live: std::collections::HashSet<(String, u32)> =
            [("n".to_string(), au)].into_iter().collect();
        let (dropped, released) = ipam.sweep_orphans(&known, &live).await;
        assert_eq!((dropped, released), (1, 2));
        // `a` survives; `b` is allocatable again.
        let c = ipam
            .allocate("n", "192.168.9.0/29", "192.168.9.1")
            .await
            .unwrap();
        assert_eq!(c, b);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
