//! Embedded DNS: a UDP server per user-defined network bound to the bridge
//! gateway, answering container name/alias lookups and forwarding everything
//! else to the host's nameservers.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tokio::net::UdpSocket;

pub async fn spawn_dns_server(
    bind_ip: Ipv4Addr,
    records: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    records_v6: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    searches: Arc<tokio::sync::RwLock<HashMap<String, Vec<String>>>>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let socket = UdpSocket::bind((bind_ip, 53)).await?;
    let handle = tokio::spawn(async move {
        let upstream: Vec<std::net::SocketAddr> = host_nameservers()
            .into_iter()
            .map(|ip| std::net::SocketAddr::from((ip, 53)))
            .collect();
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            let query = &buf[..n];
            let (name, qtype) = extract_query_name_type(query);
            // Resolve both families up front (exact, then per-querier
            // search expansion); the pure `decide` picks the reply.
            let (v4, v6) = {
                let map = records.read().await;
                let map6 = records_v6.read().await;
                let by_ip = searches.read().await;
                let peer_key = peer.ip().to_string();
                let lookup = |m: &HashMap<String, String>| -> Option<String> {
                    match name.as_ref().and_then(|n| m.get(n).cloned()) {
                        Some(ip) => Some(ip),
                        None => name.as_ref().and_then(|n| {
                            by_ip
                                .get(&peer_key)
                                .and_then(|domains| resolve_search(m, domains, n))
                        }),
                    }
                };
                (lookup(&map), lookup(&map6))
            };
            match decide(qtype, v4, v6) {
                DnsDecision::A(ip) => {
                    let reply = build_answer(query, &ip);
                    let _ = socket.send_to(&reply, peer).await;
                }
                DnsDecision::Aaaa(ip) => {
                    let reply = build_aaaa_answer(query, &ip);
                    let _ = socket.send_to(&reply, peer).await;
                }
                // Ours, wrong family: NODATA (NOERROR, no answers).
                DnsDecision::Nodata => {
                    let reply = build_error(query, 0);
                    let _ = socket.send_to(&reply, peer).await;
                }
                DnsDecision::Forward if upstream.is_empty() => {
                    let reply = build_error(query, 2);
                    let _ = socket.send_to(&reply, peer).await;
                }
                DnsDecision::Forward => {
                    if !forward(&socket, query, peer, &upstream).await {
                        let reply = build_error(query, 2);
                        let _ = socket.send_to(&reply, peer).await;
                    }
                }
            }
        }
    });
    Ok(handle)
}

/// Try a query against one querier's search domains, resolver order:
/// as-is first (already missed), then name + each domain.
fn resolve_search(
    records: &HashMap<String, String>,
    domains: &[String],
    name: &str,
) -> Option<String> {
    domains.iter().find_map(|d| {
        records
            .get(&format!("{}.{}", name, d.to_ascii_lowercase()))
            .cloned()
    })
}

async fn forward(
    socket: &UdpSocket,
    query: &[u8],
    peer: std::net::SocketAddr,
    upstream: &[std::net::SocketAddr],
) -> bool {
    // One socket per query (not per upstream): single bind, reuse for all
    // upstreams. 2s total budget.
    let Ok(s) = UdpSocket::bind(("0.0.0.0", 0)).await else {
        return false;
    };
    for up in upstream {
        if s.send_to(query, up).await.is_ok() {
            let mut rb = vec![0u8; 1500];
            if let Ok(Ok((rn, _))) =
                tokio::time::timeout(std::time::Duration::from_secs(2), s.recv_from(&mut rb)).await
            {
                let _ = socket.send_to(&rb[..rn], peer).await;
                return true;
            }
        }
    }
    false
}

/// Minimal header-only error reply (no answers): QR + RA with the given
/// RCODE, so a dead upstream fails fast instead of hanging the client.
fn build_error(query: &[u8], rcode: u8) -> Vec<u8> {
    let mut out = query.to_vec();
    if out.len() < 12 {
        return out;
    }
    out[2] |= 0x80; // QR = response
    out[3] = (out[3] & 0xF0) | 0x80 | (rcode & 0x0F); // RA + RCODE
    out
}

// Loopback upstreams are kept deliberately: the daemon answers from the
// host netns, where 127.0.0.53 (systemd-resolved) is reachable. Filtering
// them would break external resolution on exactly the hosts that need it.
// Cached by mtime (was re-read per query setup): watch + refresh.
fn host_nameservers() -> Vec<Ipv4Addr> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<(u128, Vec<Ipv4Addr>)>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new((0, Vec::new())));
    let mtime = std::fs::metadata("/etc/resolv.conf")
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    {
        let guard = cache.lock().unwrap();
        if guard.0 == mtime && mtime != 0 {
            return guard.1.clone();
        }
    }
    let v: Vec<Ipv4Addr> = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter_map(|s| s.parse().ok())
        .collect();
    *cache.lock().unwrap() = (mtime, v.clone());
    v
}

/// Pure reply selection for one query: AAAA (28) is answered from the
/// v6 registry, anything else from the v4 registry (previous behavior
/// for non-A types is preserved). A name we own but only in the other
/// family is NODATA, never forwarded (forwarding our own names would
/// answer NXDOMAIN or leak them upstream).
#[derive(Debug, PartialEq, Eq)]
enum DnsDecision {
    A(String),
    Aaaa(String),
    Nodata,
    Forward,
}

fn decide(qtype: u16, v4: Option<String>, v6: Option<String>) -> DnsDecision {
    if qtype == 28 {
        match (v4, v6) {
            (_, Some(ip)) => DnsDecision::Aaaa(ip),
            (Some(_), None) => DnsDecision::Nodata,
            (None, None) => DnsDecision::Forward,
        }
    } else {
        match v4 {
            Some(ip) => DnsDecision::A(ip),
            None => DnsDecision::Forward,
        }
    }
}

/// Extract the first (QNAME, QTYPE) from a DNS query. Unknown-shape
/// queries yield (name-so-far, 1) so they take the v4 path as before.
fn extract_query_name_type(query: &[u8]) -> (Option<String>, u16) {
    if query.len() < 12 {
        return (None, 1);
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let len = *query.get(i).unwrap_or(&0);
        if len == 0 {
            break;
        }
        // Compressed names (top bits set) only appear in answers, never
        // in a query question: stop rather than misparse.
        if len & 0xC0 != 0 {
            return (None, 1);
        }
        let Some(label) = query.get(i + 1..i + 1 + len as usize) else {
            return (None, 1);
        };
        labels.push(String::from_utf8_lossy(label).to_string());
        i += 1 + len as usize;
    }
    let qtype = query
        .get(i + 1)
        .and_then(|&hi| query.get(i + 2).map(|&lo| u16::from_be_bytes([hi, lo])))
        .unwrap_or(1);
    let name = if labels.is_empty() {
        None
    } else {
        Some(labels.join(".").to_ascii_lowercase())
    };
    (name, qtype)
}

/// Build a minimal A-record answer for the query, mirroring its question.
fn build_answer(query: &[u8], ip: &str) -> Vec<u8> {
    let mut out = query.to_vec();
    if out.len() < 12 {
        return out;
    }
    out[2] |= 0x80; // QR = response
    out[3] |= 0x80; // RA (recursion available); RCODE stays 0 = NOERROR
    out[7] = 1; // ANCOUNT = 1
    out.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4]);
    let parsed: Option<Ipv4Addr> = ip.parse().ok();
    out.extend_from_slice(&parsed.map(|p| p.octets()).unwrap_or([0, 0, 0, 0]));
    out
}

/// Build a minimal AAAA-record answer (TYPE 28, 16-byte RDATA).
fn build_aaaa_answer(query: &[u8], ip: &str) -> Vec<u8> {
    use std::net::Ipv6Addr;
    let mut out = query.to_vec();
    if out.len() < 12 {
        return out;
    }
    out[2] |= 0x80; // QR = response
    out[3] |= 0x80; // RA; RCODE stays 0 = NOERROR
    out[7] = 1; // ANCOUNT = 1
    out.extend_from_slice(&[0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 0, 0, 16]);
    let parsed: Option<Ipv6Addr> = ip.parse().ok();
    out.extend_from_slice(&parsed.map(|p| p.octets()).unwrap_or([0; 16]));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_name_extraction() {
        let mut q = vec![0u8; 12];
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&[0, 1, 0, 1]);
        let (name, qtype) = extract_query_name_type(&q);
        assert_eq!(name.as_deref(), Some("example.com"));
        assert_eq!(qtype, 1);
    }

    #[test]
    fn dns_name_extraction_lowercases() {
        let mut q = vec![0u8; 12];
        q.extend_from_slice(b"\x02DB\x00");
        q.extend_from_slice(&[0, 1, 0, 1]);
        let (name, _) = extract_query_name_type(&q);
        assert_eq!(name.as_deref(), Some("db"));
    }

    #[test]
    fn search_expansion_hits_before_miss() {
        let mut records = HashMap::new();
        records.insert("db.svc".to_string(), "10.0.0.5".to_string());
        let domains = vec!["svc".to_string()];
        assert_eq!(
            resolve_search(&records, &domains, "db").as_deref(),
            Some("10.0.0.5")
        );
        assert_eq!(resolve_search(&records, &domains, "missing"), None);
        assert_eq!(
            resolve_search(&records, &[], "db"),
            None,
            "no domains, no expansion"
        );
    }

    #[test]
    fn search_expansion_domain_case_insensitive() {
        let mut records = HashMap::new();
        records.insert("db.svc".to_string(), "10.0.0.5".to_string());
        let domains = vec!["SVC".to_string()];
        assert_eq!(
            resolve_search(&records, &domains, "db").as_deref(),
            Some("10.0.0.5")
        );
    }

    #[test]
    fn error_reply_shape() {
        let mut q = vec![0x12, 0x34];
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        q.extend_from_slice(b"\x01a\x00");
        q.extend_from_slice(&[0, 1, 0, 1]);
        let e = build_error(&q, 2);
        assert_eq!(e[2] & 0x80, 0x80, "QR set");
        assert_eq!(e[3] & 0x80, 0x80, "RA set");
        assert_eq!(e[3] & 0x0F, 2, "RCODE=SERVFAIL");
        assert_eq!(e[7], 0, "no answers");
        assert_eq!(&e[..2], &q[..2], "ID echoed");
        assert_eq!(&e[4..6], &[0, 1], "QDCOUNT preserved");
    }

    #[test]
    fn answer_shape() {
        let mut q = vec![0x12, 0x34];
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        q.extend_from_slice(b"\x01a\x00");
        q.extend_from_slice(&[0, 1, 0, 1]);
        let a = build_answer(&q, "1.2.3.4");
        assert_eq!(a[2] & 0x80, 0x80);
        assert!(a.ends_with(&[1, 2, 3, 4]));
    }

    fn query_with_qtype(name: &[u8], qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34];
        q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        q.extend_from_slice(name);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]); // QCLASS IN
        q
    }

    #[test]
    fn qtype_extraction() {
        let q = query_with_qtype(b"\x01a\x00", 28);
        let (name, qtype) = extract_query_name_type(&q);
        assert_eq!(name.as_deref(), Some("a"));
        assert_eq!(qtype, 28);
        let q = query_with_qtype(b"\x02DB\x00", 1);
        let (name, qtype) = extract_query_name_type(&q);
        assert_eq!(name.as_deref(), Some("db"));
        assert_eq!(qtype, 1);
        // Truncated queries fall back to the v4 path.
        assert_eq!(extract_query_name_type(&[0u8; 5]), (None, 1));
    }

    #[test]
    fn decide_matrix() {
        let v4 = || Some("10.0.0.5".to_string());
        let v6 = || Some("fd00::5".to_string());
        // AAAA served from the v6 lease alongside A.
        assert_eq!(decide(28, v4(), v6()), DnsDecision::Aaaa("fd00::5".into()));
        assert_eq!(decide(1, v4(), v6()), DnsDecision::A("10.0.0.5".into()));
        // Owned name, wrong family: NODATA, never forwarded.
        assert_eq!(decide(28, v4(), None), DnsDecision::Nodata);
        // Unknown name: forward upstream (existing behavior for A too).
        assert_eq!(decide(28, None, None), DnsDecision::Forward);
        assert_eq!(decide(1, None, None), DnsDecision::Forward);
        assert_eq!(decide(1, None, v6()), DnsDecision::Forward);
    }

    #[test]
    fn aaaa_answer_shape() {
        let q = query_with_qtype(b"\x01a\x00", 28);
        let a = build_aaaa_answer(&q, "fd00:dead:beef:1::5");
        assert_eq!(a[2] & 0x80, 0x80, "QR set");
        assert_eq!(a[3] & 0x0F, 0, "RCODE=NOERROR");
        assert_eq!(a[7], 1, "ANCOUNT=1");
        // RR tail: NAME ptr, TYPE=28, CLASS=IN, TTL=0, RDLEN=16, addr.
        let rr = &a[a.len() - 28..];
        assert_eq!(&rr[..6], &[0xC0, 0x0C, 0, 28, 0, 1]);
        assert_eq!(&rr[6..10], &[0, 0, 0, 0], "TTL=0");
        assert_eq!(&rr[10..12], &[0, 16], "RDLENGTH=16");
        let want: [u8; 16] = "fd00:dead:beef:1::5"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets();
        assert_eq!(&rr[12..], &want);
    }

    #[test]
    fn nodata_shape() {
        let q = query_with_qtype(b"\x01a\x00", 28);
        let n = build_error(&q, 0);
        assert_eq!(n[2] & 0x80, 0x80, "QR set");
        assert_eq!(n[3] & 0x0F, 0, "RCODE=NOERROR");
        assert_eq!(n[7], 0, "no answers");
        assert_eq!(&n[..2], &q[..2], "ID echoed");
    }
}
