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
            let name = extract_query_name(query);
            let answer = {
                let map = records.read().await;
                let exact = name.as_ref().and_then(|n| map.get(n).cloned());
                match exact {
                    Some(ip) => Some(ip),
                    None => {
                        let by_ip = searches.read().await;
                        name.as_ref().and_then(|n| {
                            by_ip
                                .get(&peer.ip().to_string())
                                .and_then(|domains| resolve_search(&map, domains, n))
                        })
                    }
                }
            };
            match answer {
                Some(ip) => {
                    let reply = build_answer(query, &ip);
                    let _ = socket.send_to(&reply, peer).await;
                }
                None if upstream.is_empty() => {
                    let reply = build_error(query, 2);
                    let _ = socket.send_to(&reply, peer).await;
                }
                None => {
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
    for up in upstream {
        if let Ok(s) = UdpSocket::bind(("0.0.0.0", 0)).await {
            if s.send_to(query, up).await.is_ok() {
                let mut rb = vec![0u8; 1500];
                if let Ok(Ok((rn, _))) =
                    tokio::time::timeout(std::time::Duration::from_secs(2), s.recv_from(&mut rb))
                        .await
                {
                    let _ = socket.send_to(&rb[..rn], peer).await;
                    return true;
                }
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
fn host_nameservers() -> Vec<Ipv4Addr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split_whitespace().nth(1))
        .filter_map(|s| s.parse().ok())
        .collect()
}

/// Extract the first QNAME from a DNS query.
fn extract_query_name(query: &[u8]) -> Option<String> {
    if query.len() < 12 {
        return None;
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let len = *query.get(i)?;
        if len == 0 {
            break;
        }
        let label = query.get(i + 1..i + 1 + len as usize)?;
        labels.push(String::from_utf8_lossy(label).to_string());
        i += 1 + len as usize;
    }
    // DNS names are case-insensitive: lowercase here so "DB" matches a
    // container named "db" (registrations lowercase on insert too).
    Some(labels.join(".").to_ascii_lowercase())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_name_extraction() {
        let mut q = vec![0u8; 12];
        q.extend_from_slice(b"\x07example\x03com\x00");
        q.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(extract_query_name(&q).as_deref(), Some("example.com"));
    }

    #[test]
    fn dns_name_extraction_lowercases() {
        let mut q = vec![0u8; 12];
        q.extend_from_slice(b"\x02DB\x00");
        q.extend_from_slice(&[0, 1, 0, 1]);
        assert_eq!(extract_query_name(&q).as_deref(), Some("db"));
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
}
