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
) -> anyhow::Result<()> {
    let socket = UdpSocket::bind((bind_ip, 53)).await?;
    tokio::spawn(async move {
        let upstream: Vec<std::net::SocketAddr> = host_nameservers()
            .into_iter()
            .map(|ip| std::net::SocketAddr::from((ip, 53)))
            .collect();
        let mut buf = vec![0u8; 1500];
        loop {
            let Ok((n, peer)) = socket.recv_from(&mut buf).await else { break };
            let query = &buf[..n];
            let name = extract_query_name(query);
            let answer = {
                let map = records.read().await;
                name.as_ref().and_then(|n| map.get(n).cloned())
            };
            match answer {
                Some(ip) => {
                    let reply = build_answer(query, &ip);
                    let _ = socket.send_to(&reply, peer).await;
                }
                None => forward(&socket, query, peer, &upstream).await,
            }
        }
    });
    Ok(())
}

async fn forward(
    socket: &UdpSocket,
    query: &[u8],
    peer: std::net::SocketAddr,
    upstream: &[std::net::SocketAddr],
) {
    for up in upstream {
        if let Ok(s) = UdpSocket::bind(("0.0.0.0", 0)).await {
            if s.send_to(query, up).await.is_ok() {
                let mut rb = vec![0u8; 1500];
                if let Ok(Ok((rn, _))) =
                    tokio::time::timeout(std::time::Duration::from_secs(2), s.recv_from(&mut rb)).await
                {
                    let _ = socket.send_to(&rb[..rn], peer).await;
                    return;
                }
            }
        }
    }
}

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
    Some(labels.join("."))
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
