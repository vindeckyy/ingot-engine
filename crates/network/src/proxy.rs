//! Userland port proxy (docker-proxy equivalent): relays host port traffic
//! to the container. Required for 127.0.0.1 reachability (DNAT can't loop
//! back into the container) and used unconditionally like dockerd's default.

use anyhow::Result;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;

pub async fn run_proxy(
    bind_ip: IpAddr,
    port: u16,
    target: std::net::SocketAddr,
    proto: &str,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    match proto {
        "udp" => run_udp(bind_ip, port, target, shutdown).await,
        _ => run_tcp(bind_ip, port, target, shutdown).await,
    }
}

async fn run_tcp(
    bind_ip: IpAddr,
    port: u16,
    target: std::net::SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let listener = tokio::net::TcpListener::bind((bind_ip, port)).await?;
    tracing::debug!("proxy tcp {}:{port} → {target}", bind_ip);
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let (mut client, _) = match accepted {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                tokio::spawn(async move {
                    let Ok(mut upstream) = tokio::net::TcpStream::connect(target).await else {
                        tracing::debug!("proxy: connect to {target} failed");
                        return;
                    };
                    tracing::debug!("proxy: relaying {target}");
                    match tokio::io::copy_bidirectional(&mut client, &mut upstream).await {
                        Ok((a, b)) => tracing::debug!("proxy: relay done {a}/{b} bytes"),
                        Err(e) => tracing::debug!("proxy: relay error {e}"),
                    }
                });
            }
        }
    }
    Ok(())
}

async fn run_udp(
    bind_ip: IpAddr,
    port: u16,
    target: std::net::SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let socket = Arc::new(tokio::net::UdpSocket::bind((bind_ip, port)).await?);
    let local_addr = socket.local_addr()?;
    let _ = local_addr;
    tracing::debug!("proxy udp {}:{port} → {target}", bind_ip);
    loop {
        // Receive one datagram, then relay it via a per-peer upstream socket.
        let mut buf = vec![0u8; 65536];
        let recv = tokio::select! {
            _ = shutdown.changed() => break,
            recv = socket.recv_from(&mut buf) => recv,
        };
        let (n, peer) = match recv {
            Ok(v) => v,
            Err(_) => break,
        };
        let payload = buf[..n].to_vec();
        let s = match tokio::net::UdpSocket::bind(("0.0.0.0", 0)).await {
            Ok(s) => s,
            Err(_) => continue,
        };
        if s.connect(target).await.is_err() {
            continue;
        }
        if s.send(&payload).await.is_err() {
            continue;
        }
        let reply_socket = socket.clone();
        let data_peer = peer;
        tokio::spawn(async move {
            let mut rb = vec![0u8; 65536];
            if let Ok(Ok((rn, _))) =
                tokio::time::timeout(std::time::Duration::from_secs(5), s.recv_from(&mut rb)).await
            {
                let _ = reply_socket.send_to(&rb[..rn], data_peer).await;
            }
        });
    }
    Ok(())
}
