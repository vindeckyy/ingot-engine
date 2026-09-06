//! Docker-style `-p` / `ports:` spec parsing shared by `ingot run` and
//! compose: `[host_ip:][host_port[-range]:]container[-range][/proto]`.
//! Ranges expand client-side exactly like the real CLI (equal-length
//! host/container ranges; anything else is an error, never a silent
//! mis-mapping).

/// One expanded binding: container key plus host part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    /// `"port/proto"` container key (e.g. `"80/tcp"`).
    pub container_key: String,
    pub host_ip: String,
    /// Empty means auto-assign an ephemeral port.
    pub host_port: String,
}

fn parse_range(s: &str, what: &str) -> Result<Vec<u16>, String> {
    if s.is_empty() {
        return Err(format!("empty {what} port"));
    }
    let (lo_s, hi_s) = match s.split_once('-') {
        Some((a, b)) => (a, b),
        None => (s, s),
    };
    let parse = |p: &str| {
        p.parse::<u16>()
            .map_err(|_| format!("invalid {what} port {p:?}"))
    };
    let lo = parse(lo_s)?;
    let hi = parse(hi_s)?;
    if lo == 0 || hi == 0 || hi < lo {
        return Err(format!("invalid {what} port range {s:?}"));
    }
    Ok((lo..=hi).collect())
}

/// Parse one spec into expanded mappings.
pub fn parse_port_spec(spec: &str) -> Result<Vec<PortMapping>, String> {
    // Trailing /proto (the container part never contains '/').
    let (rest, proto) = match spec.rsplit_once('/') {
        Some((r, p)) => (r, p),
        None => (spec, "tcp"),
    };
    if proto != "tcp" && proto != "udp" {
        return Err(format!("unsupported protocol {proto:?} (want tcp or udp)"));
    }
    // Split the container part off the right: [host:]container.
    let (host_part, container_part) = match rest.rsplit_once(':') {
        Some((h, c)) => (h, c),
        None => ("", rest),
    };
    if container_part.is_empty() {
        return Err(format!("missing container port in {spec:?}"));
    }
    // Host part: [ip:]port, empty port (or empty part) means auto-assign.
    // A bracketed IPv6 literal ([::1]:8080) keeps its colons.
    let (host_ip, host_port_s) = if host_part.is_empty() {
        (String::new(), String::new())
    } else if let Some(bracketed) = host_part.strip_prefix('[') {
        match bracketed.split_once("]:") {
            Some((ip, port)) => (ip.to_string(), port.to_string()),
            None => return Err(format!("invalid host part in {spec:?}")),
        }
    } else {
        match host_part.split_once(':') {
            Some((ip, port)) => {
                if ip.contains(':') {
                    return Err(format!(
                        "invalid host IP {ip:?} (bracket IPv6 literals like [::1])"
                    ));
                }
                (ip.to_string(), port.to_string())
            }
            None => (String::new(), host_part.to_string()),
        }
    };
    if !host_ip.is_empty() && host_ip.parse::<std::net::IpAddr>().is_err() {
        return Err(format!("invalid host IP {host_ip:?}"));
    }
    let containers = parse_range(container_part, "container")?;
    let hosts: Vec<String> = if host_port_s.is_empty() {
        vec![String::new(); containers.len()]
    } else {
        let nums = parse_range(&host_port_s, "host")?;
        if nums.len() != containers.len() {
            return Err(format!(
                "host and container port ranges must have the same length in {spec:?}"
            ));
        }
        nums.iter().map(|p| p.to_string()).collect()
    };
    Ok(containers
        .into_iter()
        .zip(hosts)
        .map(|(cport, hport)| PortMapping {
            container_key: format!("{cport}/{proto}"),
            host_ip: host_ip.clone(),
            host_port: if hport == "0" { String::new() } else { hport },
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_shapes() {
        // bare container port → auto host port
        assert_eq!(
            parse_port_spec("80").unwrap(),
            vec![PortMapping {
                container_key: "80/tcp".into(),
                host_ip: "".into(),
                host_port: "".into(),
            }]
        );
        // host:container, container/proto
        let m = parse_port_spec("8080:80").unwrap();
        assert_eq!(m[0].host_port, "8080");
        assert_eq!(m[0].host_ip, "");
        assert_eq!(
            parse_port_spec("53:53/udp").unwrap()[0].container_key,
            "53/udp"
        );
        // ip:host:container
        let m = parse_port_spec("127.0.0.1:8080:80").unwrap();
        assert_eq!(
            (m[0].host_ip.as_str(), m[0].host_port.as_str()),
            ("127.0.0.1", "8080")
        );
        // equal ranges expand pairwise
        let m = parse_port_spec("8080-8081:80-81").unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(m[0].container_key, "80/tcp");
        assert_eq!(m[0].host_port, "8080");
        assert_eq!(m[1].container_key, "81/tcp");
        assert_eq!(m[1].host_port, "8081");
        // mismatched ranges, bad protos, bad ports fail loudly
        assert!(parse_port_spec("8080-8081:80").is_err());
        assert!(parse_port_spec("8080:80/sctp").is_err());
        assert!(parse_port_spec("abc:80").is_err());
        assert!(parse_port_spec("8080:0").is_err());
        assert!(parse_port_spec("8080:notaport").is_err());
        assert!(parse_port_spec("99999:80").is_err());
        assert!(parse_port_spec("[::1]:8080:80").is_ok());
    }
}
