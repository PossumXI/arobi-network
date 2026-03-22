use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Normalize a peer endpoint into a canonical `host:port` or `[ipv6]:port` form.
///
/// Accepted inputs:
/// - `1.2.3.4:30333`
/// - `example.org:30333`
/// - `[2001:db8::1]:30333`
/// - `tcp://example.org:30333`
/// - `tcp://[2001:db8::1]:30333`
pub fn normalize_peer_endpoint(raw: &str) -> Option<String> {
    let mut s = raw.split('#').next().unwrap_or("").trim();
    if s.is_empty() {
        return None;
    }

    if let Some(rest) = s.strip_prefix("tcp://") {
        s = rest;
    }
    if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
    }
    if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
    }

    if let Some((host_port, _)) = s.split_once('/') {
        s = host_port.trim();
    }
    if s.is_empty() {
        return None;
    }

    if let Ok(addr) = s.parse::<SocketAddr>() {
        if is_unspecified_ip(&addr.ip()) {
            return None;
        }
        return Some(addr.to_string());
    }

    let (host_raw, port_raw) = s.rsplit_once(':')?;
    let port = port_raw.parse::<u16>().ok()?;
    let host_raw = host_raw.trim();
    if host_raw.is_empty() || host_raw.contains(char::is_whitespace) {
        return None;
    }

    let host = if host_raw.starts_with('[') && host_raw.ends_with(']') && host_raw.len() > 2 {
        host_raw[1..host_raw.len() - 1].to_string()
    } else {
        host_raw.to_string()
    };

    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        let addr = SocketAddr::new(IpAddr::V6(v6), port);
        if is_unspecified_ip(&addr.ip()) {
            return None;
        }
        return Some(addr.to_string());
    }

    let host_lower = host.to_ascii_lowercase();
    if host_lower.is_empty() {
        return None;
    }
    if host_lower == "0.0.0.0" || host_lower == "::" || host_lower == "[::]" {
        return None;
    }

    Some(format!("{host_lower}:{port}"))
}

/// Returns true when the endpoint resolves to a publicly dialable address.
/// Hostnames are treated as potentially public; raw IPs are filtered.
pub fn is_public_peer_endpoint(raw: &str) -> bool {
    let Some(normalized) = normalize_peer_endpoint(raw) else {
        return false;
    };

    match normalized.parse::<SocketAddr>() {
        Ok(addr) => !is_non_public_ip(&addr.ip()),
        Err(_) => true,
    }
}

fn is_unspecified_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

fn is_non_public_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_public_v4(*v4),
        IpAddr::V6(v6) => is_non_public_v6(*v6),
    }
}

fn is_non_public_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000)
        || (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
}

fn is_non_public_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    let first = segments[0];

    ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
}

#[cfg(test)]
mod tests {
    use super::{is_public_peer_endpoint, normalize_peer_endpoint};

    #[test]
    fn normalizes_ipv4() {
        assert_eq!(
            normalize_peer_endpoint("192.168.0.7:30333").as_deref(),
            Some("192.168.0.7:30333")
        );
    }

    #[test]
    fn normalizes_hostname_and_scheme() {
        assert_eq!(
            normalize_peer_endpoint("tcp://P2P.AURA-GENESIS.ORG:30333").as_deref(),
            Some("p2p.aura-genesis.org:30333")
        );
    }

    #[test]
    fn normalizes_bracketed_ipv6() {
        assert_eq!(
            normalize_peer_endpoint("tcp://[2001:db8::10]:30333").as_deref(),
            Some("[2001:db8::10]:30333")
        );
    }

    #[test]
    fn strips_inline_comment() {
        assert_eq!(
            normalize_peer_endpoint("p2p.aura-genesis.org:30333 # seed").as_deref(),
            Some("p2p.aura-genesis.org:30333")
        );
    }

    #[test]
    fn rejects_invalid_endpoint() {
        assert!(normalize_peer_endpoint("not-an-endpoint").is_none());
        assert!(normalize_peer_endpoint("0.0.0.0:30333").is_none());
        assert!(normalize_peer_endpoint("[::]:30333").is_none());
    }

    #[test]
    fn rejects_non_public_ips_for_discovery() {
        assert!(!is_public_peer_endpoint("127.0.0.1:30333"));
        assert!(!is_public_peer_endpoint("192.168.1.22:30333"));
        assert!(is_public_peer_endpoint("67.82.42.211:30333"));
        assert!(is_public_peer_endpoint("p2p.aura-genesis.org:30333"));
    }
}
