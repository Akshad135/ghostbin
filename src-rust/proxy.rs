//! Trusted-proxy client IP resolution (plan §9 deployment).
//!
//! Behind a reverse proxy the socket peer is the proxy itself, which would
//! make every client share one rate-limit bucket. When `TRUSTED_PROXIES` is
//! configured, the client IP is recovered from `X-Forwarded-For` by walking
//! the list right-to-left past trusted proxies; the first untrusted address
//! is the client. If the peer itself is not a trusted proxy the header is
//! ignored entirely — an untrusted client can spoof it at will.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use axum::http::{HeaderMap, HeaderName};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cidr {
    V4 { network: Ipv4Addr, prefix: u8 },
    V6 { network: Ipv6Addr, prefix: u8 },
}

impl Cidr {
    /// Parse a CIDR block (`192.168.0.0/16`) or bare address (`10.0.0.5`).
    /// A bare address becomes a single-host block.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let (address, prefix) = match value.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix.parse::<u8>().ok()?)),
            None => (value, None),
        };
        match address.parse::<IpAddr>().ok()? {
            IpAddr::V4(ip) => {
                let prefix = prefix.unwrap_or(32);
                if prefix > 32 {
                    return None;
                }
                Some(Cidr::V4 {
                    network: mask_v4(ip, prefix),
                    prefix,
                })
            }
            IpAddr::V6(ip) => {
                let prefix = prefix.unwrap_or(128);
                if prefix > 128 {
                    return None;
                }
                Some(Cidr::V6 {
                    network: mask_v6(ip, prefix),
                    prefix,
                })
            }
        }
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Cidr::V4 { network, prefix }, IpAddr::V4(ip)) => {
                mask_v4(ip, *prefix) == *network
            }
            (Cidr::V6 { network, prefix }, IpAddr::V6(ip)) => {
                mask_v6(ip, *prefix) == *network
            }
            _ => false,
        }
    }
}

fn mask_v4(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr::UNSPECIFIED;
    }
    let bits = u32::from(ip) & (u32::MAX << (32 - u32::from(prefix)));
    Ipv4Addr::from(bits)
}

fn mask_v6(ip: Ipv6Addr, prefix: u8) -> Ipv6Addr {
    if prefix == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let bits = u128::from(ip) & (u128::MAX << (128 - u128::from(prefix)));
    Ipv6Addr::from(bits)
}

/// Parse a comma-separated `TRUSTED_PROXIES` value. Invalid entries are
/// skipped with a warning rather than aborting startup.
pub fn parse_trusted_proxies(raw: &str) -> Vec<Cidr> {
    raw.split(',')
        .filter(|entry| !entry.trim().is_empty())
        .filter_map(|entry| match Cidr::parse(entry) {
            Some(cidr) => Some(cidr),
            None => {
                tracing::warn!("Ignoring invalid TRUSTED_PROXIES entry: {entry:?}");
                None
            }
        })
        .collect()
}

/// Parse one `X-Forwarded-For` hop. Handles bare IPs plus the common
/// `ip:port` and `[v6]:port` forms some proxies emit.
fn parse_hop(hop: &str) -> Option<IpAddr> {
    let hop = hop.trim();
    if hop.is_empty() {
        return None;
    }
    if let Ok(ip) = hop.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Some(rest) = hop.strip_prefix('[') {
        let end = rest.find(']')?;
        return rest[..end].parse::<IpAddr>().ok();
    }
    if let Some((host, port)) = hop.rsplit_once(':')
        && !port.is_empty()
        && port.chars().all(|c| c.is_ascii_digit())
    {
        return host.parse::<IpAddr>().ok();
    }
    None
}

/// Resolve the client IP for a request.
///
/// `peer` is the direct socket address. See the module docs for the
/// right-to-left walk. A malformed hop stops the walk and yields the last
/// trusted address seen — never an attacker-controlled guess.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[Cidr]) -> IpAddr {
    if trusted.is_empty() || !trusted.iter().any(|cidr| cidr.contains(peer)) {
        return peer;
    }

    let forwarded = headers
        .get_all(HeaderName::from_static("x-forwarded-for"))
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect::<Vec<_>>()
        .join(", ");
    if forwarded.trim().is_empty() {
        return peer;
    }

    let mut candidate = peer;
    for hop in forwarded.rsplit(',') {
        let Some(ip) = parse_hop(hop) else {
            break;
        };
        if trusted.iter().any(|cidr| cidr.contains(ip)) {
            candidate = ip;
        } else {
            return ip;
        }
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static("x-forwarded-for"),
            HeaderValue::from_str(value).unwrap(),
        );
        headers
    }

    /// Two header lines: proxies like HAProxy append a separate
    /// `X-Forwarded-For` line instead of comma-appending. The proxy-appended
    /// line (rightmost overall) must win over the attacker-controlled line.
    fn headers_with_xff_lines(lines: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for line in lines {
            headers.append(
                HeaderName::from_static("x-forwarded-for"),
                HeaderValue::from_str(line).unwrap(),
            );
        }
        headers
    }

    fn local_trusted() -> Vec<Cidr> {
        vec![Cidr::parse("127.0.0.0/8").unwrap(), Cidr::parse("::1").unwrap()]
    }

    #[test]
    fn cidr_parses_blocks_and_single_addresses() {
        let block = Cidr::parse("192.168.10.0/24").unwrap();
        assert!(block.contains("192.168.10.77".parse::<IpAddr>().unwrap()));
        assert!(!block.contains("192.168.11.1".parse::<IpAddr>().unwrap()));

        let host = Cidr::parse("10.1.2.3").unwrap();
        assert!(host.contains("10.1.2.3".parse::<IpAddr>().unwrap()));
        assert!(!host.contains("10.1.2.4".parse::<IpAddr>().unwrap()));

        let v6 = Cidr::parse("fd00::/8").unwrap();
        assert!(v6.contains("fd12::1".parse::<IpAddr>().unwrap()));
        assert!(!v6.contains("fe80::1".parse::<IpAddr>().unwrap()));

        assert!(Cidr::parse("10.0.0.1/33").is_none());
        assert!(Cidr::parse("not-an-ip").is_none());
        assert!(Cidr::parse("").is_none());
    }

    #[test]
    fn v4_block_does_not_match_v6_and_vice_versa() {
        let v4 = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(!v4.contains("::1".parse::<IpAddr>().unwrap()));
        let v6 = Cidr::parse("::/0").unwrap();
        assert!(!v6.contains("1.2.3.4".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn untrusted_peer_ignores_forwarded_for() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let headers = headers_with_xff("1.2.3.4");
        assert_eq!(client_ip(peer, &headers, &local_trusted()), peer);
    }

    #[test]
    fn trusted_peer_walks_right_to_left() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let client: IpAddr = "203.0.113.50".parse().unwrap();

        let headers = headers_with_xff("198.51.100.1, 203.0.113.50, 127.0.0.5");
        assert_eq!(client_ip(peer, &headers, &local_trusted()), client);
    }

    #[test]
    fn spoofed_left_entries_are_ignored() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let client: IpAddr = "203.0.113.50".parse().unwrap();

        // The attacker-controlled leftmost entry must never win.
        let headers = headers_with_xff("6.6.6.6, 203.0.113.50, 127.0.0.5");
        assert_eq!(client_ip(peer, &headers, &local_trusted()), client);
    }

    #[test]
    fn untrusted_rightmost_hop_wins_over_left_entries() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let untrusted_hop: IpAddr = "198.51.100.7".parse().unwrap();

        // First untrusted from the right is the answer, even if entries to
        // its left look plausible.
        let headers = headers_with_xff("1.1.1.1, 198.51.100.7, 127.0.0.5");
        assert_eq!(client_ip(peer, &headers, &local_trusted()), untrusted_hop);
    }

    #[test]
    fn all_trusted_chain_returns_leftmost() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let leftmost: IpAddr = "127.0.0.9".parse().unwrap();

        let headers = headers_with_xff("127.0.0.9, 127.0.0.7");
        assert_eq!(client_ip(peer, &headers, &local_trusted()), leftmost);
    }

    #[test]
    fn missing_or_malformed_header_falls_back_to_peer() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();

        assert_eq!(client_ip(peer, &HeaderMap::new(), &local_trusted()), peer);

        // Malformed hop stops the walk at the last trusted address.
        let headers = headers_with_xff("garbage, 127.0.0.5");
        let trusted_hop: IpAddr = "127.0.0.5".parse::<IpAddr>().unwrap();
        assert_eq!(client_ip(peer, &headers, &local_trusted()), trusted_hop);
    }

    #[test]
    fn hop_with_port_is_accepted() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let client: IpAddr = "203.0.113.50".parse().unwrap();

        let headers = headers_with_xff("203.0.113.50:54321, 127.0.0.5:80");
        assert_eq!(client_ip(peer, &headers, &local_trusted()), client);

        let headers = headers_with_xff("[2001:db8::1]:443, 127.0.0.5");
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        assert_eq!(client_ip(peer, &headers, &local_trusted()), v6);
    }

    #[test]
    fn parse_trusted_proxies_skips_invalid_entries() {
        let parsed = parse_trusted_proxies("10.0.0.0/8, oops, ::1");
        assert_eq!(parsed.len(), 2);
        assert!(parse_trusted_proxies("").is_empty());
    }

    #[test]
    fn empty_trusted_list_uses_peer_directly() {
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let headers = headers_with_xff("1.2.3.4");
        assert_eq!(client_ip(peer, &headers, &[]), peer);
    }

    #[test]
    fn multi_line_xff_combines_lines_right_to_left() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let client: IpAddr = "198.51.100.99".parse().unwrap();

        // Line 1 is attacker-controlled and rotates; line 2 is what the
        // trusted proxy appended. The client must come from line 2.
        let headers = headers_with_xff_lines(&["6.6.6.6, 203.0.113.10", "198.51.100.99"]);
        assert_eq!(client_ip(peer, &headers, &local_trusted()), client);

        // Same shape, all-trusted line 2: walk continues into line 1 and
        // stops at its first untrusted entry.
        let headers = headers_with_xff_lines(&["203.0.113.50", "127.0.0.5"]);
        let expected: IpAddr = "203.0.113.50".parse().unwrap();
        assert_eq!(client_ip(peer, &headers, &local_trusted()), expected);
    }
}
