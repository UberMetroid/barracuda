//! VPN UDP DNS resolver and SSRF / non-WAN destination address guard.

use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static DNS_TX_COUNTER: AtomicU16 = AtomicU16::new(1);

pub fn is_forbidden_dest(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 0b0100_0000)
                || (v4.octets()[0] == 169 && v4.octets()[1] == 254)
        }
        IpAddr::V6(_) => true,
    }
}

pub fn read_nameserver() -> Ipv4Addr {
    if let Ok(content) = fs::read_to_string("/etc/resolv.conf") {
        for line in content.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("nameserver") {
                if let Some(ns) = rest.split_whitespace().next() {
                    if let Ok(ip) = ns.parse::<Ipv4Addr>() {
                        return ip;
                    }
                }
            }
        }
    }
    Ipv4Addr::new(10, 0, 0, 243)
}

pub fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    let mut jumps = 0;
    loop {
        if pos >= pkt.len() || jumps > 16 {
            return None;
        }
        let len = pkt[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            if pos + 1 >= pkt.len() {
                return None;
            }
            return Some(pos + 2);
        }
        pos += 1 + (len as usize);
        jumps += 1;
    }
}

pub fn query_dns_a(host: &str) -> io::Result<Vec<Ipv4Addr>> {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(vec![ip]);
    }
    let ns_addr = SocketAddr::V4(SocketAddrV4::new(read_nameserver(), 53));
    let sock = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))?;
    sock.set_read_timeout(Some(Duration::from_secs(4)))?;
    sock.set_write_timeout(Some(Duration::from_secs(4)))?;

    let seq = DNS_TX_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u16;
    let txid: u16 = nanos ^ seq.rotate_left(7) ^ 0x5A3C;

    let mut q = Vec::with_capacity(64);
    q.extend_from_slice(&txid.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid DNS label",
            ));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

    sock.send_to(&q, ns_addr)?;
    let mut resp = [0u8; 1024];
    let (n, src_addr) = sock.recv_from(&mut resp)?;
    if src_addr != ns_addr || n < 12 || resp[0..2] != txid.to_be_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DNS response mismatch",
        ));
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]);
    let ancount = u16::from_be_bytes([resp[6], resp[7]]);
    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(&resp[..n], pos)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Truncated question"))?;
        if pos + 4 > n {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Truncated question tail",
            ));
        }
        pos += 4;
    }
    let mut ips = Vec::new();
    for _ in 0..ancount {
        pos = skip_dns_name(&resp[..n], pos)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Truncated answer name"))?;
        if pos + 10 > n {
            break;
        }
        let rtype = u16::from_be_bytes([resp[pos], resp[pos + 1]]);
        let rclass = u16::from_be_bytes([resp[pos + 2], resp[pos + 3]]);
        let rdlen = u16::from_be_bytes([resp[pos + 8], resp[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > n {
            break;
        }
        if rtype == 1 && rclass == 1 && rdlen == 4 {
            ips.push(Ipv4Addr::new(
                resp[pos],
                resp[pos + 1],
                resp[pos + 2],
                resp[pos + 3],
            ));
        }
        pos += rdlen;
    }
    Ok(ips)
}

pub fn resolve_safe_addr(host: &str, port: u16) -> io::Result<SocketAddr> {
    let v4_ips = query_dns_a(host)?;
    let Some(first_ip) = v4_ips.first().copied() else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "No IPv4 address resolved via VPN DNS",
        ));
    };
    for ip in &v4_ips {
        if is_forbidden_dest(IpAddr::V4(*ip)) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Destination IP blocked by SSRF / non-WAN filter",
            ));
        }
    }
    Ok(SocketAddr::V4(SocketAddrV4::new(first_ip, port)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_ssrf_forbidden_dest() {
        assert!(is_forbidden_dest(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(is_forbidden_dest(IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 10
        ))));
        assert!(is_forbidden_dest(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_forbidden_dest(IpAddr::V4(Ipv4Addr::new(
            169, 254, 169, 254
        ))));
        assert!(!is_forbidden_dest(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }
}
