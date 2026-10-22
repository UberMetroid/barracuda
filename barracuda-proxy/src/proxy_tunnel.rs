//! HTTP/HTTPS CONNECT proxy tunnel handler and bidirectional stream forwarder.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::thread;
use std::time::Duration;

use crate::dns_resolver::{is_forbidden_dest, resolve_safe_addr};
use crate::health_status::wg0_is_up;

const MAX_HEADER_BYTES: usize = 16384;

pub fn find_header_end(buf: &[u8]) -> Option<usize> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(pos + 4);
    }
    buf.windows(2).position(|w| w == b"\n\n").map(|pos| pos + 2)
}

pub fn read_http_headers(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        if buf.len() >= MAX_HEADER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Header too large",
            ));
        }
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if find_header_end(&buf).is_some() {
            break;
        }
    }
    Ok(buf)
}

pub fn parse_host_port(target: &str, default_port: u16) -> Option<(String, u16)> {
    let without_scheme = if let Some(rest) = target.strip_prefix("http://") {
        rest
    } else if let Some(rest) = target.strip_prefix("https://") {
        rest
    } else {
        target
    };
    let authority = without_scheme.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        if let Ok(port) = p.parse::<u16>() {
            return Some((h.to_string(), port));
        }
    }
    Some((authority.to_string(), default_port))
}

fn verify_upstream_peer(upstream: &TcpStream) -> bool {
    match upstream.peer_addr() {
        Ok(peer) => !is_forbidden_dest(peer.ip()) && wg0_is_up(),
        Err(_) => false,
    }
}

pub fn bidirectional_copy(mut a: TcpStream, mut b: TcpStream) {
    let Ok(mut a_clone) = a.try_clone() else {
        let _ = a.shutdown(Shutdown::Both);
        let _ = b.shutdown(Shutdown::Both);
        return;
    };
    let Ok(mut b_clone) = b.try_clone() else {
        let _ = a.shutdown(Shutdown::Both);
        let _ = b.shutdown(Shutdown::Both);
        return;
    };

    let t = thread::spawn(move || {
        let _ = io::copy(&mut a_clone, &mut b_clone);
        let _ = b_clone.shutdown(Shutdown::Write);
    });
    let _ = io::copy(&mut b, &mut a);
    let _ = a.shutdown(Shutdown::Write);
    let _ = t.join();
}

pub fn handle_proxy_client(mut client: TcpStream) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(30)));

    if !wg0_is_up() {
        let _ = client.write_all(
            b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 22\r\n\r\nVPN tunnel wg0 is down",
        );
        return;
    }

    let raw = match read_http_headers(&mut client) {
        Ok(r) if !r.is_empty() => r,
        _ => return,
    };

    let header_end = find_header_end(&raw).unwrap_or(raw.len());
    let header_str = String::from_utf8_lossy(&raw[..header_end]);
    let mut lines = header_str.lines();
    let Some(first_line) = lines.next().map(str::trim) else {
        return;
    };
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        let Some((host, port)) = parse_host_port(target, 443) else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            return;
        };
        let Ok(addr) = resolve_safe_addr(&host, port) else {
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return;
        };
        let Ok(upstream) = TcpStream::connect_timeout(&addr, Duration::from_secs(10)) else {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        };
        if !verify_upstream_peer(&upstream) {
            let _ = upstream.shutdown(Shutdown::Both);
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return;
        }
        let _ = upstream.set_read_timeout(Some(Duration::from_secs(120)));
        let _ = upstream.set_write_timeout(Some(Duration::from_secs(120)));
        if client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .is_err()
        {
            return;
        }
        bidirectional_copy(client, upstream);
    } else {
        let Some((host, port)) = parse_host_port(target, 80) else {
            let _ = client.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            return;
        };
        let Ok(addr) = resolve_safe_addr(&host, port) else {
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return;
        };
        let Ok(mut upstream) = TcpStream::connect_timeout(&addr, Duration::from_secs(10)) else {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
            return;
        };
        if !verify_upstream_peer(&upstream) {
            let _ = upstream.shutdown(Shutdown::Both);
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n");
            return;
        }
        let _ = upstream.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = upstream.set_write_timeout(Some(Duration::from_secs(30)));

        let path = if let Some(idx) = target.find("://") {
            let after_scheme = &target[idx + 3..];
            after_scheme
                .find('/')
                .map(|slash_idx| &after_scheme[slash_idx..])
                .unwrap_or("/")
        } else {
            target
        };
        let version = parts.get(2).copied().unwrap_or("HTTP/1.1");
        let mut rebuilt = format!("{method} {path} {version}\r\n");
        for line in lines {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let lower_hdr = trimmed.to_ascii_lowercase();
            if lower_hdr.starts_with("proxy-connection:")
                || lower_hdr.starts_with("proxy-authorization:")
                || lower_hdr.starts_with("connection:")
            {
                continue;
            }
            rebuilt.push_str(trimmed);
            rebuilt.push_str("\r\n");
        }
        rebuilt.push_str("Connection: close\r\n\r\n");
        if upstream.write_all(rebuilt.as_bytes()).is_err() {
            return;
        }
        if header_end < raw.len() {
            let _ = upstream.write_all(&raw[header_end..]);
        }
        bidirectional_copy(client, upstream);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_host_port_and_header_end() {
        assert_eq!(
            parse_host_port("prowlarr.servarr.com:443", 443),
            Some(("prowlarr.servarr.com".to_string(), 443))
        );
        assert_eq!(find_header_end(b"GET / HTTP/1.1\n\nbody"), Some(16));
    }
}
