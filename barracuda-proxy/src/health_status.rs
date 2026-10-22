//! Health & VPN tunnel telemetry HTTP endpoint on port 9299.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const STATE_DIR: &str = "/run/pia";

pub fn log(msg: &str) {
    eprintln!("[barracuda-proxy] {msg}");
}

pub fn wg0_is_up() -> bool {
    let Ok(oper) = fs::read_to_string("/sys/class/net/wg0/operstate") else {
        return false;
    };
    if oper.trim() == "down" {
        return false;
    }
    if let Ok(flags_str) = fs::read_to_string("/sys/class/net/wg0/flags") {
        let clean = flags_str.trim().trim_start_matches("0x");
        if let Ok(flags) = u32::from_str_radix(clean, 16) {
            return (flags & 0x1) != 0;
        }
    }
    false
}

pub fn read_state_file(name: &str) -> String {
    fs::read_to_string(format!("{STATE_DIR}/{name}"))
        .ok()
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

pub fn format_health_response(
    wg_up: bool,
    vpn_ip: &str,
    peer_ip: &str,
    region: &str,
    forwarded_port: u16,
    active_conns: usize,
    uptime: u64,
) -> String {
    let healthy = wg_up && !vpn_ip.is_empty();
    let status_code = if healthy {
        "200 OK"
    } else {
        "503 Service Unavailable"
    };
    let status_label = if healthy { "healthy" } else { "unhealthy" };

    let body = format!(
        "{{\"status\":\"{status_label}\",\"wg0_up\":{wg_up},\"vpn_exit_ip\":\"{vpn_ip}\",\"vpn_peer_ip\":\"{peer_ip}\",\"region\":\"{region}\",\"forwarded_port\":{forwarded_port},\"active_proxy_connections\":{active_conns},\"uptime_seconds\":{uptime}}}\n"
    );

    format!(
        "HTTP/1.1 {status_code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

pub fn handle_health_client(mut client: TcpStream, start_epoch: u64, active_conns: usize) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = client.set_write_timeout(Some(Duration::from_secs(5)));
    let mut req_buf = [0u8; 1024];
    let _ = client.read(&mut req_buf);

    let wg_up = wg0_is_up();
    let vpn_ip = read_state_file("vpn_ip");
    let peer_ip = read_state_file("peer_ip");
    let region = read_state_file("region");
    let port_str = read_state_file("forwarded_port");
    let forwarded_port: u16 = port_str.parse().unwrap_or(0);

    let now_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let uptime = now_epoch.saturating_sub(start_epoch);

    let resp = format_health_response(
        wg_up,
        &vpn_ip,
        &peer_ip,
        &region,
        forwarded_port,
        active_conns,
        uptime,
    );
    let _ = client.write_all(resp.as_bytes());
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_format_health_response() {
        let ok_resp = format_health_response(
            true,
            "203.0.113.5",
            "10.20.30.40",
            "ca_toronto",
            51413,
            2,
            120,
        );
        assert!(ok_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(ok_resp.contains("\"status\":\"healthy\""));

        let down_resp = format_health_response(false, "", "", "", 0, 0, 10);
        assert!(down_resp.starts_with("HTTP/1.1 503 Service Unavailable"));
    }
}
