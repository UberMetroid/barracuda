//! WireGuard interface setup, split-default routing, and VPN DNS configuration.

use std::fs;
use std::path::Path;

use crate::pia_api::WgRegion;
use crate::verify_peer::{is_valid_ipv4, run_cmd, STATE_DIR};

pub struct WgTunnelParams<'a> {
    pub privkey: &'a str,
    pub peer_ip: &'a str,
    pub server_key: &'a str,
    pub server_vip: &'a str,
    pub server_port: u16,
    pub reg: &'a WgRegion,
    pub host_gw: &'a str,
    pub host_dev: &'a str,
}

pub fn get_default_gateway_and_dev() -> Result<(String, String), String> {
    let route_out = run_cmd("ip", &["-4", "route", "show", "default"])?;
    for line in route_out.lines() {
        let tokens: Vec<&str> = line.split_whitespace().collect();
        let mut gw = None;
        let mut dev = None;
        let mut i = 0;
        while i < tokens.len() {
            if tokens[i] == "via" && i + 1 < tokens.len() {
                gw = Some(tokens[i + 1].to_string());
            } else if tokens[i] == "dev" && i + 1 < tokens.len() {
                dev = Some(tokens[i + 1].to_string());
            }
            i += 1;
        }
        if let (Some(g), Some(d)) = (gw, dev) {
            if d != "wg0" && is_valid_ipv4(&g) {
                return Ok((g, d));
            }
        }
    }
    if let (Ok(g), Ok(d)) = (
        fs::read_to_string(format!("{STATE_DIR}/host_gw")),
        fs::read_to_string(format!("{STATE_DIR}/host_dev")),
    ) {
        let g = g.trim().to_string();
        let d = d.trim().to_string();
        if is_valid_ipv4(&g) && !d.is_empty() {
            return Ok((g, d));
        }
    }
    Err("Could not determine default IPv4 gateway and interface".to_string())
}

pub fn restore_bootstrap_resolv_conf() {
    let orig_path = format!("{STATE_DIR}/resolv.conf.orig");
    if !Path::new(&orig_path).exists() {
        if let Ok(cur_dns) = fs::read_to_string("/etc/resolv.conf") {
            if !cur_dns.contains("10.0.0.24") {
                let _ = fs::write(&orig_path, &cur_dns);
            }
        }
    }
    if let Ok(orig_dns) = fs::read_to_string(&orig_path) {
        let _ = fs::write("/etc/resolv.conf", orig_dns);
    } else {
        let _ = fs::write(
            "/etc/resolv.conf",
            "nameserver 1.1.1.1\nnameserver 9.9.9.9\n",
        );
    }
}

pub fn fetch_public_ip(interface: Option<&str>) -> Option<String> {
    let urls = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ];
    for url in urls {
        let mut args = vec!["-s", "--max-time", "8"];
        if let Some(iface) = interface {
            args.push("--interface");
            args.push(iface);
        }
        args.push(url);
        if let Ok(ip) = run_cmd("curl", &args) {
            let trimmed = ip.trim().to_string();
            if is_valid_ipv4(&trimmed) {
                return Some(trimmed);
            }
        }
    }
    None
}

pub fn configure_wg0_interface(p: &WgTunnelParams<'_>) -> Result<(), String> {
    let key_file = format!("{STATE_DIR}/wg0.key");
    fs::write(&key_file, format!("{}\n", p.privkey))
        .map_err(|e| format!("Failed to write wg0.key: {e}"))?;
    let _ = run_cmd("chmod", &["600", &key_file]);

    run_cmd("ip", &["link", "add", "dev", "wg0", "type", "wireguard"])?;
    run_cmd("ip", &["link", "set", "mtu", "1420", "dev", "wg0"])?;
    run_cmd(
        "ip",
        &["address", "add", &format!("{}/32", p.peer_ip), "dev", "wg0"],
    )?;

    let endpoint = format!("{}:{}", p.reg.wg_ip, p.server_port);
    run_cmd(
        "wg",
        &[
            "set",
            "wg0",
            "private-key",
            &key_file,
            "peer",
            p.server_key,
            "endpoint",
            &endpoint,
            "allowed-ips",
            "0.0.0.0/0",
            "persistent-keepalive",
            "25",
        ],
    )?;

    run_cmd("ip", &["link", "set", "up", "dev", "wg0"])?;
    run_cmd(
        "ip",
        &[
            "-4",
            "route",
            "replace",
            &format!("{}/32", p.reg.wg_ip),
            "via",
            p.host_gw,
            "dev",
            p.host_dev,
        ],
    )?;
    let _ = run_cmd(
        "ip",
        &[
            "-4",
            "route",
            "replace",
            &format!("{}/32", p.server_vip),
            "dev",
            "wg0",
        ],
    );
    run_cmd("ip", &["-4", "route", "replace", "0.0.0.0/1", "dev", "wg0"])?;
    run_cmd(
        "ip",
        &["-4", "route", "replace", "128.0.0.0/1", "dev", "wg0"],
    )?;
    Ok(())
}

pub fn write_vpn_dns(dns_servers: &[String]) -> Result<(), String> {
    let mut resolv_content = String::from("# Managed by barracuda-wg - VPN DNS only\n");
    for dns in dns_servers {
        resolv_content.push_str(&format!("nameserver {dns}\n"));
    }
    fs::write("/etc/resolv.conf", &resolv_content)
        .map_err(|e| format!("Failed to update /etc/resolv.conf: {e}"))
}

pub fn persist_tunnel_state(
    token: &str,
    server_vip: &str,
    peer_ip: &str,
    vpn_ip: &str,
    reg: &WgRegion,
) {
    let _ = fs::write(format!("{STATE_DIR}/token"), token);
    let _ = fs::write(format!("{STATE_DIR}/server_vip"), server_vip);
    let _ = fs::write(format!("{STATE_DIR}/wg_cn"), &reg.wg_cn);
    let _ = fs::write(format!("{STATE_DIR}/wg_ip"), &reg.wg_ip);
    let _ = fs::write(format!("{STATE_DIR}/peer_ip"), peer_ip);
    let _ = fs::write(format!("{STATE_DIR}/vpn_ip"), vpn_ip);
    let _ = fs::write(format!("{STATE_DIR}/region"), &reg.id);
    for pub_file in ["vpn_ip", "region", "peer_ip"] {
        let _ = run_cmd("chmod", &["644", &format!("{STATE_DIR}/{pub_file}")]);
    }
}
