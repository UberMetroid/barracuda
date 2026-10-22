//! Barracuda WireGuard tunnel manager and fail-closed iptables killswitch.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod enforce_firewall;
mod pia_api;
mod verify_peer;
mod wireguard_config;

use std::env;
use std::fs;
use std::process::{exit, Command};
use std::thread;
use std::time::Duration;

use enforce_firewall::{
    apply_bootstrap_firewall, apply_strict_killswitch, lock_down_ipv6_and_sysctl,
};
use pia_api::{
    authenticate_pia_token, extract_dns_servers, extract_json_str, extract_json_u16,
    parse_pia_regions, register_wg_key_with_candidates,
};
use verify_peer::{
    install_pia_ca_cert, is_valid_cidr, is_valid_ipv4, is_valid_wg_key, log, run_cmd,
    run_cmd_stdin, STATE_DIR,
};
use wireguard_config::{
    configure_wg0_interface, fetch_public_ip, get_default_gateway_and_dev, persist_tunnel_state,
    restore_bootstrap_resolv_conf, write_vpn_dns, WgTunnelParams,
};

fn unwrap_or_fatal<T>(res: Result<T, String>) -> T {
    match res {
        Ok(val) => val,
        Err(e) => {
            log(&format!("FATAL: {e}"));
            exit(1);
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.iter().any(|a| a == "--verify") {
        lock_down_ipv6_and_sysctl();
        let status = Command::new("wg").args(["show", "wg0"]).output();
        match status {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => exit(0),
            _ => exit(1),
        }
    }

    unwrap_or_fatal(install_pia_ca_cert());

    let pia_user = env::var("PIA_USER").unwrap_or_default();
    let pia_pass = env::var("PIA_PASS").unwrap_or_default();
    if pia_user.is_empty() || pia_pass.is_empty() {
        log("FATAL: PIA_USER and PIA_PASS environment variables must be set");
        exit(1);
    }
    let pia_region = env::var("PIA_REGION").unwrap_or_else(|_| "auto".to_string());
    let lan_env =
        env::var("LAN_NETWORK").unwrap_or_else(|_| "192.168.1.0/24,100.64.0.0/10".to_string());
    let lan_cidrs: Vec<String> = lan_env
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| is_valid_cidr(s))
        .collect();

    let (host_gw, host_dev) = unwrap_or_fatal(get_default_gateway_and_dev());
    let _ = fs::write(format!("{STATE_DIR}/host_gw"), &host_gw);
    let _ = fs::write(format!("{STATE_DIR}/host_dev"), &host_dev);

    let _ = run_cmd("ip", &["link", "del", "dev", "wg0"]);
    restore_bootstrap_resolv_conf();

    log("Applying bootstrap firewall rules (root-only HTTPS auth + IPv6 disabled)...");
    apply_bootstrap_firewall(&lan_cidrs);

    for cidr in &lan_cidrs {
        let _ = run_cmd(
            "ip",
            &[
                "-4", "route", "replace", cidr, "via", &host_gw, "dev", &host_dev,
            ],
        );
    }

    let pre_vpn_ip = fetch_public_ip(None).unwrap_or_else(|| "0.0.0.0".to_string());
    let _ = fs::write(format!("{STATE_DIR}/host_wan_ip"), &pre_vpn_ip);
    log(&format!(
        "Host pre-VPN public IP recorded (redacted): {}.{}.x.x",
        pre_vpn_ip.split('.').next().unwrap_or("0"),
        pre_vpn_ip.split('.').nth(1).unwrap_or("0")
    ));

    log("Authenticating with PIA API v2 to obtain token...");
    let token = unwrap_or_fatal(authenticate_pia_token(&pia_user, &pia_pass));

    log("Fetching PIA v6 server list...");
    let serverlist_raw = unwrap_or_fatal(run_cmd(
        "curl",
        &[
            "-s",
            "--max-time",
            "15",
            "https://serverlist.piaservers.net/vpninfo/servers/v6",
        ],
    ));

    let regions = parse_pia_regions(&serverlist_raw, &pia_region);
    if regions.is_empty() {
        log(&format!(
            "FATAL: No port-forwarding WireGuard regions found for '{pia_region}'"
        ));
        exit(1);
    }

    let privkey = unwrap_or_fatal(run_cmd("wg", &["genkey"]));
    let pubkey = unwrap_or_fatal(run_cmd_stdin("wg", &["pubkey"], &format!("{privkey}\n")));

    let (reg, addkey_json) = unwrap_or_fatal(register_wg_key_with_candidates(
        &regions, &token, &pubkey, &host_gw, &host_dev,
    ));

    let server_key = extract_json_str(&addkey_json, "server_key").unwrap_or_default();
    let server_port = extract_json_u16(&addkey_json, "server_port").unwrap_or(1337);
    let server_vip = extract_json_str(&addkey_json, "server_vip").unwrap_or_default();
    let peer_ip = extract_json_str(&addkey_json, "peer_ip").unwrap_or_default();
    let dns_servers = extract_dns_servers(&addkey_json);

    if !is_valid_wg_key(&server_key) || !is_valid_ipv4(&server_vip) || !is_valid_ipv4(&peer_ip) {
        log(&format!(
            "FATAL: Invalid addKey response payload: {addkey_json}"
        ));
        exit(1);
    }

    log(&format!(
        "Registered with {} ({}): peer_ip={peer_ip}, server_vip={server_vip}, port={server_port}",
        reg.wg_cn, reg.id
    ));

    unwrap_or_fatal(configure_wg0_interface(&WgTunnelParams {
        privkey: &privkey,
        peer_ip: &peer_ip,
        server_key: &server_key,
        server_vip: &server_vip,
        server_port,
        reg: &reg,
        host_gw: &host_gw,
        host_dev: &host_dev,
    }));

    unwrap_or_fatal(apply_strict_killswitch(
        &reg.wg_ip,
        server_port,
        &lan_cidrs,
        &dns_servers,
    ));
    unwrap_or_fatal(write_vpn_dns(&dns_servers));

    thread::sleep(Duration::from_secs(1));
    let Some(vpn_ip) = fetch_public_ip(Some("wg0")) else {
        log("FATAL: Could not verify public IP over wg0 tunnel!");
        exit(1);
    };

    if vpn_ip == pre_vpn_ip && pre_vpn_ip != "0.0.0.0" {
        log("FATAL: VPN public IP matches pre-VPN host IP! Aborting immediately!");
        exit(1);
    }

    log(&format!(
        "SUCCESS: Tunnel wg0 verified active! Exit IP={vpn_ip} (Region: {} / {})",
        reg.id, reg.wg_cn
    ));
    persist_tunnel_state(&token, &server_vip, &peer_ip, &vpn_ip, &reg);
}
