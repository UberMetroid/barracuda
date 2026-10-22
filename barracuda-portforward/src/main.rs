//! PIA WireGuard port-forwarding daemon for Barracuda.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod bind_port;
mod signature_payload;

use std::fs;
use std::thread;
use std::time::Duration;

use bind_port::{
    ensure_wg_port_rule, log, read_state, run_cmd, update_qbittorrent_port, CA_PATH, STATE_DIR,
};
use signature_payload::{base64_decode, extract_json_str, extract_json_u16};

fn request_signature(wg_cn: &str, server_vip: &str, token: &str) -> Result<String, String> {
    let connect_to = format!("{wg_cn}::{server_vip}:");
    let token_arg = format!("token={token}");
    let sig_url = format!("https://{wg_cn}:19999/getSignature");

    run_cmd(
        "curl",
        &[
            "-sf",
            "--max-time",
            "10",
            "--interface",
            "wg0",
            "--cacert",
            CA_PATH,
            "--connect-to",
            &connect_to,
            "-G",
            "--data-urlencode",
            &token_arg,
            &sig_url,
        ],
    )
}

fn refresh_port_binding(
    wg_cn: &str,
    server_vip: &str,
    payload: &str,
    signature: &str,
) -> Result<String, String> {
    let connect_to = format!("{wg_cn}::{server_vip}:");
    let payload_arg = format!("payload={payload}");
    let sig_arg = format!("signature={signature}");
    let bind_url = format!("https://{wg_cn}:19999/bindPort");

    run_cmd(
        "curl",
        &[
            "-sf",
            "--max-time",
            "10",
            "--interface",
            "wg0",
            "--cacert",
            CA_PATH,
            "--connect-to",
            &connect_to,
            "-G",
            "--data-urlencode",
            &payload_arg,
            "--data-urlencode",
            &sig_arg,
            &bind_url,
        ],
    )
}

fn main() {
    log("Starting PIA WireGuard Port Forwarding daemon...");
    let mut current_port: Option<u16> = None;

    loop {
        let Some(token) = read_state("token") else {
            log("Waiting for /run/pia/token...");
            thread::sleep(Duration::from_secs(5));
            continue;
        };
        let Some(server_vip) = read_state("server_vip") else {
            thread::sleep(Duration::from_secs(5));
            continue;
        };
        let Some(wg_cn) = read_state("wg_cn") else {
            thread::sleep(Duration::from_secs(5));
            continue;
        };

        log(&format!(
            "Requesting port forward signature from {wg_cn} ({server_vip})..."
        ));
        let sig_resp = match request_signature(&wg_cn, &server_vip, &token) {
            Ok(r) => r,
            Err(e) => {
                log(&format!("WARN: getSignature failed: {e}"));
                thread::sleep(Duration::from_secs(15));
                continue;
            }
        };

        if extract_json_str(&sig_resp, "status").as_deref() != Some("OK") {
            log(&format!("WARN: getSignature returned non-OK: {sig_resp}"));
            thread::sleep(Duration::from_secs(30));
            continue;
        }

        let (Some(payload), Some(signature)) = (
            extract_json_str(&sig_resp, "payload"),
            extract_json_str(&sig_resp, "signature"),
        ) else {
            log("WARN: Missing payload or signature in getSignature response");
            thread::sleep(Duration::from_secs(30));
            continue;
        };

        let Some(decoded) = base64_decode(&payload) else {
            log("WARN: Failed to base64-decode payload");
            thread::sleep(Duration::from_secs(30));
            continue;
        };

        let port = match extract_json_u16(&decoded, "port") {
            Some(p) if p > 0 => p,
            _ => {
                log(&format!("WARN: Invalid port in decoded payload: {decoded}"));
                thread::sleep(Duration::from_secs(30));
                continue;
            }
        };
        let expires_at =
            extract_json_str(&decoded, "expires_at").unwrap_or_else(|| "unknown".to_string());

        log(&format!(
            "Acquired PIA forwarded port {port} (expires {expires_at})"
        ));
        ensure_wg_port_rule(port, current_port);
        current_port = Some(port);

        let port_file = format!("{STATE_DIR}/forwarded_port");
        let _ = fs::write(&port_file, port.to_string());
        let _ = run_cmd("chmod", &["644", &port_file]);
        update_qbittorrent_port(port);

        loop {
            let cur_vip = read_state("server_vip").unwrap_or_default();
            if cur_vip != server_vip {
                log("Detected VPN gateway change; re-acquiring port forward signature...");
                break;
            }

            match refresh_port_binding(&wg_cn, &server_vip, &payload, &signature) {
                Ok(bind_resp)
                    if extract_json_str(&bind_resp, "status").as_deref() == Some("OK") =>
                {
                    log(&format!(
                        "Successfully bound & refreshed port {port} on {wg_cn}"
                    ));
                    update_qbittorrent_port(port);
                }
                Ok(bind_resp) => {
                    log(&format!(
                        "WARN: bindPort returned non-OK: {bind_resp}; re-requesting signature"
                    ));
                    break;
                }
                Err(e) => {
                    log(&format!(
                        "WARN: bindPort request failed: {e}; re-requesting signature"
                    ));
                    break;
                }
            }

            thread::sleep(Duration::from_secs(900));
        }
    }
}
