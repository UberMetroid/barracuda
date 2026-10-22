//! Port-binding enforcement for iptables wg0 ingress and qBittorrent WebUI API.

use std::fs;
use std::process::Command;
use std::thread;
use std::time::Duration;

pub const STATE_DIR: &str = "/run/pia";
pub const CA_PATH: &str = "/run/pia/ca.rsa.4096.crt";

pub fn log(msg: &str) {
    eprintln!("[barracuda-portforward] {msg}");
}

pub fn run_cmd(prog: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to spawn {prog}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{prog} {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn read_state(name: &str) -> Option<String> {
    fs::read_to_string(format!("{STATE_DIR}/{name}"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn build_qbt_preferences_payload(port: u16) -> String {
    format!("json={{\"listen_port\":{port},\"upnp\":false,\"random_port\":false}}")
}

pub fn update_qbittorrent_port(port: u16) {
    let json_arg = build_qbt_preferences_payload(port);
    for _ in 0..5 {
        if run_cmd(
            "curl",
            &[
                "-sf",
                "--max-time",
                "5",
                "-X",
                "POST",
                "http://127.0.0.1:8112/api/v2/app/setPreferences",
                "--data-urlencode",
                &json_arg,
            ],
        )
        .is_ok()
        {
            log(&format!("Updated qBittorrent listening port to {port}"));
            return;
        }
        thread::sleep(Duration::from_secs(2));
    }
    log("WARN: Could not reach qBittorrent WebUI on 127.0.0.1:8112 to set listen_port yet");
}

pub fn ensure_wg_port_rule(port: u16, prev_port: Option<u16>) {
    let stale_port =
        prev_port.or_else(|| read_state("forwarded_port").and_then(|s| s.parse::<u16>().ok()));
    if let Some(old) = stale_port {
        if old != port {
            let old_s = old.to_string();
            for proto in ["tcp", "udp"] {
                let _ = run_cmd(
                    "iptables",
                    &[
                        "-D", "INPUT", "-i", "wg0", "-p", proto, "--dport", &old_s, "-j", "ACCEPT",
                    ],
                );
            }
        }
    }
    let port_s = port.to_string();
    for proto in ["tcp", "udp"] {
        if run_cmd(
            "iptables",
            &[
                "-C", "INPUT", "-i", "wg0", "-p", proto, "--dport", &port_s, "-j", "ACCEPT",
            ],
        )
        .is_err()
        {
            let _ = run_cmd(
                "iptables",
                &[
                    "-I", "INPUT", "1", "-i", "wg0", "-p", proto, "--dport", &port_s, "-j",
                    "ACCEPT",
                ],
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_build_qbt_preferences_payload() {
        let payload = build_qbt_preferences_payload(51413);
        assert_eq!(
            payload,
            "json={\"listen_port\":51413,\"upnp\":false,\"random_port\":false}"
        );
    }
}
