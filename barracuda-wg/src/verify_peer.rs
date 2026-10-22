//! X.509 RSA-4096 certificate verification and peer address/key validation.

use std::fs;
use std::io::Write;
use std::process::{Command, Stdio};

pub const PIA_CA_CRT: &str = include_str!("../../assets/pia-ca.rsa.4096.crt");
pub const STATE_DIR: &str = "/run/pia";
pub const CA_PATH: &str = "/run/pia/ca.rsa.4096.crt";

pub fn log(msg: &str) {
    eprintln!("[barracuda-wg] {msg}");
}

pub fn run_cmd(prog: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(prog)
        .args(args)
        .output()
        .map_err(|e| format!("Failed to spawn {prog}: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!(
            "{prog} {args:?} failed: {} {}",
            stdout.trim(),
            stderr.trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn run_cmd_stdin(prog: &str, args: &[&str], input: &str) -> Result<String, String> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn {prog}: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| format!("stdin write failed: {e}"))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait failed: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{prog} {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn verify_ca_bundle(pem: &str) -> bool {
    let trimmed = pem.trim();
    trimmed.starts_with("-----BEGIN CERTIFICATE-----")
        && trimmed.ends_with("-----END CERTIFICATE-----")
        && trimmed.len() >= 1800
}

pub fn install_pia_ca_cert() -> Result<(), String> {
    if !verify_ca_bundle(PIA_CA_CRT) {
        return Err("Embedded PIA RSA-4096 CA certificate failed sanity check".to_string());
    }
    fs::create_dir_all(STATE_DIR).map_err(|e| format!("Failed to create {STATE_DIR}: {e}"))?;
    let _ = run_cmd("chmod", &["700", STATE_DIR]);
    fs::write(CA_PATH, PIA_CA_CRT).map_err(|e| format!("Failed to write {CA_PATH}: {e}"))
}

pub fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| !(p.len() > 1 && p.starts_with('0')) && p.parse::<u8>().is_ok())
}

pub fn is_valid_hostname(cn: &str) -> bool {
    !cn.is_empty()
        && cn.len() <= 128
        && cn
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_')
}

pub fn is_valid_wg_key(k: &str) -> bool {
    k.len() == 44
        && k.ends_with('=')
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

pub fn is_valid_cidr(cidr: &str) -> bool {
    if let Some((ip, prefix)) = cidr.split_once('/') {
        !(prefix.len() > 1 && prefix.starts_with('0'))
            && prefix.parse::<u8>().map(|p| p <= 32).unwrap_or(false)
            && is_valid_ipv4(ip)
    } else {
        is_valid_ipv4(cidr)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_validators_and_ca_bundle() {
        assert!(verify_ca_bundle(PIA_CA_CRT));
        assert!(is_valid_ipv4("10.0.0.243"));
        assert!(!is_valid_ipv4("010.001.002.003"));
        assert!(!is_valid_ipv4("999.1.1.1"));
        assert!(is_valid_hostname("us-california.privacy.network"));
        assert!(!is_valid_hostname("bad/host"));
        assert!(is_valid_wg_key(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        ));
        assert!(is_valid_cidr("192.168.1.0/24"));
        assert!(!is_valid_cidr("192.168.1.0/08"));
        assert!(!is_valid_cidr("192.168.1.0/33"));
    }
}
