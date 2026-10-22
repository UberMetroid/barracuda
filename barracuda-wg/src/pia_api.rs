//! PIA v2 token authentication, v6 server list discovery, and WireGuard key registration.

use crate::verify_peer::{is_valid_hostname, is_valid_ipv4, log, run_cmd, run_cmd_stdin, CA_PATH};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WgRegion {
    pub id: String,
    pub wg_ip: String,
    pub wg_cn: String,
}

pub fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let target = format!("\"{key}\"");
    let bytes = json.as_bytes();
    let (mut i, mut in_str, mut esc) = (0, false, false);

    while i < bytes.len() {
        let b = bytes[i];
        if esc {
            esc = false;
        } else if b == b'\\' && in_str {
            esc = true;
        } else if b == b'"' {
            if !in_str && json[i..].starts_with(&target) {
                let after_key = i + target.len();
                if let Some(body) = json[after_key..]
                    .trim_start()
                    .strip_prefix(':')
                    .and_then(|ac| ac.trim_start().strip_prefix('"'))
                {
                    let (mut out, mut v_esc) = (String::new(), false);
                    for c in body.chars() {
                        if v_esc {
                            out.push(c);
                            v_esc = false;
                        } else if c == '\\' {
                            v_esc = true;
                        } else if c == '"' {
                            return Some(out);
                        } else {
                            out.push(c);
                        }
                    }
                }
                i = after_key;
                continue;
            }
            in_str = !in_str;
        }
        i += 1;
    }
    None
}

pub fn extract_json_u16(json: &str, key: &str) -> Option<u16> {
    let pattern = format!("\"{key}\"");
    let pos = json.find(&pattern)?;
    let rest = json[pos + pattern.len()..].trim_start();
    let after_colon = rest.strip_prefix(':')?.trim_start();
    let digits: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

pub fn extract_dns_servers(json: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(pos) = json.find("\"dns_servers\"") {
        let rest = &json[pos..];
        if let (Some(start), Some(end)) = (rest.find('['), rest.find(']')) {
            if start < end {
                for part in rest[start + 1..end].split(',') {
                    let cleaned = part.trim().trim_matches('"').trim();
                    if is_valid_ipv4(cleaned) {
                        out.push(cleaned.to_string());
                    }
                }
            }
        }
    }
    if out.is_empty() {
        out.push("10.0.0.243".to_string());
        out.push("10.0.0.242".to_string());
    }
    out
}

pub fn parse_pia_regions(raw_payload: &str, preferred_region: &str) -> Vec<WgRegion> {
    let json_line = raw_payload.lines().next().unwrap_or("");
    let (mut candidates, mut preferred) = (Vec::new(), Vec::new());

    for part in json_line.split("{\"id\":\"").skip(1) {
        let reconstructed = format!("{{\"id\":\"{part}");
        let Some(id) = extract_json_str(&reconstructed, "id") else {
            continue;
        };
        if !reconstructed.contains("\"offline\":false")
            || !reconstructed.contains("\"port_forward\":true")
        {
            continue;
        }
        if let Some(wg_pos) = reconstructed.find("\"wg\":[") {
            let wg_slice = &reconstructed[wg_pos..];
            if let (Some(wg_ip), Some(wg_cn)) = (
                extract_json_str(wg_slice, "ip"),
                extract_json_str(wg_slice, "cn"),
            ) {
                if is_valid_ipv4(&wg_ip) && is_valid_hostname(&wg_cn) {
                    let reg = WgRegion { id, wg_ip, wg_cn };
                    if preferred_region != "auto" && reg.id.eq_ignore_ascii_case(preferred_region) {
                        preferred.push(reg);
                    } else {
                        candidates.push(reg);
                    }
                }
            }
        }
    }
    preferred.extend(candidates);
    preferred
}

pub fn sanitize_curl_credential(input: &str) -> Result<String, String> {
    if input.chars().any(|c| c == '\n' || c == '\r' || c == '\0') {
        return Err("Credentials must not contain newline or NUL control characters".to_string());
    }
    Ok(input.replace('\\', "\\\\").replace('"', "\\\""))
}

pub fn authenticate_pia_token(pia_user: &str, pia_pass: &str) -> Result<String, String> {
    let safe_user = sanitize_curl_credential(pia_user)?;
    let safe_pass = sanitize_curl_credential(pia_pass)?;
    let curl_cfg = format!(
        "url = \"https://www.privateinternetaccess.com/api/client/v2/token\"\n--data-urlencode = \"username={safe_user}\"\n--data-urlencode = \"password={safe_pass}\"\n"
    );
    let token_resp = run_cmd_stdin(
        "curl",
        &["-sf", "--max-time", "15", "-X", "POST", "-K", "-"],
        &curl_cfg,
    )?;
    match extract_json_str(&token_resp, "token") {
        Some(t) if !t.is_empty() => Ok(t),
        _ => Err("Failed to parse PIA authentication token (check PIA_USER/PIA_PASS)".to_string()),
    }
}

pub fn register_wg_key_with_candidates(
    regions: &[WgRegion],
    token: &str,
    pubkey: &str,
    host_gw: &str,
    host_dev: &str,
) -> Result<(WgRegion, String), String> {
    for reg in regions.iter().take(8) {
        log(&format!(
            "Attempting WireGuard key registration in region '{}' ({} / {})...",
            reg.id, reg.wg_cn, reg.wg_ip
        ));
        let host_cidr = format!("{}/32", reg.wg_ip);
        let _ = run_cmd(
            "ip",
            &[
                "-4", "route", "replace", &host_cidr, "via", host_gw, "dev", host_dev,
            ],
        );
        let _ = run_cmd(
            "iptables",
            &[
                "-I",
                "OUTPUT",
                "1",
                "-d",
                &reg.wg_ip,
                "-p",
                "tcp",
                "--dport",
                "1337",
                "-m",
                "owner",
                "--uid-owner",
                "0",
                "-j",
                "ACCEPT",
            ],
        );

        let connect_to = format!("{}::{}:", reg.wg_cn, reg.wg_ip);
        let pt_arg = format!("pt={token}");
        let pub_arg = format!("pubkey={pubkey}");
        let url = format!("https://{}:1337/addKey", reg.wg_cn);

        let resp_res = run_cmd(
            "curl",
            &[
                "-sf",
                "--max-time",
                "10",
                "--cacert",
                CA_PATH,
                "--connect-to",
                &connect_to,
                "-G",
                "--data-urlencode",
                &pt_arg,
                "--data-urlencode",
                &pub_arg,
                &url,
            ],
        );
        let _ = run_cmd(
            "iptables",
            &[
                "-D",
                "OUTPUT",
                "-d",
                &reg.wg_ip,
                "-p",
                "tcp",
                "--dport",
                "1337",
                "-m",
                "owner",
                "--uid-owner",
                "0",
                "-j",
                "ACCEPT",
            ],
        );
        if let Ok(resp) = resp_res {
            if extract_json_str(&resp, "status").as_deref() == Some("OK") {
                return Ok((reg.clone(), resp));
            }
        }
    }
    Err("Could not register WireGuard key with any candidate PIA server".to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pia_regions_and_credentials() {
        let sample = r#"{"regions":[{"id":"ca_toronto","port_forward":true,"offline":false,"servers":{"wg":[{"ip":"1.2.3.4","cn":"toronto.privacy.network"}]}},{"id":"us_east","port_forward":false,"offline":false,"servers":{"wg":[{"ip":"5.6.7.8","cn":"east.privacy.network"}]}}]}"#;
        let regs = parse_pia_regions(sample, "us_east");
        assert_eq!(regs.len(), 1);
        assert_eq!(regs[0].id, "ca_toronto");
        assert!(sanitize_curl_credential("p123456").is_ok());
        assert!(sanitize_curl_credential("bad\npass").is_err());
    }
}
