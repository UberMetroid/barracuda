//! qBittorrent API torrent inspection and Sonarr/Radarr/Lidarr queue blocklisting.

use std::env;
use std::process::Command;

use crate::inspect_archive::{contains_bidi_override, has_blocked_extension};
use crate::verify_media::log;

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

pub fn extract_json_objects(json_input: &str) -> Vec<String> {
    let slice = json_input
        .find("\"records\"")
        .and_then(|p| {
            let after = &json_input[p + 9..];
            after.find('[').map(|s| &after[s..])
        })
        .unwrap_or(json_input);

    let mut objs = Vec::new();
    let (mut depth, mut start, mut in_str, mut esc) = (0usize, None, false, false);
    for (idx, c) in slice.char_indices() {
        if esc {
            esc = false;
        } else if c == '\\' && in_str {
            esc = true;
        } else if c == '"' {
            in_str = !in_str;
        } else if !in_str && c == '{' {
            if depth == 0 {
                start = Some(idx);
            }
            depth += 1;
        } else if !in_str && c == '}' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                if let Some(s) = start.take() {
                    objs.push(slice[s..=idx].to_string());
                }
            }
        }
    }
    objs
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

fn read_nonempty_env(name: &str) -> Option<String> {
    env::var(name)
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
}

pub fn find_matching_queue_ids(queue_json: &str, hash: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for obj in extract_json_objects(queue_json) {
        let matches = extract_json_str(&obj, "downloadId")
            .map(|dl_id| dl_id.eq_ignore_ascii_case(hash))
            .unwrap_or(false);
        if matches {
            if let Some(pos) = obj.find("\"id\":") {
                let id_digits: String = obj[pos + 5..]
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if !id_digits.is_empty() {
                    ids.push(id_digits);
                }
            }
        }
    }
    ids
}

pub fn notify_arr_blocklist(category: &str, hash: &str, name: &str, reason: &str) {
    let (url_env, key_env, api_ver) = match category {
        "sonarr" => ("SONARR_URL", "SONARR_API_KEY", "v3"),
        "radarr" => ("RADARR_URL", "RADARR_API_KEY", "v3"),
        "lidarr" => ("LIDARR_URL", "LIDARR_API_KEY", "v1"),
        _ => return,
    };
    let (Some(base_url), Some(api_key)) = (read_nonempty_env(url_env), read_nonempty_env(key_env))
    else {
        return;
    };

    log(&format!(
        "Notifying {category} ({base_url}) of malicious release '{name}' ({reason})"
    ));
    let queue_url = format!(
        "{base_url}/api/{api_ver}/queue?includeUnknownSeriesItems=true&includeUnknownMovieItems=true"
    );
    let key_header = format!("X-Api-Key: {api_key}");
    let Ok(queue_json) = run_cmd(
        "curl",
        &["-sf", "--max-time", "8", "-H", &key_header, &queue_url],
    ) else {
        return;
    };

    for id_digits in find_matching_queue_ids(&queue_json, hash) {
        let del_url = format!(
            "{base_url}/api/{api_ver}/queue/{id_digits}?removeFromClient=false&blocklist=true&skipRedownload=false"
        );
        let _ = run_cmd(
            "curl",
            &[
                "-sf",
                "--max-time",
                "8",
                "-X",
                "DELETE",
                "-H",
                &key_header,
                &del_url,
            ],
        );
        log(&format!(
            "Triggered {category} queue blocklist for queue id {id_digits}"
        ));
    }
}

pub fn poll_qbittorrent_torrents(quarantined_count: &mut u64) {
    let Ok(torrents_json) = run_cmd(
        "curl",
        &[
            "-sf",
            "--max-time",
            "5",
            "http://127.0.0.1:8212/api/v2/torrents/info",
        ],
    ) else {
        return;
    };

    for t_obj in extract_json_objects(&torrents_json) {
        let Some(hash) = extract_json_str(&t_obj, "hash").filter(|h| !h.is_empty()) else {
            continue;
        };
        let t_name = extract_json_str(&t_obj, "name").unwrap_or_else(|| "unknown".to_string());
        let category = extract_json_str(&t_obj, "category").unwrap_or_default();

        let files_url = format!("http://127.0.0.1:8212/api/v2/torrents/files?hash={hash}");
        let Ok(files_json) = run_cmd("curl", &["-sf", "--max-time", "5", &files_url]) else {
            continue;
        };

        let mut bad_reason = None;
        for f_obj in extract_json_objects(&files_json) {
            if let Some(fname) = extract_json_str(&f_obj, "name") {
                if contains_bidi_override(&fname) {
                    bad_reason = Some(format!("Unicode BiDi spoofing in '{fname}'"));
                    break;
                }
                if let Some(r) = has_blocked_extension(&fname) {
                    bad_reason = Some(format!("{r} in '{fname}'"));
                    break;
                }
            }
        }

        if let Some(reason) = bad_reason {
            log(&format!(
                "TORRENT PURGED: '{t_name}' (hash={hash}, category='{category}') -> {reason}"
            ));
            let hashes_arg = format!("hashes={hash}");
            let _ = run_cmd(
                "curl",
                &[
                    "-sf",
                    "--max-time",
                    "5",
                    "-X",
                    "POST",
                    "http://127.0.0.1:8212/api/v2/torrents/delete",
                    "-d",
                    &hashes_arg,
                    "-d",
                    "deleteFiles=true",
                ],
            );
            *quarantined_count += 1;
            notify_arr_blocklist(&category, &hash, &t_name, &reason);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_json_objects_and_records_envelope() {
        let envelope = r#"{"page":1,"records":[{"id":111,"downloadId":"AAAA"},{"id":222,"downloadId":"BBBB"}]}"#;
        let ids = find_matching_queue_ids(envelope, "bbbb");
        assert_eq!(ids, vec!["222".to_string()]);
    }
}
