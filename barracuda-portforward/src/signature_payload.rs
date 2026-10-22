//! PIA port-forward JSON payload extraction and Base64 decoding.

pub fn extract_json_str(json: &str, key: &str) -> Option<String> {
    let target = format!("\"{key}\"");
    let bytes = json.as_bytes();
    let mut i = 0;
    let mut in_str = false;
    let mut esc = false;

    while i < bytes.len() {
        let b = bytes[i];
        if esc {
            esc = false;
            i += 1;
            continue;
        }
        if b == b'\\' && in_str {
            esc = true;
            i += 1;
            continue;
        }
        if b == b'"' {
            if !in_str && json[i..].starts_with(&target) {
                let after_key = i + target.len();
                let rest = json[after_key..].trim_start();
                if let Some(after_colon) = rest.strip_prefix(':') {
                    let val_rest = after_colon.trim_start();
                    if let Some(body) = val_rest.strip_prefix('"') {
                        let mut out = String::new();
                        let mut v_esc = false;
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

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

pub fn base64_decode(input: &str) -> Option<String> {
    let clean: Vec<u8> = input
        .bytes()
        .filter(|b| !b.is_ascii_whitespace() && *b != b'=')
        .collect();
    if clean.is_empty() || clean.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut i = 0;
    while i < clean.len() {
        let b0 = b64_val(clean[i])?;
        if i + 1 >= clean.len() {
            break;
        }
        let b1 = b64_val(clean[i + 1])?;
        out.push((b0 << 2) | (b1 >> 4));
        if i + 2 < clean.len() {
            let b2 = b64_val(clean[i + 2])?;
            out.push(((b1 & 0x0f) << 4) | (b2 >> 2));
            if i + 3 < clean.len() {
                let b3 = b64_val(clean[i + 3])?;
                out.push(((b2 & 0x03) << 6) | b3);
            }
        }
        i += 4;
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_and_json_extraction() {
        let sample_b64 = "eyJwb3J0Ijo1NDMyMSwiZXhwaXJlc19hdCI6IjIwMjYtMTItMzFUMjM6NTk6NTlaIn0=";
        let decoded = base64_decode(sample_b64).unwrap();
        assert_eq!(extract_json_u16(&decoded, "port"), Some(54321));
        assert_eq!(
            extract_json_str(&decoded, "expires_at").as_deref(),
            Some("2026-12-31T23:59:59Z")
        );
    }
}
