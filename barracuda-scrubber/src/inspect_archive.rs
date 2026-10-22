//! Filename, extension, double-extension, BiDi spoofing, and archive header inspection.

pub const BLOCKED_EXTENSIONS: &[&str] = &[
    "exe", "scr", "bat", "cmd", "com", "pif", "msi", "msp", "vbs", "vbe", "js", "jse", "ws", "wsf",
    "wsc", "wsh", "ps1", "psm1", "psd1", "lnk", "inf", "reg", "hta", "cpl", "msc", "jar", "iso",
    "img", "vhd", "vhdx", "dll", "sys", "drv", "ocx", "apk", "deb", "rpm", "appimage", "sh",
    "bash", "csh", "ksh", "zsh", "py", "pl", "rb", "php", "elf", "bin", "run", "cab", "chm", "hlp",
    "url", "website", "scf",
];

pub fn contains_bidi_override(name: &str) -> bool {
    name.chars().any(|c| {
        matches!(
            c as u32,
            0x202A..=0x202E | 0x2066..=0x2069 | 0x200E | 0x200F | 0x061C
        )
    })
}

pub fn has_blocked_extension(filename: &str) -> Option<String> {
    let lower = filename.trim().to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);
    let parts: Vec<&str> = base.split('.').collect();
    if parts.len() < 2 {
        return None;
    }
    if let Some(last_ext) = parts.last() {
        let clean_ext = last_ext.trim_end_matches([' ', '.']);
        if BLOCKED_EXTENSIONS.contains(&clean_ext) {
            return Some(format!("blocked extension .{clean_ext}"));
        }
    }
    if parts.len() >= 3 {
        let penultimate = parts[parts.len() - 2];
        if [
            "exe", "lnk", "scr", "bat", "cmd", "ps1", "vbs", "hta", "msi", "com",
        ]
        .contains(&penultimate)
        {
            return Some(format!(
                "suspicious double extension .{penultimate}.{}",
                parts.last().unwrap_or(&"")
            ));
        }
    }
    None
}

pub fn inspect_zip_encryption(buf: &[u8]) -> Option<String> {
    let mut i = 0;
    let mut entry_count = 0usize;
    while i + 30 <= buf.len() {
        if &buf[i..i + 4] == b"PK\x03\x04" {
            entry_count += 1;
            if entry_count > 512 {
                return Some("ZIP bomb / excessive local header count".to_string());
            }
            let flags = u16::from_le_bytes([buf[i + 6], buf[i + 7]]);
            if (flags & 0x0001) != 0 {
                return Some("Password-protected / encrypted ZIP archive trap".to_string());
            }
            let name_len = u16::from_le_bytes([buf[i + 26], buf[i + 27]]) as usize;
            let extra_len = u16::from_le_bytes([buf[i + 28], buf[i + 29]]) as usize;
            if i + 30 + name_len <= buf.len() {
                let entry_name = String::from_utf8_lossy(&buf[i + 30..i + 30 + name_len]);
                if let Some(reason) = has_blocked_extension(&entry_name) {
                    return Some(format!("ZIP archive contains {reason} ({entry_name})"));
                }
            }
            let step = 30usize.saturating_add(name_len).saturating_add(extra_len);
            i = i.saturating_add(step.max(1));
        } else {
            i += 1;
        }
    }
    None
}

pub fn inspect_rar_encryption(buf: &[u8]) -> Option<String> {
    if buf.len() >= 16 && &buf[0..8] == b"Rar!\x1a\x07\x01\x00" {
        let mut pos = 8;
        if pos + 7 < buf.len() {
            pos += 4;
            while pos < buf.len() && (buf[pos] & 0x80) != 0 {
                pos += 1;
            }
            pos += 1;
            if pos < buf.len() {
                let header_type = buf[pos] & 0x7f;
                if header_type == 4 {
                    return Some("Encrypted RAR5 archive header trap".to_string());
                }
            }
        }
    }
    if buf.len() >= 14 && &buf[0..7] == b"Rar!\x1a\x07\x00" && buf[9] == 0x73 {
        let flags = u16::from_le_bytes([buf[10], buf[11]]);
        if (flags & 0x0080) != 0 {
            return Some("Encrypted RAR4 header trap".to_string());
        }
    }
    None
}

pub fn inspect_7z_encryption(buf: &[u8]) -> Option<String> {
    if buf.len() >= 32 && &buf[0..6] == b"7z\xbc\xaf\x27\x1c" {
        for window in buf.windows(4) {
            if window == [0x06, 0xF1, 0x07, 0x01] {
                return Some("Encrypted 7z AES archive trap".to_string());
            }
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_blocked_extensions_and_bidi() {
        assert!(has_blocked_extension("movie.mkv.exe").is_some());
        assert!(has_blocked_extension("invoice.exe.mp4").is_some());
        assert!(has_blocked_extension("movie.1080p.mkv").is_none());
        assert!(contains_bidi_override("video\u{202E}4pm.exe"));
        assert!(!contains_bidi_override("clean_video.mp4"));
    }
}
