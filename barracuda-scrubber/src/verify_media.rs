//! On-disk file magic-byte inspection, O_NOFOLLOW symlink defense, and ffprobe verification.

use std::collections::HashSet;
use std::fs::{self, File, Permissions};
use std::io::Read;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::inspect_archive::{
    contains_bidi_override, has_blocked_extension, inspect_7z_encryption, inspect_rar_encryption,
    inspect_zip_encryption,
};

const O_NOFOLLOW: i32 = 0o400_000;
const O_CLOEXEC: i32 = 0o2_000_000;
const VIDEO_EXTS: &[&str] = &[
    "mkv", "mp4", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg", "ts", "m2ts",
];
const AUDIO_EXTS: &[&str] = &[
    "mp3", "flac", "m4a", "aac", "ogg", "opus", "wav", "wma", "alac", "aiff",
];
const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "webp", "gif", "bmp", "tbn"];
const PLAYLIST_EXTS: &[&str] = &["m3u", "m3u8", "pls", "asx", "xspf", "cue"];

pub fn log(msg: &str) {
    eprintln!("[barracuda-scrubber] {msg}");
}

fn open_nofollow(path: &Path) -> Option<File> {
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW | O_CLOEXEC)
        .open(path)
        .ok()
}

pub fn inspect_magic_bytes(buf: &[u8], file_name: &str, ext: &str) -> Option<String> {
    let n = buf.len();
    if n >= 2 && &buf[0..2] == b"MZ" {
        return Some(format!(
            "PE/Windows executable magic bytes (MZ) disguised as '{file_name}'"
        ));
    }
    if n >= 4 && &buf[0..4] == b"\x7fELF" {
        return Some(format!("ELF binary magic bytes disguised as '{file_name}'"));
    }
    if n >= 20
        && &buf[0..8] == b"\x4c\x00\x00\x00\x01\x14\x02\x00"
        && &buf[8..16] == b"\x00\x00\x00\x00\xc0\x00\x00\x00"
    {
        return Some(format!(
            "Windows Shell Link (.LNK) magic header disguised as '{file_name}'"
        ));
    }
    if n >= 2 && &buf[0..2] == b"#!" {
        return Some(format!(
            "Executable script shebang (#!) disguised as '{file_name}'"
        ));
    }
    if ext == "zip" || (n >= 4 && &buf[0..4] == b"PK\x03\x04") {
        if let Some(reason) = inspect_zip_encryption(buf) {
            return Some(reason);
        }
    }
    if ext == "rar" || (n >= 7 && &buf[0..6] == b"Rar!\x1a\x07") {
        if let Some(reason) = inspect_rar_encryption(buf) {
            return Some(reason);
        }
    }
    if ext == "7z" || (n >= 6 && &buf[0..6] == b"7z\xbc\xaf\x27\x1c") {
        if let Some(reason) = inspect_7z_encryption(buf) {
            return Some(reason);
        }
    }
    if IMAGE_EXTS.contains(&ext) {
        let lower_sample = String::from_utf8_lossy(buf).to_ascii_lowercase();
        if ["<svg", "<script", "<?php"]
            .iter()
            .any(|p| lower_sample.contains(p))
        {
            return Some(format!(
                "Script/SVG payload disguised inside image '{file_name}'"
            ));
        }
    }
    if PLAYLIST_EXTS.contains(&ext) {
        let lower_sample = String::from_utf8_lossy(buf).to_ascii_lowercase();
        if ["http://", "https://", "\\", "file://"]
            .iter()
            .any(|p| lower_sample.contains(p))
        {
            return Some(format!(
                "External URL or UNC tracking beacon inside playlist '{file_name}'"
            ));
        }
    }
    None
}

pub fn verify_media_with_ffprobe(
    path: &Path,
    expect_video: bool,
    expect_audio: bool,
) -> Option<String> {
    let path_str = path.to_str()?;
    let out = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "stream=codec_type:stream_tags=filename,mimetype",
            "-of",
            "default=noprint_wrappers=1",
            path_str,
        ])
        .output()
        .ok()?;

    let display_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path_str);
    if !out.status.success() {
        return Some(format!(
            "Corrupt or fake media container rejected by ffprobe: '{display_name}'"
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
    let has_video = stdout.lines().any(|l| l.trim() == "codec_type=video");
    let has_audio = stdout.lines().any(|l| l.trim() == "codec_type=audio");

    if expect_video && !has_video {
        return Some(format!(
            "Video file '{display_name}' contains no valid video stream"
        ));
    }
    if expect_audio && !has_audio && !has_video {
        return Some(format!(
            "Audio file '{display_name}' contains no valid audio stream"
        ));
    }

    for line in stdout.lines() {
        if let Some(attached_name) = line.strip_prefix("tag:filename=") {
            if let Some(reason) = has_blocked_extension(attached_name) {
                return Some(format!(
                    "Matroska/media attachment contains {reason} ({attached_name})"
                ));
            }
        }
        if let Some(mime) = line.strip_prefix("tag:mimetype=") {
            if ["x-msdownload", "x-executable", "x-dosexec", "x-sh"]
                .iter()
                .any(|m| mime.contains(m))
            {
                return Some(format!(
                    "Suspicious executable attachment mimetype ({mime}) in media file"
                ));
            }
        }
    }
    None
}

pub fn inspect_file_on_disk(
    path: &Path,
    verified_cache: &mut HashSet<(PathBuf, u64)>,
) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if meta.file_type().is_symlink() {
        return Some("Symlink escape attempt inside download directory".to_string());
    }
    if !meta.is_file() {
        return None;
    }

    let Some(mut f) = open_nofollow(path) else {
        if fs::symlink_metadata(path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Some("Symlink TOCTOU swap detected during open_nofollow".to_string());
        }
        return None;
    };

    if let Ok(fd_meta) = f.metadata() {
        let mode = fd_meta.permissions().mode() & 0o777;
        if (mode & 0o111) != 0 {
            let _ = f.set_permissions(Permissions::from_mode((mode & !0o111) | 0o664));
        }
    }

    let file_name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if contains_bidi_override(file_name) {
        return Some(format!(
            "Unicode BiDi / RLO spoofing character in '{file_name}'"
        ));
    }

    let is_incomplete = file_name.ends_with(".!qB");
    let check_name = file_name.strip_suffix(".!qB").unwrap_or(file_name);
    if let Some(reason) = has_blocked_extension(check_name) {
        return Some(format!("{reason} in '{file_name}'"));
    }

    let ext = Path::new(check_name)
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();

    let mut buf = vec![0u8; 8192];
    let n = f.read(&mut buf).unwrap_or(0);
    buf.truncate(n);

    // Always inspect magic bytes and encrypted archive headers even for incomplete .!qB files!
    if let Some(reason) = inspect_magic_bytes(&buf, file_name, &ext) {
        return Some(reason);
    }
    if is_incomplete {
        return None;
    }

    let is_video = VIDEO_EXTS.contains(&ext.as_str());
    let is_audio = AUDIO_EXTS.contains(&ext.as_str());
    if (is_video || is_audio) && meta.len() > 0 {
        let cache_key = (path.to_path_buf(), meta.len());
        if !verified_cache.contains(&cache_key) {
            if let Some(reason) = verify_media_with_ffprobe(path, is_video, is_audio) {
                return Some(reason);
            }
            verified_cache.insert(cache_key);
        }
    }
    None
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_bytes_detection() {
        assert!(inspect_magic_bytes(b"MZ\x90\x00", "video.mkv.!qB", "mkv").is_some());
        assert!(inspect_magic_bytes(b"\x7fELF\x02", "song.mp3", "mp3").is_some());
        assert!(inspect_magic_bytes(b"#!/bin/sh\n", "readme.txt", "txt").is_some());
        assert!(inspect_magic_bytes(b"http://evil.com/track.mp3", "list.m3u", "m3u").is_some());
    }
}
