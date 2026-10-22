//! Barracuda real-time torrent and download malware scrubber.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod arr_blocklist;
mod inspect_archive;
mod verify_media;

use std::collections::HashSet;
use std::env;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use arr_blocklist::poll_qbittorrent_torrents;
use verify_media::{inspect_file_on_disk, log};

fn scan_directory_recursive(
    dir: &Path,
    verified_cache: &mut HashSet<(PathBuf, u64)>,
    quarantined_count: &mut u64,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };

        if meta.file_type().is_symlink() {
            log(&format!("SECURITY ALERT: Removing symlink escape {path:?}"));
            let _ = fs::remove_file(&path);
            *quarantined_count += 1;
            continue;
        }

        if meta.is_dir() {
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o775 {
                let _ = fs::set_permissions(&path, Permissions::from_mode(0o775));
            }
            scan_directory_recursive(&path, verified_cache, quarantined_count);
        } else if meta.is_file() {
            if let Some(reason) = inspect_file_on_disk(&path, verified_cache) {
                log(&format!(
                    "MALWARE QUARANTINED: {path:?} -> Reason: {reason}"
                ));
                let _ = fs::remove_file(&path);
                *quarantined_count += 1;
            }
        }
    }
}

fn write_scrubber_status(quarantined_count: u64, scans_completed: u64) {
    let status_json = format!(
        "{{\"scans_completed\":{scans_completed},\"quarantined_count\":{quarantined_count}}}\n"
    );
    let _ = fs::write("/tmp/barracuda-scrubber-status.json", status_json);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let once = args.iter().any(|a| a == "--once");
    let scan_root = env::var("DOWNLOADS_DIR").unwrap_or_else(|_| "/downloads".to_string());

    log(&format!(
        "Starting barracuda-scrubber security engine on {scan_root}..."
    ));
    let mut verified_cache: HashSet<(PathBuf, u64)> = HashSet::new();
    let mut quarantined_count: u64 = 0;
    let mut scans_completed: u64 = 0;
    let mut last_cache_prune = Instant::now();

    loop {
        if last_cache_prune.elapsed() > Duration::from_secs(3600) {
            verified_cache.clear();
            last_cache_prune = Instant::now();
        }

        poll_qbittorrent_torrents(&mut quarantined_count);
        scan_directory_recursive(
            Path::new(&scan_root),
            &mut verified_cache,
            &mut quarantined_count,
        );
        scans_completed += 1;
        write_scrubber_status(quarantined_count, scans_completed);

        if once {
            break;
        }
        thread::sleep(Duration::from_secs(15));
    }
}
