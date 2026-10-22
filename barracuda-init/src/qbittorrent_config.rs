//! Configuration provisioning for qBittorrent, *arr categories, and P2P IP blocklist.

use std::env;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

const CATEGORIES_JSON: &str = include_str!("../../assets/categories.json");
const DEFAULT_IPFILTER_P2P: &str = include_str!("../../assets/ipfilter.p2p");

pub const BLOCKED_FILE_GLOBS: &[&str] = &[
    "*.exe",
    "*.scr",
    "*.bat",
    "*.cmd",
    "*.com",
    "*.pif",
    "*.msi",
    "*.msp",
    "*.vbs",
    "*.vbe",
    "*.js",
    "*.jse",
    "*.ws",
    "*.wsf",
    "*.wsc",
    "*.wsh",
    "*.ps1",
    "*.psm1",
    "*.lnk",
    "*.inf",
    "*.reg",
    "*.hta",
    "*.cpl",
    "*.msc",
    "*.jar",
    "*.iso",
    "*.img",
    "*.vhd",
    "*.vhdx",
    "*.dll",
    "*.sys",
    "*.drv",
    "*.apk",
    "*.deb",
    "*.rpm",
    "*.appimage",
    "*.sh",
    "*.bash",
    "*.py",
    "*.pl",
    "*.rb",
    "*.php",
    "*.elf",
    "*.bin",
    "*.run",
    "*.cab",
    "*.chm",
    "*.hlp",
    "*.url",
    "*.website",
    "*.scf",
];

pub fn is_valid_ipv4(ip: &str) -> bool {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts
        .iter()
        .all(|p| !(p.len() > 1 && p.starts_with('0')) && p.parse::<u8>().is_ok())
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

pub fn sanitize_lan_whitelist(raw: &str) -> String {
    let valid: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|c| is_valid_cidr(c))
        .collect();
    if valid.is_empty() {
        "192.168.1.0/24".to_string()
    } else {
        valid.join(",")
    }
}

pub fn ensure_directories_and_ownership(puid: u32, pgid: u32) {
    let dirs = [
        "/config",
        "/config/qBittorrent",
        "/config/qBittorrent/config",
        "/config/qBittorrent/data",
        "/downloads",
        "/downloads/incomplete",
        "/downloads/sonarr",
        "/downloads/radarr",
        "/downloads/lidarr",
        "/downloads/prowlarr",
        "/run/pia",
        "/tmp",
    ];
    for d in dirs {
        let _ = fs::create_dir_all(d);
    }
    let _ = fs::set_permissions("/tmp", Permissions::from_mode(0o1777));

    let owner = format!("{puid}:{pgid}");
    let _ = Command::new("chown")
        .args(["-R", &owner, "/config", "/downloads"])
        .status();
    let _ = Command::new("chmod")
        .args(["-R", "2775", "/downloads"])
        .status();
}

pub fn write_categories_json() {
    let _ = fs::write(
        "/config/qBittorrent/config/categories.json",
        CATEGORIES_JSON,
    );
}

pub fn build_hardened_qbittorrent_conf(lan_subnet_whitelist: &str) -> String {
    let safe_whitelist = sanitize_lan_whitelist(lan_subnet_whitelist);
    let excluded_list = BLOCKED_FILE_GLOBS.join("\\n");
    format!(
        "[AutoRun]\nenabled=false\nprogram=\n\n\
[BitTorrent]\nSession\\AnonymousModeEnabled=true\n\
Session\\DefaultSavePath=/downloads\n\
Session\\DisableAutoTMMByDefault=false\n\
Session\\DisableAutoTMMTriggers\\CategoryChanged=false\n\
Session\\DisableAutoTMMTriggers\\CategorySavePathChanged=false\n\
Session\\DisableAutoTMMTriggers\\DefaultSavePathChanged=false\n\
Session\\Encryption=1\n\
Session\\ExcludedFileNames=\"{excluded_list}\"\n\
Session\\ExcludedFileNamesEnabled=true\n\
Session\\IPFilter=/config/qBittorrent/config/ipfilter.p2p\n\
Session\\IPFilteringEnabled=true\n\
Session\\Interface=wg0\n\
Session\\InterfaceName=wg0\n\
Session\\LSDEnabled=false\n\
Session\\PeXEnabled=true\n\
Session\\DHTEnabled=true\n\
Session\\QueueingSystemEnabled=false\n\
Session\\SubcategoriesEnabled=true\n\
Session\\TempPath=/downloads/incomplete\n\
Session\\TempPathEnabled=true\n\n\
[LegalNotice]\nAccepted=true\n\n\
[Network]\nPortForwardingEnabled=false\n\n\
[Preferences]\nBittorrent\\MaxConnecs=500\n\
Bittorrent\\MaxConnecsPerTorrent=100\n\
Bittorrent\\uTP=true\n\
Connection\\Interface=wg0\n\
Connection\\InterfaceName=wg0\n\
Connection\\ResolvePeerCountries=false\n\
Connection\\UPnP=false\n\
Downloads\\SavePath=/downloads/\n\
Downloads\\TempPath=/downloads/incomplete/\n\
Downloads\\TempPathEnabled=true\n\
Downloads\\UseIncompleteExtension=true\n\
IPFilter\\Enabled=true\n\
IPFilter\\File=/config/qBittorrent/config/ipfilter.p2p\n\
WebUI\\Address=*\n\
WebUI\\AuthSubnetWhitelist={safe_whitelist}\n\
WebUI\\AuthSubnetWhitelistEnabled=true\n\
WebUI\\CSRFProtection=false\n\
WebUI\\ClickjackingProtection=true\n\
WebUI\\HostHeaderValidation=false\n\
WebUI\\LocalHostAuth=false\n\
WebUI\\Port=8212\n\
WebUI\\SecureCookie=false\n\
WebUI\\ServerDomains=*\n"
    )
}

pub fn write_hardened_qbittorrent_conf(lan_subnet_whitelist: &str) {
    let conf = build_hardened_qbittorrent_conf(lan_subnet_whitelist);
    let _ = fs::write("/config/qBittorrent/config/qBittorrent.conf", conf);
}

pub fn update_ipfilter_blocklist(puid: u32, pgid: u32) {
    let filter_path = "/config/qBittorrent/config/ipfilter.p2p";
    let tmp_path = "/config/qBittorrent/config/ipfilter.p2p.tmp";
    if !Path::new(filter_path).exists() {
        let _ = fs::write(filter_path, DEFAULT_IPFILTER_P2P);
    }

    if let Ok(url) = env::var("BLOCKLIST_URL") {
        let trimmed = url.trim();
        if !trimmed.is_empty() {
            eprintln!("[barracuda-init] Fetching updated P2P blocklist from {trimmed}...");
            let st = Command::new("curl")
                .args([
                    "-sfL",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "--max-time",
                    "20",
                    "--interface",
                    "wg0",
                    trimmed,
                    "-o",
                    tmp_path,
                ])
                .status();
            if matches!(st, Ok(s) if s.success()) {
                let _ = fs::rename(tmp_path, filter_path);
            } else {
                let _ = fs::remove_file(tmp_path);
            }
        }
    }
    let owner = format!("{puid}:{pgid}");
    let _ = Command::new("chown").args([&owner, filter_path]).status();
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_build_hardened_qbittorrent_conf() {
        let conf = build_hardened_qbittorrent_conf("192.168.1.0/24,bad\ninjection,010.0.0.1/8");
        assert!(conf.contains("WebUI\\AuthSubnetWhitelist=192.168.1.0/24\n"));
        assert!(!conf.contains("injection"));
    }
}
