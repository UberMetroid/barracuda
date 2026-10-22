//! Daemon spawning, privilege dropping, and WireGuard tunnel health checks.

use std::fs;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command};
use std::thread;
use std::time::Duration;

pub fn parse_octal_umask(s: &str) -> u32 {
    u32::from_str_radix(s.trim(), 8).unwrap_or(0o002)
}

pub fn format_umask(umask_val: u32) -> String {
    format!("{umask_val:03o}")
}

pub fn spawn_unprivileged(
    prog: &str,
    args: &[&str],
    puid: u32,
    pgid: u32,
    umask_val: u32,
) -> Result<Child, String> {
    let uid_arg = format!("--reuid={puid}");
    let gid_arg = format!("--regid={pgid}");

    // When invoking setpriv, do NOT call .uid()/.gid() before exec so setpriv
    // starts with CAP_SETGID and can execute --clear-groups cleanly.
    let mut setpriv_cmd = Command::new("setpriv");
    setpriv_cmd
        .arg(&uid_arg)
        .arg(&gid_arg)
        .arg("--clear-groups")
        .arg("--")
        .arg(prog)
        .args(args)
        .env("HOME", "/config")
        .env("XDG_CONFIG_HOME", "/config")
        .env("XDG_DATA_HOME", "/config")
        .env("UMASK", format_umask(umask_val))
        .env_remove("PIA_USER")
        .env_remove("PIA_PASS");

    if let Ok(mut child) = setpriv_cmd.spawn() {
        thread::sleep(Duration::from_millis(50));
        if matches!(child.try_wait(), Ok(None)) {
            return Ok(child);
        }
    }

    let mut fallback = Command::new(prog);
    fallback
        .args(args)
        .env("HOME", "/config")
        .env("XDG_CONFIG_HOME", "/config")
        .env("XDG_DATA_HOME", "/config")
        .env("UMASK", format_umask(umask_val))
        .env_remove("PIA_USER")
        .env_remove("PIA_PASS")
        .uid(puid)
        .gid(pgid);

    fallback
        .spawn()
        .map_err(|e| format!("Failed to spawn {prog}: {e}"))
}

pub fn wg0_tunnel_healthy() -> bool {
    let Ok(oper) = fs::read_to_string("/sys/class/net/wg0/operstate") else {
        return false;
    };
    if oper.trim() == "down" {
        return false;
    }
    if let Ok(flags_str) = fs::read_to_string("/sys/class/net/wg0/flags") {
        let clean = flags_str.trim().trim_start_matches("0x");
        if let Ok(flags) = u32::from_str_radix(clean, 16) {
            if (flags & 0x1) == 0 {
                return false;
            }
        }
    }
    Command::new("wg")
        .args(["show", "wg0"])
        .output()
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false)
}

pub fn terminate_children(children: &mut [Child]) {
    for child in children.iter() {
        let pid_str = child.id().to_string();
        let _ = Command::new("kill").args(["-TERM", &pid_str]).status();
    }
    thread::sleep(Duration::from_secs(2));
    for child in children.iter_mut() {
        let _ = child.kill();
        if let Ok(st) = child.wait() {
            let _ = st.signal();
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_octal_umask() {
        assert_eq!(parse_octal_umask("002"), 0o002);
        assert_eq!(parse_octal_umask("022"), 0o022);
        assert_eq!(parse_octal_umask("invalid"), 0o002);
        assert_eq!(format_umask(0o002), "002");
    }
}
