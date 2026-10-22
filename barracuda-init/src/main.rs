//! Barracuda PID 1 supervisor and self-healing WireGuard watchdog.
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod qbittorrent_config;
mod spawn_daemon;

use std::env;
use std::process::{exit, Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use qbittorrent_config::{
    ensure_directories_and_ownership, update_ipfilter_blocklist, write_categories_json,
    write_hardened_qbittorrent_conf,
};
use spawn_daemon::{
    format_umask, parse_octal_umask, spawn_unprivileged, terminate_children, wg0_tunnel_healthy,
};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

fn log(msg: &str) {
    eprintln!("[barracuda-init] {msg}");
}

fn spawn_or_exit(res: Result<Child, String>) -> Child {
    match res {
        Ok(c) => c,
        Err(e) => {
            log(&format!("FATAL: {e}"));
            exit(1);
        }
    }
}

fn supervise_loop(
    puid: u32,
    pgid: u32,
    umask_val: u32,
    mut pf_child: Child,
    mut proxy_child: Child,
    mut scrubber_child: Child,
    mut qbt_child: Child,
) {
    let mut last_watchdog = Instant::now();
    let mut consecutive_wg_failures = 0u32;

    while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        if let Ok(Some(st)) = qbt_child.try_wait() {
            log(&format!(
                "WARN: qbittorrent-nox exited with {st}; restarting..."
            ));
            if let Ok(c) = spawn_unprivileged(
                "qbittorrent-nox",
                &["--webui-port=8212", "--profile=/config"],
                puid,
                pgid,
                umask_val,
            ) {
                qbt_child = c;
            }
        }
        if let Ok(Some(st)) = proxy_child.try_wait() {
            log(&format!(
                "WARN: barracuda-proxy exited with {st}; restarting..."
            ));
            if let Ok(c) = spawn_unprivileged("/bin/barracuda-proxy", &[], puid, pgid, umask_val) {
                proxy_child = c;
            }
        }
        if let Ok(Some(st)) = scrubber_child.try_wait() {
            log(&format!(
                "WARN: barracuda-scrubber exited with {st}; restarting..."
            ));
            if let Ok(c) = spawn_unprivileged("/bin/barracuda-scrubber", &[], puid, pgid, umask_val)
            {
                scrubber_child = c;
            }
        }
        if let Ok(Some(st)) = pf_child.try_wait() {
            log(&format!(
                "WARN: barracuda-portforward exited with {st}; restarting..."
            ));
            if let Ok(c) = Command::new("/bin/barracuda-portforward").spawn() {
                pf_child = c;
            }
        }

        if last_watchdog.elapsed() >= Duration::from_secs(3) {
            last_watchdog = Instant::now();
            if !wg0_tunnel_healthy() {
                consecutive_wg_failures = consecutive_wg_failures.saturating_add(1);
                log(&format!(
                    "ALERT: WireGuard interface wg0 unhealthy/down (failure #{consecutive_wg_failures})! Triggering self-healing..."
                ));
                let heal = Command::new("/bin/barracuda-wg").status();
                if matches!(heal, Ok(s) if s.success()) {
                    log("Tunnel wg0 self-healed! Restarting barracuda-portforward...");
                    consecutive_wg_failures = 0;
                    let _ = pf_child.kill();
                    let _ = pf_child.wait();
                    if let Ok(c) = Command::new("/bin/barracuda-portforward").spawn() {
                        pf_child = c;
                    }
                }
            } else {
                consecutive_wg_failures = 0;
            }
        }

        thread::sleep(Duration::from_millis(500));
    }

    log("Shutdown requested; terminating child daemons gracefully...");
    let mut children = [qbt_child, scrubber_child, proxy_child, pf_child];
    terminate_children(&mut children);
    log("Clean shutdown complete.");
}

fn main() {
    let puid: u32 = env::var("PUID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(99);
    let pgid: u32 = env::var("PGID")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let umask_str = env::var("UMASK").unwrap_or_else(|_| "002".to_string());
    let umask_val = parse_octal_umask(&umask_str);
    let lan_net =
        env::var("LAN_NETWORK").unwrap_or_else(|_| "192.168.1.0/24,100.64.0.0/10".to_string());

    log(&format!(
        "Starting barracuda-init supervisor (PUID={puid}, PGID={pgid}, UMASK={})",
        format_umask(umask_val)
    ));

    ensure_directories_and_ownership(puid, pgid);
    write_categories_json();
    write_hardened_qbittorrent_conf(&lan_net);

    log("Executing barracuda-wg to establish WireGuard VPN and strict iptables killswitch...");
    let wg_status = Command::new("/bin/barracuda-wg").status();
    match wg_status {
        Ok(s) if s.success() => log("barracuda-wg completed successfully; VPN killswitch active."),
        _ => {
            log("FATAL: barracuda-wg failed to establish VPN tunnel. Refusing to start services (fail-closed).");
            exit(1);
        }
    }

    update_ipfilter_blocklist(puid, pgid);
    let owner = format!("{puid}:{pgid}");
    let _ = Command::new("chown")
        .args(["-R", &owner, "/config", "/downloads"])
        .status();

    let pf_child = spawn_or_exit(
        Command::new("/bin/barracuda-portforward")
            .spawn()
            .map_err(|e| format!("Failed to spawn barracuda-portforward: {e}")),
    );
    let proxy_child = spawn_or_exit(spawn_unprivileged(
        "/bin/barracuda-proxy",
        &[],
        puid,
        pgid,
        umask_val,
    ));
    let scrubber_child = spawn_or_exit(spawn_unprivileged(
        "/bin/barracuda-scrubber",
        &[],
        puid,
        pgid,
        umask_val,
    ));
    let qbt_child = spawn_or_exit(spawn_unprivileged(
        "qbittorrent-nox",
        &["--webui-port=8212", "--profile=/config"],
        puid,
        pgid,
        umask_val,
    ));

    log("All child daemons launched (qbittorrent-nox:8212, barracuda-proxy:8218, health:9299, barracuda-scrubber, barracuda-portforward).");
    supervise_loop(
        puid,
        pgid,
        umask_val,
        pf_child,
        proxy_child,
        scrubber_child,
        qbt_child,
    );
}
