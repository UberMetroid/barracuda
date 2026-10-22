//! Barracuda VPN-bound HTTP/HTTPS CONNECT proxy (8118) and JSON health server (9099).
#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod dns_resolver;
mod health_status;
mod proxy_tunnel;

use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::process::exit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use health_status::{handle_health_client, log};
use proxy_tunnel::handle_proxy_client;

const MAX_CONCURRENT_CLIENTS: usize = 256;

fn main() {
    let start_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let active_clients = Arc::new(AtomicUsize::new(0));

    let health_clients = Arc::clone(&active_clients);
    thread::spawn(move || {
        let Ok(listener) = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 9099)))
        else {
            log("FATAL: Failed to bind health API on :9099");
            exit(1);
        };
        log("Health API listening on 0.0.0.0:9099 (/status)");
        for stream in listener.incoming().flatten() {
            let cur = health_clients.load(Ordering::Relaxed);
            thread::spawn(move || {
                handle_health_client(stream, start_epoch, cur);
            });
        }
    });

    let Ok(listener) = TcpListener::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8118))) else {
        log("FATAL: Failed to bind HTTP CONNECT proxy on :8118");
        exit(1);
    };
    log("HTTP/HTTPS CONNECT proxy listening on 0.0.0.0:8118");

    for stream in listener.incoming().flatten() {
        let cur = active_clients.load(Ordering::Relaxed);
        if cur >= MAX_CONCURRENT_CLIENTS {
            drop(stream);
            continue;
        }
        let counter = Arc::clone(&active_clients);
        counter.fetch_add(1, Ordering::Relaxed);
        thread::spawn(move || {
            handle_proxy_client(stream);
            counter.fetch_sub(1, Ordering::Relaxed);
        });
    }
}
