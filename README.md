# Barracuda (`b-arr-acuda`)

<p align="center">
  <img src="assets/barracuda-icon.png" alt="Barracuda Icon" width="160" />
</p>

**Barracuda** is a hardened, reproducible **GNU Guix + zero-dependency Rust** BitTorrent VPN appliance built for the `*arr` stack (`Sonarr`, `Radarr`, `Lidarr`, `Prowlarr`).

## Architecture & Binaries

All 5 workspace binaries are written in 100% safe Rust (`#![forbid(unsafe_code)]`, `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`) with zero external crate dependencies (`std` only) and strict adherence to the 16–256 line Page Rule (`AGENTS.md`):

1. **`barracuda-init`**: PID 1 container supervisor, directory & permission provisioner, hardened `qBittorrent.conf` writer, and 3-second WireGuard self-healing watchdog.
2. **`barracuda-wg`**: Private Internet Access (PIA) WireGuard authenticator, X.509 RSA-4096 peer certificate verifier (`assets/pia-ca.rsa.4096.crt`), and fail-closed `iptables`/`ip6tables` killswitch engine.
3. **`barracuda-portforward`**: PIA port-forwarding signature acquisition and 15-minute renewal daemon with automatic qBittorrent listening port synchronization.
4. **`barracuda-scrubber`**: Real-time malware scrubber (`O_NOFOLLOW` symlink defense, blocked & double extensions, Unicode BiDi spoofing, PE/ELF/LNK/shebang magic bytes, encrypted ZIP/RAR/7z trap detection, `ffprobe` stream validation, and automatic `*arr` queue blocklisting).
5. **`barracuda-proxy`**: VPN-bound HTTP/HTTPS `CONNECT` proxy (`:8118`) for Prowlarr with SSRF/non-WAN protection and JSON health telemetry server (`:9099/status`).

## Verification Ladder

```bash
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
cargo fmt --all -- --check
cargo build --release --workspace
```

## Reproducible GNU Guix Container Build

```bash
guix pack -f docker -S /bin=bin -S /etc=etc -S /share=share -m manifest.scm
```
