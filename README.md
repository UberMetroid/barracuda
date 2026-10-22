# Barracuda (`b-arr-acuda`)

<p align="center">
  <img src="assets/barracuda-icon.png" alt="Barracuda Icon" width="180" />
</p>

**Barracuda** is a hardened, bit-for-bit reproducible **GNU Guix + zero-dependency Rust** BitTorrent VPN appliance built specifically for the `*arr` media stack (**Sonarr**, **Radarr**, **Lidarr**, and **Prowlarr**).

It replaces legacy shell-scripted Arch/Alpine VPN torrent containers (`binhex-delugevpn`, `binhex-qbittorrentvpn`, `gluetun`) with 5 purpose-built, memory-safe Rust daemons and a reproducible GNU Guix store filesystem containing no package manager (`apt`/`apk`/`pacman`) and no shell-scripted supervision.

---

## Architecture & Pure-Rust Daemons

All 5 workspace binaries are written in 100% safe Rust (`#![forbid(unsafe_code)]`, `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`) with **zero external crates (`std` only)** and strict adherence to the **16–256 line Page Rule** ([`AGENTS.md`](AGENTS.md)):

| Binary | Role |
| :--- | :--- |
| **`barracuda-init`** | **PID 1 Supervisor & Watchdog**: Provisions `/config` and `/downloads/{incomplete,sonarr,radarr,lidarr,prowlarr}`, writes a pre-hardened `qBittorrent.conf` + `categories.json` + `ipfilter.p2p`, brings up `wg0` before starting any user-facing daemon, drops privileges via `setpriv` (`PUID`/`PGID`/`UMASK`), and runs a 3-second WireGuard self-healing watchdog. |
| **`barracuda-wg`** | **PIA WireGuard & Killswitch Engine**: Discovers the lowest-latency Private Internet Access (PIA) port-forwarding region, cryptographically verifies the gateway's X.509 certificate against the pinned 4096-bit RSA Root CA (`assets/pia-ca.rsa.4096.crt`), configures `wg0`, and installs a fail-closed `iptables`/`ip6tables` firewall (`DROP` default policy on `INPUT`/`OUTPUT`/`FORWARD`, explicit `DROP` on `wg0` for ports `8112,8118,9099`, and zero clearnet leakage). |
| **`barracuda-portforward`** | **Dynamic Port-Forwarding Daemon**: Requests a signed port-forwarding token from the PIA WireGuard gateway (`10.0.0.1:19999`), rebinds it every 15 minutes, updates the `wg0` firewall rule for the active peer port, and pushes the live listening port directly into `qbittorrent-nox` via localhost API. |
| **`barracuda-scrubber`** | **Real-Time Malware & Archive Trap Scrubber**: Continuously inspects `/downloads` (including in-progress `.!qB` files) and post-download hooks: blocks symlink escapes (`O_NOFOLLOW`), dangerous/double extensions (`.lnk`, `.scr`, `.exe`, `.msi`, `.bat`, `.cmd`, `.ps1`, `.vbs`, `.hta`, `.dll`, `.iso`, `.arj`, `.ace`), Unicode BiDi spoofing (`U+202E`), PE/ELF/Mach-O/LNK/shebang magic bytes, encrypted ZIP/RAR/7z password traps, and invalid media containers (`ffprobe`). Automatically purges malicious torrents and triggers `removeFromClient=true&blocklist=true&skipRedownload=false` in Sonarr/Radarr/Lidarr so a clean release is grabbed automatically. |
| **`barracuda-proxy`** | **VPN-Bound HTTP/HTTPS Proxy & Health API**: Serves an HTTP/HTTPS `CONNECT` proxy on `:8118` for Prowlarr indexers (with strict SSRF / RFC1918 blocklists and UDP DNS resolution bound directly to `wg0` -> `10.0.0.242:53`) and a JSON health endpoint on `:9099/status`. |

---

## Quick Start & Setup Instructions

### 1. Load the Prebuilt GNU Guix Container Image

Download the reproducible container tarball from the [latest GitHub Release](https://github.com/UberMetroid/barracuda/releases/latest) and load it into Docker or Podman:

```bash
curl -fL -O https://github.com/UberMetroid/barracuda/releases/download/v0.1.0/barracuda-guix-docker-x86_64.tar.gz
docker load -i barracuda-guix-docker-x86_64.tar.gz
docker tag barracuda-suite-qbittorrent-no-x:latest localhost/barracuda:latest
```

*(For Podman, replace `docker` with `podman`.)*

---

### 2. Run with Docker / Unraid CLI

> **Unraid Performance Tip**: Map `/config` directly to your ZFS/NVMe cache pool (`/mnt/cache/appdata/barracuda`) rather than `/mnt/user/appdata/barracuda` to bypass Unraid's FUSE (`shfs`) overhead.

```bash
docker run -d \
  --name=barracuda \
  --restart=unless-stopped \
  --cap-add=NET_ADMIN \
  --sysctl net.ipv4.conf.all.src_valid_mark=1 \
  --sysctl net.ipv6.conf.all.disable_ipv6=1 \
  -p 8112:8112/tcp \
  -p 8118:8118/tcp \
  -p 9099:9099/tcp \
  -e PIA_USER="p1234567" \
  -e PIA_PASS="your_pia_password" \
  -e PIA_REGION="auto" \
  -e LAN_NETWORK="192.168.1.0/24,100.64.0.0/10" \
  -e PUID="99" \
  -e PGID="100" \
  -e UMASK="002" \
  -e SONARR_URL="http://192.168.1.10:8989" \
  -e SONARR_API_KEY="your_sonarr_api_key" \
  -e RADARR_URL="http://192.168.1.10:7878" \
  -e RADARR_API_KEY="your_radarr_api_key" \
  -e LIDARR_URL="http://192.168.1.10:8686" \
  -e LIDARR_API_KEY="your_lidarr_api_key" \
  -v /mnt/cache/appdata/barracuda:/config:rw \
  -v /mnt/user/data/downloads:/downloads:rw \
  localhost/barracuda:latest
```

---

### 3. Unraid WebUI Template Installation

To install via the Unraid Docker tab with the custom Barracuda icon and pre-populated fields:

```bash
curl -fsSL https://raw.githubusercontent.com/UberMetroid/barracuda/main/unraid-template.xml \
  -o /boot/config/plugins/dockerMan/templates-user/my-barracuda.xml
```

Then in the Unraid WebUI:
1. Go to **Docker** -> **Add Container** -> select **`barracuda`** under **User Templates**.
2. Enter your **`PIA_USER`** and **`PIA_PASS`**.
3. Click **Apply**.

---

## Environment Variables Reference

| Variable | Required | Default | Description |
| :--- | :---: | :--- | :--- |
| `PIA_USER` | **Yes** | — | Your Private Internet Access username (e.g. `p1234567`). |
| `PIA_PASS` | **Yes** | — | Your Private Internet Access password. |
| `PIA_REGION` | No | `auto` | PIA region ID with port-forwarding enabled (or `auto` to automatically benchmark and select the lowest-latency port-forwarding gateway). |
| `LAN_NETWORK` | **Yes** | `192.168.1.0/24,100.64.0.0/10` | Comma-separated LAN and Tailscale CIDRs permitted to reach ports `8112`, `8118`, and `9099`. |
| `PUID` | No | `99` | Unprivileged UID for `qbittorrent-nox`, `barracuda-proxy`, and `barracuda-scrubber` (`99` = Unraid `nobody`). |
| `PGID` | No | `100` | Unprivileged GID (`100` = Unraid `users`). |
| `UMASK` | No | `002` | File creation umask (`002` creates `775` directories and `664` files for seamless `*arr` hardlinking/imports). |
| `SONARR_URL` / `SONARR_API_KEY` | No | — | Enables automatic Sonarr queue removal + release blocklisting + re-search when `barracuda-scrubber` catches a malicious download. |
| `RADARR_URL` / `RADARR_API_KEY` | No | — | Enables automatic Radarr queue removal + release blocklisting + re-search on malware detection. |
| `LIDARR_URL` / `LIDARR_API_KEY` | No | — | Enables automatic Lidarr queue removal + release blocklisting + re-search on malware detection. |

---

## Connecting the `*arr` Stack (`Sonarr`, `Radarr`, `Lidarr`, `Prowlarr`)

### 1. qBittorrent Download Client (`:8112`)
Barracuda binds the qBittorrent WebUI to port **`8112`** (the same port as Deluge, making migration effortless) and pre-creates the following categories and directories on first boot:
- `sonarr` -> `/downloads/sonarr`
- `radarr` -> `/downloads/radarr`
- `lidarr` -> `/downloads/lidarr`
- `prowlarr` -> `/downloads/prowlarr`
- Incomplete staging -> `/downloads/incomplete`

In **Sonarr / Radarr / Lidarr / Prowlarr** -> **Settings** -> **Download Clients** -> **Add (`qBittorrent`)**:
- **Host**: `<server-lan-ip>` (e.g. `192.168.1.10`)
- **Port**: `8112`
- **Category**: `sonarr` / `radarr` / `lidarr` / `prowlarr`
- *(Authentication is bypassed for trusted subnets listed in `LAN_NETWORK` by default; you can also set a WebUI password in the qBittorrent UI.)*

### 2. Prowlarr VPN HTTP/HTTPS Proxy (`:8118`)
Route Prowlarr indexer queries through the WireGuard tunnel without exposing Prowlarr itself to the VPN:
1. In **Prowlarr** -> **Settings** -> **Indexers** -> **Add (`Http` Proxy)**:
   - **Name**: `Barracuda VPN`
   - **Host**: `<server-lan-ip>` (e.g. `192.168.1.10`)
   - **Port**: `8118`
   - **Tags**: `vpn`
2. Add the `vpn` tag to any indexer you want routed through the WireGuard tunnel.

### 3. Health & Telemetry Endpoint (`:9099/status`)
Check the VPN tunnel, port-forwarding status, and qBittorrent health at any time:

```bash
curl -s http://localhost:9099/status
```
```json
{"status":"healthy","vpn_interface":"wg0","forwarded_port":51842,"qbittorrent_webui":8112,"proxy_port":8118}
```

---

## Building from Source & Verification Ladder

### 1. Rust Verification Ladder
Every `.rs` file in the workspace is gated by [`AGENTS.md`](AGENTS.md) (`16–256` lines per file, $\le 8$ files per directory, zero `unsafe`, zero `.unwrap()`/`.expect()`, zero `sh -c` calls):

```bash
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings -D clippy::unwrap_used -D clippy::expect_used -D clippy::panic
cargo fmt --all -- --check
cargo build --release --workspace
```

### 2. Multi-Engine LLM Audit (`mcode` + `vibe`)
```bash
./scripts/multi_engine_audit.sh all
```

### 3. Reproducible GNU Guix Container Build
```bash
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --workspace --target x86_64-unknown-linux-gnu
mkdir -p prebuilt && cp target/x86_64-unknown-linux-gnu/release/barracuda-* prebuilt/
guix pack -f docker -S /bin=bin -S /etc=etc -S /share=share -m manifest.scm
```
