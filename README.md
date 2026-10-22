# Barracuda

<p align="center">
  <img src="assets/barracuda-icon.png" alt="Barracuda" width="160" />
</p>

BitTorrent over VPN for the `*arr` stack (`Sonarr`, `Radarr`, `Lidarr`, `Prowlarr`), built from first principles on **Zero Trust**:

1. **Assume the network is hostile.** Default `iptables`/`ip6tables` policy is `DROP` on `INPUT`, `OUTPUT`, and `FORWARD`. Traffic can only leave over `wg0`. If the WireGuard tunnel drops, packets drop at the kernel level—before `qbittorrent-nox` even starts.
2. **Assume the torrent swarm is hostile.** Untrusted peers serve fake `.mkv.lnk` executables, Unicode Right-to-Left (`U+202E`) spoofed filenames, password-locked `.rar`/`.zip`/`.7z` traps, and corrupted payloads. Every file—including incomplete `.!qB` chunks—is inspected by magic bytes, archive headers, and `ffprobe` streams. Bad downloads are deleted on sight and automatically blocklisted in Sonarr/Radarr/Lidarr so a clean release is grabbed.
3. **Assume the container runtime is hostile.** Built with **GNU Guix** and **5 static, zero-dependency Rust binaries** (`#![forbid(unsafe_code)]`). There is no `apt`, `apk`, `pacman`, `bash` supervision loop, or third-party Rust crate supply chain inside the supervision plane. `qbittorrent-nox`, the proxy, and the scrubber run unprivileged (`PUID`/`PGID`) with supplementary groups stripped.

---

## 1. Install

### Option A: Unraid (WebUI Template)
```bash
curl -fsSL https://raw.githubusercontent.com/UberMetroid/barracuda/main/unraid-template.xml \
  -o /boot/config/plugins/dockerMan/templates-user/my-barracuda.xml
```
1. Load the image once on your Unraid host:
   ```bash
   curl -fL https://github.com/UberMetroid/barracuda/releases/download/v0.1.0/barracuda-guix-docker-x86_64.tar.gz | docker load
   docker tag barracuda-suite-qbittorrent-no-x:latest localhost/barracuda:latest
   ```
2. In Unraid: **Docker** -> **Add Container** -> select **`barracuda`** -> fill in `PIA_USER` and `PIA_PASS` -> **Apply**.

### Option B: Docker / Podman CLI
```bash
curl -fL https://github.com/UberMetroid/barracuda/releases/download/v0.1.0/barracuda-guix-docker-x86_64.tar.gz | docker load
docker tag barracuda-suite-qbittorrent-no-x:latest localhost/barracuda:latest

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
  -e LAN_NETWORK="192.168.1.0/24,100.64.0.0/10" \
  -v /mnt/cache/appdata/barracuda:/config:rw \
  -v /mnt/user/data/downloads:/downloads:rw \
  localhost/barracuda:latest
```

---

## 2. Connect Your `*arr` Apps

| Port | Service | How to Connect |
| :--- | :--- | :--- |
| **`8112`** | **qBittorrent WebUI & API** | In Sonarr / Radarr / Lidarr / Prowlarr -> **Settings -> Download Clients -> qBittorrent**. Point to `<host-ip>:8112`. Categories `sonarr`, `radarr`, `lidarr`, and `prowlarr` are pre-created automatically. |
| **`8118`** | **VPN HTTP/HTTPS Proxy** | In Prowlarr -> **Settings -> Indexers -> Add Proxy (`Http`)**. Point to `<host-ip>:8118`. Tag any indexer you want routed through the WireGuard tunnel. |
| **`9099`** | **Health & Port Status** | `curl http://<host-ip>:9099/status` returns JSON (`healthy`, active `wg0` handshake age, and live PIA forwarded port). |

---

## 3. Configuration

| Variable | Required | Default | Purpose |
| :--- | :---: | :--- | :--- |
| `PIA_USER` | **Yes** | — | Private Internet Access username (`p1234567`) |
| `PIA_PASS` | **Yes** | — | Private Internet Access password |
| `LAN_NETWORK` | **Yes** | `192.168.1.0/24,100.64.0.0/10` | Subnets allowed to reach ports `8112`, `8118`, `9099` |
| `PIA_REGION` | No | `auto` | PIA port-forwarding region ID (`auto` picks lowest latency) |
| `PUID` / `PGID` / `UMASK` | No | `99` / `100` / `002` | Unprivileged runtime UID, GID, and file creation mask |
| `SONARR_URL` / `SONARR_API_KEY` | No | — | Auto-blocklists & re-searches bad releases in Sonarr |
| `RADARR_URL` / `RADARR_API_KEY` | No | — | Auto-blocklists & re-searches bad releases in Radarr |
| `LIDARR_URL` / `LIDARR_API_KEY` | No | — | Auto-blocklists & re-searches bad releases in Lidarr |

---

## 4. Verify It Yourself (Don't Trust Us)

### Check Killswitch & Active Port
```bash
curl -s http://localhost:9099/status
docker exec barracuda iptables -S
```

### Build from Source & Reproduce the Image
```bash
cargo test --workspace --all-targets
RUSTFLAGS="-C target-feature=+crt-static" cargo build --release --workspace --target x86_64-unknown-linux-gnu
mkdir -p prebuilt && cp target/x86_64-unknown-linux-gnu/release/barracuda-* prebuilt/
guix pack -f docker -S /bin=bin -S /etc=etc -S /share=share -m manifest.scm
```
