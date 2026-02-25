# ModernVPS v3.2

> **Production-Ready VPS Setup Script**  
> Hỗ trợ kiến trúc đa tầng: **Web Server** và **Load Balancer**

---

## Mục lục

- [Tổng quan](#tổng-quan)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Cài đặt nhanh](#cài-đặt-nhanh)
- [Chế độ triển khai](#chế-độ-triển-khai)
- [Cấu trúc file](#cấu-trúc-file)
- [Chi tiết các module](#chi-tiết-các-module)
- [Menu quản trị](#menu-quản-trị)
- [Bảo mật](#bảo-mật)
- [Backup](#backup)
- [Changelog v3.2](#changelog-v32)

---

## Tổng quan

ModernVPS v3.2 là bộ script Bash tự động hoá toàn bộ quá trình thiết lập và bảo mật một VPS từ đầu. Một lệnh duy nhất thực hiện: phát hiện OS, cài đặt stack, hardening bảo mật, cấu hình Nginx, tạo CLI menu quản trị.

**Điểm khác biệt so với v2:**

- Hỗ trợ hai chế độ triển khai: **Web Server** (full stack) và **Load Balancer** (Nginx only)
- Header menu realtime — CPU load, RAM, disk, service status, SSL warning, backend health
- Menu quản trị thông minh tự tạo ra tính năng phù hợp với role của máy chủ
- Health check daemon tự động theo dõi backend, reload Nginx khi backend down/up
- Canary deploy, drain backend, maintenance mode cho Load Balancer
- WordPress auto-install, SFTP jail, OPcache manager cho Web Server
- Post-install verification báo cáo chính xác component nào failed

---

## Yêu cầu hệ thống

| Thành phần | Web Server | Load Balancer |
|---|---|---|
| **OS** | Ubuntu 22.04 / 24.04, AlmaLinux / Rocky 8–10 | Như trái |
| **RAM tối thiểu** | 1 GB (khuyến nghị 2 GB) | 512 MB |
| **Disk trống** | 3 GB | 500 MB |
| **Quyền** | root | root |
| **Kết nối** | Internet (tải packages) | Như trái |

> **Lưu ý:** Script chạy trên KVM, LXC, OpenVZ, Hyper-V, Docker.  
> Trên LXC/OpenVZ, `sysctl` kernel tuning tự động bị bỏ qua (kernel dùng chung với host).  
> Swap tự động được tạo nếu RAM < 2 GB và chưa có swap.

---

## Cài đặt nhanh

```bash
git clone https://github.com/your-org/modernvps.git
cd modernvps
sudo bash installer.sh
```

Installer hỏi tuần tự:

1. **Loại máy chủ** — Web Server hay Load Balancer
2. **PHP version** — 8.2 / 8.3 / 8.4 *(Web Server)*
3. **MariaDB version** — 11.4 / 11.8 *(Web Server)*
4. **Worker type** — WordPress / Laravel / Generic *(ảnh hưởng PHP-FPM tuning)*
5. **Admin email** — dùng cho Let's Encrypt
6. **ModSecurity WAF** — tuỳ chọn, cảnh báo nếu RAM < 1.5 GB

Quá trình cài đặt gồm **10 bước** có progress display, mất khoảng **5–15 phút** tuỳ server.

---

## Chế độ triển khai

### Web Server (Full Stack)

```
Nginx + PHP-FPM + MariaDB + phpMyAdmin + elFinder + WP-CLI
```

- PHP-FPM tự tuning theo RAM và worker type (WordPress 80 MB/worker, Laravel 60 MB, Generic 40 MB)
- OPcache tự scale: 128 MB → 256 MB → 512 MB theo RAM
- FastCGI cache key zone 32 MB, max 512 MB
- Isolated PHP-FPM pool per site (mỗi site chạy user riêng)
- MariaDB hardened: bind `127.0.0.1`, anonymous users removed, test DB dropped

### Load Balancer (Nginx Only)

```
Nginx (tuned high concurrency) + Health Check Daemon + Upstream Manager
```

- `worker_connections 65535`, `worker_rlimit_nofile 131070`
- Upstream keepalive 32 connections đến backend
- Health check tự động mỗi phút: comment out backend DOWN, reload Nginx
- `upstream_addr` + `upstream_response_time` trong access log

---

## Cấu trúc file

```
modernvps/
├── installer.sh          # Entrypoint — 10-bước wizard
└── lib/
    ├── common.sh         # Biến toàn cục, hardware detection, render_header, helpers
    ├── security.sh       # SSH hardening, nftables, Fail2ban, sysctl, auditd
    ├── stack.sh          # Nginx, PHP-FPM, MariaDB, ModSecurity, I/O scheduler
    └── tools.sh          # phpMyAdmin, elFinder, backup, CLI menu web & LB
```

Sau khi cài xong:

```
/opt/modernvps/
├── config.env            # Runtime config (SERVER_TYPE, PHP_VERSION, ...)
├── menu.sh               # CLI menu tạo ra theo SERVER_TYPE
├── .credentials          # SSH, panel, DB passwords  (chmod 600)
├── .backup-key.txt       # age private key — SAO LƯU RA NGOÀI!
├── .backup-pubkey.txt    # age public key
├── .ssl-cache            # Cache SSL expiry (TTL 1h)
└── backends.json         # Inventory backend servers (Load Balancer)

/usr/local/bin/
├── mvps                  # CLI entrypoint: sudo mvps
├── mvps-backup           # Backup script
└── mvps-healthcheck      # Health check daemon (LB only)

/backup/                  # Backup directory (chmod 700)
```

---

## Chi tiết các module

### `installer.sh`

| Bước | Nội dung |
|---|---|
| 1 | Phát hiện OS, hardware (RAM, CPU, disk type, virtualisation) |
| 2 | Kiểm tra tiên quyết: Internet (retry 3 địa chỉ), disk ≥ 2 GB, port conflicts |
| 3 | Wizard: server type, PHP/DB version, worker type, ModSecurity |
| 4 | Tạo Swap nếu RAM < 2 GB và chưa có |
| 5 | `apt update` / `dnf update` + cài prerequisites |
| 6 | Hardening bảo mật (SSH, nftables, Fail2ban, sysctl, auditd) |
| 7 | Cài stack + ModSecurity WAF |
| 8 | phpMyAdmin · elFinder · WP-CLI *(Web)* hoặc health check daemon *(LB)* |
| 9 | Backup + mvps service + tạo CLI menu |
| 10 | Post-install verification — báo cáo ✅/❌ từng component |

---

### `lib/common.sh`

Biến toàn cục, hardware detection, và **render header realtime** cho CLI menu.

**Hardware detection:**

```
gather_system_info()   — RAM, CPU cores, disk type (hdd/ssd/nvme), virt type
check_ram_pressure()   — tính RAM dự kiến, cảnh báo + hỏi xác nhận nếu > 85%
ensure_swap()          — tạo swapfile nếu RAM < 2 GB và chưa có swap
is_sysctl_writable()   — false trên LXC/OpenVZ
```

**Render header — thiết kế tối ưu hiệu năng:**

```
Nguyên tắc: render < 100ms, < 10 forks
  /proc/loadavg   → CPU load (0 fork)
  /proc/meminfo   → RAM used/total (0 fork)
  /proc/uptime    → uptime (0 fork)
  df -h /         → disk (1 fork)
  systemctl is-active × N → services (~5ms/cái)
  .ssl-cache      → SSL expiry (0 fork, TTL 1h)
  curl stub_status → conn/req/s (1 fork, timeout 1s) — LB only
  backend-status.json → backend health (0 fork) — LB only
```

**Logic màu sắc tự động:**

| Metric | Xanh | Vàng | Đỏ |
|---|---|---|---|
| CPU load | < 70% cores | 70–90% | ≥ 90% |
| RAM | < 70% | 70–85% | ≥ 85% |
| Disk | < 70% | 70–85% | ≥ 85% |
| SSL expiry | > 30 ngày (ẩn) | ≤ 30 ngày | ≤ 7 ngày |

---

### `lib/security.sh`

**SSH Hardening:**

- Port `2222`, `PermitRootLogin no`, chỉ user `deployer`
- `PasswordAuthentication no` (có key) / `yes` tạm (skip key)
- Cipher: `chacha20-poly1305`, `aes256-gcm`, `aes128-gcm`
- KexAlgorithms: `sntrup761x25519-sha512`, `curve25519-sha256`
- Skip key → tự tạo ed25519 keypair tạm + lên lịch xóa private key sau 24h (`shred -u`)
- SFTP chroot jail config cho group `sftp-users` *(Web only)*

**nftables Firewall:**

```
Policy: DROP (default)

Cho phép:
  established/related, loopback
  ICMP echo-request (rate 2/s), ICMPv6 neighbor discovery
  SSH :2222  (rate 4/min per IP)
  HTTP/HTTPS :80/:443  (rate 50/s per IP)
  Panel port  (Web only — LB không mở)

Chặn:
  blacklist_v4 / blacklist_v6 (timeout 24h)
  TCP flag attacks: NULL, SYN-RST
  Outbound: port 3333, 4444, 5555, 14444, 14433

IPv6: hỗ trợ đầy đủ
```

**Fail2ban — jails theo role:**

| Jail | Web | LB |
|---|---|---|
| `sshd` | ✅ maxretry=3, ban=1h | ✅ |
| `sshd-aggressive` | ✅ tự tạo filter nếu thiếu | ✅ |
| `nginx-http-auth` | ✅ | ❌ |
| `nginx-botsearch` | ✅ | ❌ |
| `nginx-limit-req` | ✅ | ❌ |
| `recidive` | ✅ ban=7d | ✅ |

**Sysctl — 2 profile:**

| Param | Web | LB |
|---|---|---|
| `tcp_congestion_control` | bbr | bbr |
| `net.core.somaxconn` | 65535 | 65535 |
| `ip_local_port_range` | 1024 65535 | 1024 65535 |
| `netdev_max_backlog` | — | 65536 |
| `tcp_max_orphans` | — | 65536 |
| `vm.swappiness` | 10 | 5 |

> Toàn bộ sysctl bị skip tự động trên LXC/OpenVZ.

---

### `lib/stack.sh`

**Nginx — Web Server:**

- `worker_connections` scale theo RAM: 2048 → 4096 → 8192
- FastCGI cache: `PHPCACHE:32m`, max 512 MB, inactive 60 phút
- Rate limiting: 10r/s, `login_limit` 5r/min
- Security headers: `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- TLS 1.2/1.3, OCSP Stapling, `ssl_session_tickets off`, modern cipher suite

**Nginx — Load Balancer:**

- `worker_connections 65535`, `worker_rlimit_nofile 131070`
- Upstream keepalive 32, `keepalive_requests 1000`, `keepalive_timeout 60s`
- Log format: thêm `upstream_addr` + `upstream_response_time`
- `stub_status` endpoint tại `http://127.0.0.1/nginx_status`

**PHP-FPM:**

```
pm.max_children = RAM(MB) ÷ 3 ÷ worker_mem_mb
  WordPress = 80 MB/worker
  Laravel   = 60 MB/worker
  Generic   = 40 MB/worker

OPcache:  < 4 GB → 128 MB | < 8 GB → 256 MB | ≥ 8 GB → 512 MB
Security: expose_php=Off, session.cookie_httponly/secure/strict
```

**MariaDB:**

```
innodb_buffer_pool_size  = RAM × 40%
innodb_buffer_pool_instances: 1 / 2 / 4 theo RAM
max_connections: 100 / 150 / 200 / 300 theo RAM
bind-address = 127.0.0.1, slow_query_log
```

**ModSecurity:** apt → build from source (fallback) → OWASP CRS → rollback tự động nếu `nginx -t` fail.

**I/O Scheduler:** NVMe → `none` · SSD → `mq-deadline` · HDD → `bfq`

---

### `lib/tools.sh`

**Cài đặt tools:**

- phpMyAdmin 5.2.1 — verify SHA256 checksum trước extract
- elFinder — bỏ `application/zip` khỏi `uploadAllow` (zip slip fix)
- WP-CLI — verify qua `php --info`

**Backup `/usr/local/bin/mvps-backup`:**

| Item | Web | LB |
|---|---|---|
| DB (`mysqldump --single-transaction`) | ✅ | ❌ |
| Nginx config + modernvps config | ✅ | ✅ |
| Webroot `/var/www/` | ✅ | ❌ |
| Mã hoá `age` | ✅ | ✅ |
| Tự xóa > 7 ngày | ✅ | ✅ |

Compressor: `pigz` (parallel) nếu có, fallback `gzip -6`.  
Cron: backup **01:00** hàng ngày · certbot renew **03:00 thứ Hai**.

---

## Menu quản trị

Lệnh: **`sudo mvps`**

### Header realtime (4 dòng, < 100ms)

**Web Server:**

```
═══════════════════════════════════════════
  ModernVPS v3.2 (web) | web-01 | Up 12d4h
  CPU: 1.23 | RAM: 1843/3891MB | DSK: 42%
  Nginx ✅ | PHP ✅ | DB ✅ | F2B ✅ | WAF ✅
  Sites: 8 | ⚠ SSL: example.com còn 7 ngày
═══════════════════════════════════════════
```

**Load Balancer:**

```
═══════════════════════════════════════════
  ModernVPS v3.2 (lb) | lb-01 | Up 30d12h
  CPU: 0.82 | RAM: 780/2048MB | DSK: 18%
  Nginx ✅ | F2B ✅ | NFT ✅ | Backends: 4/5 ⚠ web-03 DOWN
  Conn: 1,247 | Req/s: 342 | Maint: OFF
═══════════════════════════════════════════
```

**Giải thích:**

| Dòng | Nội dung | Nguồn |
|---|---|---|
| 1 | Version · role · hostname · uptime | `hostname -s`, `/proc/uptime` |
| 2 | CPU load avg · RAM used/total · Disk % | `/proc/loadavg`, `/proc/meminfo`, `df` |
| 3 | Service icons ✅/❌ | `systemctl is-active` |
| 4 Web | Số sites + SSL warning (≤ 30 ngày) | `sites-enabled/`, `.ssl-cache` (TTL 1h) |
| 4 LB | Connections + Req/s + maintenance flag | `stub_status`, `.maintenance-active` |

Dòng 4 hiển thị `All systems normal ✅` khi không có cảnh báo.  
Màu tự động: xanh bình thường · vàng cảnh báo · đỏ nguy hiểm.

---

### Menu Web Server — 18 options

```
 [SITES]          1) List sites       2) Create site
                  3) Delete site      4) WordPress install
 [SERVICES]       5) PHP-FPM pools    6) Database
                  7) SSL manager      8) SFTP users
 [MONITORING]     9) Log analysis    10) OPcache status
                 11) Disk & resources 12) Security status
 [SYSTEM]        13) Backup          14) Firewall
                 15) Update stack    16) CIS audit
                 17) Restart svc     18) Clear cache
```

**Chi tiết tính năng:**

- **List sites** — domain · SSL expiry màu · PHP pool · disk usage
- **Create site** — PHP version per-site · isolated FPM pool · SSL · hỏi cài WP ngay
- **WordPress install** — tạo DB → tải core → config → install → xóa default → set permissions
- **PHP-FPM pools** — workers realtime · điều chỉnh `max_children` · enable/disable pool
- **Database** — 9 options: list · create · drop · processlist · sizes · slow queries · import · export · repair
- **SSL manager** — certs + expiry màu · cấp mới · renew force · revoke · dry-run
- **SFTP users** — tạo/xóa chroot jail user (webroot/uploads/)
- **Log analysis** — top IPs · top 404/500 URLs · req/giờ ASCII chart · detect crawl bất thường
- **OPcache status** — hit rate · memory · cached files · reset

---

### Menu Load Balancer — 19 options

```
 [BACKENDS]       1) Backend status   2) Upstream manager
                  3) Thêm backend     4) Xóa backend (drain)
                  5) Canary deploy
 [ROUTING]        6) Tạo proxy vhost  7) LB method
                  8) Maintenance mode
 [SSL & SEC]      9) SSL manager     10) Firewall
                 11) Fail2ban
 [MONITORING]    12) Traffic analytics 13) Nginx stats
                 14) Xem log
 [SYSTEM]        15) Backup          16) CIS audit
                 17) Disk & resources 18) Restart Nginx
                 19) Update system
```

**Chi tiết tính năng:**

- **Backend status** — UP/DOWN màu + HTTP code + latency ms từ `backend-status.json`
- **Upstream manager** — nhiều upstream groups · LB method · `max_conns` per backend
- **Xóa backend (drain)** — set `down` → poll connections → xóa sau khi drain xong
- **Canary deploy** — % traffic (10/25/50%) → promote 100% hoặc rollback
- **Tạo proxy vhost** — `proxy_pass` đến upstream group · optional proxy cache · SSL
- **LB method** — round-robin · `least_conn` · `ip_hash` · `hash $cookie_sessionid`
- **Maintenance mode** — 503 page · dummy SSL cert · hiển thị `Maint: ON ⚠` trong header
- **Traffic analytics** — req/backend · response time/backend · top IPs · 502/504 per backend · ASCII chart
- **Nginx stats** — realtime `stub_status`: active conn · accepts · reading/writing/waiting

---

## Bảo mật

### CIS Audit — 16 checks (Web) / 11 checks (LB)

Score: 🔴 < 70% · 🟡 70–89% · 🟢 ≥ 90%

**Web Server checks:**

| # | Check | Mức |
|---|---|---|
| 1–2 | SSH: `PermitRootLogin no` · Port 2222 | Critical |
| 3 | nftables active | Critical |
| 4 | Fail2ban active | High |
| 5 | Auditd active | Medium |
| 6 | BBR enabled | Medium |
| 7 | ASLR = 2 | High |
| 8–10 | Nginx / PHP-FPM / MariaDB running | Critical |
| 11 | MariaDB bind 127.0.0.1 | High |
| 12 | OPcache enabled | Medium |
| 13 | Cron restricted | Medium |
| 14 | ModSecurity WAF | High |
| 15 | Auto updates | Medium |
| 16 | Certbot auto-renew cron | Medium |

### Credentials

```bash
cat /opt/modernvps/.credentials    # SSH, panel, DB passwords
cat /opt/modernvps/.backup-key.txt # age private key
```

> ⚠️ **Sao lưu `.backup-key.txt` ra ngoài server ngay sau khi cài.**

---

## Backup

### Chạy thủ công

```bash
sudo mvps                          # option Backup
sudo /usr/local/bin/mvps-backup    # hoặc trực tiếp
```

### Giải mã

```bash
age --decrypt \
    -i /opt/modernvps/.backup-key.txt \
    -o db-20250101.sql.gz \
    /backup/db-20250101_0100.sql.gz.age

gunzip -c db-20250101.sql.gz | mysql -u root
```

### Files

| Pattern | Nội dung | Giữ |
|---|---|---|
| `db-YYYYMMDD_HHMM.sql.gz[.age]` | mysqldump all databases | 7 ngày |
| `nginx-conf-YYYYMMDD_HHMM.tar.gz[.age]` | Nginx config + modernvps config | 7 ngày |
| `web-YYYYMMDD_HHMM.tar.gz[.age]` | `/var/www/` webroot | 7 ngày |

---

## Changelog v3.2

### Tính năng mới

**Header menu realtime (common.sh):**
- `render_header_web()` / `render_header_lb()` — 4 dòng thông tin, render < 100ms
- SSL cache `.ssl-cache` TTL 1h — tránh gọi certbot mỗi lần vào menu
- Màu tự động theo ngưỡng CPU/RAM/Disk/SSL expiry/backend health

**Installer:**
- 10-bước với `[N/10]` progress · retry Internet check · post-install verification · `trap` cleanup

**common.sh:**
- `detect_virt_type()` — KVM / LXC / OpenVZ / Docker / Hyper-V
- `ensure_swap()` — tạo swapfile tự động
- `check_ram_pressure()` — cảnh báo + xác nhận nếu RAM dự kiến > 85%
- `validate_ip()` IPv6 support

**security.sh:**
- `_ensure_sshd_aggressive_filter()` — tự tạo nếu distro thiếu
- Private key tạm xóa sau 24h (`shred -u`)
- Sysctl 2 profile: web vs LB
- `is_sysctl_writable()` guard cho container

**stack.sh:**
- `_build_modsecurity_from_source()` — implement đầy đủ (v2 chỉ `return 0`)
- `tune_nginx_lb()` — `worker_connections 65535`
- PHP-FPM 3 worker type profiles + session security settings
- MariaDB `innodb_buffer_pool_instances` theo RAM

**tools.sh:**
- MOTD cập nhật theo header rút gọn đã thống nhất (4 dòng, realtime)
- phpMyAdmin checksum verify · elFinder zip slip fix
- Health check daemon auto-failover
- Menu Web 18 options: WordPress · PHP pools · SSL manager · SFTP · OPcache · log analysis
- Menu LB 19 options: drain · canary · maintenance mode · traffic analytics

### Bug Fixes

| File | Bug | Fix |
|---|---|---|
| `stack.sh` | `<<'EOF'` → `$NGINX_USER` không expand | `<<EOF` + escape `\$` Nginx vars |
| `stack.sh` | LB `worker_connections 1024` | → `65535` |
| `stack.sh` | `_build_modsecurity_from_source()` chỉ `return 0` | Implement đầy đủ |
| `tools.sh` | `sed '/$method/d'` không expand biến | `-E` regex + marker |
| `tools.sh` | `sed /^}/i` match sai block | Marker `# MVPS_SERVERS_START/END` |
| `tools.sh` | elFinder cho upload `.zip` | Xóa `application/zip` |
| `tools.sh` | MOTD format cũ | Cập nhật header rút gọn |
| `tools.sh` | Fallback menu header dùng `${TOTAL_RAM_MB}MB RAM` | Đọc `/proc` trực tiếp |
| `installer.sh` | Internet check fail khi ICMP bị block | Retry 3 IPs + `getent hosts` |
