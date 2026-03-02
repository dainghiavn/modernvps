# ModernVPS v3.2

> **Production-Ready VPS Automation**  
> Một script duy nhất — hai role: **Web Server** · **Load Balancer** · **Cluster-aware**

---

## Mục lục

- [Tổng quan](#tổng-quan)
- [Yêu cầu hệ thống](#yêu-cầu-hệ-thống)
- [Cài đặt nhanh](#cài-đặt-nhanh)
- [Kiến trúc cluster](#kiến-trúc-cluster)
- [Cấu trúc mã nguồn](#cấu-trúc-mã-nguồn)
- [Cấu trúc sau khi cài](#cấu-trúc-sau-khi-cài)
- [Modules chi tiết](#modules-chi-tiết)
- [Menu quản trị](#menu-quản-trị)
- [Cluster Management](#cluster-management)
- [Bảo mật](#bảo-mật)
- [Backup](#backup)
- [Changelog v3.2](#changelog-v32)

---

## Tổng quan

ModernVPS v3.2 tự động hoá toàn bộ quá trình thiết lập, hardening và vận hành VPS. Một lệnh duy nhất xử lý: phát hiện OS/hardware, cài stack, hardening bảo mật, tạo CLI menu quản trị, và kết nối các node thành cluster.

**Điểm nổi bật:**

- **Dual-role:** Cùng một script, chọn Web Server (full stack) hoặc Load Balancer (Nginx only)
- **Cluster-aware:** LB ↔ Web giao tiếp qua HTTP API xác thực Bearer token — không cần SSH mở giữa các node
- **Zero-downtime deploy:** Rolling deploy tarball từ LB xuống từng web node với drain/health check tự động
- **Realtime header:** Menu CLI hiển thị CPU/RAM/disk/service/SSL/backend < 100ms, < 10 forks
- **Token rotation:** Agent token tự động rotate 30 ngày, cảnh báo 7 ngày trước khi hết hạn
- **Security-first:** nftables DROP policy, SSH hardening, Fail2ban, sysctl BBR, auditd, AppArmor
- **ModSecurity WAF v3.0.14:** Build từ source + OWASP CRS — hoạt động trên cả Web và Load Balancer, verified production trên Ubuntu 22.04

---

## Yêu cầu hệ thống

| | Web Server | Load Balancer |
|---|---|---|
| **OS** | Ubuntu 22.04 / 24.04 · AlmaLinux / Rocky 8–10 | Như trái |
| **RAM** | ≥ 1 GB (khuyến nghị 2 GB) | ≥ 512 MB |
| **Disk `/`** | ≥ 3 GB trống | ≥ 512 MB trống |
| **Disk `/usr/local/src`** | ≥ 2 GB *(nếu cài ModSecurity)* | ≥ 2 GB *(nếu cài ModSecurity)* |
| **Disk `/tmp`** | ≥ 300 MB | ≥ 300 MB |
| **Quyền** | root | root |
| **Network** | Internet + internal IP (cluster) | Internet + internal IP (cluster) |

> Script chạy trên KVM, LXC, OpenVZ, Hyper-V, Docker.  
> LXC/OpenVZ: `sysctl` kernel tuning tự động bị bỏ qua.  
> Swap tự động tạo nếu RAM < 2 GB và chưa có.  
> ModSecurity build từ source cần ~2 GB disk tạm tại `/usr/local/src` và 512 MB RAM free.

---

## Cài đặt nhanh

```bash
git clone https://github.com/dainghiavn/modernvps.git
cd modernvps
sudo bash installer.sh
```

Wizard hỏi tuần tự (5–30 phút tùy chọn ModSecurity):

| Bước | Web Server | Load Balancer |
|---|---|---|
| Loại máy chủ | web | loadbalancer |
| PHP version | 8.2 / **8.3** / 8.4 | — |
| MariaDB version | **11.4** / 11.8 | — |
| Worker type | wordpress / laravel / generic | — |
| Admin email | Let's Encrypt | Let's Encrypt |
| ModSecurity WAF | y/N | y/N |

> ⚠️ ModSecurity build từ source mất **15–25 phút** (compile C++). RAM thấp (< 512 MB free) tự động dùng `make -j1` (~30–40 phút).

---

## Kiến trúc cluster

```
┌─────────────────────────────────────────────────────┐
│  Load Balancer Node                                 │
│                                                     │
│  sudo mvps → [CLUSTER]                              │
│  mvps-cluster add-node / deploy / drain / metrics   │
│                                                     │
│  /opt/modernvps/cluster.json         ← node registry│
│  /opt/modernvps/cluster-tokens.json  ← tokens       │
│  /opt/modernvps/cluster-metrics.json ← cache 30s    │
│                                                     │
│      HTTP · Bearer Token · port 9000                │
│      Internal/private IP only                       │
│      Token rotate mỗi 30 ngày                       │
│                                                     │
│  ┌──────────────────┐  ┌──────────────────┐        │
│  │  Web Node 1      │  │  Web Node 2      │        │
│  │  10.0.0.10:9000  │  │  10.0.0.11:9000  │        │
│  │  agent/index.php │  │  agent/index.php │        │
│  │  Nginx·PHP·MariaDB  │  Nginx·PHP·MariaDB        │
│  └──────────────────┘  └──────────────────┘        │
└─────────────────────────────────────────────────────┘
```

**Agent API (port 9000, internal IP only):**

| Method | Endpoint | Mô tả |
|---|---|---|
| GET | `/mvps/health` | nginx / php / mariadb status · drain state |
| GET | `/mvps/metrics` | CPU · RAM · disk · sites · nginx_conn · SSL expiring |
| POST | `/mvps/drain` | Bắt đầu graceful drain (health trả 503) |
| POST | `/mvps/drain/cancel` | Restore nhận traffic |
| POST | `/mvps/deploy` | Upload tarball + extract async |
| GET | `/mvps/deploy/status` | pending / running / done / failed |
| POST | `/mvps/token/rotate` | LB trigger rotate token mới |

---

## Cấu trúc mã nguồn

```
modernvps/
├── installer.sh              # Entry point — 10-bước wizard
├── README.md
│
├── lib/                      # Thư viện core (auto-sourced bởi installer)
│   ├── common.sh             # Globals · hardware detection · token functions · render_header
│   ├── security.sh           # SSH · nftables · Fail2ban · sysctl · auditd · AppArmor
│   ├── stack.sh              # Nginx · PHP-FPM · MariaDB · ModSecurity · agent setup
│   └── tools.sh              # Menu · backup · WP-CLI · mvps-cluster · metrics collector
│
└── agent/
    └── index.php             # PHP cluster agent — chạy trên web node (port 9000)
```

---

## Cấu trúc sau khi cài

```
/opt/modernvps/
├── config.env                # Runtime config: SERVER_TYPE, PHP_VERSION, ...
├── menu.sh                   # CLI menu (khác nhau theo role)
├── .credentials              # Tất cả credentials (chmod 600)
├── .backup-key.txt           # age private key ← SAO LƯU RA NGOÀI NGAY!
├── .backup-pubkey.txt        # age public key
├── .ssl-cache                # SSL expiry cache (TTL 1h)
│
│   ── Web node only ─────────────────────────────────
├── agent-token.json          # Bearer token cho cluster agent (chmod 600)
│
│   ── Load Balancer only ────────────────────────────
├── cluster.json              # Danh sách web nodes
├── cluster-tokens.json       # Token của từng node (chmod 600)
├── cluster-metrics.json      # Metrics cache (cập nhật mỗi 30s)
└── backends.json             # Inventory Nginx upstream backends

/usr/local/bin/
├── mvps                      # sudo mvps → mở menu
├── mvps-backup               # Backup script (cron 01:00)
├── mvps-healthcheck          # Backend health check (cron 1 phút) — LB
├── mvps-cluster              # Cluster CLI: add-node, deploy, drain, ... — LB
├── mvps-collect-metrics      # Pull metrics từ web nodes (cron 30s) — LB
├── mvps-rotate-tokens        # Auto rotate token sắp hết hạn (cron 02:00) — LB
└── mvps-check-agent-token    # Cảnh báo token sắp hết hạn (cron 06:00) — Web

/etc/nginx/sites-available/
└── mvps-agent                # Nginx block port 9000, internal IP — Web node

/usr/lib/
└── libmodsecurity.so.3.0.14  # libmodsecurity3 build từ source (thay apt v3.0.6)

/usr/lib/nginx/modules/
└── ngx_http_modsecurity_module.so  # nginx dynamic module

/etc/nginx/modsecurity/
├── modsecurity.conf          # ModSecurity config
├── crs-setup.conf            # OWASP CRS config
└── rules/                    # OWASP Core Rule Set v4.x

/backup/                      # Backup directory (chmod 700)

/var/log/modernvps/
├── install.log
├── backup.log
├── deploy.log                # Agent deploy log
└── token-rotation.log
```

---

## Modules chi tiết

### `installer.sh` — 10 bước

| Bước | Nội dung |
|---|---|
| 1 | Phát hiện OS, hardware: RAM, CPU, disk type (hdd/ssd/nvme), virtualisation |
| 2 | Chọn server type: web / loadbalancer |
| 3 | Kiểm tra tiên quyết: Internet, disk ≥ threshold, port conflicts, nginx apt candidate |
| 4 | Wizard: PHP/DB version, worker type, ModSecurity; email (cả hai) |
| 5 | Tạo Swap nếu RAM < 2 GB |
| 6 | `apt update` / `dnf update` + cài prerequisites |
| 7 | Hardening: SSH, nftables, Fail2ban, sysctl, auditd, AppArmor |
| 8 | Stack + ModSecurity + phpMyAdmin/elFinder/WP-CLI *(Web)* |
| 8b | Cluster Agent `agent/index.php` *(Web only)* |
| 9 | Backup + mvps-cluster + metrics collector + CLI menu |
| 10 | Post-install verification — báo cáo ✅/❌ từng component |

---

### `lib/common.sh`

**Hardware detection:**

```
gather_system_info()          → RAM, CPU, disk type, virt type
check_ram_pressure()          → cảnh báo nếu RAM dự kiến > 85% (không block)
ensure_swap()                 → tạo swapfile 1–2 GB nếu cần
is_sysctl_writable()          → false trên LXC/OpenVZ
cluster_token_generate()      → sinh token: mvps_wn_[hex32]
cluster_token_write_agent()   → ghi agent-token.json (chmod 600)
cluster_token_register_node() → cập nhật cluster-tokens.json trên LB
```

**Render header realtime (< 100ms, < 10 forks):**

| Nguồn | Data | Forks |
|---|---|---|
| `/proc/loadavg` | CPU load | 0 |
| `/proc/meminfo` | RAM used/total | 0 |
| `/proc/uptime` | Uptime | 0 |
| `df -h /` | Disk % | 1 |
| `systemctl is-active` × N | Service icons ✅/❌ | ~5ms/call |
| `.ssl-cache` TTL 1h | SSL expiry | 0 |
| `curl stub_status` | Connections, req/s (LB) | 1, timeout 1s |
| `backend-status.json` | Backend health (LB) | 0 |

**Màu tự động:**

| Metric | 🟢 Xanh | 🟡 Vàng | 🔴 Đỏ |
|---|---|---|---|
| CPU load | < 70% cores | 70–90% | ≥ 90% |
| RAM | < 70% | 70–85% | ≥ 85% |
| Disk | < 70% | 70–85% | ≥ 85% |
| SSL expiry | > 30 ngày (ẩn) | ≤ 30 ngày | ≤ 7 ngày |
| Backend | all UP | ≥ 1 DOWN | all DOWN |

---

### `lib/security.sh`

**SSH Hardening:**

- Port `2222`, `PermitRootLogin no`, chỉ user `deployer`
- Drop-in `/etc/ssh/sshd_config.d/99-modernvps.conf` — không sửa file gốc
- Ciphers: `chacha20-poly1305`, `aes256-gcm`; Kex: `sntrup761x25519`, `curve25519-sha256`
- Skip key → tự tạo ed25519 keypair tạm → `shred -u` private key sau 24h
- SFTP chroot jail cho group `sftp-users` *(Web only)*

**nftables Firewall:**

```
Policy: DROP (default, IPv4 + IPv6)

Allow:
  established/related · loopback
  ICMP rate 2/s · ICMPv6 neighbor discovery
  SSH :2222          rate 4/min per IP (meter)
  HTTP/HTTPS :80/:443    rate 50/s per IP (meter)
  Panel port         Web only
  Agent port :9000   Web only · từ LB internal IP only

Block:
  blacklist_v4 / blacklist_v6  timeout 24h
  TCP NULL scan, SYN-RST
  Outbound C2 ports: 3333, 4444, 5555, 14444, 14433
```

> Port 9000 **không mở** cho đến khi `mvps-cluster add-node` được chạy.

**Fail2ban jails:**

| Jail | Web | LB |
|---|---|---|
| `sshd` maxretry=3, ban=1h | ✅ | ✅ |
| `sshd-aggressive` | ✅ | ✅ |
| `nginx-http-auth` | ✅ | ❌ |
| `nginx-botsearch` | ✅ | ❌ |
| `nginx-limit-req` | ✅ | ❌ |
| `recidive` ban=7d | ✅ | ✅ |

**Sysctl — 2 profiles:**

| Param | Web | LB |
|---|---|---|
| `tcp_congestion_control` | bbr | bbr |
| `somaxconn` | 65535 | 65535 |
| `ip_local_port_range` | — | 1024 65535 |
| `netdev_max_backlog` | — | 65535 |
| `vm.dirty_ratio` | 15% | — |
| `vm.swappiness` | 10 | 10 |

---

### `lib/stack.sh`

**Nginx:**

| Config | Web Server | Load Balancer |
|---|---|---|
| `worker_connections` | 2048–8192 (scale RAM) | 65535 |
| `worker_rlimit_nofile` | 65535 | 131070 |
| FastCGI cache | PHPCACHE:32m, max 512 MB | — |
| Proxy cache | — | PROXYCACHE:32m, max 1 GB |
| Upstream keepalive | — | 32 conn, 1000 req, 60s |
| Log format | standard | + `upstream_addr`, `upstream_response_time` |

**PHP-FPM:**

```
pm.max_children = RAM(MB) ÷ 3 ÷ worker_mem_mb

Worker type:  WordPress = 80 MB  │  Laravel = 60 MB  │  Generic = 40 MB
OPcache:      < 4 GB = 128 MB    │  < 8 GB = 256 MB  │  ≥ 8 GB = 512 MB
JIT mode:     1255 (tracing JIT, PHP 8.x)
Security:     expose_php=Off, session cookie httponly/secure/strict
open_basedir: /var/www:/tmp:/usr/share
```

**MariaDB:**

```
innodb_buffer_pool_size      = RAM × 40%
innodb_buffer_pool_instances = 1 / 2 / 4 (theo RAM)
max_connections              = 100 / 150 / 200 / 300 (theo RAM)
bind-address = 127.0.0.1, skip-name-resolve, slow_query_log
```

**ModSecurity WAF — Build từ source:**

Apt không có nginx connector động → script build hoàn toàn từ source. Quá trình 5 bước:

```
1. Build libmodsecurity3 v3.0.14
   → Clone · Init submodules (libinjection + mbedtls — targeted, không clone ALL)
   → ./configure --prefix=/usr  ← autodetect mode, không có --with-X flags
   → make -j<safe_jobs> · make install
   → Remove apt libmodsecurity3 cũ (tránh ldconfig conflict)
   → Verify symbol msc_set_request_hostname tại /usr/lib/ trực tiếp

2. Clone ModSecurity-nginx connector v1.0.4

3. Download nginx source (khớp version nginx đang chạy)

4. Build nginx dynamic module
   → ./configure --with-compat --add-dynamic-module=...
   → make modules

5. Install + dlopen verify
   → nginx -t với config test (port ngẫu nhiên 20000–29999)
   → Clone OWASP CRS v4.x → nginx reload
```

**Preflight check trước build — 11 điểm:**

| # | Check | Action nếu fail |
|---|---|---|
| 1 | git >= 2.18 (`--sort=-version:refname`) | Hard fail |
| 2 | make, gcc, g++, wget, tar | Auto-install; hard fail nếu vẫn thiếu |
| 3 | autoconf, automake, libtoolize | Auto-install `libtool libtool-bin`; warn only |
| 4 | Disk `/usr/local/src` >= 2 GB | Hard fail |
| 5 | Disk `/tmp` >= 300 MB | Hard fail |
| 6 | RAM + Swap >= 512 MB | Warn only → `make -j1` |
| 7 | Write + Exec `/usr/local/src` (noexec check) | Hard fail |
| 8 | `/usr/lib/nginx/modules` writable | Hard fail |
| 9 | nginx binary + version detectable | Hard fail |
| 10 | GitHub reachable (`git ls-remote`) | Hard fail |
| 11 | nginx.org:443 reachable (TCP) + tarball URL | Hard fail / warn only |

**`_safe_nproc()` — tính make jobs an toàn:**
```
make_jobs = min( floor(RAM_free_MB / 512), nproc )
            tối thiểu 1 · tối đa nproc
```

**Cluster Agent (`setup_mvps_agent`):**

- Nginx server block lắng nghe `LB_INTERNAL_IP:9000` (internal only)
- Copy `agent/index.php` → `/var/www/mvps-agent/`
- Sinh initial token `mvps_wn_[hex32]`, ghi `agent-token.json` (chmod 600)
- `update_agent_firewall <lb_ip>` — cập nhật nftables + nginx listen IP

---

### `lib/tools.sh`

**Tools (Web only):**

- phpMyAdmin 5.2.1 — verify SHA256 checksum trước extract
- elFinder — `uploadAllow: [image, text/plain]` (bỏ zip — fix zip-slip)
- WP-CLI — verify qua `php --info`

**Backup (`mvps-backup`):**

| Item | Web | LB |
|---|---|---|
| DB `mysqldump --single-transaction` | ✅ | ❌ |
| Nginx config + modernvps config | ✅ | ✅ |
| Webroot `/var/www/` | ✅ | ❌ |
| Mã hoá `age` | ✅ | ✅ |
| Tự xóa sau 7 ngày | ✅ | ✅ |

Compressor: `pigz -6 -p 2` nếu có, fallback `gzip -6`.

**Cron schedule:**

| Thời gian | Script | Role |
|---|---|---|
| 01:00 daily | `mvps-backup` | Cả hai |
| 02:00 daily | `mvps-rotate-tokens` | LB |
| 03:00 Monday | `certbot renew` | Web |
| 06:00 daily | `mvps-check-agent-token` | Web |
| mỗi phút | `mvps-healthcheck` | LB |
| mỗi phút | `mvps-collect-metrics` (×2, cách 30s) | LB |

---

### `agent/index.php`

PHP agent chạy trên web node. Đọc data từ `/proc` — không fork process nặng.

**Bảo mật:**

- Auth: `Authorization: Bearer <token>` — timing-safe `hash_equals()`
- Token format: `mvps_wn_[a-zA-Z0-9]{32}`, có trường `expires`
- Deploy target sanitize: chỉ `[a-zA-Z0-9_\-\/]`, chặn `..`
- SHA256 checksum verify trước khi extract tarball
- Extract async (`nohup` + background watcher) — không block LB

---

## Menu quản trị

```bash
sudo mvps
```

### Header realtime

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

### Menu Web Server — 18 options

```
 [SITES]        1) List sites         2) Create site
                3) Delete site        4) WordPress install
 [SERVICES]     5) PHP-FPM pools      6) Database (9 options)
                7) SSL manager        8) SFTP users
 [MONITORING]   9) Log analysis      10) OPcache status
               11) Disk & resources  12) Security status
 [SYSTEM]      13) Backup            14) Firewall
               15) Update stack      16) CIS audit
               17) Restart services  18) Clear cache
```

### Menu Load Balancer — 27 options

```
 [BACKENDS]     1) Backend status     2) Upstream manager
                3) Thêm backend       4) Xóa backend (drain)
                5) Canary deploy
 [ROUTING]      6) Tạo proxy vhost    7) LB method
                8) Maintenance mode
 [SSL & SEC]    9) SSL manager       10) Firewall
               11) Fail2ban
 [MONITORING]  12) Traffic analytics 13) Nginx stats
               14) Xem log
 [SYSTEM]      15) Backup            16) CIS audit
               17) Disk & resources  18) Restart Nginx
               19) Update system
 [CLUSTER]     20) Dashboard nodes   21) Add web node
               22) Remove node       23) Metrics tất cả
               24) Drain node        25) Undrain node
               26) Rolling deploy    27) Rotate token
```

---

## Cluster Management

### Setup lần đầu

```bash
# 1. Cài LB
sudo bash installer.sh          # chọn: loadbalancer

# 2. Cài Web node (ghi lại AGENT_TOKEN hiển thị cuối install)
sudo bash installer.sh          # chọn: web
# → [WARN] Agent token: mvps_wn_abc123...  ← lưu lại

# 3. Add node vào cluster (chạy trên LB)
mvps-cluster add-node web-01 10.0.0.10 mvps_wn_abc123...
# → Tự test kết nối · lưu cluster.json + cluster-tokens.json

# Lấy lại token nếu quên:
cat /opt/modernvps/agent-token.json   # trên web node
```

> **Lưu ý:** Web node và LB phải reach nhau qua internal/private IP trên port 9000. Nếu dùng public IP, đảm bảo firewall chỉ allow LB IP.

### Vận hành hàng ngày

```bash
# Dashboard realtime (refresh 5s)
mvps-cluster dashboard

# Xem metrics tất cả nodes
mvps-cluster metrics all

# Health check nhanh
mvps-cluster health all

# Drain node trước maintenance
mvps-cluster drain web-01
# ... làm việc ...
mvps-cluster undrain web-01

# Rolling deploy tarball
mvps-cluster deploy --tarball /tmp/app-v1.2.tar.gz --nodes all
mvps-cluster deploy --tarball /tmp/app-v1.2.tar.gz --nodes web-01,web-02

# Quản lý nodes
mvps-cluster list
mvps-cluster add-node web-02 10.0.0.11 mvps_wn_xyz789...
mvps-cluster remove-node web-02

# Rotate token thủ công
mvps-cluster rotate-token web-01
mvps-cluster rotate-token all
```

### Rolling deploy flow

```
Với mỗi node (tuần tự):
  1. POST /mvps/drain             → node trả 503, LB ngừng gửi traffic
  2. Chờ drain hoàn tất (max 2 phút)
  3. POST /mvps/deploy + tarball  → extract async tại /var/www/<target>
  4. Poll /mvps/deploy/status     → đợi "done" (timeout 10 phút)
  5. POST /mvps/drain/cancel      → restore traffic
  6. Chờ /mvps/health → "UP"
  7. ✅ Sang node tiếp theo

Nếu node fail:
  → Dừng rolling, giữ nguyên nodes chưa deploy
  → Auto undrain node lỗi
  → Report chi tiết lỗi
```

### Token rotation

```
Auto (LB cron 02:00 daily):
  → Kiểm tra token có expires < 7 ngày
  → Sinh new_token
  → POST /mvps/token/rotate {new_token} (auth bằng old_token)
  → Web xác nhận → lưu new_token vào agent-token.json
  → LB cập nhật cluster-tokens.json

Manual:
  mvps-cluster rotate-token <node_id>
  mvps-cluster rotate-token all
```

---

## Bảo mật

### CIS Audit

```bash
sudo mvps   # → Security status (Web) hoặc CIS audit (LB)
```

Score: 🔴 < 70% · 🟡 70–89% · 🟢 ≥ 90%

**Web Server — 16 checks (score 16/16):**
SSH no root · SSH port 2222 · nftables · Fail2ban · auditd · BBR · ASLR · Nginx · PHP-FPM · MariaDB · MariaDB bind 127.0.0.1 · OPcache · cron restricted · ModSecurity WAF · auto-updates · certbot renew

**Load Balancer — 13 checks (score 13/13):**
SSH no root · SSH port 2222 · nftables · Fail2ban · auditd · BBR · ASLR · Nginx · cron restricted · health check cron · ModSecurity WAF · maintenance mode · auto-updates

### Credentials

```bash
cat /opt/modernvps/.credentials        # Tất cả passwords
cat /opt/modernvps/agent-token.json    # Agent token — Web node
cat /opt/modernvps/cluster-tokens.json # Tokens tất cả nodes — LB
```

> ⚠️ **Sao lưu backup key ngay sau khi cài:**
> ```bash
> scp root@SERVER:/opt/modernvps/.backup-key.txt ~/.mvps-backup-key.txt
> ```

---

## Backup

```bash
# Chạy thủ công
sudo mvps-backup

# Giải mã
age --decrypt \
    -i /opt/modernvps/.backup-key.txt \
    -o db-20260101.sql.gz \
    /backup/db-20260101_0100.sql.gz.age

gunzip -c db-20260101.sql.gz | mysql -u root
```

| Pattern | Nội dung | Giữ |
|---|---|---|
| `db-YYYYMMDD_HHMM.sql.gz[.age]` | All databases | 7 ngày |
| `nginx-conf-YYYYMMDD_HHMM.tar.gz[.age]` | Nginx + modernvps config | 7 ngày |
| `web-YYYYMMDD_HHMM.tar.gz[.age]` | `/var/www/` webroot | 7 ngày |

---

## Changelog v3.2

### Tính năng mới — Cluster

| Component | Mô tả |
|---|---|
| `agent/index.php` | PHP cluster agent — 7 endpoints, Bearer token auth, async deploy |
| `mvps-cluster` | CLI: add-node, list, metrics, health, drain, undrain, deploy, rotate-token, dashboard |
| `mvps-collect-metrics` | Pull metrics 30s từ web nodes → `cluster-metrics.json` |
| `mvps-rotate-tokens` | Auto rotate token hết hạn < 7 ngày lúc 02:00 |
| `mvps-check-agent-token` | Cảnh báo token sắp hết hạn (web node, 06:00) |
| nftables agent rule | Port 9000 chỉ mở cho LB internal IP, mặc định đóng |
| LB menu [CLUSTER] | 8 options mới: 20–27 |

### Tính năng mới — Core

- Header realtime `render_header_web()` / `render_header_lb()` — < 100ms
- SSL cache `.ssl-cache` TTL 1h
- `detect_virt_type()` — KVM / LXC / OpenVZ / Docker / Hyper-V
- `ensure_swap()` tạo swapfile tự động
- `is_sysctl_writable()` guard cho container
- I/O scheduler: NVMe → `none` · SSD → `mq-deadline` · HDD → `bfq`
- `_build_modsecurity_from_source()` — production-ready, verified LB + Web
- `_preflight_modsecurity()` — 11 checks trước build, fail fast, rõ lý do
- `_safe_nproc()` — tính make jobs an toàn theo RAM thực tế
- WordPress auto-install, SFTP jail, OPcache manager
- Canary deploy, drain backend, maintenance mode (LB)

### Bug Fixes — Core

| File | Bug | Fix |
|---|---|---|
| `common.sh` | RAM warning → exit khi user chọn N | Chỉ warn, không exit |
| `common.sh` | `select` loop hang khi Enter rỗng | Thay bằng `read` + default |
| `installer.sh` | Disk check trước khi biết server type | Reorder: prompt type → disk check |
| `stack.sh` | `<<'EOF'` → `$NGINX_USER` không expand | `<<EOF` + escape `\$` Nginx vars |
| `stack.sh` | LB `worker_connections 1024` | → `65535` |
| `tools.sh` | `local` dùng ngoài function trong healthcheck | Bỏ `local` |
| `tools.sh` | nginx reload mỗi phút dù không thay đổi | Track `changed=true` |
| `tools.sh` | sed restore MVPS_DOWN thiếu capture group | Fix regex `\(.*\)` |
| `tools.sh` | certbot cron check `crontab -l` sai chỗ | Check `/etc/cron.d` |
| `tools.sh` | elFinder cho upload `.zip` | Xóa `application/zip` (zip-slip fix) |
| `tools.sh` | phpMyAdmin không verify checksum | Thêm SHA256 verify |

### Bug Fixes — ModSecurity Build

> Phát hiện qua debug trực tiếp trên Ubuntu 22.04 production.  
> **Kết quả cuối:** LB 13/13 ✅ · Web 16/16 ✅

| # | Bug | Root cause | Fix |
|---|---|---|---|
| 1 | Git tag `v3.0.12` không tồn tại | Tag hardcode | `_resolve_modsec_tag()` dynamic lookup + floor fallback `v3.0.9` |
| 2 | Submodule path sai | Path cũ | Targeted update từng submodule, không clone ALL |
| 3 | `./build.sh \|\| true` che lỗi | Silent fail | Check exit code, log tail 20 dòng khi fail |
| 4 | Configure flags sai hệ thống detect | Mix curl-config / pkg-config / header | Chiến lược detect đúng từng lib |
| 5 | PPA configure args không portable | Build-server path khác VPS | `--with-compat` làm primary, không parse PPA args |
| 6 | Không check môi trường | Build 20 phút mới fail | `_preflight_modsecurity()` 11 checks |
| 7 | `_resolve_git_tag()` stdout pollution | `log()`/`warn()` tee ra stdout trong subshell `$()` | Redirect log → stderr trong subshell |
| 8 | LB upstream.conf empty → nginx reject | Nginx 1.28 strict: upstream cần ≥1 server | Placeholder `server 127.0.0.1:1 down;` |
| 9 | `others/mbedtls` submodule thiếu | Bắt buộc từ v3.0.12+, code chỉ init libinjection | Update cả `others/mbedtls`, verify ssl.h trước build |
| 10 | `--with-curl` → mandatory → false fail | Hai code path: có flag tìm path list cứng → miss | Bỏ toàn bộ `--with-X` flags |
| 11 | `--without-X` disable dù lib có sẵn | Explicit disable | Không bao giờ pass `--without-X` |
| 12 | Operator precedence `&&`/`\|\|` sai | Chain logic tạo false positive | Dùng `if` block riêng |
| 13 | Submodule fallback clone ALL | `git submodule update` không có path | Fallback chỉ retry 2 submodule cần thiết |
| 14 | `libtool` ≠ `libtool-bin` split package | Ubuntu 18.04+: `/usr/bin/libtool` ở `libtool-bin`; `command -v libtool` fail dù `dpkg -l libtool = ii` | Check `libtoolize`; cài `libtool libtool-bin`; tools là soft-fail (warn only) |
| 15 | `--with-curl` → configure fail | ModSecurity configure tìm curl theo path list riêng khi có flag, miss dù `/usr/bin/curl-config` tồn tại | `./configure --prefix=/usr` only — autodetect luôn đúng trên Ubuntu standard |
| 16 | `libpcre3-dev` thiếu → `pcre library is required` | Comment sai "dùng pcre2 thay pcre3" — ModSecurity v3.x cần PCRE v1, không phải PCRE2 | Thêm `libpcre3-dev` vào `build_deps_base` |
| 17 | `ldconfig -p \| head -1` lấy apt v3.0.6 cũ → false fail | `/lib/x86_64-linux-gnu/` có priority cao hơn `/usr/lib/` trong ldconfig cache; apt package cũ được trả về trước | Remove apt `libmodsecurity3` sau `make install`; check trực tiếp `/usr/lib/libmodsecurity.so.3.X.XX` |

---

## Changelog v3.2.1

> Security audit và bug fixes — 4 HIGH priority issues

### Bug Fixes — HIGH Priority

| # | Bug | File | Root Cause | Fix |
|---|---|---|---|---|
| **1** | nftables blacklist không persist qua reboot | `lib/security.sh` | `blacklist_v4/v6` set có `flags timeout` chỉ tồn tại trong RAM. Reboot → mất hết IPs đã ban → attacker quay lại | Thêm `setup_blacklist_persist()`: script `/usr/local/bin/mvps-blacklist` + systemd service restore khi boot + timer auto-save mỗi 30 phút |
| **2** | Token files không được backup | `lib/tools.sh` | `mvps-backup` không include `agent-token.json`, `cluster-tokens.json`. Mất server = mất cluster access → phải re-setup toàn bộ | Thêm backup riêng cho token files với `chmod 600` + backup `.credentials`, `.backup-key.txt`, blacklist files |
| **3** | Backup script race condition | `lib/tools.sh` | Không có lock file → 2 backup job chạy song song có thể corrupt file | Thêm `flock` ở đầu script, exit nếu đã có instance khác đang chạy |
| **4** | Agent `write_deploy_state()` thiếu error handling | `agent/index.php` | `file_put_contents()` không check return value. Deploy fail nhưng LB không biết → route traffic đến node lỗi | Function return `bool`, check `$written === false`, verify sau ghi, báo HTTP 500 nếu fail |

### Thay đổi chi tiết

**`lib/security.sh` (v3.2.1)**

```bash
# Thêm hàm mới
setup_blacklist_persist()
  ├── /usr/local/bin/mvps-blacklist    # CLI: save/restore/add/del/list
  ├── /etc/systemd/system/mvps-blacklist.service      # Restore khi boot
  ├── /etc/systemd/system/mvps-blacklist-save.timer   # Auto-save mỗi 30 phút
  └── /etc/systemd/system/mvps-blacklist-save.service

# Gọi trong setup_nftables()
setup_nftables() {
    ...
    setup_blacklist_persist  # ← NEW
}
```

**`lib/tools.sh` (v3.2.1)**

```bash
# mvps-backup script thay đổi:
+ flock -n 200 (lock file /run/mvps-backup.lock)
+ Backup riêng token files:
    - agent-token.json
    - cluster-tokens.json  
    - cluster.json
    - .credentials
    - .backup-key.txt
    - blacklist-v4.txt / blacklist-v6.txt
+ Output: tokens-YYYYMMDD_HHMM.tar.gz (chmod 600)
```

**`agent/index.php` (v1.2)**

```php
// Trước (v1.1)
function write_deploy_state(...): void {
    file_put_contents(DEPLOY_STATE, json_encode($state), LOCK_EX);
}

// Sau (v1.2)  
function write_deploy_state(...): bool {
    $written = @file_put_contents(DEPLOY_STATE, json_encode($state), LOCK_EX);
    if ($written === false) {
        log_event("ERROR: Failed to write deploy state");
        return false;
    }
    // Verify sau ghi
    $verify = @file_get_contents(DEPLOY_STATE);
    if ($verify === false || json_decode($verify)['status'] !== $status) {
        return false;
    }
    return true;
}

// Trong handle_deploy()
if (!write_deploy_state('running', 'Deploy in progress', $pid)) {
    http_response_code(500);
    json_out(['error' => 'Failed to write deploy state']);
    return;
}
```

### Cấu trúc mới sau cài đặt

```
/opt/modernvps/
├── blacklist-v4.txt          # IPs bị ban (persist) ← NEW
├── blacklist-v6.txt          # IPv6 bị ban (persist) ← NEW
└── ...

/usr/local/bin/
├── mvps-blacklist            # CLI quản lý blacklist ← NEW
└── ...

/etc/systemd/system/
├── mvps-blacklist.service    # Restore blacklist khi boot ← NEW
├── mvps-blacklist-save.timer # Auto-save mỗi 30 phút ← NEW
└── mvps-blacklist-save.service

/backup/
├── tokens-YYYYMMDD_HHMM.tar.gz.age  # Token backup (encrypted) ← NEW
└── ...
```

### Verify sau cài đặt

```bash
# 1. Kiểm tra blacklist persist
systemctl status mvps-blacklist
systemctl status mvps-blacklist-save.timer
mvps-blacklist add 1.2.3.4
mvps-blacklist list
# Reboot và kiểm tra lại
reboot
mvps-blacklist list  # IP phải còn

# 2. Kiểm tra backup
mvps-backup
ls -la /backup/tokens-*.tar.gz  # File mới

# 3. Kiểm tra agent (trên web node)
curl -sf -H "Authorization: Bearer $TOKEN" \
    http://127.0.0.1:9000/mvps/health
```

---

*ModernVPS v3.2.1 · MIT License · [github.com/dainghiavn/modernvps](https://github.com/dainghiavn/modernvps)*
