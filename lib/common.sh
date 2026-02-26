#!/bin/bash
# =====================================================
# common.sh - Biến toàn cục và hàm tiện ích
# ModernVPS v3.2 - Cập nhật: Phase 1
# =====================================================

# ── Màu sắc ───────────────────────────────────────
export RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
export CYAN='\033[0;36m' BOLD='\033[1m' NC='\033[0m'

# ── Biến toàn cục ─────────────────────────────────
PANEL_PORT=$(shuf -i 8000-8999 -n 1)
PHP_VERSION="8.3"
DB_VERSION="11.4"
ADMIN_EMAIL="admin@localhost"
OS_FAMILY=""
NGINX_USER=""
TOTAL_RAM_MB=0
CPU_CORES=1
DISK_TYPE="hdd"         # hdd | ssd | nvme
VIRT_TYPE="none"        # none | kvm | lxc | openvz | docker | hyperv
SWAP_MB=0
SKIP_KEY=false
SERVER_TYPE="web"       # web | loadbalancer
INSTALL_MODSEC=false
PHP_WORKER_TYPE="wordpress"  # wordpress | laravel | generic

# Mặc định cho INSTALL_DIR nếu chưa được khai báo bởi installer.sh
# (hỗ trợ source common.sh độc lập khi debug)
: "${INSTALL_DIR:=/opt/modernvps}"
: "${BACKUP_DIR:=/backup}"
: "${LOG_FILE:=/var/log/modernvps/install.log}"

# ── Mảng cấu hình theo OS ─────────────────────────
# Lý do dùng associative array: tránh case/esac rải rác khắp file,
# tập trung cấu hình OS vào 1 chỗ duy nhất, dễ extend thêm distro.
declare -A OS_CONF=(
    [debian_pkg_cmd]="DEBIAN_FRONTEND=noninteractive apt-get install -y"
    [rhel_pkg_cmd]="dnf install -y"
    [debian_php_fpm_svc]="php${PHP_VERSION}-fpm"
    [rhel_php_fpm_svc]="php-fpm"
    [debian_php_fpm_sock]="/run/php/php${PHP_VERSION}-fpm.sock"
    [rhel_php_fpm_sock]="/run/php-fpm/www.sock"
    [debian_nginx_user]="www-data"
    [rhel_nginx_user]="nginx"
    [debian_php_ini_dir]="/etc/php/${PHP_VERSION}/fpm/php.ini"
    [rhel_php_ini_dir]="/etc/php.ini"
    [debian_php_pool_dir]="/etc/php/${PHP_VERSION}/fpm/pool.d"
    [rhel_php_pool_dir]="/etc/php-fpm.d"
    [debian_my_cnf_dir]="/etc/mysql/mariadb.conf.d"
    [rhel_my_cnf_dir]="/etc/my.cnf.d"
)

# ══════════════════════════════════════════════════
# HÀM LOG
# ══════════════════════════════════════════════════
log()  { echo -e "${GREEN}[INFO]${NC}  $1" | tee -a "$LOG_FILE"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1" | tee -a "$LOG_FILE"; }
err()  { echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE" >&2; exit 1; }
info() { echo -e "${CYAN}[NOTE]${NC}  $1" | tee -a "$LOG_FILE"; }

# Chạy lệnh, ghi log, không thoát khi lỗi
run_cmd() {
    "$@" 2>&1 | tee -a "$LOG_FILE"
    local ret=${PIPESTATUS[0]}
    [[ $ret -ne 0 && $ret -ne 130 ]] && warn "Lệnh thất bại (mã $ret): $*"
    return $ret
}

# ══════════════════════════════════════════════════
# HÀM DETECT HỆ THỐNG
# ══════════════════════════════════════════════════

# Detect OS và set NGINX_USER, OS_FAMILY
detect_os() {
    [[ ! -f /etc/os-release ]] && err "Không tìm thấy /etc/os-release"
    local ID="" VERSION_ID=""
    ID=$(. /etc/os-release && echo "$ID")
    VERSION_ID=$(. /etc/os-release && echo "$VERSION_ID")
    case "$ID" in
        ubuntu)
            [[ "$VERSION_ID" =~ ^(22|24) ]] || err "Chỉ hỗ trợ Ubuntu 22/24"
            OS_FAMILY="debian"
            NGINX_USER="${OS_CONF[debian_nginx_user]}"
            ;;
        almalinux|rocky)
            [[ "$VERSION_ID" =~ ^(8|9|10) ]] || err "Chỉ hỗ trợ AlmaLinux/Rocky 8-10"
            OS_FAMILY="rhel"
            NGINX_USER="${OS_CONF[rhel_nginx_user]}"
            ;;
        *) err "OS không hỗ trợ: $ID $VERSION_ID" ;;
    esac
    log "OS: $ID $VERSION_ID ($OS_FAMILY)"
}

# Detect loại ảo hóa — quan trọng để skip sysctl không áp dụng được
# trên LXC/OpenVZ (kernel dùng chung, không thể sửa kernel params)
detect_virt_type() {
    VIRT_TYPE="none"
    if command -v systemd-detect-virt &>/dev/null; then
        VIRT_TYPE=$(systemd-detect-virt 2>/dev/null || echo "none")
    elif [[ -f /proc/1/environ ]]; then
        # Fallback thủ công cho môi trường không có systemd-detect-virt
        grep -qa 'container=lxc' /proc/1/environ 2>/dev/null && VIRT_TYPE="lxc"
        [[ -f /proc/vz/veinfo ]] && VIRT_TYPE="openvz"
    fi
    log "Virtualization: $VIRT_TYPE"
}

# Kiểm tra sysctl có thể áp dụng không
# LXC/OpenVZ dùng kernel chung → nhiều sysctl bị ignore hoặc lỗi
is_sysctl_writable() {
    case "$VIRT_TYPE" in
        lxc|openvz) return 1 ;;
        *) return 0 ;;
    esac
}

# Thu thập thông tin phần cứng đầy đủ
gather_system_info() {
    # Dùng MemAvailable thay MemTotal để phản ánh RAM thực sự có thể dùng
    TOTAL_RAM_MB=$(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo)
    SWAP_MB=$(awk '/SwapTotal/{printf "%d", $2/1024}' /proc/meminfo)
    CPU_CORES=$(nproc 2>/dev/null || echo 1)

    # Detect disk type: phân biệt NVMe / SSD / HDD
    # NVMe: tên device bắt đầu bằng "nvme" → scheduler "none" tối ưu nhất
    # SSD:  rotational=0, không phải nvme → scheduler "mq-deadline"
    # HDD:  rotational=1 → scheduler "bfq"
    DISK_TYPE="hdd"
    local root_dev
    root_dev=$(lsblk -ndo NAME,MOUNTPOINT 2>/dev/null | awk '$2=="/" {print $1}' | head -1)
    if [[ -n "$root_dev" ]]; then
        local base_dev="${root_dev%%[0-9]*}"
        # NVMe device: nvme0n1 → base_dev = nvme0n (strip số cuối)
        # Cần xử lý riêng vì pattern khác HDD/SSD
        if [[ "$base_dev" == nvme* ]]; then
            DISK_TYPE="nvme"
        elif [[ -f "/sys/block/${base_dev}/queue/rotational" ]]; then
            local rot
            rot=$(cat "/sys/block/${base_dev}/queue/rotational" 2>/dev/null)
            [[ "$rot" == "0" ]] && DISK_TYPE="ssd"
        fi
    fi

    detect_virt_type

    log "Hardware: ${TOTAL_RAM_MB}MB RAM, ${CPU_CORES} cores, disk=${DISK_TYPE}, virt=${VIRT_TYPE}, swap=${SWAP_MB}MB"
}

# Tạo swapfile nếu RAM thấp và chưa có swap
# Lý do: Server 512MB-1GB RAM không có swap → OOM killer khi cài stack
ensure_swap() {
    # Chỉ tạo swap nếu RAM < 2GB và chưa có swap
    if (( TOTAL_RAM_MB < 2048 )) && (( SWAP_MB < 512 )); then
        # LXC/OpenVZ không thể tạo swap (kernel không cho phép)
        if [[ "$VIRT_TYPE" == "lxc" || "$VIRT_TYPE" == "openvz" ]]; then
            warn "Swap: không thể tạo trên $VIRT_TYPE — liên hệ provider để cấp swap"
            return 0
        fi
        local swap_size_mb=2048
        (( TOTAL_RAM_MB < 512 )) && swap_size_mb=1024  # RAM rất thấp → swap vừa đủ
        local swap_file="/swapfile"
        log "Tạo swapfile ${swap_size_mb}MB (RAM thấp: ${TOTAL_RAM_MB}MB)..."
        if [[ ! -f "$swap_file" ]]; then
            # Dùng fallocate nhanh hơn dd, fallback sang dd nếu filesystem không hỗ trợ
            fallocate -l "${swap_size_mb}M" "$swap_file" 2>/dev/null || \
                dd if=/dev/zero of="$swap_file" bs=1M count="$swap_size_mb" 2>/dev/null
            chmod 600 "$swap_file"
            mkswap "$swap_file" 2>/dev/null
            swapon "$swap_file" 2>/dev/null
            # Persist qua reboot
            grep -q "$swap_file" /etc/fstab 2>/dev/null || \
                echo "$swap_file none swap sw 0 0" >> /etc/fstab
            SWAP_MB=$swap_size_mb
            log "Swap: ${swap_size_mb}MB tạo tại $swap_file"
        fi
    fi
}

# Kiểm tra RAM pressure trước khi cài
# Tính tổng RAM dự kiến sẽ dùng → cảnh báo nếu > 85% TOTAL_RAM_MB
check_ram_pressure() {
    [[ "$SERVER_TYPE" != "web" ]] && return 0

    local os_base=300       # OS + services cơ bản
    local nginx_mb=50       # Nginx workers
    local modsec_mb=0
    [[ "$INSTALL_MODSEC" == "true" ]] && modsec_mb=200

    # PHP worker memory tùy use case
    local worker_mem_mb=40
    case "$PHP_WORKER_TYPE" in
        wordpress) worker_mem_mb=80  ;;  # WP + plugins nặng
        laravel)   worker_mem_mb=60  ;;
        generic)   worker_mem_mb=40  ;;
    esac

    # Tính max_children theo công thức mới (dùng 1/3 RAM, chia đúng worker size)
    local avail_for_php=$(( TOTAL_RAM_MB / 3 ))
    local max_children=$(( avail_for_php / worker_mem_mb ))
    (( max_children < 5 )) && max_children=5
    local php_total=$(( max_children * worker_mem_mb ))

    local mariadb_pool=$(( TOTAL_RAM_MB * 40 / 100 ))
    (( mariadb_pool < 128 )) && mariadb_pool=128

    local opcache_mb=128
    (( TOTAL_RAM_MB >= 4096 )) && opcache_mb=256

    # Fix H4: guard divide-by-zero — TOTAL_RAM_MB=0 trong container/môi trường thiếu /proc/meminfo
    if (( TOTAL_RAM_MB == 0 )); then
        warn "Không đọc được RAM từ /proc/meminfo — bỏ qua RAM pressure check"
        return 0
    fi

    local total_estimated=$(( os_base + nginx_mb + php_total + mariadb_pool + opcache_mb + modsec_mb ))
    local pressure_pct=$(( total_estimated * 100 / TOTAL_RAM_MB ))

    log "RAM pressure estimate: ~${total_estimated}MB / ${TOTAL_RAM_MB}MB (${pressure_pct}%)"
    log "  OS=${os_base}MB | Nginx=${nginx_mb}MB | PHP(${max_children}×${worker_mem_mb}MB)=${php_total}MB"
    log "  MariaDB=${mariadb_pool}MB | OPcache=${opcache_mb}MB | ModSec=${modsec_mb}MB"

    if (( pressure_pct > 85 )); then
    warn "⚠️  RAM pressure cao: ${pressure_pct}% — nguy cơ OOM hoặc swap nặng!"
    warn "    Khuyến nghị: Nâng RAM lên ít nhất $(( total_estimated * 120 / 100 ))MB"
    warn "    Hoặc giảm max_children PHP / MariaDB buffer pool"
    read -rp "RAM pressure cao (${pressure_pct}%). Tiếp tục? (y/N): " ok
    [[ ! "$ok" =~ ^[Yy]$ ]] && {
        warn "Hủy cài đặt. Nâng RAM lên ít nhất $(( total_estimated * 120 / 100 ))MB rồi chạy lại."
        exit 1
    }
elif (( pressure_pct > 70 )); then
    warn "RAM pressure vừa: ${pressure_pct}% — hoạt động được nhưng nên monitor"
fi
}

# ══════════════════════════════════════════════════
# HÀM VALIDATION & SANITIZE
# ══════════════════════════════════════════════════

sanitize_input() {
    local v="${1:-}"
    [[ -z "$v" ]] && { warn "Input rỗng"; return 1; }
    [[ ! "$v" =~ ^[a-zA-Z0-9._:/@-]+$ ]] && { warn "Input không hợp lệ: $v"; return 1; }
    [[ "$v" == *".."* ]] && { warn "Path traversal phát hiện: $v"; return 1; }
    printf '%s' "$v"
}

sanitize_domain() {
    local d="${1:-}"
    [[ -z "$d" ]] && { warn "Domain rỗng"; return 1; }
    [[ ! "$d" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] && { warn "Domain không hợp lệ: $d"; return 1; }
    [[ ${#d} -gt 253 ]] && { warn "Domain quá dài"; return 1; }
    printf '%s' "$d"
}

# Validate IP hỗ trợ IPv4, IPv4/CIDR, IPv6 cơ bản
validate_ip() {
    local ip="${1:-}"
    # IPv4 hoặc IPv4/CIDR
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        return 0
    fi
    # IPv6 dạng full và compressed
    if [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}(/[0-9]{1,3})?$ ]] || \
       [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,7}:([0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}(/[0-9]{1,3})?$ ]]; then
        return 0
    fi
    warn "IP không hợp lệ: $ip"
    return 1
}

# Kiểm tra port có sẵn không
check_port_available() {
    local port=$1
    ss -tuln 2>/dev/null | grep -q ":${port} " && return 1
    return 0
}

# ══════════════════════════════════════════════════
# HÀM NGINX
# ══════════════════════════════════════════════════

nginx_safe_reload() {
    # Fix C1: nginx -t ghi ra stderr, không phải stdout
    # Pipe "nginx -t 2>&1 | grep" không hoạt động đúng vì grep nhận stdout của pipeline
    # nhưng exit code của pipeline là exit code của lệnh cuối (grep), không phải nginx -t
    # → capture toàn bộ output vào biến trước, rồi grep trên biến
    local _nt_out
    _nt_out=$(nginx -t 2>&1)
    echo "$_nt_out" | tee -a "$LOG_FILE" >/dev/null
    if echo "$_nt_out" | grep -q "test is successful"; then
        systemctl reload nginx 2>/dev/null \
            || systemctl restart nginx 2>/dev/null \
            || warn "nginx restart thất bại"
    else
        warn "nginx config test thất bại — không reload. Kiểm tra: nginx -t"
    fi
    return 0
}

# ══════════════════════════════════════════════════
# HÀM PHP-FPM HELPERS
# ══════════════════════════════════════════════════

get_php_fpm_svc() {
    echo "${OS_CONF[${OS_FAMILY}_php_fpm_svc]}"
}

get_php_fpm_sock() {
    echo "${OS_CONF[${OS_FAMILY}_php_fpm_sock]}"
}

# ══════════════════════════════════════════════════
# HÀM SSH
# ══════════════════════════════════════════════════

restart_ssh() {
    local restarted=false
    for svc in ssh sshd openssh-server; do
        if systemctl restart "$svc" 2>/dev/null; then
            systemctl restart "${svc}.socket" 2>/dev/null || true
            log "SSH restarted: $svc"
            restarted=true; break
        fi
    done
    if [[ "$restarted" == "false" ]]; then
        for svc in ssh sshd; do
            service "$svc" restart 2>/dev/null && { log "SSH restarted (SysV): $svc"; restarted=true; break; }
        done
    fi
    if [[ "$restarted" == "false" ]]; then
        local pid; pid=$(pgrep -o -x sshd 2>/dev/null || true)
        [[ -n "$pid" ]] && { kill -HUP "$pid" 2>/dev/null; log "SSH reloaded: HUP $pid"; restarted=true; }
    fi
    [[ "$restarted" == "false" ]] && warn "SSH restart thất bại — thực hiện thủ công: systemctl restart ssh"
}

# ══════════════════════════════════════════════════
# HÀM PACKAGE MANAGEMENT
# ══════════════════════════════════════════════════

pkg_install() {
    local pkg
    for pkg in "$@"; do
        # Skip nếu đã cài — tránh chạy apt/dnf không cần thiết
        if [[ "$OS_FAMILY" == "debian" ]]; then
            dpkg -l "$pkg" 2>/dev/null | grep -q '^ii' && { log "Package $pkg đã cài."; continue; }
        else
            rpm -q "$pkg" &>/dev/null && { log "Package $pkg đã cài."; continue; }
        fi
        log "Cài đặt $pkg..."
        case "$OS_FAMILY" in
            debian) DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg" 2>&1 | tee -a "$LOG_FILE" ;;
            rhel)   dnf install -y "$pkg" 2>&1 | tee -a "$LOG_FILE" ;;
        esac
    done
}

update_system() {
    log "Cập nhật hệ thống..."
    case "$OS_FAMILY" in
        debian) apt-get update -y; DEBIAN_FRONTEND=noninteractive apt-get upgrade -y -o Dpkg::Options::="--force-confold" ;;
        rhel)   dnf update -y ;;
    esac
}

# Install prerequisites dùng chung cho cả web và lb
install_prereqs() {
    log "Cài prerequisites..."
    local pkgs_common=(
        curl wget git nano htop fail2ban nftables aide certbot
        unzip logrotate pigz jq
    )
    # jq: cần cho backend inventory của load balancer
    case "$OS_FAMILY" in
        debian)
            pkgs_common+=(
                software-properties-common clamav clamav-daemon
                apparmor apparmor-utils apache2-utils auditd audispd-plugins acct
                libnginx-mod-http-brotli-filter libnginx-mod-http-brotli-static
            )
            ;;
        rhel)
            pkgs_common+=(
                epel-release clamd httpd-tools audit psacct
            )
            ;;
    esac
    pkg_install "${pkgs_common[@]}" 2>/dev/null || true
    systemctl enable --now fail2ban 2>/dev/null || true
    systemctl enable --now auditd 2>/dev/null || true

    # Init AIDE database nếu chưa có (tránh aide --check fail sau cài)
    if command -v aide &>/dev/null && [[ ! -f /var/lib/aide/aide.db ]]; then
        log "Khởi tạo AIDE database (lần đầu)..."
        aide --init > /var/log/aide-init.log 2>&1 || true
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db 2>/dev/null || true
    fi
}

# ══════════════════════════════════════════════════
# HÀM PROMPT / WIZARD CÀI ĐẶT
# ══════════════════════════════════════════════════

prompt_server_type() {
    echo ""
    echo -e "${BOLD}=== Chọn loại máy chủ ===${NC}"
    echo "1) Web Server    (Nginx + PHP + MariaDB + Tools)"
    echo "2) Load Balancer (Nginx reverse proxy, không PHP/DB)"
    read -rp "Chọn (1/2) [1]: " choice
    case "$choice" in
        2) SERVER_TYPE="loadbalancer" ;;
        *) SERVER_TYPE="web" ;;
    esac
    log "Server type: $SERVER_TYPE"
}

# Chỉ dùng cho web server — hỏi PHP version, MariaDB, email, PHP worker type
prompt_choices() {
    echo ""
    echo -e "${BOLD}=== Cấu hình Web Server ===${NC}"
    echo ""

    echo "Chọn PHP version:"
    echo "  1) 8.2   2) 8.3 (khuyến nghị)   3) 8.4"
    read -rp "Chọn (1/2/3) [2]: " _php_choice
    case "${_php_choice:-2}" in
        1) PHP_VERSION="8.2" ;;
        3) PHP_VERSION="8.4" ;;
        *) PHP_VERSION="8.3" ;;
    esac

    # Cập nhật OS_CONF sau khi PHP_VERSION thay đổi
    # Quan trọng: phải update ngay để các hàm gọi sau dùng đúng version
    OS_CONF[debian_php_fpm_svc]="php${PHP_VERSION}-fpm"
    OS_CONF[debian_php_fpm_sock]="/run/php/php${PHP_VERSION}-fpm.sock"
    OS_CONF[debian_php_ini_dir]="/etc/php/${PHP_VERSION}/fpm/php.ini"
    OS_CONF[debian_php_pool_dir]="/etc/php/${PHP_VERSION}/fpm/pool.d"

    echo "Chọn MariaDB version:"
    echo "  1) 11.4 (LTS, ổn định)   2) 11.8 (mới nhất)"
    read -rp "Chọn (1/2) [1]: " _db_choice
    case "${_db_choice:-1}" in
        2) DB_VERSION="11.8" ;;
        *) DB_VERSION="11.4" ;;
    esac

    # Hỏi use case để tính đúng memory per PHP worker
    echo ""
    echo "Ứng dụng chủ yếu chạy là gì? (ảnh hưởng tính toán PHP-FPM)"
    echo "1) WordPress / WooCommerce  (~80MB/worker)"
    echo "2) Laravel / Framework      (~60MB/worker)"
    echo "3) PHP thuần / nhẹ          (~40MB/worker)"
    read -rp "Chọn (1/2/3) [1]: " wtype
    case "$wtype" in
        2) PHP_WORKER_TYPE="laravel" ;;
        3) PHP_WORKER_TYPE="generic" ;;
        *) PHP_WORKER_TYPE="wordpress" ;;
    esac

    read -rp "Admin email [admin@localhost]: " ADMIN_EMAIL
    ADMIN_EMAIL="${ADMIN_EMAIL:-admin@localhost}"

    echo ""
    info "Panel port: $PANEL_PORT | RAM: ${TOTAL_RAM_MB}MB | CPU: ${CPU_CORES} cores | PHP worker: $PHP_WORKER_TYPE"
}

prompt_modsecurity() {
    echo ""
    if [[ "$SERVER_TYPE" == "loadbalancer" ]]; then
        echo -e "${YELLOW}ModSecurity WAF trên Load Balancer bảo vệ tập trung toàn cụm backend.${NC}"
    else
        echo -e "${YELLOW}ModSecurity WAF + OWASP CRS bảo vệ web application.${NC}"
    fi

    if (( TOTAL_RAM_MB < 1500 )); then
        warn "RAM dưới 1.5GB — ModSecurity có thể ảnh hưởng hiệu năng đáng kể."
    fi

    read -rp "Cài ModSecurity? (y/N): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        INSTALL_MODSEC=true
    else
        INSTALL_MODSEC=false
        warn "Bỏ qua ModSecurity."
    fi
}

# ══════════════════════════════════════════════════
# HÀM RENDER HEADER MENU (dùng chung cho cả 2 menu)
# ══════════════════════════════════════════════════
#
# Thiết kế tối ưu hiệu năng:
# - Đọc /proc/* trực tiếp (0 fork) cho CPU, RAM, uptime
# - df một lần (1 fork) cho disk
# - systemctl is-active (1 fork nhẹ × N services)
# - SSL: đọc cache file, không gọi certbot mỗi lần
# - Tổng: < 10 forks, render < 100ms

# Màu động theo ngưỡng — dùng cho CPU/RAM/Disk
_color_threshold() {
    local val=$1 warn_at=$2 crit_at=$3
    if (( val >= crit_at )); then
        printf '%s' "$RED"
    elif (( val >= warn_at )); then
        printf '%s' "$YELLOW"
    else
        printf '%s' "$GREEN"
    fi
}

# Lấy % CPU load so với số cores (load_1min / CPU_CORES × 100)
_get_cpu_pct() {
    local load1 cores pct
    read -r load1 _ < /proc/loadavg
    cores=$(nproc 2>/dev/null || echo 1)
    # Bash không tính float → nhân 100 trước rồi chia
    # load1 dạng "1.23" → dùng awk để tính
    pct=$(awk -v l="$load1" -v c="$cores" 'BEGIN{printf "%d", l/c*100}')
    printf '%s' "$pct"
}

# Cập nhật SSL cache (TTL 1 giờ) — tránh gọi certbot mỗi lần render
_refresh_ssl_cache() {
    local cache_file="${INSTALL_DIR}/.ssl-cache"
    local cache_ttl=3600
    # Nếu cache còn mới → skip
    if [[ -f "$cache_file" ]]; then
        local age=$(( $(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0) ))
        (( age < cache_ttl )) && return 0
    fi
    # Refresh cache từ certbot
    if command -v certbot &>/dev/null; then
        certbot certificates 2>/dev/null | awk '
            /Domains:/{dom=$2}
            /VALID: ([0-9]+) day/{
                match($0,/VALID: ([0-9]+)/,a)
                if(dom!="" && a[1]!="") print dom ":" a[1]
            }
        ' > "$cache_file" 2>/dev/null || true
    fi
}

# Kiểm tra SSL sắp hết hạn — trả về chuỗi warning hoặc rỗng
_check_ssl_expiry() {
    local cache_file="${INSTALL_DIR}/.ssl-cache"
    [[ ! -f "$cache_file" ]] && return 0
    local warn_str=""
    while IFS=: read -r domain days; do
        [[ -z "$domain" || -z "$days" ]] && continue
        if (( days <= 7 )); then
            warn_str="${RED}⚠ SSL URGENT: ${domain} còn ${days}d${NC}"
            break  # Hiện 1 cái nghiêm trọng nhất
        elif (( days <= 30 )); then
            warn_str="${YELLOW}⚠ SSL: ${domain} còn ${days} ngày${NC}"
        fi
    done < "$cache_file"
    printf '%s' "$warn_str"
}

# Render header cho Web Server
render_header_web() {
    # ── Thu thập dữ liệu ──────────────────────────
    local hostname; hostname=$(hostname -s 2>/dev/null || echo "unknown")

    # Uptime từ /proc/uptime (số giây, không fork)
    local uptime_sec; read -r uptime_sec _ < /proc/uptime
    local uptime_str
    uptime_str=$(awk -v s="$uptime_sec" 'BEGIN{
        d=int(s/86400); h=int((s%86400)/3600)
        printf "%dd%dh", d, h
    }')

    # CPU load (không fork)
    local load1; read -r load1 _ < /proc/loadavg
    local cpu_pct; cpu_pct=$(_get_cpu_pct)
    local cpu_color; cpu_color=$(_color_threshold "$cpu_pct" 70 90)

    # RAM từ /proc/meminfo (không fork)
    local ram_used_mb ram_total_mb ram_pct
    read -r ram_used_mb ram_total_mb < <(
        awk '/MemTotal/{t=$2} /MemAvailable/{a=$2}
             END{printf "%d %d", (t-a)/1024, t/1024}' /proc/meminfo
    )
    ram_pct=$(( ram_used_mb * 100 / (ram_total_mb + 1) ))
    local ram_color; ram_color=$(_color_threshold "$ram_pct" 70 85)

    # Disk (1 fork)
    local disk_info; disk_info=$(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2" "$5}')
    local disk_pct; disk_pct=$(df / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
    local disk_color; disk_color=$(_color_threshold "${disk_pct:-0}" 70 85)

    # Services status
    local svc_nginx svc_php svc_db svc_f2b svc_waf
    svc_nginx=$(systemctl is-active nginx    2>/dev/null)
    svc_php=$(systemctl is-active "$(get_php_fpm_svc)" 2>/dev/null)
    svc_db=$(systemctl is-active mariadb    2>/dev/null)
    svc_f2b=$(systemctl is-active fail2ban  2>/dev/null)
    # WAF: check modsecurity on trong nginx.conf
    grep -q 'modsecurity on' /etc/nginx/nginx.conf 2>/dev/null && svc_waf="active" || svc_waf="inactive"

    _svc_icon() { [[ "$1" == "active" ]] && echo "✅" || echo "❌"; }

    # Số sites đang enable
    local site_count; site_count=$(ls /etc/nginx/sites-enabled/ 2>/dev/null | grep -v '^\.' | wc -l)

    # SSL warning (đọc cache, không fork nặng)
    _refresh_ssl_cache
    local ssl_warn; ssl_warn=$(_check_ssl_expiry)

    # Context dòng 4
    local line4
    if [[ -n "$ssl_warn" ]]; then
        line4="Sites: ${site_count} | $(echo -e "$ssl_warn")"
    else
        line4="Sites: ${site_count} | Uptime: ${uptime_str} | All systems normal ✅"
    fi

    # ── Render ────────────────────────────────────
    echo "═══════════════════════════════════════════"
    printf "  ModernVPS v3.2 (web) | %s | Up %s\n" "$hostname" "$uptime_str"
    printf "  CPU: ${cpu_color}%-4s${NC} | RAM: ${ram_color}%s/%sMB${NC} | DSK: ${disk_color}%s${NC}\n" \
        "${load1}" "${ram_used_mb}" "${ram_total_mb}" "${disk_info}"
    printf "  Nginx %s | PHP %s | DB %s | F2B %s | WAF %s\n" \
        "$(_svc_icon "$svc_nginx")" "$(_svc_icon "$svc_php")" \
        "$(_svc_icon "$svc_db")"   "$(_svc_icon "$svc_f2b")" \
        "$(_svc_icon "$svc_waf")"
    echo -e "  ${line4}"
    echo "═══════════════════════════════════════════"
}

# Render header cho Load Balancer
render_header_lb() {
    # ── Thu thập dữ liệu ──────────────────────────
    local hostname; hostname=$(hostname -s 2>/dev/null || echo "unknown")

    local uptime_sec; read -r uptime_sec _ < /proc/uptime
    local uptime_str
    uptime_str=$(awk -v s="$uptime_sec" 'BEGIN{
        d=int(s/86400); h=int((s%86400)/3600)
        printf "%dd%dh", d, h
    }')

    local load1; read -r load1 _ < /proc/loadavg
    local cpu_pct; cpu_pct=$(_get_cpu_pct)
    local cpu_color; cpu_color=$(_color_threshold "$cpu_pct" 70 90)

    local ram_used_mb ram_total_mb ram_pct
    read -r ram_used_mb ram_total_mb < <(
        awk '/MemTotal/{t=$2} /MemAvailable/{a=$2}
             END{printf "%d %d", (t-a)/1024, t/1024}' /proc/meminfo
    )
    ram_pct=$(( ram_used_mb * 100 / (ram_total_mb + 1) ))
    local ram_color; ram_color=$(_color_threshold "$ram_pct" 70 85)

    local disk_info; disk_info=$(df -h / 2>/dev/null | awk 'NR==2{print $3"/"$2" "$5}')
    local disk_pct; disk_pct=$(df / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5); print $5}')
    local disk_color; disk_color=$(_color_threshold "${disk_pct:-0}" 70 85)

    # Services
    local svc_nginx svc_f2b svc_nft
    svc_nginx=$(systemctl is-active nginx   2>/dev/null)
    svc_f2b=$(systemctl is-active fail2ban  2>/dev/null)
    nft list tables 2>/dev/null | grep -q modernvps && svc_nft="active" || svc_nft="inactive"

    _svc_icon() { [[ "$1" == "active" ]] && echo "✅" || echo "❌"; }

    # Backend status từ file cache của health check script
    local backend_status="N/A"
    local status_file="${INSTALL_DIR}/backend-status.json"
    if [[ -f "$status_file" ]] && command -v jq &>/dev/null; then
        local total up down_list
        total=$(jq '.backends | length' "$status_file" 2>/dev/null || echo 0)
        up=$(jq '[.backends[] | select(.status=="UP")] | length' "$status_file" 2>/dev/null || echo 0)
        local down=$(( total - up ))
        if (( down > 0 )); then
            # Lấy tên backend đầu tiên bị DOWN để hiển thị cảnh báo
            local first_down
            first_down=$(jq -r '[.backends[] | select(.status=="DOWN")][0].label // .ip' "$status_file" 2>/dev/null)
            backend_status="${YELLOW}${up}/${total} ⚠ ${first_down} DOWN${NC}"
        else
            backend_status="${GREEN}${up}/${total} ✅${NC}"
        fi
    fi

    # Nginx connections từ stub_status (timeout 1s — không block nếu nginx chết)
    local conn_info="N/A" rps_info="N/A"
    if [[ "$svc_nginx" == "active" ]]; then
        local stub; stub=$(curl -sf --max-time 1 http://127.0.0.1/nginx_status 2>/dev/null)
        if [[ -n "$stub" ]]; then
            conn_info=$(echo "$stub" | awk '/Active connections/{print $3}')
            rps_info=$(echo "$stub" | awk 'NR==3{print $3}')
        fi
    fi

    # Maintenance mode
    local maint_str="${GREEN}OFF${NC}"
    [[ -f "${INSTALL_DIR}/.maintenance-active" ]] && maint_str="${RED}ON ⚠${NC}"

    # ── Render ────────────────────────────────────
    echo "═══════════════════════════════════════════"
    printf "  ModernVPS v3.2 (lb) | %s | Up %s\n" "$hostname" "$uptime_str"
    printf "  CPU: ${cpu_color}%-4s${NC} | RAM: ${ram_color}%s/%sMB${NC} | DSK: ${disk_color}%s${NC}\n" \
        "${load1}" "${ram_used_mb}" "${ram_total_mb}" "${disk_info}"
    printf "  Nginx %s | F2B %s | NFT %s | Backends: " \
        "$(_svc_icon "$svc_nginx")" "$(_svc_icon "$svc_f2b")" "$(_svc_icon "$svc_nft")"
    echo -e "$backend_status"
    echo -e "  Conn: ${conn_info} | Req/s: ${rps_info} | Maint: ${maint_str}"
    echo "═══════════════════════════════════════════"
}

# ══════════════════════════════════════════════════
# HÀM HIỂN THỊ THÔNG TIN SAU CÀI ĐẶT
# ══════════════════════════════════════════════════

show_final_info() {
    local TOOLS_PASS="" DEPLOYER_PASS=""
    [[ -f "$INSTALL_DIR/.credentials" ]] && {
        TOOLS_PASS=$(grep 'TOOLS_PASS=' "$INSTALL_DIR/.credentials" | cut -d= -f2)
        DEPLOYER_PASS=$(grep 'DEPLOYER_PASS=' "$INSTALL_DIR/.credentials" | cut -d= -f2)
    }
    local server_ip; server_ip=$(hostname -I 2>/dev/null | awk '{print $1}')

    log ""
    log "════════════════════════════════════════"
    log "✅  ModernVPS v3.2 CÀI ĐẶT HOÀN TẤT!"
    log "════════════════════════════════════════"
    log ""
    log "─── KẾT NỐI SSH ────────────────────────"
    if [[ "$SKIP_KEY" == "true" ]]; then
        log "  Phương thức : Password (tạm thời)"
        log "  Lệnh kết nối: ssh deployer@${server_ip} -p 2222"
        log "  User        : deployer"
        log "  Password    : $DEPLOYER_PASS"
        log ""
        warn "  ⚠️  HÃY THÊM SSH KEY RỒI TẮT PASSWORD:"
        warn "  1. Tạo key : ssh-keygen -t ed25519"
        warn "  2. Copy    : ssh-copy-id -p 2222 deployer@${server_ip}"
        warn "  3. Tắt pw  : sửa PasswordAuthentication no trong sshd_config"
    else
        log "  Phương thức : SSH Key (an toàn)"
        log "  Lệnh kết nối: ssh deployer@${server_ip} -p 2222"
        log "  User        : deployer"
        [[ -n "$DEPLOYER_PASS" ]] && log "  Sudo pass   : $DEPLOYER_PASS"
    fi
    log ""

    if [[ "$SERVER_TYPE" == "web" ]]; then
        log "─── CÔNG CỤ QUẢN TRỊ WEB ───────────────"
        log "  phpMyAdmin  : http://${server_ip}:${PANEL_PORT}/pma"
        log "  File Manager: http://${server_ip}:${PANEL_PORT}/filemanager"
        log "  Đăng nhập   : admin / $TOOLS_PASS"
        log ""
    fi

    log "─── QUẢN LÝ HỆ THỐNG ───────────────────"
    log "  Loại server : $SERVER_TYPE"
    log "  Lệnh quản lý: sudo mvps"
    log "  Backup      : $BACKUP_DIR (tự động 1AM hàng ngày)"
    log ""
    warn "⚠️  QUAN TRỌNG — Lưu lại ngay:"
    warn "  1. Credentials : cat ${INSTALL_DIR}/.credentials"
    warn "  2. Backup key  : cat ${INSTALL_DIR}/.backup-key.txt"
    warn "  3. Root login đã TẮT — chỉ dùng user 'deployer'"
    log "════════════════════════════════════════"
}
# ══════════════════════════════════════════════════
# CLUSTER TOKEN MANAGEMENT
# ══════════════════════════════════════════════════

# Sinh token có format mvps_XX_[a-z0-9]{32}
# $1: prefix — "lb" hoặc "wn" (web node)
cluster_token_generate() {
    local prefix="${1:-wn}"
    printf 'mvps_%s_%s' "$prefix" \
        "$(openssl rand -hex 16 2>/dev/null || cat /dev/urandom | tr -dc 'a-z0-9' | head -c32)"
}

# Ghi token file cho web node agent
# $1: token string
cluster_token_write_agent() {
    local token="$1"
    local token_file="/opt/modernvps/agent-token.json"
    mkdir -p /opt/modernvps
    printf '{"token":"%s","issued":"%s","expires":"%s","rotated_by":"installer"}\n' \
        "$token" \
        "$(date -Iseconds)" \
        "$(date -Iseconds -d '+30 days')" \
        > "$token_file"
    chmod 600 "$token_file"
    log "Agent token đã ghi vào $token_file"
}

# Ghi cluster-tokens.json trên LB cho một node
# $1: node_id, $2: token
cluster_token_register_node() {
    local node_id="$1" token="$2"
    local token_file="/opt/modernvps/cluster-tokens.json"

    # Tạo file nếu chưa có
    [[ ! -f "$token_file" ]] && echo '{"nodes":{}}' > "$token_file"
    chmod 600 "$token_file"

    # Cần jq để thao tác JSON an toàn
    if command -v jq &>/dev/null; then
        local tmp; tmp=$(mktemp)
        jq --arg id "$node_id" --arg tok "$token" \
           --arg iss "$(date -Iseconds)" \
           --arg exp "$(date -Iseconds -d '+30 days')" \
           '.nodes[$id] = {"token":$tok,"issued":$iss,"expires":$exp}' \
           "$token_file" > "$tmp" && mv "$tmp" "$token_file"
        chmod 600 "$token_file"
    else
        warn "jq không có — ghi token file thủ công"
        # Fallback đơn giản (không dùng cho production nhiều node)
        printf '{"nodes":{"%s":{"token":"%s","issued":"%s","expires":"%s"}}}\n' \
            "$node_id" "$token" "$(date -Iseconds)" \
            "$(date -Iseconds -d '+30 days')" > "$token_file"
        chmod 600 "$token_file"
    fi
    log "Token đã đăng ký cho node $node_id trong cluster-tokens.json"
}
