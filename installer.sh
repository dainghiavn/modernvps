#!/bin/bash
# =====================================================
# ModernVPS Panel v3.2 - PRODUCTION READY
# Hỗ trợ Web Server và Load Balancer
# ModernVPS v3.2 - Cập nhật: Phase 2
# =====================================================

# ── Strict mode ───────────────────────────────────
# -u: lỗi khi dùng biến chưa khai báo
# -o pipefail: lỗi khi bất kỳ lệnh nào trong pipe thất bại
set -uo pipefail

# IFS chuẩn: space, tab, newline — tránh word splitting bất ngờ
IFS=$' \t\n'

# ── SCRIPT_DIR ────────────────────────────────────
# readonly: không bị ghi đè khi source các lib vào
# >/dev/null 2>&1: tránh Double Path do CDPATH
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

# ── Hằng số hệ thống ──────────────────────────────
# Khai báo tại đây để các lib được source vào có thể dùng ngay
# common.sh có fallback ": ${INSTALL_DIR:=...}" để hỗ trợ source độc lập
readonly MVPS_VERSION="3.2"
readonly INSTALL_DIR="/opt/modernvps"
readonly BACKUP_DIR="/backup"
readonly LOG_FILE="/var/log/modernvps/install.log"

# Tạo thư mục log TRƯỚC khi source lib — hàm log() cần LOG_FILE tồn tại
mkdir -p /var/log/modernvps
touch "$LOG_FILE" 2>/dev/null || true

# ── Load modules ──────────────────────────────────
# Thứ tự source quan trọng: common.sh phải được load trước
# vì các lib khác phụ thuộc vào biến/hàm của nó
for _lib in common security stack tools; do
    _lib_path="${SCRIPT_DIR}/lib/${_lib}.sh"
    if [[ ! -f "$_lib_path" ]]; then
        echo "[ERROR] Không tìm thấy lib: ${_lib_path}" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$_lib_path"
done
unset _lib _lib_path

# ══════════════════════════════════════════════════
# KIỂM TRA TIÊN QUYẾT
# ══════════════════════════════════════════════════

check_prerequisites() {
    log "Kiểm tra tiên quyết hệ thống..."

    # ── Kết nối Internet ──────────────────────────
    # Thử nhiều địa chỉ phòng trường hợp 8.8.8.8 bị block (một số VPS provider)
    local net_ok=false
    for host in 8.8.8.8 1.1.1.1 9.9.9.9; do
        if ping -c 1 -W 2 "$host" >/dev/null 2>&1; then
            net_ok=true
            break
        fi
    done
    if [[ "$net_ok" == "false" ]]; then
        # Fallback: thử DNS lookup thay vì ping (một số firewall block ICMP)
        if ! getent hosts github.com >/dev/null 2>&1; then
            err "Không có kết nối Internet. Kiểm tra lại network."
        fi
        warn "Ping bị block nhưng DNS OK — tiếp tục cài đặt"
    fi

    # ── Dung lượng đĩa ───────────────────────────
    local root_avail_kb
    root_avail_kb=$(df / 2>/dev/null | awk 'NR==2 {print $4}')

    # Ngưỡng tối thiểu theo SERVER_TYPE (đã được set trước hàm này)
    # Web server: ~3GB (PHP + MariaDB + tools + webroot)
    # Load balancer: ~512MB (chỉ Nginx + config)
    local min_disk_kb min_disk_label
    if [[ "$SERVER_TYPE" == "loadbalancer" ]]; then
        min_disk_kb=524288   # 512MB
        min_disk_label="512MB"
    else
        min_disk_kb=3145728  # 3GB
        min_disk_label="3GB"
    fi

    if (( root_avail_kb < min_disk_kb )); then
        warn "Dung lượng trống: $(( root_avail_kb / 1024 ))MB — cần ít nhất ${min_disk_label} cho ${SERVER_TYPE}"
        read -rp "Vẫn tiếp tục? (y/N): " _disk_ok
        # Nếu user biết mình đang làm gì thì cho tiếp tục
        [[ ! "$_disk_ok" =~ ^[Yy]$ ]] && err "Hủy cài đặt: không đủ dung lượng đĩa"
    else
        log "Disk OK: $(( root_avail_kb / 1024 ))MB trống (cần ${min_disk_label})"
    fi

    # ── Port availability ─────────────────────────
    # Kiểm tra các port quan trọng — chỉ cảnh báo, không dừng
    # (user có thể đang chạy service khác hợp lệ)
    check_port_available 2222 \
        || warn "Port 2222 đang dùng — SSH hardening có thể xung đột"
    check_port_available 80  \
        || warn "Port 80 đang dùng — Nginx có thể không start được"
    check_port_available 443 \
        || warn "Port 443 đang dùng — Nginx SSL có thể không start được"

    # Panel port: chỉ cần kiểm tra với web server
    # Nhưng SERVER_TYPE chưa chắc đã set ở đây → check luôn, không hại gì
    local _retry=0
    while ! check_port_available "$PANEL_PORT" && (( _retry < 5 )); do
        PANEL_PORT=$(shuf -i 8000-8999 -n 1)
        (( _retry++ ))
    done
    (( _retry > 0 )) && warn "Panel port đã đổi sang: $PANEL_PORT"

    # ── Nginx version pre-check ───────────────────
    # Ubuntu apt nginx = 1.18.0 có bug shared memory zone allocator
    # Script sẽ tự thêm ppa:ondrej/nginx khi cài, nhưng warn sớm để user biết
    if [[ "${OS_FAMILY:-}" == "debian" ]]; then
        local _apt_ng_ver _ng_maj _ng_min
        _apt_ng_ver=$(apt-cache policy nginx 2>/dev/null \
            | awk '/Candidate:/{print $2}' | grep -oP '^[0-9]+\.[0-9]+' | head -1)
        if [[ -n "$_apt_ng_ver" ]]; then
            _ng_maj=$(echo "$_apt_ng_ver" | cut -d. -f1)
            _ng_min=$(echo "$_apt_ng_ver" | cut -d. -f2)
            if (( _ng_maj == 1 && _ng_min < 20 )); then
                warn "Ubuntu apt nginx candidate = ${_apt_ng_ver} (cũ, có bug shared memory)"
                warn "Script sẽ tự upgrade lên nginx 1.24+ qua ppa:ondrej/nginx"
            else
                log "nginx apt candidate: ${_apt_ng_ver} — OK"
            fi
        fi
    fi

    log "Tiên quyết: OK (disk=$(( root_avail_kb/1024 ))MB free, panel_port=$PANEL_PORT)"
}

# ══════════════════════════════════════════════════
# POST-INSTALL VERIFICATION
# Kiểm tra sau khi cài xong — báo cáo những gì failed
# ══════════════════════════════════════════════════

_post_install_verify() {
    log "Kiểm tra sau cài đặt..."
    local fail_count=0
    local results=()

    # Helper check service
    _chk() {
        local label="$1" svc="$2"
        if systemctl is-active "$svc" &>/dev/null; then
            results+=("  ✅ ${label}")
        else
            results+=("  ❌ ${label} (thử: systemctl status ${svc})")
            (( fail_count++ ))
        fi
    }

    # Nginx — bắt buộc cả hai mode
    _chk "Nginx"    "nginx"
    _chk "Fail2ban" "fail2ban"

    # Nginx version — warn nếu vẫn còn Ubuntu 1.18 (có bug shared memory zone)
    local _ng_ver _ng_maj _ng_min
    _ng_ver=$(nginx -v 2>&1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    _ng_maj=$(echo "$_ng_ver" | cut -d. -f1)
    _ng_min=$(echo "$_ng_ver" | cut -d. -f2)
    if (( _ng_maj == 1 && _ng_min < 20 )); then
        results+=("  ⚠️  nginx ${_ng_ver} — quá cũ (Ubuntu default), dễ gặp lỗi shared memory zone")
        (( fail_count++ ))
    else
        results+=("  ✅ nginx ${_ng_ver} — version OK")
    fi

    # nginx -t — kiểm tra config syntax trực tiếp (chính xác hơn systemctl is-active)
    local _nt_out
    _nt_out=$(nginx -t 2>&1)
    if echo "$_nt_out" | grep -q "test is successful"; then
        results+=("  ✅ nginx config: syntax OK")
    else
        local _nt_err; _nt_err=$(echo "$_nt_out" | grep "\[emerg\]" | head -1)
        results+=("  ❌ nginx config: ${_nt_err:-test failed — chạy: nginx -t}")
        (( fail_count++ ))
    fi

    # nftables
    if nft list tables 2>/dev/null | grep -q modernvps; then
        results+=("  ✅ nftables (modernvps table)")
    else
        results+=("  ❌ nftables (bảng modernvps chưa load)")
        (( fail_count++ ))
    fi

    # Web-only services
    if [[ "$SERVER_TYPE" == "web" ]]; then
        _chk "PHP-FPM"  "$(get_php_fpm_svc)"
        _chk "MariaDB"  "mariadb"

        # phpMyAdmin accessible
        if [[ -d "/var/www/html/pma" ]]; then
            results+=("  ✅ phpMyAdmin (đã cài)")
        else
            results+=("  ⚠️  phpMyAdmin (chưa cài hoặc cài thất bại)")
        fi
    fi

    # WP-CLI — web only
    if [[ "$SERVER_TYPE" == "web" ]]; then
        if command -v wp &>/dev/null; then
            results+=("  ✅ WP-CLI")
        else
            results+=("  ⚠️  WP-CLI (chưa cài — WordPress install sẽ tự cài khi cần)")
        fi
    fi

    # ModSecurity
    if [[ "$INSTALL_MODSEC" == "true" ]]; then
        if grep -q 'modsecurity on' /etc/nginx/nginx.conf 2>/dev/null; then
            results+=("  ✅ ModSecurity WAF")
        else
            results+=("  ❌ ModSecurity WAF (cài thất bại)")
            (( fail_count++ ))
        fi
    fi

    # Backup script
    if [[ -x /usr/local/bin/mvps-backup ]]; then
        results+=("  ✅ Backup script")
    else
        results+=("  ❌ Backup script (/usr/local/bin/mvps-backup)")
        (( fail_count++ ))
    fi

    # mvps command
    if [[ -x /usr/local/bin/mvps ]]; then
        results+=("  ✅ mvps command")
    else
        results+=("  ❌ mvps command (/usr/local/bin/mvps)")
        (( fail_count++ ))
    fi

    # In kết quả
    echo ""
    log "── Kết quả post-install verification ──"
    for r in "${results[@]}"; do
        echo -e "$r" | tee -a "$LOG_FILE"
    done
    echo ""

    if (( fail_count == 0 )); then
        log "✅ Tất cả components đã sẵn sàng!"
    else
        warn "⚠️  ${fail_count} component(s) có vấn đề — xem log: $LOG_FILE"
    fi

    return $fail_count
}

# ══════════════════════════════════════════════════
# PROGRESS DISPLAY
# Hiển thị tiến trình cài đặt cho user
# ══════════════════════════════════════════════════

_step() {
    local step="$1" total="$2" label="$3"
    echo ""
    echo -e "${CYAN}[${step}/${total}]${NC} ${BOLD}${label}${NC}"
    echo "────────────────────────────────────────"
}

# ══════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════

main() {
    # ── Kiểm tra root ─────────────────────────────
    [[ $EUID -ne 0 ]] && {
        echo "[ERROR] Chạy với quyền root: sudo bash $0" >&2
        exit 1
    }

    # ── Banner ────────────────────────────────────
    clear
    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║     ModernVPS v${MVPS_VERSION} Installer             ║${NC}"
    echo -e "${BOLD}║     Production-Ready VPS Setup Script    ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo "  Log file : $LOG_FILE"
    echo "  Bắt đầu  : $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""

    # ── Bước 1: Detect & gather ───────────────────
    _step 1 10 "Phát hiện hệ thống"
    detect_os || err "Không nhận diện được OS"
    gather_system_info

    # In thông tin hardware sau khi detect
    echo ""
    echo -e "  OS      : $(. /etc/os-release && echo "$PRETTY_NAME")"
    echo -e "  RAM     : ${TOTAL_RAM_MB}MB"
    echo -e "  CPU     : ${CPU_CORES} cores"
    echo -e "  Disk    : ${DISK_TYPE}"
    echo -e "  Virt    : ${VIRT_TYPE}"
    echo -e "  Swap    : ${SWAP_MB}MB"
    echo ""

    # ── Bước 2: Chọn server type TRƯỚC ───────────
    # Lý do: check_prerequisites() cần biết SERVER_TYPE
    # để dùng ngưỡng disk đúng (web=3GB, lb=500MB)
    _step 2 10 "Chọn loại máy chủ"
    prompt_server_type

    # ── Bước 3: Kiểm tra tiên quyết ──────────────
    _step 3 10 "Kiểm tra tiên quyết & Cấu hình"
    check_prerequisites

    # ── Wizard cấu hình (tiếp bước 3) ────────────
    # Cấu hình theo loại server
    if [[ "$SERVER_TYPE" == "web" ]]; then
        prompt_choices   # PHP version, MariaDB, worker type, email
    else
        # Load balancer: chỉ cần email cho SSL
        echo ""
        read -rp "Admin email [admin@localhost]: " ADMIN_EMAIL
        ADMIN_EMAIL="${ADMIN_EMAIL:-admin@localhost}"
        # LB không cần PHP/DB → ghi N/A vào config.env sau
        PHP_VERSION="N/A"
        DB_VERSION="N/A"
    fi

    # Hỏi ModSecurity (cả 2 loại server)
    prompt_modsecurity

    # Với web server: tính RAM pressure SAU KHI biết đủ thông tin
    # (PHP worker type, ModSecurity) — phải gọi sau prompt_choices + prompt_modsecurity
    if [[ "$SERVER_TYPE" == "web" ]]; then
        check_ram_pressure
    fi

    # ── Bước 4: Swap ──────────────────────────────
    _step 4 10 "Kiểm tra và tạo Swap"
    ensure_swap

    # ── Bước 5: Update + prereqs ──────────────────
    _step 5 10 "Cập nhật hệ thống và cài prerequisites"
    update_system   || warn "System update có lỗi — tiếp tục"
    install_prereqs || warn "Một số prereqs cài thất bại"

    # ── Khởi tạo thư mục làm việc ─────────────────
    # Tạo TRƯỚC setup_security vì hàm đó cần ghi .credentials
    mkdir -p "$INSTALL_DIR" "$BACKUP_DIR"
    : > "$INSTALL_DIR/.credentials"
    chmod 600 "$INSTALL_DIR/.credentials"

    # ── Bước 6: Bảo mật hệ thống ──────────────────
    _step 6 10 "Hardening bảo mật hệ thống"
    setup_security
    setup_server_hardening || warn "Server hardening chưa hoàn tất"

    # ── Bước 7: Cài stack ─────────────────────────
    _step 7 10 "Cài đặt Web Stack / Load Balancer"
    install_nginx_stack  || err "Cài stack thất bại — không thể tiếp tục"
    setup_nginx_global   || warn "Nginx global config có lỗi"

    # ModSecurity WAF
    if [[ "$INSTALL_MODSEC" == "true" ]]; then
        setup_modsecurity || warn "ModSecurity WAF không khả dụng"
    else
        log "Bỏ qua ModSecurity theo yêu cầu"
    fi

    # Restart fail2ban sau khi nginx đã start và log files tồn tại
    # setup_security() chạy trước nginx → fail2ban có thể crash vì thiếu log
    # Restart lại ở đây để đảm bảo tất cả nginx jails active
    if systemctl is-enabled fail2ban &>/dev/null; then
        log "Restart fail2ban sau khi nginx đã start..."
        systemctl restart fail2ban 2>/dev/null             || warn "Fail2ban restart lần 2 thất bại — xem: journalctl -u fail2ban"
    fi

    # I/O scheduler tuning
    tune_io_scheduler || true

    # ── Bước 8: Công cụ quản trị ──────────────────
    _step 8 10 "Cài đặt công cụ quản trị"
    if [[ "$SERVER_TYPE" == "web" ]]; then
        install_tools   || warn "Một số tools cài thất bại"
    else
        log "Bỏ qua phpMyAdmin/elFinder (Load Balancer không cần)"
        # LB: setup nginx stub_status cho header monitoring
        # (đã được setup trong tune_nginx_lb() ở stack.sh)
    fi

    # ── Bước 8b: Cluster Agent (web node only) ───
    if [[ "$SERVER_TYPE" == "web" ]]; then
        setup_mvps_agent || warn "Cluster Agent chưa cài — có thể cài sau bằng: mvps → Cluster"
    fi

    # ── Bước 9: Backup + Menu service ─────────────
    _step 9 10 "Cấu hình Backup và mvps service"
    setup_backup       || warn "Backup setup chưa hoàn tất"
    setup_mvps_service || warn "mvps service setup chưa hoàn tất"

    # ── Bước 10: Hoàn tất ─────────────────────────
    _step 10 10 "Kiểm tra và hoàn tất"

    # Post-install verification
    _post_install_verify || true  # Không dừng dù có component fail

    # Ghi timestamp hoàn tất vào log
    echo "" >> "$LOG_FILE"
    echo "═══════════════════════════════════════" >> "$LOG_FILE"
    echo "ModernVPS v${MVPS_VERSION} install completed: $(date)" >> "$LOG_FILE"
    echo "Server type : ${SERVER_TYPE}" >> "$LOG_FILE"
    echo "OS          : $(. /etc/os-release && echo "$PRETTY_NAME")" >> "$LOG_FILE"
    echo "RAM         : ${TOTAL_RAM_MB}MB | CPU: ${CPU_CORES} cores | Disk: ${DISK_TYPE}" >> "$LOG_FILE"
    echo "═══════════════════════════════════════" >> "$LOG_FILE"

    # Hiển thị thông tin kết nối và credentials
    show_final_info
}

# ── Entrypoint ────────────────────────────────────
# Trap để cleanup nếu script bị interrupt
trap 'echo ""; warn "Cài đặt bị ngắt (signal). Log: $LOG_FILE"' INT TERM

main "$@"
