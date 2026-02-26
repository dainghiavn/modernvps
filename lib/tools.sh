#!/bin/bash
# =====================================================
# tools.sh - Cài đặt công cụ, backup, menu
# ModernVPS v3.2 - Cập nhật: Phase 3+4
# =====================================================

# ══════════════════════════════════════════════════
# SERVER HARDENING (sudoers, logrotate, MOTD)
# ══════════════════════════════════════════════════

setup_server_hardening() {
    log "Server hardening bổ sung..."

    # sudoers: deployer chỉ được chạy đúng các lệnh cần thiết
    # Tách lệnh theo SERVER_TYPE để giảm attack surface
    if [[ "$SERVER_TYPE" == "web" ]]; then
        cat > /etc/sudoers.d/deployer <<EOF
deployer ALL=(ALL) NOPASSWD: \\
    /bin/systemctl restart nginx, \\
    /bin/systemctl reload nginx, \\
    /bin/systemctl status nginx, \\
    /bin/systemctl restart php*-fpm, \\
    /bin/systemctl status php*-fpm, \\
    /bin/systemctl restart mariadb, \\
    /bin/systemctl status mariadb, \\
    /usr/local/bin/mvps, \\
    /usr/local/bin/mvps-backup, \\
    /usr/bin/certbot
EOF
    else
        cat > /etc/sudoers.d/deployer <<EOF
deployer ALL=(ALL) NOPASSWD: \\
    /bin/systemctl restart nginx, \\
    /bin/systemctl reload nginx, \\
    /bin/systemctl status nginx, \\
    /usr/local/bin/mvps, \\
    /usr/local/bin/mvps-backup, \\
    /usr/sbin/nft, \\
    /usr/bin/certbot
EOF
    fi
    chmod 440 /etc/sudoers.d/deployer
    visudo -cf /etc/sudoers.d/deployer 2>/dev/null || {
        warn "sudoers không hợp lệ — revert"
        rm -f /etc/sudoers.d/deployer
    }

    # Auto updates
    if [[ "$OS_FAMILY" == "debian" ]]; then
        pkg_install unattended-upgrades 2>/dev/null || true
        systemctl enable unattended-upgrades 2>/dev/null || true
    elif [[ "$OS_FAMILY" == "rhel" ]]; then
        pkg_install dnf-automatic 2>/dev/null || true
        systemctl enable --now dnf-automatic.timer 2>/dev/null || true
    fi

    # Disable services không cần thiết
    local unused=(avahi-daemon cups postfix sendmail whoopsie bluetooth)
    for svc in "${unused[@]}"; do
        systemctl disable --now "$svc" 2>/dev/null || true
    done

    # ClamAV update
    command -v freshclam &>/dev/null && { freshclam --quiet 2>/dev/null || true; }

    # Process accounting
    systemctl enable --now psacct 2>/dev/null \
        || systemctl enable --now acct 2>/dev/null || true

    # Logrotate
    cat > /etc/logrotate.d/modernvps <<'EOF'
/var/log/modernvps/*.log {
    weekly
    missingok
    rotate 12
    compress
    notifempty
}
/var/log/nginx/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        [ -f /run/nginx.pid ] && kill -USR1 $(cat /run/nginx.pid) 2>/dev/null || true
    endscript
}
EOF

    # MOTD — hiển thị header rút gọn khi SSH vào
    # Format thống nhất với render_header_web/lb trong menu
    cat > /etc/update-motd.d/99-modernvps <<'MOTDEOF'
#!/bin/bash
source /opt/modernvps/config.env 2>/dev/null || true

# Thu thập dữ liệu từ /proc (0 fork)
read -r _up _  < /proc/uptime 2>/dev/null
_ud=$(awk -v s="${_up:-0}" 'BEGIN{printf "%dd%dh",s/86400,(s%86400)/3600}')
_h=$(hostname -s 2>/dev/null || echo "unknown")
read -r _rm _rt < <(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{printf "%d %d",(t-a)/1024,t/1024}' /proc/meminfo 2>/dev/null)
read -r _load _ < /proc/loadavg 2>/dev/null
_disk=$(df -h / 2>/dev/null | awk 'NR==2{print $5}')

# Service icons
_si() { systemctl is-active "$1" &>/dev/null && echo "✅" || echo "❌"; }
_ni() { [[ "$1" == "active" ]] && echo "✅" || echo "❌"; }

echo "═══════════════════════════════════════════"
printf "  ModernVPS v3.2 (%s) | %s | Up %s\n" "${SERVER_TYPE:-unknown}" "$_h" "$_ud"
printf "  CPU: %-4s | RAM: %s/%sMB | DSK: %s\n" "$_load" "${_rm:-?}" "${_rt:-?}" "${_disk:-?}"
if [[ "${SERVER_TYPE:-}" == "web" ]]; then
    _waf="❌"; grep -q 'modsecurity on' /etc/nginx/nginx.conf 2>/dev/null && _waf="✅"
    printf "  Nginx %s | PHP %s | DB %s | F2B %s | WAF %s\n" \
        "$(_si nginx)" "$(_si "php${PHP_VERSION:-8.3}-fpm" 2>/dev/null || _si php-fpm)" \
        "$(_si mariadb)" "$(_si fail2ban)" "$_waf"
    _sites=$(ls /etc/nginx/sites-enabled/ 2>/dev/null | grep -v '^\.' | wc -l)
    printf "  Sites: %s | sudo mvps để quản trị\n" "$_sites"
else
    _nft="❌"; nft list tables 2>/dev/null | grep -q modernvps && _nft="✅"
    printf "  Nginx %s | F2B %s | NFT %s\n" \
        "$(_si nginx)" "$(_si fail2ban)" "$_nft"
    printf "  sudo mvps để quản trị load balancer\n"
fi
echo "═══════════════════════════════════════════"
MOTDEOF
    chmod +x /etc/update-motd.d/99-modernvps
    log "Server hardening bổ sung hoàn tất"
}

# ══════════════════════════════════════════════════
# INSTALL TOOLS (phpMyAdmin, elFinder) — web only
# Fix: verify phpMyAdmin checksum trước khi extract
# Fix: elFinder uploadAllow bỏ application/zip (zip slip risk)
# ══════════════════════════════════════════════════

install_tools() {
    [[ "$SERVER_TYPE" != "web" ]] && return 0

    log "Cài phpMyAdmin + elFinder (port $PANEL_PORT)..."
    local TOOLS_PASS
    TOOLS_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c16)
    htpasswd -bc /etc/nginx/.htpasswd admin "$TOOLS_PASS" 2>/dev/null

    _install_phpmyadmin
    _install_elfinder

    # Nginx vhost cho panel
    local sock; sock=$(get_php_fpm_sock)
    cat > /etc/nginx/sites-available/tools-panel <<EOF
server {
    listen ${PANEL_PORT};
    server_name _;
    root /var/www/html;
    index index.php index.html;

    auth_basic "ModernVPS Admin";
    auth_basic_user_file /etc/nginx/.htpasswd;

    limit_req  zone=req_limit burst=10 nodelay;
    limit_conn zone=conn_limit 5;

    location ~ \\.php\$ {
        try_files \$uri =404;
        fastcgi_pass unix:${sock};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
    }
    location ~ /\\. { deny all; }
    access_log /var/log/nginx/panel-access.log;
    error_log  /var/log/nginx/panel-error.log warn;
}
EOF
    ln -sf /etc/nginx/sites-available/tools-panel \
           /etc/nginx/sites-enabled/tools-panel
    nginx_safe_reload

    {
        echo "TOOLS_USER=admin"
        echo "TOOLS_PASS=${TOOLS_PASS}"
        echo "PANEL_PORT=${PANEL_PORT}"
    } >> "${INSTALL_DIR}/.credentials"
    chmod 600 "${INSTALL_DIR}/.credentials"
    log "Tools: admin / ${TOOLS_PASS} (port ${PANEL_PORT})"
}

_install_phpmyadmin() {
    [[ -d "/var/www/html/pma" ]] && return 0

    local PMA_VER="5.2.1"
    local PMA_URL="https://files.phpmyadmin.net/phpMyAdmin/${PMA_VER}/phpMyAdmin-${PMA_VER}-all-languages.tar.gz"
    local PMA_SHA256_URL="https://files.phpmyadmin.net/phpMyAdmin/${PMA_VER}/phpMyAdmin-${PMA_VER}-all-languages.tar.gz.sha256"
    local PMA_TGZ="/tmp/pma-${PMA_VER}.tar.gz"

    log "Tải phpMyAdmin ${PMA_VER}..."
    wget -q -O "$PMA_TGZ" "$PMA_URL" || { warn "Tải phpMyAdmin thất bại"; return 1; }

    # Verify checksum — tránh supply chain attack
    local expected_sha actual_sha
    expected_sha=$(wget -qO- "$PMA_SHA256_URL" 2>/dev/null | awk '{print $1}')
    actual_sha=$(sha256sum "$PMA_TGZ" | awk '{print $1}')
    if [[ -n "$expected_sha" && "$expected_sha" != "$actual_sha" ]]; then
        warn "phpMyAdmin checksum không khớp! Bỏ qua cài đặt."
        rm -f "$PMA_TGZ"
        return 1
    fi

    tar -xzf "$PMA_TGZ" -C /tmp/
    mv "/tmp/phpMyAdmin-${PMA_VER}-all-languages" /var/www/html/pma
    rm -f "$PMA_TGZ"

    # Config
    local PMA_SECRET; PMA_SECRET=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c32)
    cp /var/www/html/pma/config.sample.inc.php /var/www/html/pma/config.inc.php
    sed -i "s/\\\$cfg\['blowfish_secret'\] = ''/\\\$cfg['blowfish_secret'] = '${PMA_SECRET}'/" \
        /var/www/html/pma/config.inc.php
    cat >> /var/www/html/pma/config.inc.php <<'PMAEOF'
$cfg['TempDir'] = './tmp/';
$cfg['LoginCookieValidity'] = 1800;
$cfg['DefaultLang'] = 'vi';
PMAEOF

    mkdir -p /var/www/html/pma/tmp
    chown -R "${NGINX_USER}:${NGINX_USER}" /var/www/html/pma
    find /var/www/html/pma -type d -exec chmod 755 {} \;
    find /var/www/html/pma -type f -exec chmod 644 {} \;
    chmod 755 /var/www/html/pma/tmp
    log "phpMyAdmin ${PMA_VER} đã cài"
}

_install_elfinder() {
    [[ -f "/var/www/html/filemanager/elfinder.html" ]] && return 0
    rm -rf /var/www/html/filemanager

    log "Tải elFinder..."
    git clone --quiet --depth 1 --branch 2.1.62 \
    	https://github.com/Studio-42/elFinder.git \
    	/var/www/html/filemanager 2>/dev/null || {
    	mkdir -p /var/www/html/filemanager
    	wget -q -O /tmp/elfinder.tar.gz \
        	"https://github.com/Studio-42/elFinder/archive/refs/tags/2.1.62.tar.gz" \
        	2>/dev/null || { warn "Tải elFinder thất bại"; return 1; }
    	tar -xzf /tmp/elfinder.tar.gz --strip-components=1 \
        	-C /var/www/html/filemanager/
    	rm -f /tmp/elfinder.tar.gz
     }

    [[ ! -f "/var/www/html/filemanager/elfinder.html" ]] && {
        warn "elFinder không cài được — bỏ qua"
        return 1
    }

    # connector.minimal.php — Fix: bỏ application/zip (zip slip risk)
    cat > /var/www/html/filemanager/php/connector.minimal.php <<'CONNEOF'
<?php
error_reporting(0);
require './autoload.php';
$opts = [
    'roots' => [[
        'driver'        => 'LocalFileSystem',
        'path'          => '/var/www/',
        'URL'           => '/',
        // Chỉ cho phép upload ảnh và text — không cho zip (zip slip risk)
        'uploadDeny'    => ['all'],
        'uploadAllow'   => ['image', 'text/plain'],
        'uploadOrder'   => ['deny', 'allow'],
        'accessControl' => 'access',
        'uploadMaxSize' => '10M',
    ]]
];
function access($attr, $path, $data, $volume, $isDir, $relpath) {
    return strpos(basename($path), '.') === 0
        ? !($attr == 'read' || $attr == 'write')
        : null;
}
$connector = new elFinderConnector(new elFinder($opts));
$connector->run();
CONNEOF

    echo '<?php header("Location: elfinder.html"); exit; ?>' \
        > /var/www/html/filemanager/index.php
    chown -R "${NGINX_USER}:${NGINX_USER}" /var/www/html/filemanager
    find /var/www/html/filemanager -type d -exec chmod 755 {} \;
    find /var/www/html/filemanager -type f -exec chmod 644 {} \;
    log "elFinder đã cài"
}

# ══════════════════════════════════════════════════
# BACKUP SETUP
# Cải tiến: thêm backup /etc/nginx/conf.d/ cho LB,
# backup script kiểm tra SERVER_TYPE
# ══════════════════════════════════════════════════

setup_backup() {
    log "Cấu hình backup..."
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"

    # age: mã hoá backup end-to-end
    command -v age &>/dev/null || pkg_install age 2>/dev/null || true
    if command -v age-keygen &>/dev/null && [[ ! -f "${INSTALL_DIR}/.backup-key.txt" ]]; then
        age-keygen -o "${INSTALL_DIR}/.backup-key.txt" 2>/dev/null || true
        chmod 600 "${INSTALL_DIR}/.backup-key.txt" 2>/dev/null || true
        grep "public key:" "${INSTALL_DIR}/.backup-key.txt" \
            | awk '{print $NF}' > "${INSTALL_DIR}/.backup-pubkey.txt" 2>/dev/null || true
        warn "BACKUP KEY: ${INSTALL_DIR}/.backup-key.txt — SAO LƯU RA NGOÀI NGAY!"
    fi

    # Viết backup script — không dùng biến từ installer,
    # đọc config.env runtime để hoạt động khi chạy qua cron
    cat > /usr/local/bin/mvps-backup <<'BKEOF'
#!/bin/bash
set -uo pipefail
source /opt/modernvps/config.env 2>/dev/null || {
    echo "[ERROR] Không đọc được config.env" >&2; exit 1
}
BACKUP_DIR="${BACKUP_DIR:-/backup}"
TODAY=$(date +%Y%m%d_%H%M)
LOG="/var/log/modernvps/backup.log"
mkdir -p "$BACKUP_DIR"

echo "$(date): Bắt đầu backup (${SERVER_TYPE})" >> "$LOG"

# Compressor: pigz nhanh hơn gzip nếu có
COMPRESS="gzip -6"
command -v pigz &>/dev/null && COMPRESS="pigz -6 -p 2"

# Backup DB — chỉ khi web server và mysql khả dụng
if [[ "${SERVER_TYPE:-}" == "web" ]] && command -v mysqldump &>/dev/null; then
    mysqldump -u root --single-transaction --quick --all-databases 2>/dev/null \
        | $COMPRESS > "${BACKUP_DIR}/db-${TODAY}.sql.gz" \
        && echo "$(date): DB backup OK" >> "$LOG" \
        || echo "$(date): DB backup FAILED" >> "$LOG"
fi

# Backup Nginx config (cả hai loại server)
tar cf - \
    /etc/nginx/sites-enabled/ \
    /etc/nginx/conf.d/ \
    /etc/nginx/snippets/ \
    /opt/modernvps/ \
    2>/dev/null \
    | $COMPRESS > "${BACKUP_DIR}/nginx-conf-${TODAY}.tar.gz" \
    && echo "$(date): nginx-conf backup OK" >> "$LOG"

# Backup webroot — chỉ cho web server
if [[ "${SERVER_TYPE:-}" == "web" ]] && [[ -d /var/www ]]; then
    tar cf - /var/www/ 2>/dev/null \
        | $COMPRESS > "${BACKUP_DIR}/web-${TODAY}.tar.gz" \
        && echo "$(date): web backup OK" >> "$LOG"
fi

# Mã hoá bằng age nếu có public key
if command -v age &>/dev/null && [[ -f "${INSTALL_DIR}/.backup-pubkey.txt" ]]; then
    pubkey=$(cat "${INSTALL_DIR}/.backup-pubkey.txt")
    for f in "${BACKUP_DIR}/"*-"${TODAY}"*.gz; do
        [[ -f "$f" ]] || continue
        age -r "$pubkey" -o "${f}.age" "$f" \
            && rm -f "$f" \
            && echo "$(date): Encrypted: $(basename "$f")" >> "$LOG"
    done
fi

# Dọn backup cũ > 7 ngày
find "$BACKUP_DIR" -name "*.gz" -mtime +7 -delete 2>/dev/null
find "$BACKUP_DIR" -name "*.age" -mtime +7 -delete 2>/dev/null
echo "$(date): Backup hoàn tất" >> "$LOG"
BKEOF
    chmod +x /usr/local/bin/mvps-backup

    # Cron: 1AM mỗi ngày
    cat > /etc/cron.d/modernvps-backup <<'EOF'
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 1 * * * root /usr/local/bin/mvps-backup
EOF

    # Setup certbot auto-renew (web server)
    if [[ "$SERVER_TYPE" == "web" ]] && command -v certbot &>/dev/null; then
        # certbot renew cronjob nếu chưa có
        # Fix: check /etc/cron.d (system crontab) thay vì crontab -l (user crontab)
        if ! grep -q certbot /etc/cron.d/modernvps-backup 2>/dev/null; then
            cat >> /etc/cron.d/modernvps-backup <<'EOF'
0 3 * * 1 root certbot renew --quiet --post-hook "systemctl reload nginx"
EOF
        fi
    fi

    log "Backup: daily 1AM | /usr/local/bin/mvps-backup"
}

# ══════════════════════════════════════════════════
# SETUP MVPS SERVICE
# Tạo config.env, health check script (LB),
# WP-CLI (web), và menu phù hợp
# ══════════════════════════════════════════════════

setup_mvps_service() {
    log "Cài đặt mvps service và menu..."
    mkdir -p "$INSTALL_DIR"

    # config.env — runtime config cho menu và backup script
    cat > "${INSTALL_DIR}/config.env" <<EOF
PHP_VERSION=${PHP_VERSION}
DB_VERSION=${DB_VERSION}
PHP_WORKER_TYPE=${PHP_WORKER_TYPE:-wordpress}
ADMIN_EMAIL=${ADMIN_EMAIL}
BACKUP_DIR=${BACKUP_DIR}
OS_FAMILY=${OS_FAMILY}
NGINX_USER=${NGINX_USER}
PANEL_PORT=${PANEL_PORT}
TOTAL_RAM_MB=${TOTAL_RAM_MB}
CPU_CORES=${CPU_CORES}
DISK_TYPE=${DISK_TYPE}
VIRT_TYPE=${VIRT_TYPE}
INSTALL_DIR=${INSTALL_DIR}
SERVER_TYPE=${SERVER_TYPE}
INSTALL_MODSEC=${INSTALL_MODSEC}
EOF
    chmod 600 "${INSTALL_DIR}/config.env"

    # Cài WP-CLI cho web server
    if [[ "$SERVER_TYPE" == "web" ]]; then
        _install_wpcli
    fi

    # Setup health check script cho LB
    if [[ "$SERVER_TYPE" == "loadbalancer" ]]; then
        _setup_lb_healthcheck
    fi

    # Tạo menu theo SERVER_TYPE
    if [[ "$SERVER_TYPE" == "web" ]]; then
        _create_menu_web
    else
        _create_menu_lb
        _setup_metrics_collector
    fi

    # mvps command wrapper
    cat > /usr/local/bin/mvps <<'CMDEOF'
#!/bin/bash
[[ $EUID -ne 0 ]] && { echo "Dùng: sudo mvps"; exit 1; }
exec bash /opt/modernvps/menu.sh
CMDEOF
    chmod +x /usr/local/bin/mvps

    # Cài mvps-cluster (chỉ trên LB)
    if [[ "$SERVER_TYPE" == "loadbalancer" ]]; then
        _install_mvps_cluster
    fi

    # Token rotation cron (cả LB và Web node)
    _setup_token_rotation_cron

    # systemd service — đánh dấu ModernVPS đã ready
    cat > /etc/systemd/system/modernvps.service <<'SVCEOF'
[Unit]
Description=ModernVPS v3.2
After=network.target nginx.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/bash -c 'echo "ModernVPS ready $(date)" > /run/modernvps.ready'
ExecStop=/bin/rm -f /run/modernvps.ready

[Install]
WantedBy=multi-user.target
SVCEOF
    systemctl daemon-reload
    systemctl enable modernvps.service 2>/dev/null || true
    log "mvps command sẵn sàng: sudo mvps"
}

_install_wpcli() {
    command -v wp &>/dev/null && { log "WP-CLI đã có"; return 0; }
    log "Cài WP-CLI..."
    local wpcli_url="https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar"
    if wget -q -O /usr/local/bin/wp "$wpcli_url" 2>/dev/null; then
        chmod +x /usr/local/bin/wp
        # Verify
        php /usr/local/bin/wp --info --allow-root &>/dev/null \
            && log "WP-CLI đã cài" \
            || { warn "WP-CLI verify thất bại — xóa"; rm -f /usr/local/bin/wp; }
    else
        warn "WP-CLI tải thất bại — WordPress auto-install sẽ tự cài khi cần"
    fi
}

# Health check script cho Load Balancer
# Chạy qua cron 30s, ghi kết quả vào backend-status.json
# Menu header đọc file này để hiển thị realtime status
_setup_lb_healthcheck() {
    log "Cài health check script cho LB..."
    mkdir -p "${INSTALL_DIR}"

    cat > /usr/local/bin/mvps-healthcheck <<'HCEOF'
#!/bin/bash
# ModernVPS LB Health Check
# Chạy mỗi 30s qua cron — kiểm tra HTTP backends
set -uo pipefail
INSTALL_DIR="/opt/modernvps"
UPSTREAM_CONF="/etc/nginx/conf.d/upstream.conf"
STATUS_FILE="${INSTALL_DIR}/backend-status.json"
INVENTORY="${INSTALL_DIR}/backends.json"
TIMEOUT=5

# Đọc danh sách backends từ inventory (nếu có) hoặc parse upstream.conf
declare -a BACKENDS=()
if [[ -f "$INVENTORY" ]] && command -v jq &>/dev/null; then
    mapfile -t BACKENDS < <(
        jq -r '.backends[] | "\(.ip):\(.port):\(.label // .ip)"' "$INVENTORY" 2>/dev/null
    )
elif [[ -f "$UPSTREAM_CONF" ]]; then
    # Parse dạng: server IP:PORT weight=...
    while IFS= read -r line; do
        if [[ "$line" =~ ^[[:space:]]*server[[:space:]]+([0-9.]+):([0-9]+) ]]; then
            _ip="${BASH_REMATCH[1]}"
            _port="${BASH_REMATCH[2]}"
            BACKENDS+=("${_ip}:${_port}:${_ip}")
        fi
    done < "$UPSTREAM_CONF"
fi

# ── Gap #3 Fix: Merge nodes từ cluster.json vào danh sách check ──
# Healthcheck chỉ đọc backends.json (inventory Nginx thủ công)
# Nodes join qua mvps-cluster không tự xuất hiện ở đây → monitor miss
# Fix: đọc thêm cluster.json, thêm node nếu chưa có trong BACKENDS
CLUSTER_JSON="/opt/modernvps/cluster.json"
if [[ -f "$CLUSTER_JSON" ]] && command -v jq &>/dev/null; then
    while IFS='|' read -r cid cip; do
        [[ -z "$cid" || -z "$cip" ]] && continue
        # Chỉ thêm nếu IP chưa có trong BACKENDS (tránh duplicate)
        # Fix C2: 'local' không hợp lệ ngoài function — dùng biến bình thường
        _already=false
        for _b in "${BACKENDS[@]:-}"; do
            [[ "$_b" == "${cip}:"* ]] && { _already=true; break; }
        done
        if [[ "$_already" == "false" ]]; then
            BACKENDS+=("${cip}:80:${cid}")
        fi
    done < <(jq -r '.nodes[] | "\(.id)|\(.internal_ip)"' "$CLUSTER_JSON" 2>/dev/null)
fi

[[ ${#BACKENDS[@]} -eq 0 ]] && exit 0

# Check từng backend
# Fix #1: bỏ local (top-level script, không có function)
# Fix #2: track changed để chỉ reload khi cần
# Fix #3: sửa sed restore pattern MVPS_DOWN
declare -a results=()
changed=false
for entry in "${BACKENDS[@]}"; do
    IFS=: read -r ip port label <<< "$entry"
    start_ms=$(date +%s%3N)
    http_code=$(curl -sf --max-time "$TIMEOUT" \
        -o /dev/null -w "%{http_code}" \
        "http://${ip}:${port}/" 2>/dev/null || echo "000")
    end_ms=$(date +%s%3N)
    latency=$(( end_ms - start_ms ))

    status="UP"
    [[ "$http_code" == "000" || "$http_code" -ge 500 ]] && status="DOWN"

    results+=("{\"ip\":\"${ip}\",\"port\":${port},\"label\":\"${label}\",\"status\":\"${status}\",\"http_code\":${http_code},\"latency_ms\":${latency},\"last_check\":\"$(date -Iseconds)\"}")

    # Auto comment/uncomment trong upstream.conf khi trạng thái thay đổi
    if [[ -f "$UPSTREAM_CONF" ]]; then
        if [[ "$status" == "DOWN" ]]; then
            # Comment out backend DOWN — capture toàn bộ server line vào group \1
            if sed -i "s|^\([[:space:]]*server ${ip}:${port}[^;]*;\)|    # MVPS_DOWN \1|" \
                "$UPSTREAM_CONF" 2>/dev/null; then
                changed=true
            fi
        else
            # Fix #3: restore — pattern dùng group \1 bao quanh server line
            if sed -i "s|^[[:space:]]*# MVPS_DOWN \(.*server ${ip}:${port}[^;]*;\)|\1|" \
                "$UPSTREAM_CONF" 2>/dev/null; then
                changed=true
            fi
        fi
    fi
done

# Ghi status JSON
json_backends=$(IFS=,; echo "${results[*]}")
printf '{"updated":"%s","backends":[%s]}\n' \
    "$(date -Iseconds)" "$json_backends" > "$STATUS_FILE"

# Fix #2: chỉ reload nginx khi có thay đổi trạng thái backend
if [[ "$changed" == "true" ]] && nginx -t &>/dev/null; then
    systemctl reload nginx 2>/dev/null || true
fi
HCEOF
    chmod +x /usr/local/bin/mvps-healthcheck

    # Cron mỗi phút (minimum cron interval = 1 phút)
    # Script sẽ chạy nhanh < 5s × số backend
    cat >> /etc/cron.d/modernvps-backup <<'EOF'
* * * * * root /usr/local/bin/mvps-healthcheck
EOF

    # Khởi tạo inventory file
    [[ ! -f "${INSTALL_DIR}/backends.json" ]] && \
        echo '{"backends":[]}' > "${INSTALL_DIR}/backends.json"

    log "Health check: /usr/local/bin/mvps-healthcheck (cron mỗi phút)"
}

# ══════════════════════════════════════════════════
# MENU WEB SERVER
# Tính năng mới: list sites, SSL manager, PHP-FPM pool,
# WordPress install, log analysis, SFTP users,
# OPcache status, DB extended
# ══════════════════════════════════════════════════

_create_menu_web() {
    log "Tạo menu Web Server..."
    cat > "${INSTALL_DIR}/menu.sh" <<'MENUEOF'
#!/bin/bash
# ModernVPS v3.2 Menu - Web Server
set -uo pipefail
source /opt/modernvps/config.env 2>/dev/null || { echo "Config missing!"; exit 1; }

# ── Màu sắc ─────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }
err()  { echo -e "${RED}[ERR]${NC}   $1"; }

# ── Helper functions ─────────────────────────────
get_php_fpm_svc()  {
    case "$OS_FAMILY" in
        debian) echo "php${PHP_VERSION}-fpm" ;; rhel) echo "php-fpm" ;;
    esac
}
get_php_fpm_sock() {
    case "$OS_FAMILY" in
        debian) echo "/run/php/php${PHP_VERSION}-fpm.sock" ;; rhel) echo "/run/php-fpm/www.sock" ;;
    esac
}
get_php_pool_dir() {
    case "$OS_FAMILY" in
        debian) echo "/etc/php/${PHP_VERSION}/fpm/pool.d" ;; rhel) echo "/etc/php-fpm.d" ;;
    esac
}
nginx_safe_reload() {
    nginx -t &>/dev/null \
        && { systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null; } \
        || { warn "nginx config lỗi — xem: nginx -t"; nginx -t; }
}
sanitize_domain() {
    local d="${1:-}"
    [[ -z "$d" ]] && return 1
    [[ ! "$d" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] && { warn "Domain không hợp lệ: $d"; return 1; }
    printf '%s' "$d"
}
sanitize_input() {
    local v="${1:-}"
    [[ -z "$v" ]] && return 1
    [[ ! "$v" =~ ^[a-zA-Z0-9._:/@-]+$ ]] && { warn "Input không hợp lệ: $v"; return 1; }
    [[ "$v" == *".."* ]] && { warn "Path traversal: $v"; return 1; }
    printf '%s' "$v"
}
validate_ip() { [[ "${1:-}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; }
press_enter() { echo ""; read -rp "Enter để tiếp tục..."; }

# ════════════════════════════════════════════════
# SITES MANAGEMENT
# ════════════════════════════════════════════════

do_list_sites() {
    echo ""
    echo -e "${BOLD}── Danh sách Sites ──────────────────────────${NC}"
    printf "%-30s %-6s %-20s %-10s\n" "DOMAIN" "SSL" "PHP POOL" "DISK"
    echo "────────────────────────────────────────────────────────"
    for vhost in /etc/nginx/sites-enabled/*; do
        [[ -f "$vhost" ]] || continue
        local domain; domain=$(basename "$vhost")
        [[ "$domain" == "tools-panel" ]] && continue

        # SSL expiry
        local ssl_info="no SSL"
        local cert_path="/etc/letsencrypt/live/${domain}/fullchain.pem"
        if [[ -f "$cert_path" ]]; then
            local exp_date; exp_date=$(openssl x509 -noout -enddate -in "$cert_path" 2>/dev/null | cut -d= -f2)
            local exp_ts;   exp_ts=$(date -d "$exp_date" +%s 2>/dev/null || echo 0)
            local now_ts;   now_ts=$(date +%s)
            local days_left=$(( (exp_ts - now_ts) / 86400 ))
            if (( days_left <= 7 )); then
                ssl_info="${RED}${days_left}d URGENT${NC}"
            elif (( days_left <= 30 )); then
                ssl_info="${YELLOW}${days_left}d${NC}"
            else
                ssl_info="${GREEN}${days_left}d${NC}"
            fi
        fi

        # PHP pool
        local pool_name="shared"
        local safe_name; safe_name=$(echo "$domain" | tr '.' '_' | tr '-' '_' | head -c30)
        [[ -f "$(get_php_pool_dir)/${safe_name}.conf" ]] && pool_name="$safe_name"

        # Disk
        local disk="N/A"
        [[ -d "/var/www/${domain}" ]] && disk=$(du -sh "/var/www/${domain}" 2>/dev/null | cut -f1)

        printf "%-30s %-6b %-20s %-10s\n" "$domain" "$ssl_info" "$pool_name" "$disk"
    done
    echo ""
}

do_create_site() {
    echo ""
    read -rp "Domain: " DOMAIN
    DOMAIN=$(sanitize_domain "$DOMAIN") || return
    read -rp "Webroot [/var/www/$DOMAIN]: " ROOT
    ROOT="${ROOT:-/var/www/${DOMAIN}}"
    read -rp "PHP version [${PHP_VERSION}]: " SITE_PHP
    SITE_PHP="${SITE_PHP:-${PHP_VERSION}}"
    read -rp "Isolated PHP-FPM pool? (y/n) [y]: " ISO_FPM
    ISO_FPM="${ISO_FPM:-y}"

    local site_user="${NGINX_USER}"
    local sock; sock=$(get_php_fpm_sock)

    if [[ "$ISO_FPM" == "y" ]]; then
        local safe_name; safe_name=$(echo "$DOMAIN" | tr '.' '_' | tr '-' '_' | head -c30)
        site_user="web_${safe_name}"
        id "$site_user" &>/dev/null || {
            useradd -r -M -s /usr/sbin/nologin -d "$ROOT" "$site_user" 2>/dev/null || true
            usermod -aG "$site_user" "$NGINX_USER" 2>/dev/null || true
        }
        local pool_dir
        case "$OS_FAMILY" in
            debian) pool_dir="/etc/php/${SITE_PHP}/fpm/pool.d" ;;
            rhel)   pool_dir="/etc/php-fpm.d" ;;
        esac
        sock="/run/php/php-${safe_name}.sock"
        cat > "${pool_dir}/${safe_name}.conf" <<POOLEOF
[${safe_name}]
user  = ${site_user}
group = ${site_user}
listen       = ${sock}
listen.owner = ${NGINX_USER}
listen.group = ${NGINX_USER}
listen.mode  = 0660
pm                   = ondemand
pm.max_children      = 10
pm.process_idle_timeout = 10s
pm.max_requests      = 500
php_admin_flag[log_errors]          = on
php_admin_value[error_log]          = /var/log/php-fpm-${safe_name}.log
php_admin_value[open_basedir]       = ${ROOT}:/tmp:/usr/share
php_admin_value[sys_temp_dir]       = /tmp
php_admin_value[upload_tmp_dir]     = /tmp
security.limit_extensions           = .php
POOLEOF
        systemctl restart "$(get_php_fpm_svc)" 2>/dev/null || true
        log "PHP-FPM pool: ${safe_name} → ${sock}"
    fi

    mkdir -p "$ROOT"
    cat > "${ROOT}/index.html" <<HTMLEOF
<!DOCTYPE html><html><head><title>${DOMAIN}</title></head>
<body><h1>${DOMAIN}</h1><p>ModernVPS — Ready!</p></body></html>
HTMLEOF
    chown -R "${site_user}:${site_user}" "$ROOT"
    find "$ROOT" -type d -exec chmod 750 {} \;
    find "$ROOT" -type f -exec chmod 640 {} \;

    cat > "/etc/nginx/sites-available/${DOMAIN}" <<VEOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};
    root ${ROOT};
    index index.php index.html;

    limit_req  zone=req_limit burst=30 nodelay;
    limit_conn zone=conn_limit 50;

    include /etc/nginx/snippets/security.conf;
    include /etc/nginx/snippets/static-cache.conf;

    location / { try_files \$uri \$uri/ /index.php?\$query_string; }

    location ~ \\.php\$ {
        try_files \$uri =404;
        fastcgi_pass unix:${sock};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_hide_header X-Powered-By;
        include /etc/nginx/snippets/fastcgi-cache.conf;
    }
    location ~ /\\. { deny all; }

    access_log /var/log/nginx/${DOMAIN}-access.log;
    error_log  /var/log/nginx/${DOMAIN}-error.log warn;
}
VEOF
    ln -sf "/etc/nginx/sites-available/${DOMAIN}" \
           "/etc/nginx/sites-enabled/${DOMAIN}"
    nginx_safe_reload

    # SSL
    read -rp "Cấp SSL ngay? (y/n) [n]: " DOSSL
    if [[ "${DOSSL:-n}" == "y" ]]; then
        certbot --nginx -d "$DOMAIN" -d "www.${DOMAIN}" \
            --email "$ADMIN_EMAIL" --agree-tos --non-interactive 2>/dev/null \
            || warn "SSL thất bại — thử lại sau bằng option SSL manager"
        nginx_safe_reload
    fi

    # WordPress
    read -rp "Cài WordPress? (y/n) [n]: " DOWP
    [[ "${DOWP:-n}" == "y" ]] && do_wordpress_install "$DOMAIN" "$ROOT" "$site_user"

    log "Site ${DOMAIN} sẵn sàng! (FPM: $([ "$ISO_FPM" == "y" ] && echo isolated || echo shared))"
}

do_delete_site() {
    echo ""
    do_list_sites
    read -rp "Domain cần xóa: " DOMAIN
    DOMAIN=$(sanitize_domain "$DOMAIN") || return

    read -rp "Xác nhận xóa site '${DOMAIN}'? (yes/no): " CONFIRM
    [[ "$CONFIRM" != "yes" ]] && { warn "Đã hủy"; return; }

    rm -f "/etc/nginx/sites-enabled/${DOMAIN}" \
          "/etc/nginx/sites-available/${DOMAIN}"
    nginx_safe_reload

    # Xóa PHP-FPM pool
    local safe_name; safe_name=$(echo "$DOMAIN" | tr '.' '_' | tr '-' '_' | head -c30)
    local pool_file; pool_file="$(get_php_pool_dir)/${safe_name}.conf"
    if [[ -f "$pool_file" ]]; then
        rm -f "$pool_file"
        systemctl restart "$(get_php_fpm_svc)" 2>/dev/null || true
        userdel "web_${safe_name}" 2>/dev/null || true
        log "Đã xóa isolated pool: ${safe_name}"
    fi

    # Xóa SSL cert
    read -rp "Xóa SSL cert? (y/n) [n]: " DELSSL
    [[ "${DELSSL:-n}" == "y" ]] && \
        certbot delete --cert-name "$DOMAIN" --non-interactive 2>/dev/null \
        && log "SSL cert đã xóa"

    # Xóa webroot
    read -rp "Xóa webroot /var/www/${DOMAIN}? (y/n) [n]: " DELROOT
    [[ "${DELROOT:-n}" == "y" ]] && rm -rf "/var/www/${DOMAIN}" \
        && log "Webroot đã xóa"

    log "Site ${DOMAIN} đã xóa hoàn toàn"
}

# ════════════════════════════════════════════════
# WORDPRESS AUTO INSTALL
# ════════════════════════════════════════════════

do_wordpress_install() {
    local DOMAIN="${1:-}"
    local ROOT="${2:-}"
    local SITE_USER="${3:-${NGINX_USER}}"

    # Nếu gọi từ menu (không có arg) → hỏi domain
    if [[ -z "$DOMAIN" ]]; then
        echo ""
        do_list_sites
        read -rp "Domain cần cài WordPress: " DOMAIN
        DOMAIN=$(sanitize_domain "$DOMAIN") || return
        ROOT="/var/www/${DOMAIN}"
        # Tìm site_user từ pool
        local safe_name; safe_name=$(echo "$DOMAIN" | tr '.' '_' | tr '-' '_' | head -c30)
        id "web_${safe_name}" &>/dev/null && SITE_USER="web_${safe_name}"
    fi

    [[ ! -d "$ROOT" ]] && { warn "Webroot ${ROOT} chưa tồn tại — tạo site trước"; return 1; }

    # Đảm bảo WP-CLI có sẵn
    if ! command -v wp &>/dev/null; then
        log "Cài WP-CLI..."
        wget -q -O /usr/local/bin/wp \
            "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar" \
            && chmod +x /usr/local/bin/wp || { warn "Không cài được WP-CLI"; return 1; }
    fi

    # Thu thập thông tin
    read -rp "Site title [${DOMAIN}]: " WP_TITLE
    WP_TITLE="${WP_TITLE:-${DOMAIN}}"
    read -rp "Admin username [wpadmin]: " WP_ADMIN
    WP_ADMIN="${WP_ADMIN:-wpadmin}"
    read -rp "Admin email [${ADMIN_EMAIL}]: " WP_EMAIL
    WP_EMAIL="${WP_EMAIL:-${ADMIN_EMAIL}}"
    local WP_PASS; WP_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9!@#$' | head -c16)

    # Tạo DB cho WordPress
    local DB_NAME; DB_NAME="wp_$(echo "$DOMAIN" | tr '.' '_' | tr '-' '_' | head -c20)"
    local DB_USER; DB_USER="wp_$(openssl rand -hex 4)"
    local DB_PASS; DB_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c20)
    mysql -u root <<SQL 2>/dev/null || { warn "Tạo database thất bại"; return 1; }
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
FLUSH PRIVILEGES;
SQL

    log "Tải WordPress core..."
    sudo -u "$SITE_USER" wp core download \
        --path="$ROOT" --locale=vi --allow-root --quiet 2>/dev/null \
        || wp core download --path="$ROOT" --allow-root --quiet 2>/dev/null \
        || { warn "Tải WordPress thất bại"; return 1; }

    sudo -u "$SITE_USER" wp config create \
        --path="$ROOT" \
        --dbname="$DB_NAME" \
        --dbuser="$DB_USER" \
        --dbpass="$DB_PASS" \
        --dbhost="localhost" \
        --dbcharset="utf8mb4" \
        --allow-root --quiet 2>/dev/null \
        || { warn "wp config create thất bại"; return 1; }

    # Thêm security keys tự động
    wp config shuffle-salts --path="$ROOT" --allow-root --quiet 2>/dev/null || true

    # Fix M3: dùng https:// chỉ khi cert đã tồn tại thực sự
    # Nếu user chưa cấp SSL (chọn n), WP install với https → redirect loop
    # → không vào được admin, CSS/JS bị block do HSTS
    local _wp_scheme="http"
    if [[ -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
        _wp_scheme="https"
    fi

    wp core install \
        --path="$ROOT" \
        --url="${_wp_scheme}://${DOMAIN}" \
        --title="$WP_TITLE" \
        --admin_user="$WP_ADMIN" \
        --admin_password="$WP_PASS" \
        --admin_email="$WP_EMAIL" \
        --skip-email \
        --allow-root --quiet 2>/dev/null \
        || { warn "wp core install thất bại"; return 1; }

    # Set permissions chuẩn WordPress
    chown -R "${SITE_USER}:${SITE_USER}" "$ROOT"
    find "$ROOT" -type d -exec chmod 750 {} \;
    find "$ROOT" -type f -exec chmod 640 {} \;
    chmod 600 "${ROOT}/wp-config.php"

    # Xóa default content
    wp post delete 1 2 --force --path="$ROOT" --allow-root --quiet 2>/dev/null || true
    wp plugin delete hello akismet --path="$ROOT" --allow-root --quiet 2>/dev/null || true

    # Lưu credentials — ghi scheme thực tế (http hoặc https tùy thời điểm install)
    local _final_url="${_wp_scheme}://${DOMAIN}"
    {
        echo ""
        echo "# WordPress: ${DOMAIN}"
        echo "WP_URL=${_final_url}"
        echo "WP_ADMIN=${WP_ADMIN}"
        echo "WP_PASS=${WP_PASS}"
        echo "WP_DB=${DB_NAME} | ${DB_USER} | ${DB_PASS}"
    } >> "${INSTALL_DIR}/.credentials"
    chmod 600 "${INSTALL_DIR}/.credentials"

    echo ""
    log "✅ WordPress đã cài xong!"
    log "   URL   : ${_final_url}/wp-admin"
    log "   User  : ${WP_ADMIN}"
    log "   Pass  : ${WP_PASS}"
    [[ "$_wp_scheme" == "http" ]] && \
        warn "   ⚠ Cài với HTTP — sau khi cấp SSL, chạy: sudo mvps → SSL manager → cấp SSL"
    [[ "$_wp_scheme" == "http" ]] && \
        warn "   Rồi update WP URL: wp option update siteurl https://${DOMAIN} --allow-root"
    warn "   Lưu credentials: cat ${INSTALL_DIR}/.credentials"
}

# ════════════════════════════════════════════════
# PHP-FPM POOL MANAGER
# ════════════════════════════════════════════════

do_php_pool_manager() {
    echo ""
    echo "1) Xem status pools   3) Điều chỉnh max_children"
    echo "2) Reload 1 pool      4) Enable/Disable pool"
    read -rp "Chọn: " C
    case "$C" in
        1)
            echo ""
            echo -e "${BOLD}── PHP-FPM Pools ────────────────────${NC}"
            for pool_conf in "$(get_php_pool_dir)"/*.conf; do
                [[ -f "$pool_conf" ]] || continue
                local pname; pname=$(basename "$pool_conf" .conf)
                local sock; sock=$(grep '^listen ' "$pool_conf" 2>/dev/null | awk '{print $3}')
                local max_ch; max_ch=$(grep '^pm.max_children' "$pool_conf" 2>/dev/null | awk '{print $3}')
                local pm_mode; pm_mode=$(grep '^pm ' "$pool_conf" 2>/dev/null | awk '{print $3}')
                # Đếm workers đang chạy (nếu sock tồn tại)
                local workers="?"
                [[ -S "$sock" ]] && workers=$(ps aux 2>/dev/null | grep -c "php-fpm: pool ${pname}" || echo "?")
                printf "  %-25s pm=%-10s max=%-5s workers=%s\n" \
                    "$pname" "$pm_mode" "$max_ch" "$workers"
            done
            ;;
        2)
            read -rp "Tên pool: " PNAME
            local pool_file; pool_file="$(get_php_pool_dir)/${PNAME}.conf"
            [[ ! -f "$pool_file" ]] && { warn "Pool không tồn tại: $PNAME"; return; }
            systemctl restart "$(get_php_fpm_svc)" 2>/dev/null \
                && log "Pool ${PNAME} đã reload" \
                || warn "Restart PHP-FPM thất bại"
            ;;
        3)
            read -rp "Tên pool [www]: " PNAME; PNAME="${PNAME:-www}"
            local pool_file; pool_file="$(get_php_pool_dir)/${PNAME}.conf"
            [[ ! -f "$pool_file" ]] && { warn "Pool không tồn tại: $PNAME"; return; }
            local cur; cur=$(grep '^pm.max_children' "$pool_file" | awk '{print $3}')
            read -rp "max_children hiện tại=${cur}, giá trị mới: " NEW_MAX
            [[ ! "$NEW_MAX" =~ ^[0-9]+$ ]] && { warn "Không hợp lệ"; return; }
            sed -i "s/^pm.max_children.*/pm.max_children = ${NEW_MAX}/" "$pool_file"
            systemctl restart "$(get_php_fpm_svc)" 2>/dev/null \
                && log "max_children → ${NEW_MAX}" || warn "Restart thất bại"
            ;;
        4)
            read -rp "Tên pool: " PNAME
            local pool_file; pool_file="$(get_php_pool_dir)/${PNAME}.conf"
            [[ ! -f "$pool_file" ]] && { warn "Pool không tồn tại"; return; }
            echo "1) Enable  2) Disable"
            read -rp "Chọn: " ED
            if [[ "$ED" == "2" ]]; then
                mv "$pool_file" "${pool_file}.disabled"
                systemctl restart "$(get_php_fpm_svc)" 2>/dev/null
                log "Pool ${PNAME} đã disable"
            else
                [[ -f "${pool_file}.disabled" ]] && \
                    mv "${pool_file}.disabled" "$pool_file"
                systemctl restart "$(get_php_fpm_svc)" 2>/dev/null
                log "Pool ${PNAME} đã enable"
            fi
            ;;
    esac
}

# ════════════════════════════════════════════════
# DATABASE MANAGER (mở rộng)
# ════════════════════════════════════════════════

do_manage_db() {
    echo ""
    echo "1) List DB      4) Processlist   7) Import SQL"
    echo "2) Create DB    5) DB sizes      8) Export DB"
    echo "3) Drop DB      6) Slow queries  9) Repair/Optimize"
    read -rp "Chọn: " C
    case "$C" in
        1) mysql -u root -e "SHOW DATABASES;" 2>/dev/null ;;
        2)
            read -rp "DB name: " DBNAME; DBNAME=$(sanitize_input "$DBNAME") || return
            read -rp "DB user: " DBUSER; DBUSER=$(sanitize_input "$DBUSER") || return
            local DBPASS; DBPASS=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c20)
            mysql -u root <<SQL 2>/dev/null || { warn "Lỗi MySQL"; return; }
CREATE DATABASE IF NOT EXISTS \`${DBNAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DBUSER}'@'localhost' IDENTIFIED BY '${DBPASS}';
GRANT ALL PRIVILEGES ON \`${DBNAME}\`.* TO '${DBUSER}'@'localhost';
FLUSH PRIVILEGES;
SQL
            log "DB:${DBNAME} | User:${DBUSER} | Pass:${DBPASS}"
            echo "$(date +%F) | ${DBNAME} | ${DBUSER} | ${DBPASS}" >> "${INSTALL_DIR}/.db-credentials"
            chmod 600 "${INSTALL_DIR}/.db-credentials"
            ;;
        3)
            read -rp "DB cần xóa: " DBNAME; DBNAME=$(sanitize_input "$DBNAME") || return
            read -rp "Gõ 'yes' để xác nhận: " CONFIRM
            [[ "$CONFIRM" == "yes" ]] && \
                mysql -u root -e "DROP DATABASE IF EXISTS \`${DBNAME}\`;" 2>/dev/null \
                && log "Đã xóa: ${DBNAME}"
            ;;
        4) mysql -u root -e "SHOW FULL PROCESSLIST;" 2>/dev/null ;;
        5) mysql -u root -e "SELECT table_schema AS DB,
            ROUND(SUM(data_length+index_length)/1024/1024,2) AS 'MB'
            FROM information_schema.TABLES
            GROUP BY table_schema
            ORDER BY SUM(data_length+index_length) DESC;" 2>/dev/null ;;
        6)
            echo "Slow queries gần đây:"
            tail -50 /var/log/mysql/slow.log 2>/dev/null | grep -A3 "Query_time" | head -60
            ;;
        7)
            read -rp "DB target: " DBNAME; DBNAME=$(sanitize_input "$DBNAME") || return
            read -rp "Đường dẫn file SQL (/backup hoặc /tmp): " SQL_FILE
            # Fix H2: validate SQL_FILE để tránh path traversal / đọc file hệ thống
            # Chỉ chấp nhận .sql hoặc .sql.gz trong thư mục an toàn
            if [[ ! "$SQL_FILE" =~ \.(sql|sql\.gz)$ ]]; then
                warn "Chỉ chấp nhận file .sql hoặc .sql.gz"; return
            fi
            if [[ ! "$SQL_FILE" =~ ^(/backup|/tmp)/ ]]; then
                warn "File phải nằm trong /backup hoặc /tmp"; return
            fi
            # Resolve symlink để tránh symlink attack ra ngoài whitelist dirs
            local real_sql; real_sql=$(realpath "$SQL_FILE" 2>/dev/null)
            if [[ ! "$real_sql" =~ ^(/backup|/tmp)/ ]]; then
                warn "Path traversal phát hiện — từ chối"; return
            fi
            [[ ! -f "$real_sql" ]] && { warn "File không tồn tại: $real_sql"; return; }
            mysql -u root "$DBNAME" < "$real_sql" 2>/dev/null \
                && log "Import thành công vào ${DBNAME}" \
                || warn "Import thất bại"
            ;;
        8)
            read -rp "DB cần export: " DBNAME; DBNAME=$(sanitize_input "$DBNAME") || return
            local out="/backup/export-${DBNAME}-$(date +%Y%m%d_%H%M).sql.gz"
            mysqldump -u root --single-transaction "$DBNAME" 2>/dev/null \
                | gzip > "$out" \
                && log "Export: $out" \
                || warn "Export thất bại"
            ;;
        9)
            read -rp "DB cần repair/optimize: " DBNAME; DBNAME=$(sanitize_input "$DBNAME") || return
            mysqlcheck -u root --repair --optimize "$DBNAME" 2>/dev/null \
                && log "Repair/Optimize ${DBNAME} xong" \
                || warn "mysqlcheck thất bại"
            ;;
    esac
}

# ════════════════════════════════════════════════
# SSL MANAGER
# ════════════════════════════════════════════════

do_ssl_manager() {
    echo ""
    echo "1) Xem certs + expiry   3) Renew 1 domain"
    echo "2) Cấp SSL mới          4) Revoke cert"
    echo "5) Test auto-renew"
    read -rp "Chọn: " C
    case "$C" in
        1)
            echo ""
            echo -e "${BOLD}── SSL Certificates ─────────────────${NC}"
            certbot certificates 2>/dev/null | awk '
                /Certificate Name:/{name=$NF}
                /Domains:/{doms=$0; sub(/.*Domains: /,"",doms)}
                /VALID: ([0-9]+) day/{
                    match($0,/VALID: ([0-9]+)/,a)
                    days=a[1]+0
                    status=(days<=7 ? "🔴 URGENT" : (days<=30 ? "🟡 "days"d" : "🟢 "days"d"))
                    printf "  %-35s %s\n", name, status
                }
            ' || echo "  (Không có cert nào)"
            ;;
        2)
            read -rp "Domain: " DOMAIN; DOMAIN=$(sanitize_domain "$DOMAIN") || return
            read -rp "Thêm www.${DOMAIN}? (y/n) [y]: " ADDWWW
            local certbot_args="--nginx -d ${DOMAIN}"
            [[ "${ADDWWW:-y}" == "y" ]] && certbot_args+=" -d www.${DOMAIN}"
            certbot $certbot_args --email "$ADMIN_EMAIL" \
                --agree-tos --non-interactive 2>/dev/null \
                && nginx_safe_reload && log "SSL đã cấp cho ${DOMAIN}" \
                || warn "SSL thất bại — kiểm tra DNS đã trỏ về server chưa"
            ;;
        3)
            read -rp "Domain: " DOMAIN; DOMAIN=$(sanitize_domain "$DOMAIN") || return
            certbot renew --cert-name "$DOMAIN" --force-renewal \
                --post-hook "systemctl reload nginx" 2>/dev/null \
                && log "Renew thành công" || warn "Renew thất bại"
            ;;
        4)
            read -rp "Domain cần revoke: " DOMAIN; DOMAIN=$(sanitize_domain "$DOMAIN") || return
            read -rp "Xác nhận revoke cert '${DOMAIN}'? (yes/no): " CONFIRM
            [[ "$CONFIRM" != "yes" ]] && return
            certbot revoke --cert-name "$DOMAIN" --non-interactive 2>/dev/null \
                && log "Đã revoke ${DOMAIN}" || warn "Revoke thất bại"
            ;;
        5)
            log "Test certbot auto-renew (dry run)..."
            certbot renew --dry-run 2>&1 | tail -20
            ;;
    esac
}

# ════════════════════════════════════════════════
# SFTP JAIL USER MANAGER
# ════════════════════════════════════════════════

do_sftp_users() {
    echo ""
    echo "1) List SFTP users   3) Xóa user"
    echo "2) Tạo SFTP user     4) Reset password"
    read -rp "Chọn: " C
    case "$C" in
        1)
            echo ""
            echo -e "${BOLD}── SFTP Jail Users ──────────────────${NC}"
            getent group sftp-users 2>/dev/null | tr ':' '\n' | tail -1 | tr ',' '\n' \
                | while read -r u; do
                    [[ -z "$u" ]] && continue
                    local home; home=$(getent passwd "$u" | cut -d: -f6)
                    printf "  %-20s → %s\n" "$u" "${home:-?}"
                done
            ;;
        2)
            read -rp "Username: " SFTP_USER; SFTP_USER=$(sanitize_input "$SFTP_USER") || return
            read -rp "Webroot để jail vào: " SFTP_ROOT
            [[ ! -d "$SFTP_ROOT" ]] && { warn "Webroot không tồn tại"; return; }

            local SFTP_PASS; SFTP_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c12)

            # Fix H1: SFTP chroot yêu cầu ChrootDirectory owned root:root
            # KHÔNG được chown webroot trực tiếp → PHP-FPM mất quyền write → site chết
            # Giải pháp: tạo wrapper directory riêng owned root, webroot là subdir writeable
            local chroot_base="/srv/sftp/${SFTP_USER}"
            mkdir -p "${chroot_base}"
            chown root:root "${chroot_base}"
            chmod 755 "${chroot_base}"

            # Tạo subdir 'www' bên trong chroot — user sẽ vào đây (có quyền write)
            local chroot_www="${chroot_base}/www"
            mkdir -p "$chroot_www"

            # Bind mount webroot vào chroot/www để user thấy file thật
            if mount --bind "$SFTP_ROOT" "$chroot_www" 2>/dev/null; then
                # Persist bind mount qua reboot
                grep -q "$chroot_www" /etc/fstab 2>/dev/null || \
                    echo "${SFTP_ROOT}  ${chroot_www}  none  bind  0  0" >> /etc/fstab
                chown "${SFTP_USER}:${SFTP_USER}" "$chroot_www" 2>/dev/null || true
            else
                # Fallback nếu mount --bind không được: symlink (ít secure hơn nhưng vẫn OK)
                warn "mount --bind thất bại — dùng symlink fallback"
                rmdir "$chroot_www" 2>/dev/null
                ln -sf "$SFTP_ROOT" "$chroot_www"
            fi

            # Tạo user với home = chroot_base (không phải webroot)
            useradd -M -s /usr/sbin/nologin -d "$chroot_base" \
                -g sftp-users "$SFTP_USER" 2>/dev/null || \
                usermod -g sftp-users -d "$chroot_base" "$SFTP_USER" 2>/dev/null
            echo "${SFTP_USER}:${SFTP_PASS}" | chpasswd

            log "SFTP user: ${SFTP_USER} | Pass: ${SFTP_PASS}"
            log "Jail: ${chroot_base} | Webroot: ${chroot_www} → ${SFTP_ROOT}"
            log "Kết nối: sftp -P 2222 ${SFTP_USER}@$(hostname -I | awk '{print $1}')"
            log "Sau khi login vào /www để truy cập webroot"
            ;;
        3)
            read -rp "Username cần xóa: " SFTP_USER
            # Fix H3: validate + guard trước khi userdel
            # Không sanitize → có thể xóa 'root', 'deployer', user hệ thống
            SFTP_USER=$(sanitize_input "$SFTP_USER") || return
            # Guard: user phải tồn tại
            if ! id "$SFTP_USER" &>/dev/null; then
                warn "User không tồn tại: ${SFTP_USER}"; return
            fi
            # Guard: chỉ xóa user thuộc group sftp-users — tránh xóa nhầm deployer/root
            if ! groups "$SFTP_USER" 2>/dev/null | grep -q sftp-users; then
                warn "Từ chối: ${SFTP_USER} không thuộc group sftp-users"; return
            fi
            # Unmount bind nếu có trước khi xóa user
            local _chroot="/srv/sftp/${SFTP_USER}"
            if mountpoint -q "${_chroot}/www" 2>/dev/null; then
                umount "${_chroot}/www" 2>/dev/null || true
                sed -i "\|${_chroot}/www|d" /etc/fstab 2>/dev/null || true
            fi
            rm -rf "$_chroot" 2>/dev/null || true
            userdel "$SFTP_USER" 2>/dev/null \
                && log "Đã xóa SFTP user: ${SFTP_USER}" \
                || warn "Xóa thất bại"
            ;;
        4)
            read -rp "Username: " SFTP_USER
            SFTP_USER=$(sanitize_input "$SFTP_USER") || return
            if ! id "$SFTP_USER" &>/dev/null; then
                warn "User không tồn tại: ${SFTP_USER}"; return
            fi
            local NEW_PASS; NEW_PASS=$(openssl rand -base64 12 | tr -dc 'a-zA-Z0-9' | head -c12)
            echo "${SFTP_USER}:${NEW_PASS}" | chpasswd \
                && log "Password mới: ${NEW_PASS}" \
                || warn "Đổi password thất bại"
            ;;
    esac
}

# ════════════════════════════════════════════════
# OPCACHE STATUS
# ════════════════════════════════════════════════

do_opcache_status() {
    echo ""
    log "Lấy OPcache stats..."
    local tmp_script="/tmp/mvps_opcache_$$.php"
    cat > "$tmp_script" <<'PHPEOF'
<?php
$s = opcache_get_status(false);
if (!$s) { echo "OPcache disabled\n"; exit; }
$m = $s['memory_usage'];
$used = round($m['used_memory']/1024/1024, 1);
$free = round($m['free_memory']/1024/1024, 1);
$total = $used + $free;
$pct = round($used/$total*100, 1);
$ks = $s['opcache_statistics'];
$hit = $ks['opcache_hit_rate'] ?? 0;
printf("  Hit rate    : %.1f%%\n", $hit);
printf("  Memory      : %.1fMB / %.1fMB used (%.1f%%)\n", $used, $total, $pct);
printf("  Cached files: %d\n", $ks['num_cached_scripts'] ?? 0);
printf("  Hits/Misses : %d / %d\n", $ks['hits'] ?? 0, $ks['misses'] ?? 0);
printf("  Restarts    : %d\n", $s['restart_cause'] !== 'none' ? 1 : 0);
PHPEOF
    php "$tmp_script" 2>/dev/null || warn "Không lấy được OPcache stats"
    rm -f "$tmp_script"

    echo ""
    read -rp "Reset OPcache ngay? (y/n) [n]: " RESET
    if [[ "${RESET:-n}" == "y" ]]; then
        local tmp_reset="/tmp/mvps_opcache_reset_$$.php"
        echo '<?php opcache_reset(); echo "OPcache reset OK\n";' > "$tmp_reset"
        php "$tmp_reset" 2>/dev/null && log "OPcache đã reset" \
            || { systemctl reload "$(get_php_fpm_svc)" 2>/dev/null; log "PHP-FPM reloaded (reset OPcache)"; }
        rm -f "$tmp_reset"
    fi
}

# ════════════════════════════════════════════════
# LOG ANALYSIS
# ════════════════════════════════════════════════

do_log_analysis() {
    echo ""
    echo "1) Tail realtime       4) Requests/giờ"
    echo "2) Top 10 IPs hôm nay  5) Detect crawl bất thường"
    echo "3) Top URL 404/500     6) Log domain cụ thể"
    read -rp "Chọn: " C
    case "$C" in
        1)
            echo "(Ctrl+C để dừng)"
            tail -f /var/log/nginx/access.log 2>/dev/null || true
            ;;
        2)
            echo -e "${BOLD}Top 10 IPs hôm nay:${NC}"
            local today; today=$(date '+%d/%b/%Y')
            awk -v d="$today" '$0 ~ d {print $1}' \
                /var/log/nginx/access.log 2>/dev/null \
                | sort | uniq -c | sort -rn | head -10 \
                | awk '{printf "  %6d  %s\n", $1, $2}'
            ;;
        3)
            echo -e "${BOLD}Top URLs lỗi 404/500:${NC}"
            awk '$9 ~ /^(404|500)$/ {print $9, $7}' \
                /var/log/nginx/access.log 2>/dev/null \
                | sort | uniq -c | sort -rn | head -15 \
                | awk '{printf "  %6d  %s %s\n", $1, $2, $3}'
            ;;
        4)
            echo -e "${BOLD}Requests/giờ (24h qua):${NC}"
            awk '{
                match($4, /\[([^:]+):([0-9]+):/, a)
                print a[2]
            }' /var/log/nginx/access.log 2>/dev/null \
                | sort | uniq -c | sort -k2 -n | tail -24 \
                | awk '{printf "  %02dh: %d reqs\n", $2, $1}'
            ;;
        5)
            echo -e "${BOLD}IPs có > 1000 requests hôm nay (nghi crawl):${NC}"
            local today; today=$(date '+%d/%b/%Y')
            awk -v d="$today" '$0 ~ d {print $1}' \
                /var/log/nginx/access.log 2>/dev/null \
                | sort | uniq -c | sort -rn \
                | awk '$1 > 1000 {printf "  %7d  %s\n", $1, $2}'
            ;;
        6)
            read -rp "Domain: " D
            local log_file="/var/log/nginx/${D}-access.log"
            [[ ! -f "$log_file" ]] && { warn "Không tìm thấy log: $log_file"; return; }
            echo "(Ctrl+C để dừng)"
            tail -f "$log_file" 2>/dev/null || true
            ;;
    esac
}

# ════════════════════════════════════════════════
# FIREWALL
# ════════════════════════════════════════════════

do_firewall() {
    echo ""
    echo "1) Xem rules   3) Unblock IP  5) Fail2ban status"
    echo "2) Block IP    4) Mở port     6) Blocked list"
    read -rp "Chọn: " C
    case "$C" in
        1) nft list ruleset 2>/dev/null ;;
        2)
            read -rp "IP cần block: " BIP
            validate_ip "$BIP" || return
            nft add element inet modernvps blacklist_v4 "{ $BIP }" 2>/dev/null \
                && log "Blocked: $BIP" || warn "Thất bại"
            ;;
        3)
            read -rp "IP cần unblock: " UIP
            validate_ip "$UIP" || return
            nft delete element inet modernvps blacklist_v4 "{ $UIP }" 2>/dev/null \
                && log "Unblocked: $UIP" || warn "Không tìm thấy"
            ;;
        4)
            read -rp "Port cần mở: " P
            [[ ! "$P" =~ ^[0-9]+$ ]] && { warn "Port không hợp lệ"; return; }
            nft add rule inet modernvps input tcp dport "$P" ct state new accept 2>/dev/null \
                && log "Đã mở port $P (runtime — không persist reboot)" \
                || warn "Thất bại"
            ;;
        5) fail2ban-client status 2>/dev/null ;;
        6) nft list set inet modernvps blacklist_v4 2>/dev/null ;;
    esac
}

# ════════════════════════════════════════════════
# CIS AUDIT (web)
# ════════════════════════════════════════════════

do_cis_audit() {
    echo ""
    echo -e "${BOLD}═══ CIS Security Audit (Web Server) ═══${NC}"
    local score=0 total=0
    _chk() {
        local label="$1"; shift
        total=$(( total+1 ))
        if eval "$*" &>/dev/null; then
            echo -e "  ${GREEN}✅${NC} $label"
            score=$(( score+1 ))
        else
            echo -e "  ${RED}❌${NC} $label"
        fi
    }
    _chk "SSH: no root login"    "grep -q 'PermitRootLogin no' /etc/ssh/sshd_config.d/99-modernvps.conf"
    _chk "SSH: port 2222"        "grep -q 'Port 2222' /etc/ssh/sshd_config.d/99-modernvps.conf"
    _chk "nftables active"       "systemctl is-active nftables"
    _chk "Fail2ban active"       "systemctl is-active fail2ban"
    _chk "Auditd active"         "systemctl is-active auditd"
    _chk "BBR enabled"           "sysctl -n net.ipv4.tcp_congestion_control | grep -q bbr"
    _chk "ASLR = 2"              "[ \$(sysctl -n kernel.randomize_va_space) -eq 2 ]"
    _chk "Nginx running"         "systemctl is-active nginx"
    _chk "PHP-FPM running"       "systemctl is-active $(get_php_fpm_svc)"
    _chk "MariaDB running"       "systemctl is-active mariadb"
    _chk "MariaDB bind 127.0.0.1" "mysql -u root -e 'SHOW VARIABLES LIKE \"bind_address\"' 2>/dev/null | grep -q 127.0.0.1"
    _chk "OPcache enabled"       "php -r 'echo ini_get(\"opcache.enable\");' 2>/dev/null | grep -q 1"
    _chk "Cron restricted"       "test -f /etc/cron.allow"
    _chk "ModSecurity WAF"       "grep -q 'modsecurity on' /etc/nginx/nginx.conf 2>/dev/null"
    _chk "Auto updates"          "systemctl is-active unattended-upgrades 2>/dev/null || systemctl is-active dnf-automatic.timer 2>/dev/null"
    _chk "Certbot auto-renew"    "grep -q certbot /etc/cron.d/modernvps-backup 2>/dev/null"
    echo ""
    local pct=$(( score * 100 / total ))
    local c="$RED"
    (( pct >= 70 )) && c="$YELLOW"
    (( pct >= 90 )) && c="$GREEN"
    echo -e "  Score: ${c}${score}/${total} (${pct}%)${NC}"
    (( pct < 70 )) && warn "Cần cải thiện bảo mật — xem log: /var/log/modernvps/install.log"
}

# ════════════════════════════════════════════════
# MAIN MENU LOOP — WEB SERVER
# ════════════════════════════════════════════════

source /opt/modernvps/lib/common.sh 2>/dev/null || true

while true; do
    clear
    render_header_web 2>/dev/null || {
        _up=""; _rm=""; _rt=""; _load=""; _disk=""; _h=""; _ud=""
        read -r _up _ < /proc/uptime 2>/dev/null
        _ud=$(awk -v s="${_up:-0}" 'BEGIN{printf "%dd%dh",s/86400,(s%86400)/3600}')
        _h=$(hostname -s 2>/dev/null || echo "unknown")
        read -r _rm _rt < <(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{printf "%d %d",(t-a)/1024,t/1024}' /proc/meminfo 2>/dev/null)
        read -r _load _ < /proc/loadavg 2>/dev/null
        _disk=$(df -h / 2>/dev/null | awk 'NR==2{print $5}')
        echo "═══════════════════════════════════════════"
        printf "  ModernVPS v3.2 (web) | %s | Up %s\n" "$_h" "$_ud"
        printf "  CPU: %-4s | RAM: %s/%sMB | DSK: %s\n" "$_load" "${_rm:-?}" "${_rt:-?}" "${_disk:-?}"
        echo "═══════════════════════════════════════════"
    }
    echo ""
    echo -e " ${BOLD}[SITES]${NC}"
    echo "  1) List sites          2) Create site"
    echo "  3) Delete site         4) WordPress install"
    echo ""
    echo -e " ${BOLD}[SERVICES]${NC}"
    echo "  5) PHP-FPM pools       6) Database"
    echo "  7) SSL manager         8) SFTP users"
    echo ""
    echo -e " ${BOLD}[MONITORING]${NC}"
    echo "  9) Log analysis       10) OPcache status"
    echo " 11) Disk & resources   12) Security status"
    echo ""
    echo -e " ${BOLD}[SYSTEM]${NC}"
    echo " 13) Backup             14) Firewall"
    echo " 15) Update stack       16) CIS audit"
    echo " 17) Restart services   18) Clear cache"
    echo "  0) Exit"
    echo "═══════════════════════════════════════════"
    read -rp "Chọn: " CHOICE
    case "$CHOICE" in
        1)  do_list_sites || true ;;
        2)  do_create_site || true ;;
        3)  do_delete_site || true ;;
        4)  do_wordpress_install || true ;;
        5)  do_php_pool_manager || true ;;
        6)  do_manage_db || true ;;
        7)  do_ssl_manager || true ;;
        8)  do_sftp_users || true ;;
        9)  do_log_analysis || true ;;
        10) do_opcache_status || true ;;
        11) echo "── Disk ──"; df -h / /var/www "$BACKUP_DIR" 2>/dev/null
            echo "── Memory ──"; free -h
            echo "── Load ──"; uptime
            echo "── Connections ──"; ss -s 2>/dev/null | head -5
            ;;
        12) /etc/update-motd.d/99-modernvps 2>/dev/null || true ;;
        13) log "Chạy backup..."; /usr/local/bin/mvps-backup && log "Done!" \
            || warn "Backup có lỗi"; ls -lh "$BACKUP_DIR"/ 2>/dev/null | tail -5 ;;
        14) do_firewall || true ;;
        15) log "Updating..."
            case "$OS_FAMILY" in
                debian) apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y ;;
                rhel)   dnf update -y ;;
            esac
            systemctl restart nginx "$(get_php_fpm_svc)" mariadb 2>/dev/null
            log "Updated!" ;;
        16) do_cis_audit || true ;;
        17) systemctl restart nginx "$(get_php_fpm_svc)" mariadb 2>/dev/null \
            && log "✅ Services restarted" || warn "Một số service thất bại" ;;
        18) rm -rf /var/cache/nginx/fastcgi/* 2>/dev/null
            systemctl reload "$(get_php_fpm_svc)" 2>/dev/null
            log "✅ Cache + OPcache đã clear" ;;
        0)  exit 0 ;;
        *)  warn "Lựa chọn không hợp lệ" ;;
    esac
    press_enter
done
MENUEOF
    chmod +x "${INSTALL_DIR}/menu.sh"
    log "Menu Web Server đã tạo"
}

# ══════════════════════════════════════════════════
# MENU LOAD BALANCER
# Tính năng: backend health status, upstream manager,
# proxy vhost, maintenance mode, canary deploy,
# drain backend, traffic analytics, nginx stats
# ══════════════════════════════════════════════════

_create_menu_lb() {
    log "Tạo menu Load Balancer..."
    cat > "${INSTALL_DIR}/menu.sh" <<'MENUEOF'
#!/bin/bash
# ModernVPS v3.2 Menu - Load Balancer
set -uo pipefail
source /opt/modernvps/config.env 2>/dev/null || { echo "Config missing!"; exit 1; }

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
log()  { echo -e "${GREEN}[INFO]${NC}  $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }

nginx_safe_reload() {
    nginx -t &>/dev/null \
        && { systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null; } \
        || { warn "nginx config lỗi"; nginx -t; }
}
sanitize_domain() {
    local d="${1:-}"
    [[ -z "$d" ]] && return 1
    [[ ! "$d" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] && { warn "Domain không hợp lệ: $d"; return 1; }
    printf '%s' "$d"
}
sanitize_input() {
    local v="${1:-}"
    [[ -z "$v" ]] && return 1
    [[ ! "$v" =~ ^[a-zA-Z0-9._:/@-]+$ ]] && { warn "Input không hợp lệ: $v"; return 1; }
    printf '%s' "$v"
}
validate_ip() { [[ "${1:-}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; }
press_enter() { echo ""; read -rp "Enter để tiếp tục..."; }

INSTALL_DIR="/opt/modernvps"
INVENTORY="${INSTALL_DIR}/backends.json"
STATUS_FILE="${INSTALL_DIR}/backend-status.json"
UPSTREAM_CONF="/etc/nginx/conf.d/upstream.conf"
MAINTENANCE_FLAG="${INSTALL_DIR}/.maintenance-active"

# ════════════════════════════════════════════════
# BACKEND STATUS (đọc từ health check cache)
# ════════════════════════════════════════════════

do_backend_status() {
    echo ""
    echo -e "${BOLD}── Backend Health Status ────────────────────${NC}"
    if [[ ! -f "$STATUS_FILE" ]] || ! command -v jq &>/dev/null; then
        # Fallback: parse upstream.conf trực tiếp
        echo "  (Health check chưa chạy — hiển thị config)"
        grep -E '^\s*server\s+' "$UPSTREAM_CONF" 2>/dev/null \
            | sed 's/^[[:space:]]*/  /' \
            || echo "  Chưa có backend nào"
        return
    fi
    local updated; updated=$(jq -r '.updated' "$STATUS_FILE" 2>/dev/null || echo "?")
    echo "  Last check: ${updated}"
    echo ""
    printf "  %-20s %-6s %-8s %-12s %s\n" "IP:PORT" "CODE" "STATUS" "LATENCY" "LABEL"
    echo "  ─────────────────────────────────────────────────────"
    jq -r '.backends[] |
        "\(.ip):\(.port)|\(.http_code)|\(.status)|\(.latency_ms)ms|\(.label)"
    ' "$STATUS_FILE" 2>/dev/null \
    | while IFS='|' read -r addr code status latency label; do
        local color="$GREEN"
        [[ "$status" == "DOWN" ]] && color="$RED"
        printf "  %-20s %-6s ${color}%-8s${NC} %-12s %s\n" \
            "$addr" "$code" "$status" "$latency" "$label"
    done
}

# ════════════════════════════════════════════════
# UPSTREAM MANAGER — quản lý nhiều upstream groups
# Fix bug: dùng marker comment thay vì sed /^}/i
# ════════════════════════════════════════════════

_upstream_file() {
    local group="${1:-backend}"
    echo "/etc/nginx/conf.d/upstream-${group}.conf"
}

_init_upstream() {
    local group="${1:-backend}" method="${2:-}"
    local ufile; ufile=$(_upstream_file "$group")
    [[ -f "$ufile" ]] && return 0
    {
        printf "upstream %s {\n" "$group"
        [[ -n "$method" ]] && printf "    %s;\n" "$method"
        printf "    keepalive 32;\n"
        printf "    keepalive_requests 1000;\n"
        printf "    keepalive_timeout  60s;\n"
        printf "    # MVPS_SERVERS_START\n"
        printf "    # MVPS_SERVERS_END\n"
        printf "}\n"
    } > "$ufile"
}

do_upstream_manager() {
    echo ""
    echo "1) List upstream groups   3) Tạo group mới"
    echo "2) Thêm backend vào group  4) Xóa group"
    read -rp "Chọn: " C
    case "$C" in
        1)
            echo ""
            echo -e "${BOLD}── Upstream Groups ──────────────────${NC}"
            for f in /etc/nginx/conf.d/upstream-*.conf; do
                [[ -f "$f" ]] || continue
                local gname; gname=$(basename "$f" .conf | sed 's/upstream-//')
                local method; method=$(grep -E '^\s*(least_conn|ip_hash|hash|random)' "$f" | head -1 | xargs)
                local count; count=$(grep -c '^\s*server ' "$f" 2>/dev/null || echo 0)
                printf "  %-20s backends=%-4s method=%s\n" \
                    "$gname" "$count" "${method:-round-robin}"
            done
            ;;
        2)
            read -rp "Tên upstream group [backend]: " GROUP
            GROUP="${GROUP:-backend}"
            read -rp "IP backend: " IP; validate_ip "$IP" || return
            read -rp "Port [80]: " PORT; PORT="${PORT:-80}"
            read -rp "Weight [1]: " WEIGHT; WEIGHT="${WEIGHT:-1}"
            read -rp "max_conns [0=unlimited]: " MAX_CONNS; MAX_CONNS="${MAX_CONNS:-0}"
            read -rp "Label/ghi chú: " LABEL; LABEL="${LABEL:-${IP}}"
            _init_upstream "$GROUP"
            local ufile; ufile=$(_upstream_file "$GROUP")
            local server_line="    server ${IP}:${PORT} weight=${WEIGHT} max_fails=3 fail_timeout=30s"
            (( MAX_CONNS > 0 )) && server_line+=" max_conns=${MAX_CONNS}"
            server_line+=";"
            # Chèn vào trước marker MVPS_SERVERS_END (chính xác, không ảnh hưởng block khác)
            sed -i "s|    # MVPS_SERVERS_END|${server_line}\n    # MVPS_SERVERS_END|" "$ufile"
            # Lưu vào inventory
            if command -v jq &>/dev/null; then
                local tmp; tmp=$(mktemp)
                jq --arg ip "$IP" --arg port "$PORT" \
                   --arg label "$LABEL" --arg group "$GROUP" \
                   --arg date "$(date -Iseconds)" \
                   '.backends += [{"ip":$ip,"port":($port|tonumber),"label":$label,"group":$group,"added":$date,"status":"unknown"}]' \
                   "$INVENTORY" > "$tmp" 2>/dev/null && mv "$tmp" "$INVENTORY"
            fi
            nginx_safe_reload
            log "Đã thêm ${IP}:${PORT} vào upstream '${GROUP}' (label: ${LABEL})"
            ;;
        3)
            read -rp "Tên group mới: " GROUP; GROUP=$(sanitize_input "$GROUP") || return
            echo "LB method: 1) round-robin  2) least_conn  3) ip_hash  4) hash \$cookie_sessionid"
            read -rp "Chọn [1]: " M
            local method=""
            case "$M" in
                2) method="least_conn" ;;
                3) method="ip_hash" ;;
                4) method="hash \$cookie_sessionid consistent" ;;
            esac
            _init_upstream "$GROUP" "$method"
            nginx_safe_reload
            log "Upstream group '${GROUP}' đã tạo (method: ${method:-round-robin})"
            ;;
        4)
            read -rp "Tên group cần xóa: " GROUP
            local ufile; ufile=$(_upstream_file "$GROUP")
            [[ ! -f "$ufile" ]] && { warn "Group không tồn tại"; return; }
            read -rp "Xác nhận xóa group '${GROUP}'? (yes/no): " CONFIRM
            [[ "$CONFIRM" != "yes" ]] && return
            rm -f "$ufile"
            # Xóa khỏi inventory
            command -v jq &>/dev/null && {
                local tmp; tmp=$(mktemp)
                jq --arg g "$GROUP" '.backends = [.backends[] | select(.group != $g)]' \
                    "$INVENTORY" > "$tmp" 2>/dev/null && mv "$tmp" "$INVENTORY"
            }
            nginx_safe_reload
            log "Group '${GROUP}' đã xóa"
            ;;
    esac
}

do_remove_backend() {
    echo ""
    do_backend_status
    echo ""
    read -rp "Tên group [backend]: " GROUP; GROUP="${GROUP:-backend}"
    read -rp "IP cần xóa: " IP; validate_ip "$IP" || return
    read -rp "Port [80]: " PORT; PORT="${PORT:-80}"
    local ufile; ufile=$(_upstream_file "$GROUP")
    [[ ! -f "$ufile" ]] && { warn "Group không tồn tại"; return; }
    sed -i "/server ${IP}:${PORT}/d" "$ufile"
    # Xóa khỏi inventory
    command -v jq &>/dev/null && {
        local tmp; tmp=$(mktemp)
        jq --arg ip "$IP" --arg port "$PORT" \
            '.backends = [.backends[] | select(.ip != $ip or (.port|tostring) != $port)]' \
            "$INVENTORY" > "$tmp" 2>/dev/null && mv "$tmp" "$INVENTORY"
    }
    nginx_safe_reload
    log "Đã xóa ${IP}:${PORT} khỏi '${GROUP}'"
}

# ════════════════════════════════════════════════
# LB METHOD (fix bug: $method expand đúng)
# ════════════════════════════════════════════════

do_set_lb_method() {
    echo ""
    read -rp "Tên upstream group [backend]: " GROUP; GROUP="${GROUP:-backend}"
    local ufile; ufile=$(_upstream_file "$GROUP")
    [[ ! -f "$ufile" ]] && { warn "Group '${GROUP}' không tồn tại"; return; }

    echo "1) round-robin (mặc định)"
    echo "2) least_conn — ít connections nhất"
    echo "3) ip_hash    — sticky theo IP"
    echo "4) hash \$cookie_sessionid — sticky session"
    read -rp "Chọn (1-4): " M
    local new_method=""
    case "$M" in
        2) new_method="least_conn" ;;
        3) new_method="ip_hash" ;;
        4) new_method='hash $cookie_sessionid consistent' ;;
    esac

    # Xóa method cũ, thêm method mới sau dòng "upstream NAME {"
    # Dùng sed với địa chỉ cụ thể, không phải /block/ để tránh bug gốc
    sed -i -E '/^\s*(least_conn|ip_hash|hash |random)/d' "$ufile"
    if [[ -n "$new_method" ]]; then
        # Chèn sau dòng "upstream GROUP {"
        sed -i "/upstream ${GROUP} {/a\\    ${new_method};" "$ufile"
    fi

    nginx_safe_reload
    log "LB method '${GROUP}': ${new_method:-round-robin}"
}

# ════════════════════════════════════════════════
# TẠO PROXY VHOST
# ════════════════════════════════════════════════

do_create_proxy_vhost() {
    echo ""
    read -rp "Domain: " DOMAIN; DOMAIN=$(sanitize_domain "$DOMAIN") || return
    read -rp "Upstream group [backend]: " GROUP; GROUP="${GROUP:-backend}"
    read -rp "Enable proxy cache? (y/n) [n]: " CACHE; CACHE="${CACHE:-n}"

    cat > "/etc/nginx/sites-available/${DOMAIN}" <<VEOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN} www.${DOMAIN};

    include /etc/nginx/snippets/security.conf;

    location / {
        proxy_pass http://${GROUP};
        include /etc/nginx/snippets/proxy-params.conf;
$(if [[ "$CACHE" == "y" ]]; then
cat <<CEOF
        proxy_cache         PROXYCACHE;
        proxy_cache_valid   200 302 10m;
        proxy_cache_valid   404 1m;
        proxy_cache_bypass  \$http_cache_control;
        add_header          X-Cache \$upstream_cache_status;
CEOF
fi)
    }

    access_log /var/log/nginx/${DOMAIN}-access.log main;
    error_log  /var/log/nginx/${DOMAIN}-error.log warn;
}
VEOF
    ln -sf "/etc/nginx/sites-available/${DOMAIN}" \
           "/etc/nginx/sites-enabled/${DOMAIN}"
    nginx_safe_reload

    read -rp "Cấp SSL ngay? (y/n) [n]: " DOSSL
    if [[ "${DOSSL:-n}" == "y" ]]; then
        certbot --nginx -d "$DOMAIN" -d "www.${DOMAIN}" \
            --email "$ADMIN_EMAIL" --agree-tos --non-interactive 2>/dev/null \
            || warn "SSL thất bại"
        nginx_safe_reload
    fi
    log "Proxy vhost ${DOMAIN} → upstream '${GROUP}' đã tạo"
}

# ════════════════════════════════════════════════
# MAINTENANCE MODE
# ════════════════════════════════════════════════

do_maintenance_mode() {
    echo ""
    if [[ -f "$MAINTENANCE_FLAG" ]]; then
        echo -e "  Trạng thái: ${RED}MAINTENANCE ON${NC}"
        read -rp "Tắt maintenance mode? (y/n): " OFF
        if [[ "${OFF:-n}" == "y" ]]; then
            rm -f "$MAINTENANCE_FLAG"
            rm -f /etc/nginx/sites-enabled/maintenance
            nginx_safe_reload
            log "Maintenance mode TẮT — backends đã khôi phục"
        fi
        return
    fi

    echo -e "  Trạng thái: ${GREEN}BÌNH THƯỜNG${NC}"
    read -rp "Bật maintenance mode? (y/n): " ON
    [[ "${ON:-n}" != "y" ]] && return

    # Tạo maintenance page
    mkdir -p /var/www/maintenance
    cat > /var/www/maintenance/index.html <<'MHTML'
<!DOCTYPE html>
<html lang="vi">
<head><meta charset="UTF-8"><title>Bảo trì hệ thống</title>
<style>body{font-family:sans-serif;text-align:center;padding:100px;background:#f5f5f5}
h1{color:#e74c3c}p{color:#666}</style></head>
<body>
<h1>🔧 Đang bảo trì hệ thống</h1>
<p>Chúng tôi đang nâng cấp hệ thống. Vui lòng quay lại sau.</p>
<p><small>Estimated time: 30 minutes</small></p>
</body></html>
MHTML

    cat > /etc/nginx/sites-available/maintenance <<'MEOF'
# Fix C4: maintenance mode KHÔNG dùng default_server trên port 80
# để tránh conflict với default-lb block (cả 2 cùng là default_server → nginx fail)
# Thay bằng priority cao hơn: server_name _ + listen 80 (không default_server)
# nginx chọn block này trước vì nó được load sớm hơn trong sites-enabled (symlink alphabetic)
server {
    listen 80;
    listen [::]:80;
    listen 443 ssl;
    server_name _;
    root /var/www/maintenance;
    ssl_certificate     /etc/nginx/ssl/dummy.crt;
    ssl_certificate_key /etc/nginx/ssl/dummy.key;
    location / {
        try_files $uri /index.html;
        return 503;
    }
    error_page 503 /index.html;
    add_header Retry-After 1800;
}
MEOF
    # Tạo dummy SSL cert nếu chưa có
    if [[ ! -f /etc/nginx/ssl/dummy.crt ]]; then
        mkdir -p /etc/nginx/ssl
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/dummy.key \
            -out /etc/nginx/ssl/dummy.crt \
            -subj "/CN=maintenance" &>/dev/null || true
    fi

    ln -sf /etc/nginx/sites-available/maintenance \
           /etc/nginx/sites-enabled/maintenance
    touch "$MAINTENANCE_FLAG"
    nginx_safe_reload
    warn "⚠️  MAINTENANCE MODE BẬT — toàn bộ traffic trả 503"
}

# ════════════════════════════════════════════════
# DRAIN BACKEND (chờ connections drain trước khi xóa)
# ════════════════════════════════════════════════

do_drain_backend() {
    echo ""
    do_backend_status
    echo ""
    read -rp "Tên group [backend]: " GROUP; GROUP="${GROUP:-backend}"
    read -rp "IP cần drain: " IP; validate_ip "$IP" || return
    read -rp "Port [80]: " PORT; PORT="${PORT:-80}"
    local ufile; ufile=$(_upstream_file "$GROUP")
    [[ ! -f "$ufile" ]] && { warn "Group không tồn tại"; return; }

    # Fix M2: kiểm tra 'down' đã tồn tại trước khi thêm — tránh duplicate 'down down'
    # Nginx vẫn chạy nhưng pattern restore sẽ chỉ xóa được 1 'down' → backend stuck
    if grep -q "server ${IP}:${PORT}.*down" "$ufile" 2>/dev/null; then
        warn "Backend ${IP}:${PORT} đã ở trạng thái down"
    else
        sed -i "s|server ${IP}:${PORT}\([^;]*\);|server ${IP}:${PORT}\1 down;|" "$ufile"
        nginx_safe_reload
        warn "Backend ${IP}:${PORT} đang drain (marked down — nginx ngừng gửi request mới)..."
    fi

    # Fix M1: stub_status chỉ cho biết TỔNG connections của toàn nginx,
    # KHÔNG phân biệt được connections đến backend cụ thể nào.
    # Monitoring tổng connections không có ý nghĩa — traffic mới vẫn đến backends khác.
    # Giải pháp đúng: dùng timeout cố định đủ cho long-running requests hoàn thành,
    # kết hợp đọc access log để phát hiện request cuối đến backend này.
    local timeout=60  # 60s đủ cho request HTTP thông thường (nâng lên nếu có long-poll)
    local elapsed=0
    local last_req_time=0

    warn "Chờ ${timeout}s drain — request đang xử lý sẽ hoàn thành trong thời gian này..."
    while (( elapsed < timeout )); do
        # Đọc access log, tìm request gần nhất đến backend này (nếu log có upstream_addr)
        local last_hit; last_hit=$(awk -v ip="$IP" -v port="$PORT" '
            $0 ~ (ip ":" port) { last=$0 }
            END { if(last!="") print NR }
        ' /var/log/nginx/access.log 2>/dev/null)

        # Hiển thị progress rõ ràng — không pretend đang đếm connections
        printf "  Drain: %ds/%ds | Backend: %s:%s [DOWN] | Requests mới: không có\r" \
            "$elapsed" "$timeout" "$IP" "$PORT"
        sleep 5
        elapsed=$(( elapsed + 5 ))
    done
    echo ""
    log "Drain timeout ${timeout}s đã hết — backend đã ngừng nhận request mới"

    read -rp "Xóa backend ${IP}:${PORT} khỏi config? (y/n): " REMOVE
    if [[ "${REMOVE:-n}" == "y" ]]; then
        sed -i "/server ${IP}:${PORT}/d" "$ufile"
        command -v jq &>/dev/null && {
            local tmp; tmp=$(mktemp)
            jq --arg ip "$IP" --arg port "$PORT" \
                '.backends = [.backends[] | select(.ip != $ip or (.port|tostring) != $port)]' \
                "$INVENTORY" > "$tmp" 2>/dev/null && mv "$tmp" "$INVENTORY"
        }
        nginx_safe_reload
        log "Backend ${IP}:${PORT} đã xóa sau drain"
    else
        # Restore lại — xóa chính xác ' down' suffix (tránh xóa nhầm nếu có param 'download' etc)
        sed -i "s|\(server ${IP}:${PORT}[^;]*\) down;|\1;|" "$ufile"
        nginx_safe_reload
        log "Backend ${IP}:${PORT} đã khôi phục — đang nhận traffic trở lại"
    fi
}

# ════════════════════════════════════════════════
# CANARY DEPLOY
# ════════════════════════════════════════════════

do_canary_deploy() {
    echo ""
    do_backend_status
    echo ""
    read -rp "Tên group [backend]: " GROUP; GROUP="${GROUP:-backend}"
    local ufile; ufile=$(_upstream_file "$GROUP")
    [[ ! -f "$ufile" ]] && { warn "Group không tồn tại"; return; }

    read -rp "IP backend canary (version mới): " CANARY_IP
    validate_ip "$CANARY_IP" || return
    read -rp "Port [80]: " CANARY_PORT; CANARY_PORT="${CANARY_PORT:-80}"

    echo "% traffic cho canary:"
    echo "1) 10%   2) 25%   3) 50%"
    read -rp "Chọn [1]: " PCT_CHOICE
    local canary_pct=10
    case "$PCT_CHOICE" in
        2) canary_pct=25 ;;
        3) canary_pct=50 ;;
    esac

    # Đếm số backends hiện tại (không counting canary — canary chưa được thêm lúc này)
    local total_backends; total_backends=$(grep -c '^\s*server ' "$ufile" 2>/dev/null || echo 1)
    # Tính weight: canary_pct% → weight canary, 100-canary_pct% chia đều cho còn lại
    local canary_weight=$(( canary_pct ))
    local stable_weight=$(( 100 - canary_pct ))
    (( total_backends > 1 )) && stable_weight=$(( stable_weight / total_backends ))
    (( stable_weight < 1 )) && stable_weight=1

    # Bước 1: Giảm weight stable backends TRƯỚC khi thêm canary
    # Fix H5: nếu thêm canary trước rồi mới sed stable weight,
    # regex "server IP:PORT weight=N" cũng match canary line vừa thêm
    # → canary_weight bị ghi đè thành stable_weight → canary nhận sai % traffic
    # Giải pháp: đổi thứ tự — sed stable trước, insert canary sau
    sed -i "s|\(server [0-9.]*:[0-9]* weight=\)[0-9]*|\1${stable_weight}|g" "$ufile" 2>/dev/null || true

    # Bước 2: Thêm canary backend với weight riêng — marker # CANARY để phân biệt
    sed -i "s|    # MVPS_SERVERS_END|    server ${CANARY_IP}:${CANARY_PORT} weight=${canary_weight} max_fails=3 fail_timeout=30s; # CANARY\n    # MVPS_SERVERS_END|" "$ufile"

    nginx_safe_reload
    warn "Canary deploy: ${CANARY_IP}:${CANARY_PORT} nhận ~${canary_pct}% traffic (weight=${canary_weight})"
    warn "Stable backends nhận ~$(( 100 - canary_pct ))% (weight=${stable_weight} mỗi backend)"
    echo ""
    echo "1) Promote canary lên 100%   2) Rollback (xóa canary)"
    read -rp "Chọn: " ACTION
    case "$ACTION" in
        1)
            # Xóa tất cả stable backends (không có # CANARY), giữ lại canary
            sed -i '/# CANARY/!{/^\s*server /d}' "$ufile"
            # Bỏ tag # CANARY khỏi line canary và reset weight về 1
            sed -i 's| # CANARY||' "$ufile"
            sed -i "s|\(server ${CANARY_IP}:${CANARY_PORT}[^;]* weight=\)[0-9]*|\11|" "$ufile"
            nginx_safe_reload
            log "Canary promoted → 100% traffic (weight=1)"
            ;;
        2)
            # Xóa dòng canary, restore weight stable về 1
            sed -i '/# CANARY/d' "$ufile"
            sed -i "s|\(server [0-9.]*:[0-9]* weight=\)[0-9]*|\11|g" "$ufile" 2>/dev/null || true
            nginx_safe_reload
            log "Canary rolled back — stable backends restored weight=1"
            ;;
    esac
}

# ════════════════════════════════════════════════
# TRAFFIC ANALYTICS
# ════════════════════════════════════════════════

do_traffic_analytics() {
    echo ""
    echo "1) Requests/backend hôm nay   3) Top 10 source IPs"
    echo "2) Response time trung bình   4) 502/504 per backend"
    echo "5) Requests/giờ (ASCII chart)"
    read -rp "Chọn: " C
    case "$C" in
        1)
            echo -e "${BOLD}Requests/backend hôm nay:${NC}"
            local today; today=$(date '+%d/%b/%Y')
            awk -v d="$today" '$0 ~ d && /upstream=/ {
                match($0, /upstream=([^ ]+)/, a); print a[1]
            }' /var/log/nginx/access.log 2>/dev/null \
                | sort | uniq -c | sort -rn \
                | awk '{printf "  %7d  %s\n", $1, $2}'
            ;;
        2)
            echo -e "${BOLD}Response time trung bình (ms) per backend:${NC}"
            awk '/upstream=/ && /upstream_rt=/ {
                match($0, /upstream=([^ ]+)/, a)
                match($0, /upstream_rt=([0-9.]+)/, b)
                sum[a[1]] += b[1]+0; cnt[a[1]]++
            }
            END {
                for (k in sum) printf "  %-25s %.0f ms\n", k, sum[k]/cnt[k]*1000
            }' /var/log/nginx/access.log 2>/dev/null | sort -t= -k2 -rn
            ;;
        3)
            echo -e "${BOLD}Top 10 source IPs:${NC}"
            awk '{print $1}' /var/log/nginx/access.log 2>/dev/null \
                | sort | uniq -c | sort -rn | head -10 \
                | awk '{printf "  %7d  %s\n", $1, $2}'
            ;;
        4)
            echo -e "${BOLD}502/504 errors per backend:${NC}"
            awk '$9 ~ /^(502|504)$/ && /upstream=/ {
                match($0, /upstream=([^ ]+)/, a)
                print $9, a[1]
            }' /var/log/nginx/access.log 2>/dev/null \
                | sort | uniq -c | sort -rn | head -20 \
                | awk '{printf "  %6d  %s  %s\n", $1, $2, $3}'
            ;;
        5)
            echo -e "${BOLD}Requests/giờ hôm nay:${NC}"
            local today; today=$(date '+%d/%b/%Y')
            awk -v d="$today" '$0 ~ d {
                match($4, /:[0-9]+:([0-9]+):/, a); print a[1]
            }' /var/log/nginx/access.log 2>/dev/null \
                | sort | uniq -c | sort -k2 -n \
                | awk '{
                    bar=""; n=int($1/100)
                    for(i=0;i<n;i++) bar=bar"█"
                    printf "  %02dh [%-30s] %d\n", $2, bar, $1
                }'
            ;;
    esac
}

# ════════════════════════════════════════════════
# NGINX STATS (stub_status)
# ════════════════════════════════════════════════

do_nginx_stats() {
    echo ""
    local stub; stub=$(curl -sf --max-time 2 http://127.0.0.1/nginx_status 2>/dev/null)
    if [[ -z "$stub" ]]; then
        warn "Không lấy được nginx stub_status"
        warn "Kiểm tra: /etc/nginx/conf.d/stub-status.conf"
        return
    fi
    echo -e "${BOLD}── Nginx Realtime Stats ────────────────${NC}"
    echo "$stub" | awk '
        /Active connections/{printf "  Active connections : %s\n", $3}
        /server accepts/{getline; printf "  Accepts/Handled   : %s / %s\n", $1, $2; printf "  Total requests    : %s\n", $3}
        /Reading:/{printf "  Reading: %s | Writing: %s | Waiting: %s\n", $2, $4, $6}
    '
}

# ════════════════════════════════════════════════
# FIREWALL
# ════════════════════════════════════════════════

do_firewall() {
    echo ""
    echo "1) Xem rules   3) Unblock IP  5) Fail2ban status"
    echo "2) Block IP    4) Mở port     6) Blocked list"
    read -rp "Chọn: " C
    case "$C" in
        1) nft list ruleset 2>/dev/null ;;
        2)
            read -rp "IP cần block: " BIP; validate_ip "$BIP" || return
            nft add element inet modernvps blacklist_v4 "{ $BIP }" 2>/dev/null \
                && log "Blocked: $BIP" || warn "Thất bại"
            ;;
        3)
            read -rp "IP cần unblock: " UIP; validate_ip "$UIP" || return
            nft delete element inet modernvps blacklist_v4 "{ $UIP }" 2>/dev/null \
                && log "Unblocked: $UIP" || warn "Không tìm thấy"
            ;;
        4)
            read -rp "Port: " P
            [[ ! "$P" =~ ^[0-9]+$ ]] && { warn "Port không hợp lệ"; return; }
            nft add rule inet modernvps input tcp dport "$P" ct state new accept 2>/dev/null \
                && log "Đã mở $P (runtime)" || warn "Thất bại"
            ;;
        5) fail2ban-client status 2>/dev/null ;;
        6) nft list set inet modernvps blacklist_v4 2>/dev/null ;;
    esac
}

# ════════════════════════════════════════════════
# CIS AUDIT (LB)
# ════════════════════════════════════════════════

do_cis_audit() {
    echo ""
    echo -e "${BOLD}═══ CIS Security Audit (Load Balancer) ═══${NC}"
    local score=0 total=0
    _chk() {
        local label="$1"; shift
        total=$(( total+1 ))
        if eval "$*" &>/dev/null; then
            echo -e "  ${GREEN}✅${NC} $label"
            score=$(( score+1 ))
        else
            echo -e "  ${RED}❌${NC} $label"
        fi
    }
    _chk "SSH: no root login"   "grep -q 'PermitRootLogin no' /etc/ssh/sshd_config.d/99-modernvps.conf"
    _chk "SSH: port 2222"       "grep -q 'Port 2222' /etc/ssh/sshd_config.d/99-modernvps.conf"
    _chk "nftables active"      "systemctl is-active nftables"
    _chk "Fail2ban active"      "systemctl is-active fail2ban"
    _chk "Auditd active"        "systemctl is-active auditd"
    _chk "BBR enabled"          "sysctl -n net.ipv4.tcp_congestion_control | grep -q bbr"
    _chk "ASLR = 2"             "[ \$(sysctl -n kernel.randomize_va_space) -eq 2 ]"
    _chk "Nginx running"        "systemctl is-active nginx"
    _chk "Cron restricted"      "test -f /etc/cron.allow"
    _chk "Health check cron"    "grep -q mvps-healthcheck /etc/cron.d/modernvps-backup 2>/dev/null"
    _chk "ModSecurity WAF"      "grep -q 'modsecurity on' /etc/nginx/nginx.conf 2>/dev/null"
    _chk "Maintenance: OFF"     "test ! -f ${MAINTENANCE_FLAG}"
    _chk "Auto updates"         "systemctl is-active unattended-upgrades 2>/dev/null || systemctl is-active dnf-automatic.timer 2>/dev/null"
    echo ""
    local pct=$(( score * 100 / total ))
    local c="$RED"
    (( pct >= 70 )) && c="$YELLOW"
    (( pct >= 90 )) && c="$GREEN"
    echo -e "  Score: ${c}${score}/${total} (${pct}%)${NC}"
}

# ════════════════════════════════════════════════
# MAIN MENU LOOP — LOAD BALANCER
# ════════════════════════════════════════════════

source /opt/modernvps/lib/common.sh 2>/dev/null || true

while true; do
    clear
    render_header_lb 2>/dev/null || {
        _up=""; _rm=""; _rt=""; _load=""; _disk=""; _h=""; _ud=""
        read -r _up _ < /proc/uptime 2>/dev/null
        _ud=$(awk -v s="${_up:-0}" 'BEGIN{printf "%dd%dh",s/86400,(s%86400)/3600}')
        _h=$(hostname -s 2>/dev/null || echo "unknown")
        read -r _rm _rt < <(awk '/MemTotal/{t=$2}/MemAvailable/{a=$2}END{printf "%d %d",(t-a)/1024,t/1024}' /proc/meminfo 2>/dev/null)
        read -r _load _ < /proc/loadavg 2>/dev/null
        _disk=$(df -h / 2>/dev/null | awk 'NR==2{print $5}')
        echo "═══════════════════════════════════════════"
        printf "  ModernVPS v3.2 (lb) | %s | Up %s\n" "$_h" "$_ud"
        printf "  CPU: %-4s | RAM: %s/%sMB | DSK: %s\n" "$_load" "${_rm:-?}" "${_rt:-?}" "${_disk:-?}"
        echo "═══════════════════════════════════════════"
    }
    echo ""
    echo -e " ${BOLD}[BACKENDS]${NC}"
    echo "  1) Backend status       2) Upstream manager"
    echo "  3) Thêm backend         4) Xóa backend (drain)"
    echo "  5) Canary deploy"
    echo ""
    echo -e " ${BOLD}[ROUTING]${NC}"
    echo "  6) Tạo proxy vhost      7) LB method"
    echo "  8) Maintenance mode"
    echo ""
    echo -e " ${BOLD}[SSL & SECURITY]${NC}"
    echo "  9) SSL manager         10) Firewall"
    echo " 11) Fail2ban"
    echo ""
    echo -e " ${BOLD}[MONITORING]${NC}"
    echo " 12) Traffic analytics   13) Nginx stats"
    echo " 14) Xem log (tail)"
    echo ""
    echo -e " ${BOLD}[CLUSTER]${NC}"
    echo " 20) Dashboard nodes     21) Add web node"
    echo " 22) Remove node         23) Metrics tất cả"
    echo " 24) Drain node          25) Undrain node"
    echo " 26) Rolling deploy      27) Rotate token"
    echo ""
    echo -e " ${BOLD}[SYSTEM]${NC}"
    echo " 15) Backup              16) CIS audit"
    echo " 17) Disk & resources    18) Restart Nginx"
    echo " 19) Update system        0) Thoát"
    echo "═══════════════════════════════════════════"
    read -rp "Chọn: " CHOICE
    case "$CHOICE" in
        1)  do_backend_status || true ;;
        2)  do_upstream_manager || true ;;
        3)  echo ""; read -rp "Tên group [backend]: " _G; _G="${_G:-backend}"
            read -rp "IP backend: " _IP; validate_ip "$_IP" || { press_enter; continue; }
            read -rp "Port [80]: " _P; _P="${_P:-80}"
            read -rp "Weight [1]: " _W; _W="${_W:-1}"
            read -rp "Label: " _L; _L="${_L:-${_IP}}"
            _init_upstream "$_G"
            _uf=$(_upstream_file "$_G")
            sed -i "s|    # MVPS_SERVERS_END|    server ${_IP}:${_P} weight=${_W} max_fails=3 fail_timeout=30s;\n    # MVPS_SERVERS_END|" "$_uf"
            command -v jq &>/dev/null && {
                _tmp=$(mktemp)
                jq --arg ip "$_IP" --arg port "$_P" --arg label "$_L" --arg group "$_G" \
                   --arg date "$(date -Iseconds)" \
                   '.backends += [{"ip":$ip,"port":($port|tonumber),"label":$label,"group":$group,"added":$date,"status":"unknown"}]' \
                   "$INVENTORY" > "$_tmp" 2>/dev/null && mv "$_tmp" "$INVENTORY"
            }
            nginx_safe_reload
            log "Đã thêm ${_IP}:${_P} vào '${_G}'" ;;
        4)  do_drain_backend || true ;;
        5)  do_canary_deploy || true ;;
        6)  do_create_proxy_vhost || true ;;
        7)  do_set_lb_method || true ;;
        8)  do_maintenance_mode || true ;;
        9)
            echo "1) List certs  2) Cấp SSL  3) Renew"
            read -rp "Chọn: " SC
            case "$SC" in
                1) certbot certificates 2>/dev/null ;;
                2)
                    read -rp "Domain: " D; D=$(sanitize_domain "$D") || true
                    certbot --nginx -d "$D" --email "$ADMIN_EMAIL" \
                        --agree-tos --non-interactive 2>/dev/null \
                        && nginx_safe_reload && log "SSL: $D" || warn "SSL thất bại"
                    ;;
                3) certbot renew --post-hook "systemctl reload nginx" 2>/dev/null \
                    && log "Renew OK" || warn "Renew thất bại" ;;
            esac
            ;;
        10) do_firewall || true ;;
        11) fail2ban-client status 2>/dev/null ;;
        12) do_traffic_analytics || true ;;
        13) do_nginx_stats || true ;;
        14)
            echo "1) access.log  2) error.log"
            read -rp "Chọn: " LT
            case "$LT" in
                1) echo "(Ctrl+C để dừng)"; tail -f /var/log/nginx/access.log 2>/dev/null ;;
                2) echo "(Ctrl+C để dừng)"; tail -f /var/log/nginx/error.log 2>/dev/null ;;
            esac
            ;;
        15) log "Chạy backup..."; /usr/local/bin/mvps-backup && log "Done!" \
            || warn "Backup có lỗi"; ls -lh "$BACKUP_DIR"/ 2>/dev/null | tail -5 ;;
        16) do_cis_audit || true ;;
        17) echo "── Disk ──"; df -h / "$BACKUP_DIR" 2>/dev/null
            echo "── Memory ──"; free -h
            echo "── Load ──"; uptime
            echo "── Connections ──"; ss -s 2>/dev/null | head -5
            ;;
        18) systemctl restart nginx 2>/dev/null \
            && log "✅ Nginx restarted" || warn "Restart thất bại" ;;
        19) case "$OS_FAMILY" in
                debian) apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y ;;
                rhel)   dnf update -y ;;
            esac
            systemctl restart nginx 2>/dev/null
            log "Updated!" ;;
        # ── CLUSTER ──────────────────────────────────
        20) /usr/local/bin/mvps-cluster dashboard ;;
        21) echo ""
            read -rp "Node ID (vd: web-01): " _NID
            read -rp "Internal IP: "          _NIP
            read -rp "Agent token (từ web node): " _NTOK
            /usr/local/bin/mvps-cluster add-node "$_NID" "$_NIP" "$_NTOK" ;;
        22) echo ""
            read -rp "Node ID cần xóa: " _NID
            read -rp "Xác nhận xóa ${_NID}? (y/N): " _CONF
            [[ "$_CONF" =~ ^[Yy]$ ]] \
                && /usr/local/bin/mvps-cluster remove-node "$_NID" \
                || warn "Hủy" ;;
        23) /usr/local/bin/mvps-cluster metrics all ;;
        24) echo ""
            read -rp "Node ID cần drain: " _NID
            /usr/local/bin/mvps-cluster drain "$_NID" ;;
        25) echo ""
            read -rp "Node ID cần undrain: " _NID
            /usr/local/bin/mvps-cluster undrain "$_NID" ;;
        26) echo ""
            read -rp "Đường dẫn tarball: " _TAR
            read -rp "Nodes (all hoặc web-01,web-02): " _NODES
            _NODES="${_NODES:-all}"
            /usr/local/bin/mvps-cluster deploy --tarball "$_TAR" --nodes "$_NODES" ;;
        27) echo ""
            read -rp "Node ID (hoặc 'all'): " _NID
            /usr/local/bin/mvps-cluster rotate-token "$_NID" ;;
        0)  exit 0 ;;
        *)  warn "Lựa chọn không hợp lệ" ;;
    esac
    press_enter
done
MENUEOF
    chmod +x "${INSTALL_DIR}/menu.sh"
    log "Menu Load Balancer đã tạo"
}
# ══════════════════════════════════════════════════
# MVPS-CLUSTER SCRIPT (chạy trên LB)
# CLI tool quản lý cluster: add-node, metrics, drain, deploy
# ══════════════════════════════════════════════════

_install_mvps_cluster() {
    log "Cài mvps-cluster CLI..."

    cat > /usr/local/bin/mvps-cluster << 'CLEOF'
#!/bin/bash
# ModernVPS Cluster Manager v1.0
# Chạy trên LB node — quản lý web nodes qua HTTP API
set -uo pipefail

source /opt/modernvps/config.env 2>/dev/null || {
    echo "[ERROR] Không đọc được config.env" >&2; exit 1
}

CLUSTER_JSON="/opt/modernvps/cluster.json"
TOKENS_JSON="/opt/modernvps/cluster-tokens.json"
METRICS_JSON="/opt/modernvps/cluster-metrics.json"
AGENT_PORT=9000
CURL_TIMEOUT=10

# ── Màu sắc ──────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✅${NC} $*"; }
fail() { echo -e "${RED}❌${NC} $*"; }
warn() { echo -e "${YELLOW}⚠${NC}  $*"; }
info() { echo -e "${CYAN}ℹ${NC}  $*"; }

# ── Helpers ───────────────────────────────────────

# Lấy token của node từ cluster-tokens.json
get_node_token() {
    local node_id="$1"
    [[ ! -f "$TOKENS_JSON" ]] && { echo ""; return 1; }
    jq -r --arg id "$node_id" '.nodes[$id].token // ""' "$TOKENS_JSON" 2>/dev/null
}

# Gọi agent API trên một node
# $1: node_id, $2: method (GET/POST), $3: endpoint, $4: extra curl args
agent_call() {
    local node_id="$1" method="$2" endpoint="$3"
    shift 3
    local extra=("$@")

    local ip port token
    ip=$(jq -r --arg id "$node_id" '.nodes[] | select(.id==$id) | .internal_ip' \
        "$CLUSTER_JSON" 2>/dev/null)
    port=$(jq -r --arg id "$node_id" '.nodes[] | select(.id==$id) | .agent_port // 9000' \
        "$CLUSTER_JSON" 2>/dev/null)
    token=$(get_node_token "$node_id")

    [[ -z "$ip" || -z "$token" ]] && {
        echo '{"error":"node not found or no token"}'; return 1
    }

    curl -sf --max-time "$CURL_TIMEOUT" \
        -X "$method" \
        -H "Authorization: Bearer ${token}" \
        -H "Accept: application/json" \
        "${extra[@]}" \
        "http://${ip}:${port}${endpoint}" 2>/dev/null
}

# Lấy danh sách node IDs từ cluster.json
list_node_ids() {
    [[ ! -f "$CLUSTER_JSON" ]] && return
    jq -r '.nodes[].id' "$CLUSTER_JSON" 2>/dev/null
}

# ── Commands ─────────────────────────────────────

cmd_help() {
    echo -e "${BOLD}mvps-cluster${NC} — ModernVPS Cluster Manager"
    echo ""
    echo "  add-node   <id> <internal_ip> <token>   Thêm web node vào cluster"
    echo "  remove-node <id>                         Xóa web node khỏi cluster"
    echo "  list                                     Danh sách nodes + trạng thái"
    echo "  metrics    [node_id|all]                 Metrics CPU/RAM/disk/sites"
    echo "  health     [node_id|all]                 Health check tất cả services"
    echo "  drain      <node_id>                     Graceful drain node"
    echo "  undrain    <node_id>                     Restore traffic về node"
    echo "  deploy     --tarball <file> [--nodes <id,id|all>]  Rolling deploy"
    echo "  rotate-token <node_id>                   Rotate token của node"
    echo "  rotate-token all                         Rotate tất cả tokens"
    echo "  dashboard                                Live dashboard (refresh 5s)"
}

cmd_add_node() {
    local node_id="${1:-}" ip="${2:-}" token="${3:-}"
    [[ -z "$node_id" || -z "$ip" || -z "$token" ]] && {
        echo "Usage: mvps-cluster add-node <id> <internal_ip> <token>"
        exit 1
    }

    # Validate IP
    if ! echo "$ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        fail "IP không hợp lệ: $ip"; exit 1
    fi

    # Validate token format
    if ! echo "$token" | grep -qE '^mvps_wn_[a-zA-Z0-9]{32}$'; then
        fail "Token không đúng format (cần: mvps_wn_xxx...32 chars)"
        info "Lấy token từ web node: cat /opt/modernvps/agent-token.json"
        exit 1
    fi

    # Test kết nối trước khi lưu
    info "Kiểm tra kết nối đến ${ip}:${AGENT_PORT}..."
    local result
    result=$(curl -sf --max-time 5 \
        -H "Authorization: Bearer ${token}" \
        "http://${ip}:${AGENT_PORT}/mvps/health" 2>/dev/null) || {
        fail "Không kết nối được đến agent ${ip}:${AGENT_PORT}"
        warn "Kiểm tra: firewall web node có mở port 9000 cho LB IP không?"
        exit 1
    }

    local overall; overall=$(echo "$result" | jq -r '.overall // "UNKNOWN"' 2>/dev/null)

    # Khởi tạo cluster.json nếu chưa có
    if [[ ! -f "$CLUSTER_JSON" ]]; then
        jq -n --arg lb "$(hostname -s)" \
            '{"version":"1.0","lb_id":$lb,"updated":"","nodes":[]}' \
            > "$CLUSTER_JSON"
        chmod 600 "$CLUSTER_JSON"
    fi

    # Thêm node vào cluster.json
    local tmp; tmp=$(mktemp)
    jq --arg id "$node_id" --arg ip "$ip" --arg port "$AGENT_PORT" \
       --arg added "$(date -Iseconds)" \
       '.nodes += [{"id":$id,"internal_ip":$ip,"agent_port":($port|tonumber),
         "status":"active","added":$added,"last_seen":$added}]
        | .updated = (now | todate)' \
        "$CLUSTER_JSON" > "$tmp" && mv "$tmp" "$CLUSTER_JSON"
    chmod 600 "$CLUSTER_JSON"

    # Lưu token vào cluster-tokens.json
    if [[ ! -f "$TOKENS_JSON" ]]; then
        echo '{"nodes":{}}' > "$TOKENS_JSON"
        chmod 600 "$TOKENS_JSON"
    fi
    local tmp2; tmp2=$(mktemp)
    jq --arg id "$node_id" --arg tok "$token" \
       --arg iss "$(date -Iseconds)" \
       --arg exp "$(date -Iseconds -d '+30 days')" \
       '.nodes[$id] = {"token":$tok,"issued":$iss,"expires":$exp}' \
       "$TOKENS_JSON" > "$tmp2" && mv "$tmp2" "$TOKENS_JSON"
    chmod 600 "$TOKENS_JSON"

    # ── Gap #1 Fix: Thêm node vào Nginx upstream ngay sau khi join cluster ──
    # Nếu không làm bước này, node join cluster nhưng LB không forward traffic
    local upstream_group="backend"
    local upstream_port=80
    read -rp "Thêm ${ip} vào Nginx upstream group [backend/bỏ qua]: " _ug
    if [[ -n "$_ug" && "$_ug" != "bỏ qua" ]]; then
        upstream_group="$_ug"
        read -rp "Port web node [80]: " _up; upstream_port="${_up:-80}"
        local ufile="/etc/nginx/conf.d/upstream-${upstream_group}.conf"

        # Tạo upstream group nếu chưa có
        if [[ ! -f "$ufile" ]]; then
            {   printf "upstream %s {\n" "$upstream_group"
                printf "    least_conn;\n"
                printf "    keepalive 32;\n"
                printf "    keepalive_requests 1000;\n"
                printf "    keepalive_timeout  60s;\n"
                printf "    # MVPS_SERVERS_START\n"
                printf "    # MVPS_SERVERS_END\n"
                printf "}\n"
            } > "$ufile"
            info "Tạo upstream group mới: ${upstream_group}"
        fi

        # Kiểm tra đã tồn tại chưa để tránh duplicate
        if grep -q "server ${ip}:${upstream_port}" "$ufile" 2>/dev/null; then
            warn "server ${ip}:${upstream_port} đã có trong upstream '${upstream_group}'"
        else
            local srv_line="    server ${ip}:${upstream_port} weight=1 max_fails=3 fail_timeout=30s;"
            sed -i "s|    # MVPS_SERVERS_END|${srv_line}\n    # MVPS_SERVERS_END|" "$ufile"

            # Lưu vào backends.json inventory để healthcheck biết
            local inv="/opt/modernvps/backends.json"
            [[ ! -f "$inv" ]] && echo '{"backends":[]}' > "$inv"
            if command -v jq &>/dev/null; then
                local _tmp; _tmp=$(mktemp)
                jq --arg ip "$ip" --arg port "$upstream_port" \
                   --arg label "$node_id" --arg group "$upstream_group" \
                   --arg date "$(date -Iseconds)" \
                   '.backends += [{"ip":$ip,"port":($port|tonumber),"label":$label,
                     "group":$group,"added":$date,"status":"unknown"}]' \
                   "$inv" > "$_tmp" 2>/dev/null && mv "$_tmp" "$inv"
            fi

            # Reload nginx
            if nginx -t &>/dev/null; then
                systemctl reload nginx 2>/dev/null \
                    && ok "Đã thêm ${ip}:${upstream_port} vào upstream '${upstream_group}' — nginx reloaded" \
                    || warn "nginx reload thất bại — kiểm tra: nginx -t"
            else
                warn "nginx config lỗi sau khi thêm upstream — kiểm tra: nginx -t"
            fi
        fi
    else
        info "Bỏ qua upstream — thêm thủ công qua: sudo mvps → option 3 (Thêm backend)"
    fi

    ok "Node ${node_id} (${ip}) đã thêm vào cluster — health: ${overall}"
}

cmd_remove_node() {
    local node_id="${1:-}"
    [[ -z "$node_id" ]] && { echo "Usage: mvps-cluster remove-node <id>"; exit 1; }

    [[ ! -f "$CLUSTER_JSON" ]] && { fail "cluster.json không tồn tại"; exit 1; }

    # Lấy IP trước khi xóa khỏi cluster.json
    local ip; ip=$(jq -r --arg id "$node_id" \
        '.nodes[] | select(.id==$id) | .internal_ip' "$CLUSTER_JSON" 2>/dev/null)

    if [[ -z "$ip" ]]; then
        fail "Node '${node_id}' không tồn tại trong cluster"
        exit 1
    fi

    # ── Gap #2 Fix: Drain trước, xóa upstream, rồi mới xóa khỏi cluster.json ──
    # Không drain → drop request đang xử lý ngay lập tức

    # Bước 1: Drain node — agent trả 503 cho LB health check
    info "Bước 1/3: Drain node ${node_id} (${ip})..."
    agent_call "$node_id" POST /mvps/drain >/dev/null 2>&1 \
        && info "Node đang drain — LB ngừng gửi request mới" \
        || warn "Drain agent thất bại (node có thể offline) — tiếp tục xóa"

    # Bước 2: Xóa khỏi tất cả Nginx upstream conf → LB không forward nữa
    info "Bước 2/3: Xóa ${ip} khỏi Nginx upstream..."
    local removed_from_nginx=false
    for ufile in /etc/nginx/conf.d/upstream-*.conf; do
        [[ -f "$ufile" ]] || continue
        if grep -q "server ${ip}:" "$ufile" 2>/dev/null; then
            sed -i "/server ${ip}:/d" "$ufile"
            removed_from_nginx=true
        fi
    done
    # Xóa khỏi backends.json inventory
    local inv="/opt/modernvps/backends.json"
    if [[ -f "$inv" ]] && command -v jq &>/dev/null; then
        local _tmp; _tmp=$(mktemp)
        jq --arg ip "$ip" \
            '.backends = [.backends[] | select(.ip != $ip)]' \
            "$inv" > "$_tmp" 2>/dev/null && mv "$_tmp" "$inv"
    fi
    if [[ "$removed_from_nginx" == "true" ]]; then
        if nginx -t &>/dev/null; then
            systemctl reload nginx 2>/dev/null \
                && info "Nginx reloaded — ${ip} không còn nhận traffic"
        else
            warn "nginx config lỗi — kiểm tra thủ công: nginx -t"
        fi
    else
        info "Không tìm thấy ${ip} trong upstream conf (có thể chưa được thêm)"
    fi

    # Bước 3: Chờ drain graceful (15s đủ cho request đang xử lý hoàn thành)
    info "Bước 3/3: Chờ drain graceful (15s)..."
    sleep 15

    # Xóa khỏi cluster.json
    local tmp; tmp=$(mktemp)
    jq --arg id "$node_id" 'del(.nodes[] | select(.id==$id)) | .updated=(now|todate)' \
        "$CLUSTER_JSON" > "$tmp" && mv "$tmp" "$CLUSTER_JSON"

    # Xóa token
    if [[ -f "$TOKENS_JSON" ]]; then
        local tmp2; tmp2=$(mktemp)
        jq --arg id "$node_id" 'del(.nodes[$id])' "$TOKENS_JSON" > "$tmp2" \
            && mv "$tmp2" "$TOKENS_JSON"
    fi

    ok "Node ${node_id} (${ip}) đã xóa khỏi cluster an toàn"
}

cmd_list() {
    [[ ! -f "$CLUSTER_JSON" ]] && { warn "Chưa có node nào trong cluster"; return; }

    local nodes; nodes=$(jq -r '.nodes[].id' "$CLUSTER_JSON" 2>/dev/null)
    [[ -z "$nodes" ]] && { warn "Cluster trống"; return; }

    printf "\n${BOLD}%-12s %-16s %-10s %-12s %-10s${NC}\n" \
        "NODE ID" "INTERNAL IP" "STATUS" "HEALTH" "LAST SEEN"
    echo "────────────────────────────────────────────────────────────"

    while IFS= read -r node_id; do
        local ip last_seen
        ip=$(jq -r --arg id "$node_id" '.nodes[] | select(.id==$id) | .internal_ip' \
            "$CLUSTER_JSON")
        last_seen=$(jq -r --arg id "$node_id" '.nodes[] | select(.id==$id) | .last_seen' \
            "$CLUSTER_JSON" | cut -c1-16 | tr 'T' ' ')

        # Quick health check (timeout ngắn)
        local health="UNKNOWN"
        local result
        result=$(agent_call "$node_id" GET /mvps/health 2>/dev/null) && \
            health=$(echo "$result" | jq -r '.overall // "UNKNOWN"' 2>/dev/null)

        local color="$NC"
        case "$health" in
            UP)       color="$GREEN" ;;
            DRAINING) color="$YELLOW" ;;
            DEGRADED|UNKNOWN) color="$RED" ;;
        esac

        printf "%-12s %-16s %-10s ${color}%-12s${NC} %-10s\n" \
            "$node_id" "$ip" "active" "$health" "$last_seen"
    done <<< "$nodes"
    echo ""
}

cmd_metrics() {
    local target="${1:-all}"
    local node_ids=()

    if [[ "$target" == "all" ]]; then
        mapfile -t node_ids < <(list_node_ids)
    else
        node_ids=("$target")
    fi

    [[ ${#node_ids[@]} -eq 0 ]] && { warn "Không có node nào"; return; }

    printf "\n${BOLD}%-10s %-6s %-5s %-5s %-16s %-8s %-6s %-8s${NC}\n" \
        "NODE" "CPU1m" "RAM%" "DSK%" "RAM (used/total)" "SITES" "CONN" "DRAINING"
    echo "────────────────────────────────────────────────────────────────────────────"

    for node_id in "${node_ids[@]}"; do
        local result; result=$(agent_call "$node_id" GET /mvps/metrics 2>/dev/null)
        if [[ -z "$result" ]]; then
            printf "%-10s ${RED}%-6s${NC}\n" "$node_id" "OFFLINE"
            continue
        fi

        local cpu ram_pct ram_used ram_total disk_pct sites conn draining
        cpu=$(echo "$result"       | jq -r '.cpu.load1 // "?"')
        ram_pct=$(echo "$result"   | jq -r '.ram.used_pct // "?"')
        ram_used=$(echo "$result"  | jq -r '.ram.used_mb // "?"')
        ram_total=$(echo "$result" | jq -r '.ram.total_mb // "?"')
        disk_pct=$(echo "$result"  | jq -r '.disk.used_pct // "?"')
        sites=$(echo "$result"     | jq -r '.sites // "?"')
        conn=$(echo "$result"      | jq -r '.nginx_conn // "?"')
        draining=$(echo "$result"  | jq -r 'if .draining then "YES" else "no" end')

        # Màu theo ngưỡng RAM
        local ram_color="$GREEN"
        (( $(echo "$ram_pct > 85" | bc -l 2>/dev/null || echo 0) )) && ram_color="$RED"
        (( $(echo "$ram_pct > 70" | bc -l 2>/dev/null || echo 0) )) && ram_color="$YELLOW"

        printf "%-10s %-6s ${ram_color}%-5s${NC} %-5s %-16s %-8s %-6s %-8s\n" \
            "$node_id" "$cpu" "${ram_pct}%" "${disk_pct}%" \
            "${ram_used}/${ram_total}MB" "$sites" "$conn" "$draining"

        # Cảnh báo SSL sắp hết hạn
        local ssl_warn; ssl_warn=$(echo "$result" | \
            jq -r '.ssl_expiring[] | "  ⚠ SSL \(.domain): \(.days_left) ngày"' 2>/dev/null)
        [[ -n "$ssl_warn" ]] && echo -e "${YELLOW}${ssl_warn}${NC}"
    done
    echo ""
}

cmd_drain() {
    local node_id="${1:-}"
    [[ -z "$node_id" ]] && { echo "Usage: mvps-cluster drain <node_id>"; exit 1; }

    info "Drain node ${node_id}..."
    local result; result=$(agent_call "$node_id" POST /mvps/drain)
    local status; status=$(echo "$result" | jq -r '.status // "error"' 2>/dev/null)

    case "$status" in
        draining|already_draining)
            ok "Node ${node_id} đang drain — LB sẽ ngừng gửi traffic sau health check"
            info "Kiểm tra: mvps-cluster health ${node_id}"
            ;;
        *)
            fail "Drain thất bại: $result"
            ;;
    esac
}

cmd_undrain() {
    local node_id="${1:-}"
    [[ -z "$node_id" ]] && { echo "Usage: mvps-cluster undrain <node_id>"; exit 1; }

    info "Restore traffic về node ${node_id}..."
    local result; result=$(agent_call "$node_id" POST /mvps/drain/cancel)
    local status; status=$(echo "$result" | jq -r '.status // "error"' 2>/dev/null)

    [[ "$status" == "active" || "$status" == "not_draining" ]] \
        && ok "Node ${node_id} đã active — LB sẽ gửi traffic trở lại" \
        || fail "Undrain thất bại: $result"
}

cmd_deploy() {
    local tarball="" nodes_arg="all"

    # Parse args
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --tarball) tarball="$2"; shift 2 ;;
            --nodes)   nodes_arg="$2"; shift 2 ;;
            *) shift ;;
        esac
    done

    [[ -z "$tarball" ]] && { echo "Usage: mvps-cluster deploy --tarball <file> [--nodes all|id1,id2]"; exit 1; }
    [[ ! -f "$tarball" ]] && { fail "File không tồn tại: $tarball"; exit 1; }

    # Build danh sách nodes
    local node_ids=()
    if [[ "$nodes_arg" == "all" ]]; then
        mapfile -t node_ids < <(list_node_ids)
    else
        IFS=',' read -ra node_ids <<< "$nodes_arg"
    fi

    [[ ${#node_ids[@]} -eq 0 ]] && { warn "Không có node nào để deploy"; exit 1; }

    local checksum; checksum=$(sha256sum "$tarball" | cut -d' ' -f1)
    local filesize; filesize=$(du -sh "$tarball" | cut -f1)

    echo ""
    echo -e "${BOLD}═══ Rolling Deploy ═══${NC}"
    echo "  Tarball : $(basename "$tarball") (${filesize})"
    echo "  SHA256  : ${checksum}"
    echo "  Nodes   : ${node_ids[*]}"
    echo ""
    read -rp "Xác nhận deploy? (y/N): " confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { info "Hủy deploy"; exit 0; }

    local failed=0
    for node_id in "${node_ids[@]}"; do
        echo ""
        echo -e "${CYAN}── Node: ${node_id} ──────────────────────${NC}"

        # Bước 1: Drain
        info "[1/5] Drain node ${node_id}..."
        cmd_drain "$node_id"

        # Bước 2: Chờ health check trả 503 (max 2 phút)
        info "[2/5] Chờ drain hoàn tất..."
        local waited=0
        while (( waited < 120 )); do
            local health_result; health_result=$(agent_call "$node_id" GET /mvps/health 2>/dev/null)
            local hstatus; hstatus=$(echo "$health_result" | jq -r '.overall // ""')
            [[ "$hstatus" == "DRAINING" ]] && break
            sleep 3; (( waited += 3 ))
        done
        (( waited >= 120 )) && { warn "Drain timeout — tiếp tục deploy..."; }

        # Bước 3: Upload tarball
        info "[3/5] Upload tarball (${filesize})..."
        local deploy_result
        deploy_result=$(agent_call "$node_id" POST /mvps/deploy \
            -F "tarball=@${tarball}" \
            -F "checksum=${checksum}" \
            -F "target=html" \
            --max-time 600 2>/dev/null)

        local dstatus; dstatus=$(echo "$deploy_result" | jq -r '.status // "error"' 2>/dev/null)
        if [[ "$dstatus" != "running" ]]; then
            fail "Deploy upload thất bại: $deploy_result"
            cmd_undrain "$node_id"
            (( failed++ ))
            continue
        fi

        # Bước 4: Poll deploy status
        info "[4/5] Chờ deploy hoàn tất..."
        local poll_waited=0
        local final_status=""
        while (( poll_waited < 600 )); do
            sleep 5; (( poll_waited += 5 ))
            local poll_result; poll_result=$(agent_call "$node_id" GET /mvps/deploy/status 2>/dev/null)
            final_status=$(echo "$poll_result" | jq -r '.status // "unknown"' 2>/dev/null)
            [[ "$final_status" == "done" || "$final_status" == "failed" ]] && break
            printf "."
        done
        echo ""

        if [[ "$final_status" != "done" ]]; then
            fail "Deploy thất bại (status: ${final_status}) — xem log trên node"
            cmd_undrain "$node_id"
            (( failed++ ))
            continue
        fi
        ok "Deploy xong!"

        # Bước 5: Undrain + health check
        info "[5/5] Restore traffic..."
        cmd_undrain "$node_id"

        # Chờ health UP
        local health_waited=0
        while (( health_waited < 60 )); do
            local hr; hr=$(agent_call "$node_id" GET /mvps/health 2>/dev/null)
            [[ "$(echo "$hr" | jq -r '.overall // ""')" == "UP" ]] && break
            sleep 3; (( health_waited += 3 ))
        done

        ok "Node ${node_id} healthy — deploy thành công!"
    done

    echo ""
    if (( failed == 0 )); then
        ok "Rolling deploy hoàn tất — ${#node_ids[@]}/${#node_ids[@]} nodes thành công"
    else
        fail "Deploy hoàn tất với ${failed} lỗi — kiểm tra log các node thất bại"
    fi
}

cmd_rotate_token() {
    local target="${1:-}"
    [[ -z "$target" ]] && { echo "Usage: mvps-cluster rotate-token <node_id|all>"; exit 1; }

    local node_ids=()
    [[ "$target" == "all" ]] \
        && mapfile -t node_ids < <(list_node_ids) \
        || node_ids=("$target")

    for node_id in "${node_ids[@]}"; do
        info "Rotate token cho ${node_id}..."

        # Sinh token mới
        local new_token; new_token="mvps_wn_$(openssl rand -hex 16)"

        # Gửi đến agent (dùng token cũ để auth)
        local result
        result=$(agent_call "$node_id" POST /mvps/token/rotate \
            -H "Content-Type: application/json" \
            -d "{\"new_token\":\"${new_token}\"}" 2>/dev/null)

        local rstatus; rstatus=$(echo "$result" | jq -r '.status // "error"' 2>/dev/null)
        if [[ "$rstatus" == "rotated" ]]; then
            # Cập nhật token trong cluster-tokens.json
            local tmp; tmp=$(mktemp)
            jq --arg id "$node_id" --arg tok "$new_token" \
               --arg iss "$(date -Iseconds)" \
               --arg exp "$(date -Iseconds -d '+30 days')" \
               '.nodes[$id] = {"token":$tok,"issued":$iss,"expires":$exp}' \
               "$TOKENS_JSON" > "$tmp" && mv "$tmp" "$TOKENS_JSON"
            chmod 600 "$TOKENS_JSON"
            ok "Token ${node_id} đã rotate — hết hạn: $(date -d '+30 days' '+%Y-%m-%d')"
        else
            fail "Rotate thất bại cho ${node_id}: $result"
        fi
    done
}

cmd_dashboard() {
    local _old_trap; _old_trap=$(trap -p INT TERM)  # lưu trap cũ
    trap 'echo -e "\nThoát dashboard."; break' INT TERM

    while true; do
        clear
        echo -e "${BOLD}ModernVPS Cluster Dashboard${NC} — $(date '+%Y-%m-%d %H:%M:%S') (Ctrl+C để thoát)"
        echo "═══════════════════════════════════════════════════════════════════"
        cmd_list
        cmd_metrics all
        sleep 5
    done

    # Restore trap cũ sau khi thoát vòng lặp
    eval "$_old_trap"
}

# ── Main ─────────────────────────────────────────
CMD="${1:-help}"
shift || true

case "$CMD" in
    add-node)      cmd_add_node "$@" ;;
    remove-node)   cmd_remove_node "$@" ;;
    list)          cmd_list ;;
    metrics)       cmd_metrics "${1:-all}" ;;
    health)
        target="${1:-all}"
        [[ "$target" == "all" ]] \
            && mapfile -t _ids < <(list_node_ids) \
            || _ids=("$target")
        for _id in "${_ids[@]}"; do
            result=$(agent_call "$_id" GET /mvps/health 2>/dev/null)
            overall=$(echo "$result" | jq -r '.overall // "OFFLINE"' 2>/dev/null)
            echo -e "$([ "$overall" = UP ] && echo "${GREEN}✅${NC}" || echo "${RED}❌${NC}") ${_id}: ${overall}"
        done
        ;;
    drain)         cmd_drain "$@" ;;
    undrain)       cmd_undrain "$@" ;;
    deploy)        cmd_deploy "$@" ;;
    rotate-token)  cmd_rotate_token "$@" ;;
    dashboard)     cmd_dashboard ;;
    help|--help|-h) cmd_help ;;
    *) echo "Unknown command: $CMD"; cmd_help; exit 1 ;;
esac
CLEOF
    chmod +x /usr/local/bin/mvps-cluster
    log "mvps-cluster CLI đã cài: mvps-cluster help"
}

# ══════════════════════════════════════════════════
# TOKEN ROTATION CRON
# Chạy hàng ngày, rotate token nếu còn < 7 ngày
# ══════════════════════════════════════════════════

_setup_token_rotation_cron() {
    if [[ "$SERVER_TYPE" == "loadbalancer" ]]; then
        # LB: rotate token của tất cả nodes sắp hết hạn
        cat > /usr/local/bin/mvps-rotate-tokens << 'ROTEOF'
#!/bin/bash
# ModernVPS Token Rotation — chạy bởi cron hàng ngày
TOKENS_JSON="/opt/modernvps/cluster-tokens.json"
LOG="/var/log/modernvps/token-rotation.log"

[[ ! -f "$TOKENS_JSON" ]] && exit 0
command -v jq &>/dev/null || exit 0

log() { echo "$(date -Iseconds) $*" >> "$LOG"; }

# Tìm nodes có token hết hạn trong 7 ngày
now=$(date +%s)
threshold=$(( now + 7 * 86400 ))

jq -r '.nodes | to_entries[] | "\(.key) \(.value.expires)"' "$TOKENS_JSON" 2>/dev/null \
| while read -r node_id expires; do
    exp_ts=$(date -d "$expires" +%s 2>/dev/null || echo 0)
    if (( exp_ts < threshold )); then
        log "Rotating token cho node: $node_id (hết hạn: $expires)"
        /usr/local/bin/mvps-cluster rotate-token "$node_id" >> "$LOG" 2>&1 \
            && log "OK: $node_id" \
            || log "FAIL: $node_id"
    fi
done
ROTEOF
        chmod +x /usr/local/bin/mvps-rotate-tokens

        # Cron 2AM hàng ngày
        cat >> /etc/cron.d/modernvps-backup << 'EOF'
0 2 * * * root /usr/local/bin/mvps-rotate-tokens
EOF
        log "Token rotation cron: 2AM daily"
    fi

    if [[ "$SERVER_TYPE" == "web" ]]; then
        # Web node: kiểm tra token sắp hết hạn → ghi cảnh báo vào log
        cat > /usr/local/bin/mvps-check-agent-token << 'CHKEOF'
#!/bin/bash
TOKEN_FILE="/opt/modernvps/agent-token.json"
LOG="/var/log/modernvps/install.log"
[[ ! -f "$TOKEN_FILE" ]] && exit 0
command -v jq &>/dev/null || exit 0

expires=$(jq -r '.expires // ""' "$TOKEN_FILE" 2>/dev/null)
[[ -z "$expires" ]] && exit 0

exp_ts=$(date -d "$expires" +%s 2>/dev/null || echo 0)
now=$(date +%s)
days_left=$(( (exp_ts - now) / 86400 ))

if (( days_left <= 7 )); then
    echo "$(date -Iseconds) [WARN] Agent token hết hạn trong ${days_left} ngày — LB cần rotate" >> "$LOG"
fi
CHKEOF
        chmod +x /usr/local/bin/mvps-check-agent-token
        cat >> /etc/cron.d/modernvps-backup << 'EOF'
0 6 * * * root /usr/local/bin/mvps-check-agent-token
EOF
        log "Agent token check cron: 6AM daily"
    fi
}

# ══════════════════════════════════════════════════
# CLUSTER METRICS COLLECTOR (cron 30s trên LB)
# Pull metrics từ tất cả nodes → cluster-metrics.json
# ══════════════════════════════════════════════════

_setup_metrics_collector() {
    [[ "$SERVER_TYPE" != "loadbalancer" ]] && return 0

    cat > /usr/local/bin/mvps-collect-metrics << 'COLEOF'
#!/bin/bash
# ModernVPS Metrics Collector — chạy mỗi phút qua cron
# (cron min interval = 1 phút, script chạy 2 lần cách nhau 30s)
METRICS_JSON="/opt/modernvps/cluster-metrics.json"
CLUSTER_JSON="/opt/modernvps/cluster.json"
TOKENS_JSON="/opt/modernvps/cluster-tokens.json"

[[ ! -f "$CLUSTER_JSON" ]] && exit 0
command -v jq &>/dev/null || exit 0

collect_once() {
    local results="[]"
    while IFS= read -r node_id; do
        local ip token port
        ip=$(jq -r --arg id "$node_id" '.nodes[] | select(.id==$id) | .internal_ip' \
            "$CLUSTER_JSON" 2>/dev/null)
        port=$(jq -r --arg id "$node_id" '.nodes[] | select(.id==$id) | .agent_port // 9000' \
            "$CLUSTER_JSON" 2>/dev/null)
        token=$(jq -r --arg id "$node_id" '.nodes[$id].token // ""' \
            "$TOKENS_JSON" 2>/dev/null)

        [[ -z "$ip" || -z "$token" ]] && continue

        local m
        m=$(curl -sf --max-time 5 \
            -H "Authorization: Bearer ${token}" \
            "http://${ip}:${port}/mvps/metrics" 2>/dev/null) || \
            m='{"node_id":"'"$node_id"'","error":"offline"}'

        results=$(echo "$results" | jq --argjson node "$m" '. += [$node]' 2>/dev/null \
            || echo "$results")

    done < <(jq -r '.nodes[].id' "$CLUSTER_JSON" 2>/dev/null)

    jq -n --argjson nodes "$results" \
        '{"updated":(now|todate),"nodes":$nodes}' > "$METRICS_JSON" 2>/dev/null
}

collect_once
sleep 30
collect_once
COLEOF
    chmod +x /usr/local/bin/mvps-collect-metrics

    # Cron mỗi phút (script tự chạy 2 lần cách 30s)
    cat >> /etc/cron.d/modernvps-backup << 'EOF'
* * * * * root /usr/local/bin/mvps-collect-metrics
EOF
    log "Metrics collector: cron mỗi phút (30s interval)"
}
