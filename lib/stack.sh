#!/bin/bash
# =====================================================
# stack.sh - Cài đặt Nginx, PHP, MariaDB, ModSecurity
#            Phân biệt Web Server và Load Balancer
# ModernVPS v3.2 - Cập nhật: Phase 1
# =====================================================

# ══════════════════════════════════════════════════
# CÀI ĐẶT STACK CHÍNH
# ══════════════════════════════════════════════════

# ══════════════════════════════════════════════════
# NGINX PPA SETUP — Fix Ubuntu 1.18 shared memory zone bug
# Ubuntu apt nginx 1.18 (2020): ssl_session_cache shared:SSL +
# fastcgi_cache_path keys_zone + limit_conn_zone cùng http{} block
# → slab allocator exhausted → limit_conn_zone size=0 → nginx fail
# Giải pháp: upgrade lên nginx 1.24+ từ ppa:ondrej/nginx
# ══════════════════════════════════════════════════

_install_nginx_from_ppa() {
    # Skip nếu nginx đã đủ mới (>= 1.20)
    if command -v nginx &>/dev/null; then
        local _cur _maj _min
        _cur=$(nginx -v 2>&1 | grep -oP '[0-9]+\.[0-9]+(?:\.[0-9]+)?' | head -1)
        _maj=$(echo "$_cur" | cut -d. -f1)
        _min=$(echo "$_cur" | cut -d. -f2)
        if (( _maj > 1 )) || (( _maj == 1 && _min >= 20 )); then
            log "nginx ${_cur} đã đủ mới — bỏ qua PPA setup"
            return 0
        fi
        warn "nginx ${_cur} cũ (< 1.20) — upgrade để fix shared memory zone bug..."
    fi

    log "Thêm ppa:ondrej/nginx (nginx 1.24/1.26 stable)..."
    apt-get install -y software-properties-common gnupg2 curl ca-certificates \
        2>/dev/null || true

    # Ưu tiên ppa:ondrej/nginx
    if add-apt-repository -y ppa:ondrej/nginx 2>/dev/null; then
        apt-get update -y -qq 2>/dev/null || true
        log "ppa:ondrej/nginx thêm thành công"
    else
        warn "ppa:ondrej/nginx không khả dụng — dùng nginx.org official..."
        local codename; codename=$(lsb_release -cs 2>/dev/null || echo "jammy")
        curl -fsSL https://nginx.org/keys/nginx_signing.key \
            | gpg --dearmor -o /etc/apt/trusted.gpg.d/nginx-archive-keyring.gpg 2>/dev/null \
            || { warn "Không lấy được nginx.org key — giữ Ubuntu nginx"; return 0; }
        echo "deb http://nginx.org/packages/ubuntu ${codename} nginx" \
            > /etc/apt/sources.list.d/nginx-official.list
        cat > /etc/apt/preferences.d/99nginx-official <<'PINEOF'
Package: nginx*
Pin: origin nginx.org
Pin-Priority: 1001
PINEOF
        apt-get update -y -qq 2>/dev/null || true
        log "nginx.org official repo thêm thành công"
    fi

    # Upgrade nếu nginx đã cài
    if command -v nginx &>/dev/null; then
        apt-get install -y --only-upgrade nginx 2>/dev/null || true
        local _new; _new=$(nginx -v 2>&1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log "nginx upgraded → ${_new}"
    fi
}

# Verify nginx version sau cài — warn nếu vẫn còn 1.18
_verify_nginx_version() {
    local _ver _maj _min
    _ver=$(nginx -v 2>&1 | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    _maj=$(echo "$_ver" | cut -d. -f1)
    _min=$(echo "$_ver" | cut -d. -f2)
    if (( _maj == 1 && _min < 20 )); then
        warn "nginx ${_ver} vẫn còn cũ — có thể gặp shared memory zone bug"
        warn "Chạy thủ công: add-apt-repository ppa:ondrej/nginx && apt upgrade nginx"
        return 1
    fi
    log "nginx ${_ver}: OK (>= 1.20)"
    return 0
}

install_nginx_stack() {
    if [[ "$SERVER_TYPE" == "web" ]]; then
        log "Cài full web stack (Nginx + PHP${PHP_VERSION} + MariaDB)..."
        case "$OS_FAMILY" in
            debian)
                # Upgrade nginx lên 1.24+ trước khi cài stack (fix shared memory zone bug)
                _install_nginx_from_ppa

                # Dùng PPA ondrej/php để có PHP 8.2/8.3/8.4 mới nhất trên Ubuntu
                add-apt-repository -y ppa:ondrej/php 2>/dev/null || true
                apt-get update -y
                pkg_install nginx \
                    "php${PHP_VERSION}-fpm" \
                    "php${PHP_VERSION}-mysql" \
                    "php${PHP_VERSION}-cli" \
                    "php${PHP_VERSION}-curl" \
                    "php${PHP_VERSION}-gd" \
                    "php${PHP_VERSION}-mbstring" \
                    "php${PHP_VERSION}-xml" \
                    "php${PHP_VERSION}-opcache" \
                    "php${PHP_VERSION}-bcmath" \
                    "php${PHP_VERSION}-zip" \
                    "php${PHP_VERSION}-imagick" \
                    "php${PHP_VERSION}-intl" \
                    "php${PHP_VERSION}-apcu" \
                    "php${PHP_VERSION}-redis" \
                    mariadb-server mariadb-client
                ;;
            rhel)
                local remi_ver; remi_ver=$(rpm -E %rhel)
                dnf install -y \
                    "https://rpms.remirepo.net/enterprise/remi-release-${remi_ver}.rpm" \
                    2>/dev/null || true
                dnf module reset php -y 2>/dev/null || true
                dnf module enable "php:remi-${PHP_VERSION}" -y
                pkg_install nginx php-fpm php-mysqlnd php-cli php-curl php-gd \
                    php-mbstring php-xml php-opcache php-bcmath php-zip \
                    php-intl php-pecl-apcu php-pecl-redis mariadb-server mariadb
                ;;
        esac

        tune_php
        tune_mariadb

        systemctl enable nginx "$(get_php_fpm_svc)" mariadb 2>/dev/null || true
        systemctl restart "$(get_php_fpm_svc)" 2>/dev/null \
            || systemctl start "$(get_php_fpm_svc)" 2>/dev/null || true
        systemctl restart mariadb 2>/dev/null \
            || systemctl start mariadb 2>/dev/null || true

    else
        log "Cài Nginx only (Load Balancer mode)..."
        _install_nginx_from_ppa
        pkg_install nginx
        systemctl enable nginx 2>/dev/null || true
        # Tune Nginx riêng cho LB — không dùng chung config với web
        tune_nginx_lb
    fi

    _verify_nginx_version || true
    log "Stack đã cài xong!"
}

# ══════════════════════════════════════════════════
# PHP-FPM TUNING
# ══════════════════════════════════════════════════

tune_php() {
    log "Tuning PHP-FPM (RAM: ${TOTAL_RAM_MB}MB, type: ${PHP_WORKER_TYPE})..."
    local fpm_ini="${OS_CONF[${OS_FAMILY}_php_ini_dir]}"
    local fpm_pool_dir="${OS_CONF[${OS_FAMILY}_php_pool_dir]}"

    # Hardening php.ini — tắt expose_php tránh lộ version
    if [[ -f "$fpm_ini" ]]; then
        sed -i \
            -e 's/^expose_php.*/expose_php = Off/' \
            -e 's/^allow_url_fopen.*/allow_url_fopen = Off/' \
            -e 's/^upload_max_filesize.*/upload_max_filesize = 64M/' \
            -e 's/^post_max_size.*/post_max_size = 64M/' \
            -e 's/^memory_limit.*/memory_limit = 256M/' \
            -e 's/^max_execution_time.*/max_execution_time = 300/' \
            -e 's/^session.cookie_httponly.*/session.cookie_httponly = 1/' \
            -e 's/^session.cookie_secure.*/session.cookie_secure = 1/' \
            -e 's/^session.use_strict_mode.*/session.use_strict_mode = 1/' \
            "$fpm_ini"
    fi

    # OPcache — tăng theo RAM
    local opcache_mem=128
    (( TOTAL_RAM_MB >= 4096 )) && opcache_mem=256
    (( TOTAL_RAM_MB >= 8192 )) && opcache_mem=512

    local opcache_conf
    case "$OS_FAMILY" in
        debian) opcache_conf="/etc/php/${PHP_VERSION}/fpm/conf.d/99-modernvps-opcache.ini" ;;
        rhel)   opcache_conf="/etc/php.d/99-modernvps-opcache.ini" ;;
    esac

    cat > "$opcache_conf" <<EOF
[opcache]
opcache.enable=1
opcache.memory_consumption=${opcache_mem}
opcache.max_accelerated_files=20000
opcache.revalidate_freq=60
opcache.validate_timestamps=1
; JIT mode 1255: tracing JIT — tối ưu cho PHP 8.x
opcache.jit=1255
opcache.jit_buffer_size=64M
EOF

    # Tính max_children theo PHP_WORKER_TYPE từ common.sh
    # Mỗi loại app có memory footprint khác nhau:
    # WordPress/WooCommerce: ~80MB/worker (nhiều plugin)
    # Laravel/Framework:     ~60MB/worker
    # PHP generic/nhẹ:       ~40MB/worker
    local worker_mem_mb=80
    case "${PHP_WORKER_TYPE:-wordpress}" in
        laravel)   worker_mem_mb=60 ;;
        generic)   worker_mem_mb=40 ;;
        wordpress) worker_mem_mb=80 ;;
    esac

    # Dùng 1/3 RAM cho PHP-FPM pool
    # Phần còn lại dành cho MariaDB (40%), OS + Nginx (20%)
    local avail_for_php=$(( TOTAL_RAM_MB / 3 ))
    local max_children=$(( avail_for_php / worker_mem_mb ))
    (( max_children < 5   )) && max_children=5
    (( max_children > 200 )) && max_children=200

    local start_servers=$(( max_children / 4 ))
    (( start_servers < 2 )) && start_servers=2
    local min_spare=$start_servers
    local max_spare=$(( max_children / 2 ))
    (( max_spare < 4 )) && max_spare=4

    cat > "${fpm_pool_dir}/www.conf" <<EOF
; ModernVPS PHP-FPM pool — global default
; Worker type: ${PHP_WORKER_TYPE} (~${worker_mem_mb}MB/worker)
[www]
user  = ${NGINX_USER}
group = ${NGINX_USER}
listen       = $(get_php_fpm_sock)
listen.owner = ${NGINX_USER}
listen.group = ${NGINX_USER}
listen.mode  = 0660

; dynamic: spawn worker theo nhu cầu thực tế
pm                   = dynamic
pm.max_children      = ${max_children}
pm.start_servers     = ${start_servers}
pm.min_spare_servers = ${min_spare}
pm.max_spare_servers = ${max_spare}
; max_requests: tự restart worker sau N requests — tránh memory leak
pm.max_requests      = 1000
pm.status_path       = /fpm-status

php_admin_flag[log_errors]          = on
php_admin_value[error_log]          = /var/log/php-fpm-error.log
php_admin_value[open_basedir]       = /var/www:/tmp:/usr/share
php_admin_value[sys_temp_dir]       = /tmp
php_admin_value[upload_tmp_dir]     = /tmp
; Chỉ cho phép thực thi .php — tránh upload shell disguise
security.limit_extensions           = .php
EOF

    log "PHP-FPM: pm=dynamic, max=${max_children}, start=${start_servers}, mem=${worker_mem_mb}MB/worker, OPcache=${opcache_mem}MB"
}

# ══════════════════════════════════════════════════
# MARIADB TUNING
# ══════════════════════════════════════════════════

tune_mariadb() {
    log "Tuning MariaDB (RAM: ${TOTAL_RAM_MB}MB)..."

    # InnoDB buffer pool: 40% RAM — phần quan trọng nhất của MariaDB performance
    local pool_mb=$(( TOTAL_RAM_MB * 40 / 100 ))
    (( pool_mb < 128 )) && pool_mb=128

    # max_connections tăng theo RAM
    local max_conn=100
    (( TOTAL_RAM_MB >= 2048 )) && max_conn=150
    (( TOTAL_RAM_MB >= 4096 )) && max_conn=200
    (( TOTAL_RAM_MB >= 8192 )) && max_conn=300

    # query_cache_size: disabled từ MariaDB 10.1.7+
    # Dùng table_open_cache thay thế
    local table_cache=2000
    (( TOTAL_RAM_MB >= 4096 )) && table_cache=4000

    local my_cnf_dir="${OS_CONF[${OS_FAMILY}_my_cnf_dir]}"
    mkdir -p "$my_cnf_dir" /var/log/mysql
    chown mysql:mysql /var/log/mysql 2>/dev/null || true

    cat > "${my_cnf_dir}/99-modernvps.cnf" <<EOF
[mysqld]
# Bảo mật: chỉ lắng nghe localhost, tắt DNS lookup
bind-address        = 127.0.0.1
skip-name-resolve
skip-external-locking

# InnoDB — engine chính
innodb_buffer_pool_size         = ${pool_mb}M
; instances: 1 cho RAM < 1GB, tăng lên 2-4 với RAM lớn hơn
innodb_buffer_pool_instances    = $(( pool_mb < 1024 ? 1 : (pool_mb < 4096 ? 2 : 4) ))
innodb_flush_log_at_trx_commit  = 2
innodb_flush_method             = O_DIRECT
innodb_file_per_table           = 1
innodb_read_io_threads          = $(( CPU_CORES > 4 ? 4 : CPU_CORES ))
innodb_write_io_threads         = $(( CPU_CORES > 4 ? 4 : CPU_CORES ))

# Connections
max_connections     = ${max_conn}
max_allowed_packet  = 64M
table_open_cache    = ${table_cache}
thread_cache_size   = 16

# Charset mặc định UTF8MB4 — hỗ trợ emoji và Unicode đầy đủ
character-set-server  = utf8mb4
collation-server      = utf8mb4_unicode_ci

# Slow query log — phát hiện query chậm
slow_query_log      = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time     = 1

# Binary log — hỗ trợ point-in-time recovery (optional, comment nếu không cần)
# log_bin           = /var/log/mysql/mysql-bin
# expire_logs_days  = 7
EOF

    # Secure MariaDB installation — xóa anonymous user, test database
    # Chỉ chạy nếu MariaDB đang running và có thể kết nối không cần pass
    if systemctl is-active mariadb &>/dev/null \
        && mysql -u root -e "SELECT 1" &>/dev/null 2>&1; then
        mysql -u root <<'SQL' 2>/dev/null || true
DELETE FROM mysql.global_priv
    WHERE User='' OR (User='root' AND Host NOT IN ('localhost','127.0.0.1','::1'));
DROP DATABASE IF EXISTS test;
DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';
FLUSH PRIVILEGES;
SQL
        log "MariaDB: anonymous users và test database đã xóa"
    fi

    log "MariaDB: buffer=${pool_mb}MB, max_conn=${max_conn}, table_cache=${table_cache}"
}

# ══════════════════════════════════════════════════
# NGINX LB TUNING (chỉ cho Load Balancer)
# Tách riêng để không lẫn với web server config
# ══════════════════════════════════════════════════

tune_nginx_lb() {
    log "Tuning Nginx cho Load Balancer..."

    # Upstream keepalive default — tái sử dụng connection đến backend
    # Giảm overhead TCP handshake đáng kể khi traffic cao
    local upstream_conf="/etc/nginx/conf.d/upstream.conf"
    [[ -f "$upstream_conf" ]] && return 0  # Không ghi đè nếu đã tồn tại

    cat > "$upstream_conf" <<'EOF'
# ModernVPS Load Balancer — Default upstream
# Chỉnh sửa qua: sudo mvps → Upstream manager
upstream backend {
    # Placeholder: nginx BẮT BUỘC có ít nhất 1 server directive trong upstream block
    # server down: nginx accept config nhưng không route traffic đến server này
    # Backend thật sẽ được thêm qua: sudo mvps → Upstream manager
    server 127.0.0.1:1 down;

    # keepalive: số connection persistent tối đa đến mỗi backend
    # Giữ connection mở thay vì đóng sau mỗi request → giảm latency
    keepalive 32;
    keepalive_requests 1000;
    keepalive_timeout  60s;
}
EOF

    # Nginx stub_status — cần cho header LB (connections, req/s)
    # Chỉ cho phép truy cập từ localhost
    cat > "/etc/nginx/conf.d/stub-status.conf" <<'EOF'
# ModernVPS — Nginx stub_status (internal only)
server {
    listen 127.0.0.1:8080;
    server_name localhost;
    access_log off;

    location /nginx_status {
        stub_status;
        allow 127.0.0.1;
        deny  all;
    }
}
EOF

    # Bug fix #2: LB cần ít nhất 1 default server block trong sites-enabled
    # Nếu không nginx -t pass nhưng không có server nào handle request thực
    # → tạo default block trả 444 (drop connection không response)
    # Fix C4: KHÔNG dùng default_server — conflict với maintenance mode block
    # (tools.sh:do_maintenance_mode cũng có listen 80 → nginx fail nếu cả 2 default_server)
    cat > /etc/nginx/sites-available/default-lb <<'EOF'
# ModernVPS LB — Default catch-all server block
# Dùng server_name _ thay vì default_server để tránh conflict với maintenance mode
server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 444;
    access_log off;
}
EOF
    ln -sf /etc/nginx/sites-available/default-lb \
           /etc/nginx/sites-enabled/default-lb

    log "Nginx LB: upstream template và stub_status đã tạo"
}

# ══════════════════════════════════════════════════
# NGINX GLOBAL CONFIG
# Bug fix: dùng printf thay vì heredoc quoted để expand $NGINX_USER đúng
# ══════════════════════════════════════════════════

setup_nginx_global() {
    log "Cấu hình Nginx global (SERVER_TYPE=${SERVER_TYPE})..."
    systemctl stop nginx 2>/dev/null || true

    mkdir -p /var/cache/nginx/fastcgi \
             /etc/nginx/{sites-available,sites-enabled,conf.d,snippets}
    chown "${NGINX_USER}:${NGINX_USER}" /var/cache/nginx/fastcgi 2>/dev/null || true

    # Xóa symlink lỗi (trỏ đến thư mục không tồn tại) và default site
    find /etc/nginx/sites-enabled -maxdepth 1 -type l 2>/dev/null \
        | while read -r lnk; do
            [[ ! -e "$(readlink -f "$lnk" 2>/dev/null)" ]] && rm -f "$lnk"
          done
    rm -f /etc/nginx/sites-enabled/default

    if [[ "$SERVER_TYPE" == "web" ]]; then
        _setup_nginx_web
    else
        _setup_nginx_lb
    fi

    # Test config trước khi start
    # Bug fix: nginx -t ghi ra stderr → redirect 2>&1 trước khi grep
    local _nginx_test
    _nginx_test=$(nginx -t 2>&1)
    echo "$_nginx_test" | tee -a "$LOG_FILE"
    if echo "$_nginx_test" | grep -q "test is successful"; then
        systemctl start nginx 2>/dev/null \
            || systemctl restart nginx 2>/dev/null \
            || warn "Nginx start thất bại — xem: journalctl -u nginx"
        log "Nginx global: cấu hình OK, đã start"
    else
        warn "Nginx config lỗi — KHÔNG start nginx. Xem chi tiết ở trên."
    fi
}

# ── Nginx config cho Web Server ───────────────────
# Fix bug gốc: dùng printf + cat thay vì <<'EOF' (quoted heredoc ngăn expand biến)
# Sau đó không cần sed để thay $NGINX_USER nữa
_setup_nginx_web() {
    log "Tạo nginx.conf cho Web Server..."

    # Tính worker_connections theo RAM
    local worker_conn=2048
    (( TOTAL_RAM_MB >= 2048 )) && worker_conn=4096
    (( TOTAL_RAM_MB >= 4096 )) && worker_conn=8192

    # Dùng printf để ghi dòng đầu có biến, sau đó cat heredoc cho phần còn lại
    # Lý do tách: heredoc không quote để expand biến nhưng dễ gây lỗi nếu
    # biến chứa ký tự đặc biệt → chỉ expand đúng biến cần thiết
    cat > /etc/nginx/nginx.conf <<EOF
user ${NGINX_USER};
worker_processes auto;
worker_rlimit_nofile 65535;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

# Load dynamic modules — main context, TRƯỚC events {}
# load_module chỉ hợp lệ ở main context, không phải http {}
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections ${worker_conn};
    multi_accept on;
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    server_tokens off;

    log_format main '\$remote_addr - [\$time_local] "\$request" \$status '
                    '\$body_bytes_sent "\$http_referer" "\$http_user_agent" '
                    'rt=\$request_time';
    access_log /var/log/nginx/access.log main buffer=64k flush=5m;

    sendfile       on;
    tcp_nopush     on;
    tcp_nodelay    on;
    keepalive_timeout   65;
    keepalive_requests  10000;

    client_max_body_size        64M;
    client_body_buffer_size     128k;
    client_header_buffer_size   4k;
    large_client_header_buffers 4 32k;
    client_body_timeout   30;
    client_header_timeout 30;
    send_timeout          30;

    gzip             on;
    gzip_vary        on;
    gzip_comp_level  4;
    gzip_min_length  256;
    gzip_proxied     any;
    gzip_types
        text/plain text/css text/xml text/javascript
        application/json application/javascript application/xml
        application/rss+xml image/svg+xml font/woff2;

    fastcgi_cache_path /var/cache/nginx/fastcgi
        levels=1:2 keys_zone=PHPCACHE:32m inactive=60m
        max_size=512m use_temp_path=off;
    fastcgi_cache_key "\$scheme\$request_method\$host\$request_uri";
    fastcgi_cache_use_stale error timeout updating http_500 http_503;

    limit_req_zone  \$binary_remote_addr zone=req_limit:10m   rate=10r/s;
    limit_req_zone  \$binary_remote_addr zone=login_limit:10m rate=5r/m;
    limit_conn_zone \$binary_remote_addr zone=conn_limit:10m;
    limit_req_status  429;
    limit_conn_status 429;

    add_header X-Frame-Options           "SAMEORIGIN"                   always;
    add_header X-Content-Type-Options    "nosniff"                      always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin" always;
    add_header X-XSS-Protection          "1; mode=block"                always;
    add_header Permissions-Policy        "geolocation=(), camera=(), microphone=()" always;

    open_file_cache          max=20000 inactive=30s;
    open_file_cache_valid    60s;
    open_file_cache_min_uses 2;

    ssl_protocols           TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers             ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_session_cache       shared:SSL:10m;
    ssl_session_timeout     1d;
    ssl_session_tickets     off;
    ssl_stapling            on;
    ssl_stapling_verify     on;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    _create_nginx_snippets_web
    log "Nginx web: worker_connections=${worker_conn}"
}

# Tạo các snippet dùng chung cho vhost web
_create_nginx_snippets_web() {
    # security.conf — hardening headers và block scanner phổ biến
    cat > /etc/nginx/snippets/security.conf <<'EOF'
# ModernVPS security snippet
if ($http_user_agent ~* (nikto|sqlmap|nmap|masscan|dirbuster|burpsuite|zgrab|censys|shodan|nuclei)) {
    return 403;
}
if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS)$) {
    return 405;
}
# Block hidden files và backup files
location ~ /\.                                    { deny all; access_log off; log_not_found off; }
location ~* \.(sql|bak|log|env|git|svn|htpasswd)$ { deny all; access_log off; log_not_found off; }
autoindex off;
EOF

    # static-cache.conf — cache headers cho static assets
    cat > /etc/nginx/snippets/static-cache.conf <<'EOF'
# ModernVPS static cache snippet
location ~* \.(jpg|jpeg|png|gif|ico|webp|avif|svg|woff2?)$ {
    expires 90d;
    add_header Cache-Control "public, immutable";
    add_header Vary "Accept-Encoding";
    access_log off;
}
location ~* \.(css|js|ttf|eot)$ {
    expires 365d;
    add_header Cache-Control "public, immutable";
    access_log off;
}
EOF

    # fastcgi-cache.conf — FastCGI cache cho PHP
    # skip_cache: POST requests, có query string, user đã login
    cat > /etc/nginx/snippets/fastcgi-cache.conf <<'EOF'
# ModernVPS FastCGI cache snippet
set $skip_cache 0;
if ($request_method = POST)                                    { set $skip_cache 1; }
if ($query_string != "")                                       { set $skip_cache 1; }
if ($http_cookie ~* "wordpress_logged_in|PHPSESSID|woocommerce_") { set $skip_cache 1; }
if ($request_uri ~* "(/wp-admin/|/wp-login.php|/xmlrpc.php)") { set $skip_cache 1; }
fastcgi_cache             PHPCACHE;
fastcgi_cache_valid 200   5m;
fastcgi_cache_valid 404   1m;
fastcgi_cache_bypass      $skip_cache;
fastcgi_no_cache          $skip_cache;
add_header X-Cache        $upstream_cache_status;
EOF

    # proxy-params.conf — dùng cho vhost proxy đến backend (LB mode hoặc upstream)
    cat > /etc/nginx/snippets/proxy-params.conf <<'EOF'
# ModernVPS proxy params snippet
proxy_http_version      1.1;
proxy_set_header        Upgrade           $http_upgrade;
proxy_set_header        Connection        "upgrade";
proxy_set_header        Host              $host;
proxy_set_header        X-Real-IP         $remote_addr;
proxy_set_header        X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header        X-Forwarded-Proto $scheme;
proxy_hide_header       X-Powered-By;
proxy_connect_timeout   10s;
proxy_send_timeout      60s;
proxy_read_timeout      60s;
proxy_buffer_size       128k;
proxy_buffers           4 256k;
proxy_busy_buffers_size 256k;
EOF

    log "Nginx snippets: security, static-cache, fastcgi-cache, proxy-params đã tạo"
}

# ── Nginx config cho Load Balancer ───────────────
_setup_nginx_lb() {
    log "Tạo nginx.conf cho Load Balancer..."

    # LB cần worker_connections cao hơn web server nhiều
    # Mỗi connection đến client cần 1 connection đến backend → ×2
    # worker_rlimit_nofile phải >= worker_connections × worker_processes
    local worker_conn=65535

    cat > /etc/nginx/nginx.conf <<EOF
user ${NGINX_USER};
worker_processes auto;
worker_rlimit_nofile 131070;
pid /run/nginx.pid;
error_log /var/log/nginx/error.log warn;

# Load dynamic modules — main context (trước events {})
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections ${worker_conn};
    multi_accept on;
    use epoll;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    server_tokens off;

    # Log format LB: thêm upstream_addr và upstream_response_time
    # để phân tích hiệu năng từng backend
    log_format main '\$remote_addr - [\$time_local] "\$request" \$status '
                    '\$body_bytes_sent "\$http_user_agent" '
                    'upstream=\$upstream_addr '
                    'upstream_rt=\$upstream_response_time '
                    'rt=\$request_time';
    access_log /var/log/nginx/access.log main buffer=64k flush=5m;

    sendfile       on;
    tcp_nopush     on;
    tcp_nodelay    on;
    keepalive_timeout  65;
    keepalive_requests 10000;

    # Proxy timeout — LB nên có timeout rõ ràng để không block khi backend chậm
    proxy_connect_timeout  10s;
    proxy_send_timeout     60s;
    proxy_read_timeout     60s;

    gzip            on;
    gzip_vary       on;
    gzip_comp_level 4;
    gzip_min_length 256;
    gzip_proxied    any;
    gzip_types
        text/plain text/css application/json application/javascript
        text/xml application/xml image/svg+xml;

    # Proxy cache path — optional, dùng khi muốn cache response từ backend
    proxy_cache_path /var/cache/nginx/proxy
        levels=1:2 keys_zone=PROXYCACHE:32m inactive=60m
        max_size=1g use_temp_path=off;

    add_header X-Frame-Options           "SAMEORIGIN"                   always;
    add_header X-Content-Type-Options    "nosniff"                      always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin" always;

    ssl_protocols           TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers             ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache       shared:SSL:20m;
    ssl_session_timeout     1d;
    ssl_session_tickets     off;
    ssl_stapling            on;
    ssl_stapling_verify     on;

    # Bug fix: LB nginx.conf thiếu rate limit zones — vhost dùng zone=conn_limit
    # gây lỗi "zero size shared memory zone" khi nginx -t
    # Phải khai báo trong http {} context, TRƯỚC include sites-enabled/*
    limit_conn_zone \$binary_remote_addr zone=conn_limit:10m;
    limit_req_zone  \$binary_remote_addr zone=req_limit:10m   rate=20r/s;
    limit_req_zone  \$binary_remote_addr zone=login_limit:10m rate=5r/m;
    limit_req_status  429;
    limit_conn_status 429;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

    # Tạo thư mục proxy cache
    mkdir -p /var/cache/nginx/proxy
    chown "${NGINX_USER}:${NGINX_USER}" /var/cache/nginx/proxy 2>/dev/null || true

    # Tạo snippets dùng cho proxy vhost
    _create_nginx_snippets_lb

    log "Nginx LB: worker_connections=${worker_conn}"
}

# Tạo snippets cho Load Balancer
_create_nginx_snippets_lb() {
    # proxy-params đã tạo chung trong _create_nginx_snippets_web
    # Tạo thêm snippet riêng cho LB
    mkdir -p /etc/nginx/snippets

    cat > /etc/nginx/snippets/proxy-params.conf <<'EOF'
# ModernVPS LB proxy params
proxy_http_version      1.1;
proxy_set_header        Connection        "";
proxy_set_header        Host              $host;
proxy_set_header        X-Real-IP         $remote_addr;
proxy_set_header        X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header        X-Forwarded-Proto $scheme;
proxy_hide_header       X-Powered-By;
proxy_hide_header       Server;
proxy_connect_timeout   10s;
proxy_send_timeout      60s;
proxy_read_timeout      60s;
proxy_buffer_size       128k;
proxy_buffers           4 256k;
proxy_busy_buffers_size 256k;
# Retry nếu backend lỗi — tự động failover sang backend tiếp theo
proxy_next_upstream     error timeout http_502 http_503 http_504;
proxy_next_upstream_tries 3;
EOF

    cat > /etc/nginx/snippets/security.conf <<'EOF'
# ModernVPS LB security snippet
if ($http_user_agent ~* (nikto|sqlmap|nmap|masscan|dirbuster|burpsuite|zgrab|nuclei)) {
    return 403;
}
if ($request_method !~ ^(GET|HEAD|POST|PUT|DELETE|PATCH|OPTIONS)$) {
    return 405;
}
location ~ /\. { deny all; access_log off; log_not_found off; }
EOF

    log "Nginx LB snippets: proxy-params, security đã tạo"
}

# ══════════════════════════════════════════════════
# MODSECURITY WAF
# Strategy: "Verified Smart Pin"
#   - Không hardcode URL, không hardcode tag mù
#   - _resolve_*_tag(): dùng git ls-remote detect tag thực tế
#   - Floor version = last known-good, dùng khi network fail
#   - ABI stable: libmodsec + connector pin cùng nhau
#   - nginx connector: --with-compat làm primary (PPA args không portable)
# ══════════════════════════════════════════════════

# ──────────────────────────────────────────────────
# Helper: resolve tag thực tế từ git remote
# Args: $1=repo_url $2=pattern(glob) $3=floor_version $4=exclude_pattern(optional)
# Output: tag name lên stdout
# Logic: git ls-remote → filter stable → lấy latest >= floor → fallback floor
# ──────────────────────────────────────────────────
_resolve_git_tag() {
    local repo_url="$1"
    local pattern="$2"       # VD: "refs/tags/v3.*"
    local floor="$3"         # VD: "v3.0.9" — sàn tối thiểu, fallback khi network fail
    local exclude="${4:-}"   # VD: "rc\|alpha\|beta\|RC" — loại prerelease

    # ── CRITICAL: hàm này được gọi qua $() subshell ──────────────
    # $() capture toàn bộ stdout → log()/warn() dùng echo|tee ra stdout
    # → biến nhận giá trị sẽ chứa cả log message lẫn tag name → git clone fail
    # Fix: TẤT CẢ log/warn trong hàm này phải redirect >&2
    # Chỉ echo tag name thuần ra stdout — không có gì khác
    # ─────────────────────────────────────────────────────────────

    # git ls-remote: không cần clone, chỉ query remote refs
    # --sort=-version:refname: sort semver descending (cần git >= 2.18, Ubuntu 22.04 có 2.34)
    # timeout 15s: tránh hang khi network chậm
    local raw_tags
    raw_tags=$(timeout 15 git ls-remote --tags --sort='-version:refname' \
        "$repo_url" "${pattern}" 2>/dev/null \
        | awk '{print $2}' \
        | grep -v '\^{}' \
        | sed 's|refs/tags/||')

    if [[ -z "$raw_tags" ]]; then
        warn "Không kết nối được ${repo_url} — dùng floor version ${floor}" >&2
        echo "$floor"
        return 0
    fi

    # Lọc bỏ prerelease nếu có exclude pattern
    local stable_tags="$raw_tags"
    if [[ -n "$exclude" ]]; then
        stable_tags=$(echo "$raw_tags" | grep -v -E "$exclude") || true
    fi

    if [[ -z "$stable_tags" ]]; then
        warn "Không tìm thấy stable tag (pattern=${pattern}) — dùng floor ${floor}" >&2
        echo "$floor"
        return 0
    fi

    # Lấy tag mới nhất (đã sort descending từ ls-remote)
    local latest; latest=$(echo "$stable_tags" | head -1)

    # Verify tag này >= floor bằng cách so sánh semver đơn giản
    # (chỉ cần so phần major.minor.patch — không dùng sort -V để tránh fork thừa)
    local latest_num floor_num
    latest_num=$(echo "$latest" | grep -oP '\d+\.\d+\.\d+' | head -1 \
                 | awk -F. '{printf "%05d%05d%05d", $1,$2,$3}')
    floor_num=$(echo "$floor" | grep -oP '\d+\.\d+\.\d+' | head -1 \
                | awk -F. '{printf "%05d%05d%05d", $1,$2,$3}')

    if [[ -n "$latest_num" && -n "$floor_num" ]] \
        && (( 10#$latest_num >= 10#$floor_num )); then
        log "Tag resolved: ${latest} (>= floor ${floor})" >&2
        echo "$latest"   # ← CHỈ tag name ra stdout, không có gì khác
    else
        warn "Tag ${latest} < floor ${floor} — dùng floor" >&2
        echo "$floor"
    fi
}

# Resolve tag cho libmodsecurity3 (floor: v3.0.9 — version có msc_set_request_hostname)
_resolve_modsec_tag() {
    _resolve_git_tag \
        "https://github.com/SpiderLabs/ModSecurity" \
        "refs/tags/v3.*" \
        "v3.0.9" \
        "rc\|alpha\|beta\|RC\|dev"
}

# Resolve tag cho ModSecurity-nginx connector (floor: v1.0.3)
_resolve_connector_tag() {
    _resolve_git_tag \
        "https://github.com/SpiderLabs/ModSecurity-nginx" \
        "refs/tags/v1.*" \
        "v1.0.3" \
        "rc\|alpha\|beta\|RC\|dev"
}


# ──────────────────────────────────────────────────
# [XÓA] Hàm cũ — đã được thay bằng _preflight_modsecurity() bên dưới
# Giữ lại placeholder để không lỗi nếu có code cũ gọi hàm này
# ──────────────────────────────────────────────────
_preflight_modsec_check_DEPRECATED() {
    log "Pre-flight check trước khi build ModSecurity..."
    local preflight_ok=true

    # ── 1. Disk space ──────────────────────────────────────────────
    # Cần tối thiểu 2GB trên /usr/local/src:
    #   ModSecurity source:        ~50MB
    #   mbedtls submodule:         ~30MB
    #   libinjection submodule:    ~5MB
    #   nginx source:              ~10MB
    #   build artifacts (make):   ~500MB
    #   install to /usr:           ~20MB
    #   buffer an toàn:           ~400MB
    # Tổng: ~1GB thực tế, yêu cầu 2GB để có buffer
    local src_mount
    src_mount=$(df /usr/local/src 2>/dev/null | awk 'NR==2{print $6}')
    [[ -z "$src_mount" ]] && src_mount=$(df /usr/local 2>/dev/null | awk 'NR==2{print $6}')
    [[ -z "$src_mount" ]] && src_mount="/"

    local disk_avail_mb
    disk_avail_mb=$(df -m "$src_mount" 2>/dev/null | awk 'NR==2{print $4}')
    if [[ -z "$disk_avail_mb" ]] || (( disk_avail_mb < 2048 )); then
        warn "Disk space không đủ: ${disk_avail_mb}MB available tại ${src_mount} (cần >= 2048MB)"
        warn "Build ModSecurity yêu cầu ~2GB để compile + artifacts"
        preflight_ok=false
    else
        log "✓ Disk: ${disk_avail_mb}MB available tại ${src_mount} (>= 2048MB)"
    fi

    # ── 2. RAM available ───────────────────────────────────────────
    # make -j$(nproc) trên 4 core cần ~800MB RAM (mỗi compiler ~200MB)
    # Nếu có swap thì tính cả swap vào — make có thể dùng swap
    local mem_avail_mb swap_avail_mb total_virtual_mb
    mem_avail_mb=$(awk '/MemAvailable/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
    swap_avail_mb=$(awk '/SwapFree/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
    total_virtual_mb=$(( mem_avail_mb + swap_avail_mb ))

    # Tính số job make dựa trên RAM thực có — tránh OOM
    # Mỗi compiler job cần ~200MB; floor là 1 job
    local safe_jobs
    # Lấy cpu_cores an toàn — nproc edge case: 0, hoặc quá lớn (>32)
    local cpu_cores_pf; cpu_cores_pf=$(nproc 2>/dev/null || echo 1)
    (( cpu_cores_pf < 1 )) && cpu_cores_pf=1
    (( cpu_cores_pf > 32 )) && cpu_cores_pf=32
    safe_jobs=$(( mem_avail_mb / 200 ))
    (( safe_jobs < 1 )) && safe_jobs=1
    (( safe_jobs > cpu_cores_pf )) && safe_jobs=$cpu_cores_pf

    if (( total_virtual_mb < 512 )); then
        warn "RAM+Swap rất thấp: ${total_virtual_mb}MB (RAM=${mem_avail_mb}MB, Swap=${swap_avail_mb}MB)"
        warn "Build có thể bị OOM kill — ensure_swap() nên đã chạy trước bước này"
        preflight_ok=false
    elif (( mem_avail_mb < 400 )); then
        warn "RAM available thấp: ${mem_avail_mb}MB — sẽ dùng make -j${safe_jobs} (CPU cores: ${cpu_cores_pf})"
        # Không fail — có thể build với ít job hơn, chỉ chậm hơn
    else
        log "✓ RAM: ${mem_avail_mb}MB available (Swap: ${swap_avail_mb}MB), make -j${safe_jobs}"
    fi

    # Export để _build_modsecurity_from_source dùng
    MODSEC_MAKE_JOBS=$safe_jobs

    # ── 3. /usr/local/src write permission ────────────────────────
    # Script chạy với root — trường hợp fail: mount read-only, noexec, SELinux deny
    mkdir -p /usr/local/src 2>/dev/null || true
    if ! touch /usr/local/src/.mvps_write_test 2>/dev/null; then
        warn "/usr/local/src không writable — kiểm tra mount flags hoặc SELinux"
        preflight_ok=false
    else
        rm -f /usr/local/src/.mvps_write_test
        log "✓ /usr/local/src: writable"
    fi

    # ── 4. /usr/local/src exec permission ─────────────────────────
    # noexec mount: script chạy được nhưng compiled binary không execute được
    # Test bằng cách tạo tiny script và chạy
    local _exec_test; _exec_test=$(mktemp /usr/local/src/.mvps_exec_XXXXXX)
    echo '#!/bin/sh' > "$_exec_test" && echo 'exit 0' >> "$_exec_test"
    chmod +x "$_exec_test" 2>/dev/null || true
    if ! bash "$_exec_test" 2>/dev/null; then
        warn "/usr/local/src mounted noexec — build sẽ fail khi chạy ./configure"
        preflight_ok=false
    else
        log "✓ /usr/local/src: exec OK"
    fi
    rm -f "$_exec_test"

    # ── 5. Network connectivity ────────────────────────────────────
    # Cần kết nối đến 3 host:
    #   github.com      → clone ModSecurity, connector
    #   nginx.org       → download nginx source tarball
    # Test bằng TCP connect (không cần wget/curl — nhanh hơn)
    local _net_ok=true
    local _hosts=("github.com:443" "nginx.org:443")
    for _host_port in "${_hosts[@]}"; do
        local _h="${_host_port%%:*}" _p="${_host_port##*:}"
        if ! timeout 8 bash -c "echo >/dev/tcp/${_h}/${_p}" 2>/dev/null; then
            warn "Network: không kết nối được ${_h}:${_p} (timeout 8s)"
            _net_ok=false
        fi
    done
    if [[ "$_net_ok" == "true" ]]; then
        log "✓ Network: github.com:443, nginx.org:443 reachable"
    else
        warn "Network check thất bại — git clone và wget sẽ fail"
        preflight_ok=false
    fi

    # ── 6. Required build tools ────────────────────────────────────
    # Các tool PHẢI có trước khi build — không thể cài trong lúc build
    local _required_tools=(git make gcc g++ wget tar)
    local _missing_tools=()
    for _tool in "${_required_tools[@]}"; do
        command -v "$_tool" &>/dev/null 2>&1 || _missing_tools+=("$_tool")
    done
    if (( ${#_missing_tools[@]} > 0 )); then
        warn "Thiếu build tools: ${_missing_tools[*]} — thử cài..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            "${_missing_tools[@]}" > /dev/null 2>&1 || true
        # Check lại sau khi cài
        local _still_missing=()
        for _tool in "${_missing_tools[@]}"; do
            command -v "$_tool" &>/dev/null 2>&1 || _still_missing+=("$_tool")
        done
        if (( ${#_still_missing[@]} > 0 )); then
            warn "Vẫn thiếu tools sau khi cài: ${_still_missing[*]}"
            preflight_ok=false
        else
            log "✓ Build tools: đã cài thành công"
        fi
    else
        log "✓ Build tools: git make gcc g++ wget tar — tất cả có sẵn"
    fi

    # ── 7. autoconf/automake/libtool cho build.sh ─────────────────
    # build.sh gọi autoreconf → cần autoconf, automake, libtool
    local _autotools=(autoconf automake libtool)
    local _missing_auto=()
    for _t in "${_autotools[@]}"; do
        command -v "$_t" &>/dev/null 2>&1 || _missing_auto+=("$_t")
    done
    if (( ${#_missing_auto[@]} > 0 )); then
        warn "Thiếu autotools: ${_missing_auto[*]} — thử cài..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            "${_missing_auto[@]}" > /dev/null 2>&1 || true
        local _still_auto=()
        for _t in "${_missing_auto[@]}"; do
            command -v "$_t" &>/dev/null 2>&1 || _still_auto+=("$_t")
        done
        if (( ${#_still_auto[@]} > 0 )); then
            warn "Vẫn thiếu autotools: ${_still_auto[*]} — build.sh sẽ fail"
            preflight_ok=false
        else
            log "✓ Autotools: đã cài thành công"
        fi
    else
        log "✓ Autotools: autoconf automake libtool — tất cả có sẵn"
    fi

    # ── 8. nginx version + verify source URL ─────────────────────
    # nginx -v: detect version → download đúng source cho module build
    # Verify URL thực sự: tránh lãng phí 15 phút build rồi download fail
    local _nver=""
    if ! nginx -v 2>&1 | grep -q 'nginx/'; then
        systemctl start nginx 2>/dev/null || true
        sleep 1
    fi
    _nver=$(nginx -v 2>&1 | grep -oP 'nginx/\K[\d.]+')
    if [[ -z "$_nver" ]]; then
        warn "nginx -v thất bại — không xác định được version để download source"
        preflight_ok=false
    else
        log "✓ nginx version: ${_nver}"
        # Verify nginx source tarball tồn tại trên nginx.org (HEAD request)
        local _nginx_url="https://nginx.org/download/nginx-${_nver}.tar.gz"
        if curl -fsI --max-time 10 --connect-timeout 5 \
                "$_nginx_url" &>/dev/null 2>&1; then
            log "✓ nginx-${_nver}.tar.gz: có sẵn tại nginx.org"
        else
            warn "nginx-${_nver}.tar.gz không verify được tại nginx.org"
            warn "  URL: ${_nginx_url} — download sẽ thử lại lúc build"
            # Không fail — có thể do CDN cache chậm
        fi
    fi

    # ── 9. /usr/lib/nginx/modules writable ───────────────────────
    # Đích install .so — phải writable TRƯỚC KHI build
    # Trên một số hệ thống /usr/lib là read-only overlay
    local _mod_dir="/usr/lib/nginx/modules"
    mkdir -p "$_mod_dir" 2>/dev/null || true
    if ! touch "${_mod_dir}/.mvps_write_test" 2>/dev/null; then
        warn "${_mod_dir} không writable — .so sẽ không cài được"
        preflight_ok=false
    else
        rm -f "${_mod_dir}/.mvps_write_test"
        log "✓ ${_mod_dir}: writable"
    fi

    # ── Kết quả preflight ──────────────────────────────────────────
    if [[ "$preflight_ok" == "true" ]]; then
        log "✓ Pre-flight check PASSED — bắt đầu build ModSecurity"
        return 0
    else
        warn "Pre-flight check FAILED — xem các [WARN] ở trên để khắc phục"
        return 1
    fi
}

# ──────────────────────────────────────────────────
# Helper: tính số job make an toàn theo RAM khả dụng
# make -j$(nproc) trên VPS 1GB RAM + ModSecurity → OOM killer
# Rule: 1 job per 512MB RAM free, tối thiểu 1, tối đa nproc
# ──────────────────────────────────────────────────
_safe_nproc() {
    local mem_free_mb
    mem_free_mb=$(awk '/MemAvailable/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null)
    mem_free_mb="${mem_free_mb:-512}"

    local safe_jobs=$(( mem_free_mb / 512 ))
    (( safe_jobs < 1 )) && safe_jobs=1

    local cpu_jobs; cpu_jobs=$(nproc 2>/dev/null || echo 1)
    (( safe_jobs > cpu_jobs )) && safe_jobs=$cpu_jobs

    echo "$safe_jobs"
}

# ══════════════════════════════════════════════════
# PREFLIGHT — Kiểm tra môi trường trước build ModSecurity
# Fail fast, rõ lý do, thay vì build 20-30 phút rồi mới fail
#
# Kiểm tra đầy đủ (theo thứ tự từ nhanh → chậm):
#   1. git version >= 2.18
#   2. Build tools + autotools (auto-install nếu thiếu)
#   3. Disk /usr/local/src >= 2GB
#   4. Disk /tmp >= 300MB
#   5. RAM/Swap tổng >= 512MB
#   6. Write + Exec permission /usr/local/src
#   7. /usr/lib/nginx/modules writable
#   8. nginx binary + version detectablee
#   9. GitHub reachable (git ls-remote — test đúng protocol)
#  10. nginx.org reachable (TCP connect)
#  11. nginx source tarball URL verify (HEAD request)
#
# Return: 0 = OK, 1 = fail (đã log lý do cụ thể)
# ══════════════════════════════════════════════════
_preflight_modsecurity() {
    log "Preflight check môi trường build ModSecurity..."
    local ok=true

    # ── 1. git version >= 2.18 ────────────────────────────────────
    # _resolve_git_tag() dùng --sort=-version:refname: cần git >= 2.18
    # Ubuntu 20.04: git 2.25 ✅ | Ubuntu 22.04: git 2.34 ✅
    local git_ver git_maj git_min
    git_ver=$(git --version 2>/dev/null | grep -oP '[\d]+\.[\d]+\.[\d]+' | head -1)
    if [[ -z "$git_ver" ]]; then
        warn "  ✗ git: không tìm thấy"
        ok=false
    else
        git_maj=$(echo "$git_ver" | cut -d. -f1)
        git_min=$(echo "$git_ver" | cut -d. -f2)
        if (( git_maj < 2 || ( git_maj == 2 && git_min < 18 ) )); then
            warn "  ✗ git ${git_ver} < 2.18 — --sort=-version:refname không hỗ trợ"
            ok=false
        else
            log "  ✓ git ${git_ver} (>= 2.18)"
        fi
    fi

    # ── 2. Build tools — auto-install nếu thiếu ──────────────────
    # Kiểm tra TRƯỚC khi cài deps trong build function
    # Auto-install ngay tại đây: nếu cài fail → fail rõ ràng sớm
    local _need_tools=() _need_auto=()
    for _t in make gcc g++ wget tar; do
        command -v "$_t" &>/dev/null || _need_tools+=("$_t")
    done
    for _t in autoconf automake libtool; do
        command -v "$_t" &>/dev/null || _need_auto+=("$_t")
    done

    if (( ${#_need_tools[@]} > 0 || ${#_need_auto[@]} > 0 )); then
        local _all_missing=("${_need_tools[@]}" "${_need_auto[@]}")
        warn "  ⚠ Thiếu tools: ${_all_missing[*]} — thử cài..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
            "${_all_missing[@]}" > /tmp/modsec-preflight-tools.log 2>&1 || true
        # Verify lại sau khi cài
        local _still_missing=()
        for _t in make gcc g++ wget tar autoconf automake libtool; do
            command -v "$_t" &>/dev/null || _still_missing+=("$_t")
        done
        if (( ${#_still_missing[@]} > 0 )); then
            warn "  ✗ Vẫn thiếu sau cài: ${_still_missing[*]}"
            ok=false
        else
            log "  ✓ Build tools + autotools: OK (đã cài)"
        fi
    else
        log "  ✓ Build tools: make gcc g++ wget tar autoconf automake libtool"
    fi

    # ── 3. Disk /usr/local/src >= 2GB ────────────────────────────
    # ModSecurity src ~50MB + mbedtls ~30MB + libinjection ~5MB
    # + build artifacts ~500MB + nginx src + build ~110MB
    # + buffer an toàn → yêu cầu 2GB
    local _src_path="/usr/local/src"
    mkdir -p "$_src_path" 2>/dev/null || true
    local _src_mb
    _src_mb=$(df -m "$_src_path" 2>/dev/null | awk 'NR==2{print $4}')
    _src_mb="${_src_mb:-0}"
    if (( _src_mb < 2048 )); then
        warn "  ✗ Disk ${_src_path}: ${_src_mb}MB — cần >= 2048MB"
        ok=false
    else
        log "  ✓ Disk ${_src_path}: ${_src_mb}MB (>= 2GB)"
    fi

    # ── 4. Disk /tmp >= 300MB ─────────────────────────────────────
    # Build logs (modsec-*.log) + nginx tarball ~10MB + configure artifacts
    local _tmp_mb
    _tmp_mb=$(df -m /tmp 2>/dev/null | awk 'NR==2{print $4}')
    _tmp_mb="${_tmp_mb:-0}"
    if (( _tmp_mb < 300 )); then
        warn "  ✗ Disk /tmp: ${_tmp_mb}MB — cần >= 300MB"
        ok=false
    else
        log "  ✓ Disk /tmp: ${_tmp_mb}MB (>= 300MB)"
    fi

    # ── 5. RAM + Swap tổng >= 512MB ──────────────────────────────
    # make -j với ModSecurity: mỗi job ~200-300MB
    # Tính cả swap: nếu swap tốt thì build được dù RAM thấp (chỉ chậm hơn)
    local _mem_mb _swap_mb _virtual_mb
    _mem_mb=$(awk '/MemAvailable/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
    _swap_mb=$(awk '/SwapFree/{printf "%d", $2/1024}' /proc/meminfo 2>/dev/null || echo 0)
    _virtual_mb=$(( _mem_mb + _swap_mb ))
    if (( _virtual_mb < 512 )); then
        warn "  ✗ RAM+Swap: ${_virtual_mb}MB (RAM=${_mem_mb}MB Swap=${_swap_mb}MB) — cần >= 512MB"
        warn "    ensure_swap() nên đã chạy trước bước này"
        ok=false
    elif (( _mem_mb < 400 )); then
        warn "  ⚠ RAM free thấp: ${_mem_mb}MB — sẽ dùng make -j$(_safe_nproc) (build chậm hơn)"
        log "  ✓ RAM+Swap đủ: ${_virtual_mb}MB"
        # KHÔNG fail — _safe_nproc() sẽ giới hạn jobs
    else
        log "  ✓ RAM: ${_mem_mb}MB free, Swap: ${_swap_mb}MB (make -j$(_safe_nproc) jobs)"
    fi

    # ── 6. Write + Exec permission /usr/local/src ─────────────────
    # Write: git clone, make, install artifacts
    # Exec: ./configure, compiled binary chạy được (không phải noexec mount)
    if ! touch "${_src_path}/.mvps_wtest" 2>/dev/null; then
        warn "  ✗ ${_src_path}: không có quyền ghi (read-only mount?)"
        ok=false
    else
        rm -f "${_src_path}/.mvps_wtest"
        log "  ✓ Write permission ${_src_path}: OK"
    fi

    # Noexec check: tạo tiny script và chạy
    local _exec_test; _exec_test=$(mktemp "${_src_path}/.mvps_exec_XXXXXX")
    printf '#!/bin/sh\nexit 0\n' > "$_exec_test"
    chmod +x "$_exec_test" 2>/dev/null || true
    if ! bash "$_exec_test" 2>/dev/null; then
        warn "  ✗ ${_src_path}: mounted noexec — ./configure sẽ fail"
        ok=false
    else
        log "  ✓ Exec permission ${_src_path}: OK (không phải noexec)"
    fi
    rm -f "$_exec_test"

    # ── 7. /usr/lib/nginx/modules writable ───────────────────────
    # Đích install .so — phải writable trước khi build
    # Fail case: /usr là read-only overlay (một số container/immutable OS)
    local _mod_dir="/usr/lib/nginx/modules"
    mkdir -p "$_mod_dir" 2>/dev/null || true
    if ! touch "${_mod_dir}/.mvps_wtest" 2>/dev/null; then
        warn "  ✗ ${_mod_dir}: không có quyền ghi — .so sẽ không cài được"
        ok=false
    else
        rm -f "${_mod_dir}/.mvps_wtest"
        log "  ✓ Write permission ${_mod_dir}: OK"
    fi

    # ── 8. nginx binary + version detectable ─────────────────────
    # Cần nginx -v để biết version → download đúng source tarball
    local _nginx_ver=""
    if ! command -v nginx &>/dev/null; then
        warn "  ✗ nginx: binary không tìm thấy"
        ok=false
    else
        _nginx_ver=$(nginx -v 2>&1 | grep -oP 'nginx/\K[\d.]+')
        if [[ -z "$_nginx_ver" ]]; then
            warn "  ✗ nginx -v: không detect được version"
            ok=false
        else
            log "  ✓ nginx: ${_nginx_ver}"
        fi
    fi

    # ── 9. GitHub reachable ───────────────────────────────────────
    # Dùng git ls-remote (test đúng protocol git dùng)
    # Tốt hơn TCP connect đơn thuần — verify cả TLS + Git protocol
    if timeout 12 git ls-remote --quiet \
            "https://github.com/SpiderLabs/ModSecurity" HEAD \
            &>/dev/null 2>&1; then
        log "  ✓ GitHub (git ls-remote): reachable"
    else
        warn "  ✗ GitHub không kết nối được — clone ModSecurity sẽ fail"
        ok=false
    fi

    # ── 10. nginx.org reachable (TCP) ────────────────────────────
    # TCP connect nhanh hơn git ls-remote — chỉ cần verify port 443 open
    if timeout 8 bash -c 'echo >/dev/tcp/nginx.org/443' 2>/dev/null; then
        log "  ✓ nginx.org:443: reachable"
    else
        warn "  ✗ nginx.org:443 không kết nối được — wget nginx source sẽ fail"
        ok=false
    fi

    # ── 11. nginx source tarball URL verify (chỉ khi biết version) ──
    # HEAD request nhẹ (~0 bytes) — verify URL tồn tại trước khi wget
    # Fail case: nginx.org chưa publish tarball cho version mới nhất (edge case)
    if [[ -n "$_nginx_ver" ]] && command -v curl &>/dev/null; then
        local _tarball_url="https://nginx.org/download/nginx-${_nginx_ver}.tar.gz"
        if curl -fsI --max-time 10 --connect-timeout 5 \
                "$_tarball_url" &>/dev/null 2>&1; then
            log "  ✓ nginx-${_nginx_ver}.tar.gz: có sẵn tại nginx.org"
        else
            warn "  ⚠ nginx-${_nginx_ver}.tar.gz: không verify được URL"
            warn "    ${_tarball_url}"
            warn "    Build sẽ tiếp tục — wget sẽ thử lại khi build"
            # KHÔNG fail: CDN cache miss, wget có thể thành công
        fi
    fi

    # ── Kết quả ───────────────────────────────────────────────────
    if [[ "$ok" == "false" ]]; then
        warn "Preflight FAILED — xem các [✗] ở trên để khắc phục trước khi build"
        return 1
    fi
    log "Preflight PASSED (git OK, tools OK, disk OK, RAM OK, network OK)"
    return 0
}


# ──────────────────────────────────────────────────
# Build libmodsecurity3 + nginx connector từ source
# Gọi khi: apt không có package, hoặc .so connector thiếu
# ──────────────────────────────────────────────────
_build_modsecurity_from_source() {
    # ── Preflight: fail fast thay vì build 20 phút rồi fail ──────
    _preflight_modsecurity || return 1

    # ── ROOT CAUSE FIXES ──────────────────────────────────────────
    # #1: Tag v3.0.12 không tồn tại → dùng _resolve_modsec_tag()
    # #2: submodule sai tên/thiếu mbedtls → dùng đúng path + verify header
    # #3: ./build.sh || true che lỗi → check exit code
    # #4: --with-X hardcode sai → dùng detection đúng tool
    # #5: PPA configure args không portable → --with-compat làm primary
    # #6: Không check môi trường trước → _preflight_modsecurity()
    # ─────────────────────────────────────────────────────────────
    log "Build ModSecurity từ source (15-25 phút)..."

    local src_dir="/usr/local/src"
    local so_dest="/usr/lib/nginx/modules/ngx_http_modsecurity_module.so"

    # Tính số job an toàn dựa trên RAM thực tế
    local make_jobs; make_jobs=$(_safe_nproc)

    # ── Resolve tag thực tế (Verified Smart Pin) ──────────────────
    log "Resolving ModSecurity tag từ upstream..."
    local modsec_tag connector_tag
    modsec_tag=$(_resolve_modsec_tag)
    connector_tag=$(_resolve_connector_tag)
    log "Sử dụng: libmodsecurity=${modsec_tag}, connector=${connector_tag}"

    # ── Dependencies ──────────────────────────────────────────────
    # libpcre2-dev: thay libpcre3-dev (deprecated Ubuntu 22.04+)
    # libcurl4-openssl-dev: BẮT BUỘC — không dùng 2>/dev/null để thấy lỗi
    local build_deps_base=(
        git build-essential cmake automake libtool
        libpcre2-dev libssl-dev zlib1g-dev libxml2-dev
        libyajl-dev libcurl4-openssl-dev pkgconf wget
    )
    # Optional: lua, maxminddb, fuzzy, geoip (deprecated)
    local build_deps_opt=(libmaxminddb-dev libfuzzy-dev libgeoip-dev liblua5.3-dev)

    log "Cài build dependencies..."
    if ! pkg_install "${build_deps_base[@]}"; then
        warn "Một số build dependency cài thất bại — thử tiếp tục"
    fi
    for _dep in "${build_deps_opt[@]}"; do
        pkg_install "$_dep" 2>/dev/null || true
    done

    # Verify deps thiết yếu bằng pkg-config
    local missing_deps=()
    for _pc in libssl libxml-2.0 zlib; do
        pkg-config --exists "$_pc" 2>/dev/null || missing_deps+=("$_pc")
    done
    (( ${#missing_deps[@]} > 0 )) && \
        warn "Thiếu pkg-config cho: ${missing_deps[*]} — configure có thể fail"

    # ── Bước 1: Build libmodsecurity3 từ source ──────────────────
    log "Clone ModSecurity ${modsec_tag}..."
    rm -rf "${src_dir}/ModSecurity"
    if ! git clone --depth 1 --branch "${modsec_tag}" \
            "https://github.com/SpiderLabs/ModSecurity" \
            "${src_dir}/ModSecurity" 2>/dev/null; then
        warn "Clone tag ${modsec_tag} thất bại — kiểm tra kết nối network"
        return 1
    fi

    cd "${src_dir}/ModSecurity" || return 1

    # Init submodules bắt buộc:
    # others/libinjection: parser SQLi/XSS — BẮT BUỘC mọi version
    # others/mbedtls:      TLS library     — BẮT BUỘC từ v3.0.12+
    # bindings/python / test/test-cases   — KHÔNG cần (~100MB+)
    log "Init submodules (libinjection + mbedtls)..."
    git submodule init

    # Update từng submodule riêng — KHÔNG dùng update không có path (clone ALL)
    local submod_ok=true
    git submodule update --depth=1 -- others/libinjection 2>/dev/null \
        || { warn "Submodule others/libinjection update thất bại"; submod_ok=false; }
    git submodule update --depth=1 -- others/mbedtls 2>/dev/null \
        || { warn "Submodule others/mbedtls update thất bại"; submod_ok=false; }

    # Fallback: retry không --depth (một số mirror giới hạn shallow clone)
    if [[ "$submod_ok" == "false" ]]; then
        warn "Thử lại submodule update không --depth (fallback)..."
        submod_ok=true
        git submodule update -- others/libinjection 2>/dev/null \
            || { warn "Retry others/libinjection thất bại"; submod_ok=false; }
        git submodule update -- others/mbedtls 2>/dev/null \
            || { warn "Retry others/mbedtls thất bại"; submod_ok=false; }
        if [[ "$submod_ok" == "false" ]]; then
            warn "Không thể clone submodule bắt buộc — kiểm tra kết nối network"
            return 1
        fi
    fi

    # Verify header tồn tại trước khi build
    if [[ ! -f "others/libinjection/src/libinjection.h" ]]; then
        warn "others/libinjection/src/libinjection.h không tìm thấy"
        return 1
    fi
    if [[ ! -f "others/mbedtls/include/mbedtls/ssl.h" ]]; then
        warn "others/mbedtls/include/mbedtls/ssl.h không tìm thấy"
        return 1
    fi
    log "✓ Submodules OK: libinjection + mbedtls"

    # build.sh: generate autoconf files — phải thành công, không || true
    log "Generate build system (build.sh)..."
    if ! ./build.sh > /tmp/modsec-build.log 2>&1; then
        warn "build.sh thất bại:"
        tail -20 /tmp/modsec-build.log | tee -a "$LOG_FILE"
        return 1
    fi

    # ── Configure flags ───────────────────────────────────────────
    # Nguyên tắc: lib FOUND → --with-X | lib ABSENT → không pass gì
    # KHÔNG dùng --without-X: explicit disable dù lib có thể có
    # curl dùng curl-config (không phải pkg-config)
    # geoip dùng header check (không có .pc file)
    log "Configure libmodsecurity3..."
    local conf_flags=("--prefix=/usr")

    # Curl: check curl-config binary (tool configure thực sự dùng)
    local _curl_ok=false
    command -v curl-config &>/dev/null 2>&1 && _curl_ok=true
    if [[ "$_curl_ok" == "false" ]]; then
        warn "curl-config không tìm thấy — thử reinstall libcurl4-openssl-dev..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall \
            libcurl4-openssl-dev > /tmp/modsec-curl-install.log 2>&1 || true
        command -v curl-config &>/dev/null 2>&1 \
            && { _curl_ok=true; log "✓ curl-config OK sau reinstall"; }
    fi
    [[ "$_curl_ok" == "true" ]] \
        && conf_flags+=("--with-curl") && log "✓ curl: --with-curl" \
        || warn "curl-config vẫn không có — build không có curl support"

    # Yajl: có .pc file → dùng pkg-config
    pkg-config --exists yajl 2>/dev/null \
        && conf_flags+=("--with-yajl") && log "✓ yajl: --with-yajl" || true

    # GeoIP: check header (không có .pc)
    { [[ -f /usr/include/GeoIP.h ]] \
        || dpkg -l libgeoip-dev 2>/dev/null | grep -q '^ii'; } \
        && conf_flags+=("--with-geoip") && log "✓ geoip: --with-geoip" || true

    # MaxMind: có .pc file
    pkg-config --exists libmaxminddb 2>/dev/null \
        && conf_flags+=("--with-maxmind") && log "✓ maxmind: --with-maxmind" || true

    # Lua: check pkg-config
    { pkg-config --exists lua5.3 2>/dev/null \
        || pkg-config --exists lua5.4 2>/dev/null \
        || pkg-config --exists lua 2>/dev/null; } \
        && conf_flags+=("--with-lua") && log "✓ lua: --with-lua" || true

    log "Configure flags: ${conf_flags[*]}"
    if ! ./configure "${conf_flags[@]}" > /tmp/modsec-configure.log 2>&1; then
        warn "ModSecurity configure thất bại:"
        tail -30 /tmp/modsec-configure.log | tee -a "$LOG_FILE"
        return 1
    fi

    log "Build libmodsecurity3 (make -j${make_jobs})..."
    if ! make -j"${make_jobs}" > /tmp/modsec-make.log 2>&1; then
        warn "ModSecurity make -j${make_jobs} thất bại:"
        tail -20 /tmp/modsec-make.log | tee -a "$LOG_FILE"
        # Fallback: make -j1 tránh OOM race condition khi parallel
        warn "Thử lại make -j1 (single-threaded)..."
        if ! make -j1 > /tmp/modsec-make.log 2>&1; then
            warn "ModSecurity make -j1 cũng thất bại:"
            tail -20 /tmp/modsec-make.log | tee -a "$LOG_FILE"
            return 1
        fi
        log "✓ Build thành công với make -j1"
    fi

    if ! make install > /tmp/modsec-install.log 2>&1; then
        warn "ModSecurity make install thất bại"
        return 1
    fi
    ldconfig

    # Verify symbol msc_set_request_hostname trong .so
    local libso
    libso=$(ldconfig -p 2>/dev/null \
        | grep 'libmodsecurity\.so' | awk '{print $NF}' | head -1)
    [[ -z "$libso" ]] && libso="/usr/lib/libmodsecurity.so"
    if [[ -f "$libso" ]] \
        && ! nm -D "$libso" 2>/dev/null | grep -q "msc_set_request_hostname"; then
        warn "Symbol msc_set_request_hostname không có trong ${libso}"
        return 1
    fi
    log "✓ libmodsecurity3 ${modsec_tag}: symbol OK"

    # ── Bước 2: Clone nginx connector ────────────────────────────
    log "Clone ModSecurity-nginx connector ${connector_tag}..."
    rm -rf "${src_dir}/ModSecurity-nginx"
    if ! git clone --depth 1 --branch "${connector_tag}" \
            "https://github.com/SpiderLabs/ModSecurity-nginx" \
            "${src_dir}/ModSecurity-nginx" 2>/dev/null; then
        warn "Clone connector ${connector_tag} thất bại"
        return 1
    fi

    # ── Bước 3: Download nginx source khớp version ───────────────
    local nginx_ver
    nginx_ver=$(nginx -v 2>&1 | grep -oP 'nginx/\K[\d.]+')
    [[ -z "$nginx_ver" ]] && { warn "Không xác định được Nginx version"; return 1; }

    local nginx_src="${src_dir}/nginx-${nginx_ver}"
    if [[ ! -d "$nginx_src" ]]; then
        log "Download Nginx source ${nginx_ver}..."
        if ! wget -q --timeout=60 \
                "https://nginx.org/download/nginx-${nginx_ver}.tar.gz" \
                -O "/tmp/nginx-${nginx_ver}.tar.gz"; then
            warn "Download nginx-${nginx_ver}.tar.gz thất bại"
            return 1
        fi
        tar -xzf "/tmp/nginx-${nginx_ver}.tar.gz" -C "$src_dir"
        rm -f "/tmp/nginx-${nginx_ver}.tar.gz"
    fi

    # ── Bước 4: Build nginx dynamic module ───────────────────────
    cd "$nginx_src" || return 1
    log "Build nginx dynamic module (nginx ${nginx_ver}, --with-compat, -j${make_jobs})..."

    if ! ./configure --with-compat \
            --add-dynamic-module="${src_dir}/ModSecurity-nginx" \
            > /tmp/nginx-modsec-configure.log 2>&1; then
        warn "Nginx configure thất bại:"
        tail -20 /tmp/nginx-modsec-configure.log | tee -a "$LOG_FILE"
        return 1
    fi

    if ! make modules -j"${make_jobs}" > /tmp/nginx-modsec-make.log 2>&1; then
        warn "Nginx make modules thất bại:"
        tail -20 /tmp/nginx-modsec-make.log | tee -a "$LOG_FILE"
        return 1
    fi

    # ── Bước 5: Install .so + verify dlopen ──────────────────────
    [[ ! -f "objs/ngx_http_modsecurity_module.so" ]] && {
        warn "Build xong nhưng .so không tìm thấy tại objs/"
        return 1
    }

    mkdir -p /usr/lib/nginx/modules
    cp -f "objs/ngx_http_modsecurity_module.so" "$so_dest"
    chmod 644 "$so_dest"

    # dlopen test: chọn port ngẫu nhiên tránh conflict với port 19998 đang dùng
    local test_port
    test_port=$(shuf -i 20000-29999 -n 1)
    # Đảm bảo port không bị chiếm
    while ss -tlnp 2>/dev/null | grep -q ":${test_port} "; do
        test_port=$(shuf -i 20000-29999 -n 1)
    done

    local tmp_conf; tmp_conf=$(mktemp /tmp/nginx-modsec-test-XXXXXX.conf)
    cat > "$tmp_conf" <<NGINXTEST
load_module ${so_dest};
events { worker_connections 1024; }
http { server { listen ${test_port}; location / { return 200; } } }
NGINXTEST
    local dlopen_err
    dlopen_err=$(nginx -t -c "$tmp_conf" 2>&1)
    rm -f "$tmp_conf"

    if echo "$dlopen_err" | grep -q "test is successful"; then
        log "✓ ModSecurity ${modsec_tag} build thành công (dlopen verified, port=${test_port})"
        return 0
    else
        warn "Module dlopen thất bại: ${dlopen_err}"
        rm -f "$so_dest"
        return 1
    fi
}

# ──────────────────────────────────────────────────
# Cài và cấu hình ModSecurity WAF
# Layer 1: apt/dnf (nhanh, OS native)
# Layer 2: build từ source (fallback khi apt thiếu .so connector)
# Layer 3: warn + skip (không fail script chính)
# ──────────────────────────────────────────────────
setup_modsecurity() {
    log "Cấu hình ModSecurity WAF..."
    local modsec_ready=false

    # Kiểm tra module đã có chưa (build trước đó hoặc cài ngoài)
    if [[ -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ]] \
        || nginx -V 2>&1 | grep -qi modsecurity; then
        modsec_ready=true
        log "ModSecurity module đã có sẵn — bỏ qua bước cài"
    fi

    # ── Layer 1: Debian/Ubuntu — thử apt ────────────────────────
    # Ubuntu 20.04 focal:  libnginx-mod-http-modsecurity có trong repo → cài được
    # Ubuntu 22.04+:       package bị remove → apt fail → rơi vào build từ source
    # ondrej/nginx PPA:    không bundle .so connector → phải build từ source dù sao
    # → Cài libmodsecurity3 (library) nếu có; .so connector luôn cần build
    if [[ "$modsec_ready" == "false" && "$OS_FAMILY" == "debian" ]]; then
        log "Thử cài libmodsecurity3 qua apt..."
        apt-get update -y -qq 2>/dev/null || true

        # Chỉ cài library nếu có trong repo — không phải connector .so
        if apt-cache show libmodsecurity3 &>/dev/null 2>&1; then
            pkg_install libmodsecurity3 2>/dev/null || true
            log "libmodsecurity3 đã cài qua apt (library only)"
        else
            log "libmodsecurity3 không có trong apt repo — sẽ build từ source"
        fi

        # libnginx-mod-http-modsecurity: chỉ có trên Ubuntu 20.04 focal
        # Trên 22.04+: package không tồn tại → skip, không gây lỗi
        local modsec_nginx_pkg="libnginx-mod-http-modsecurity"
        if apt-cache show "$modsec_nginx_pkg" &>/dev/null 2>&1 \
            && pkg_install "$modsec_nginx_pkg" 2>/dev/null \
            && [[ -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ]]; then
            modsec_ready=true
            log "ModSecurity nginx connector đã cài qua apt (${modsec_nginx_pkg})"
        else
            log "Không tìm thấy nginx connector qua apt — cần build từ source"
        fi
    fi

    # ── Layer 1: RHEL/AlmaLinux/Rocky — thử EPEL + mod_security ─
    # EPEL cung cấp mod_security (v2.x, Apache) — không phải v3.x cho Nginx
    # Nếu có nginx-mod-modsecurity từ EPEL → dùng, không thì build
    if [[ "$modsec_ready" == "false" && "$OS_FAMILY" == "rhel" ]]; then
        log "Thử cài ModSecurity qua EPEL (RHEL/AlmaLinux)..."
        dnf install -y epel-release 2>/dev/null || true
        dnf makecache --quiet 2>/dev/null || true

        # nginx-mod-modsecurity: có trong EPEL cho RHEL 8/9 nhưng không phải lúc nào cũng có
        if dnf list available nginx-mod-modsecurity &>/dev/null 2>&1 \
            && pkg_install nginx-mod-modsecurity libmodsecurity 2>/dev/null \
            && [[ -f /usr/lib64/nginx/modules/ngx_http_modsecurity_module.so ]]; then
            # RHEL dùng /usr/lib64 — tạo symlink để logic phía dưới dùng chung path
            mkdir -p /usr/lib/nginx/modules
            ln -sf /usr/lib64/nginx/modules/ngx_http_modsecurity_module.so \
                   /usr/lib/nginx/modules/ngx_http_modsecurity_module.so 2>/dev/null || true
            modsec_ready=true
            log "ModSecurity đã cài qua EPEL (nginx-mod-modsecurity)"
        else
            log "nginx-mod-modsecurity không có trên EPEL — cần build từ source"
        fi
    fi

    # ── Layer 2: Build từ source (fallback cho cả debian + rhel) ─
    if [[ "$modsec_ready" == "false" ]]; then
        warn "ModSecurity nginx connector chưa có — build từ source (15-25 phút)..."
        if _build_modsecurity_from_source; then
            modsec_ready=true
        else
            warn "Build ModSecurity từ source thất bại — bỏ qua WAF"
            return 0
        fi
    fi

    # ── Layer 3: Skip nếu cả 2 đều fail ────────────────────────
    if [[ "$modsec_ready" == "false" ]]; then
        warn "ModSecurity không khả dụng — bỏ qua WAF"
        return 0
    fi

    # ── Kích hoạt module trong nginx.conf ────────────────────────
    # Ưu tiên modules-enabled symlink (distro native)
    # Fallback: inject load_module vào đầu nginx.conf
    if [[ -f /usr/share/nginx/modules-available/mod-modsecurity.conf ]]; then
        ln -sf /usr/share/nginx/modules-available/mod-modsecurity.conf \
               /etc/nginx/modules-enabled/50-mod-modsecurity.conf 2>/dev/null || true
    elif [[ -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ]] \
        && ! grep -rq 'ngx_http_modsecurity_module' \
               /etc/nginx/modules-enabled/ /etc/nginx/nginx.conf 2>/dev/null; then
        # Absolute path — relative 'modules/' resolve từ nginx prefix, không portable
        sed -i '1i load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;' \
            /etc/nginx/nginx.conf
    fi

    # Validate sau khi load module — revert ngay nếu fail
    if ! nginx -t 2>/dev/null; then
        warn "ModSecurity module load thất bại — revert"
        rm -f /etc/nginx/modules-enabled/50-mod-modsecurity.conf
        sed -i '/ngx_http_modsecurity_module/d' /etc/nginx/nginx.conf 2>/dev/null || true
        nginx_safe_reload
        return 0
    fi

    mkdir -p /etc/nginx/modsec

    # ── Copy modsecurity.conf từ nhiều nguồn (theo thứ tự ưu tiên) ──
    local modsec_conf_src=""
    for _path in \
        /usr/local/src/ModSecurity/modsecurity.conf-recommended \
        /usr/share/modsecurity-crs/modsecurity.conf-recommended \
        /etc/modsecurity/modsecurity.conf-recommended; do
        [[ -f "$_path" ]] && { modsec_conf_src="$_path"; break; }
    done

    if [[ -n "$modsec_conf_src" ]]; then
        cp "$modsec_conf_src" /etc/nginx/modsec/modsecurity.conf
        # Bật enforcement mode (default file là DetectionOnly — chỉ log, không block)
        sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' \
            /etc/nginx/modsec/modsecurity.conf
        local unicode_src="${modsec_conf_src%/*}/unicode.mapping"
        [[ -f "$unicode_src" ]] \
            && cp "$unicode_src" /etc/nginx/modsec/ 2>/dev/null || true
    else
        # Config tối thiểu — khi không tìm thấy recommended file
        cat > /etc/nginx/modsec/modsecurity.conf <<'SECEOF'
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecResponseBodyAccess Off
SecTmpDir /tmp/
SecDataDir /tmp/
SecAuditEngine RelevantOnly
SecAuditLog /var/log/nginx/modsec_audit.log
SecAuditLogType Serial
SecStatusEngine Off
SECEOF
    fi

    [[ ! -f /etc/nginx/modsec/unicode.mapping ]] \
        && touch /etc/nginx/modsec/unicode.mapping

    # ── Clone OWASP CRS ──────────────────────────────────────────
    if [[ ! -d "/etc/nginx/modsec/crs" ]]; then
        log "Clone OWASP Core Rule Set..."
        git clone --quiet --depth 1 \
            "https://github.com/coreruleset/coreruleset.git" \
            /etc/nginx/modsec/crs 2>/dev/null || true
        [[ -f /etc/nginx/modsec/crs/crs-setup.conf.example ]] \
            && cp /etc/nginx/modsec/crs/crs-setup.conf.example \
                  /etc/nginx/modsec/crs/crs-setup.conf
    fi

    # ── Tạo main.conf include all ────────────────────────────────
    if [[ -d "/etc/nginx/modsec/crs/rules" ]]; then
        cat > /etc/nginx/modsec/main.conf <<'MODSEOF'
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs/crs-setup.conf
Include /etc/nginx/modsec/crs/rules/*.conf
# Rule 920350: block IP-based Host header — disable để tránh false positive
SecRuleRemoveById 920350
MODSEOF
    else
        echo 'Include /etc/nginx/modsec/modsecurity.conf' \
            > /etc/nginx/modsec/main.conf
    fi

    # ── Inject modsecurity on vào nginx.conf ────────────────────
    if ! grep -q 'modsecurity on' /etc/nginx/nginx.conf 2>/dev/null; then
        sed -i '/include \/etc\/nginx\/conf\.d\/\*\.conf;/i\
    modsecurity on;\
    modsecurity_rules_file /etc/nginx/modsec/main.conf;' \
            /etc/nginx/nginx.conf 2>/dev/null || true
    fi

    # ── Final validation ─────────────────────────────────────────
    if nginx -t 2>/dev/null; then
        systemctl reload nginx 2>/dev/null \
            || systemctl restart nginx 2>/dev/null || true
        log "ModSecurity WAF + OWASP CRS: ACTIVE!"
    else
        warn "ModSecurity config lỗi — tắt WAF"
        sed -i '/modsecurity on/d; /modsecurity_rules_file/d' \
            /etc/nginx/nginx.conf 2>/dev/null || true
        sed -i '/ngx_http_modsecurity_module/d' \
            /etc/nginx/nginx.conf 2>/dev/null || true
        rm -f /etc/nginx/modules-enabled/50-mod-modsecurity.conf
        nginx_safe_reload
    fi
}

# ══════════════════════════════════════════════════
# I/O SCHEDULER TUNING
# Mở rộng: hỗ trợ thêm NVMe (scheduler=none tối ưu nhất)
# ══════════════════════════════════════════════════

tune_io_scheduler() {
    local root_dev
    root_dev=$(lsblk -ndo NAME,MOUNTPOINT 2>/dev/null \
        | awk '$2=="/" {print $1}' | head -1)
    [[ -z "$root_dev" ]] && return 0

    # NVMe: tên device dạng nvme0n1 → base là nvme0n1 (không strip số)
    # HDD/SSD: sda1 → base là sda
    local base_dev
    if [[ "$root_dev" == nvme* ]]; then
        # NVMe partition: nvme0n1p1 → block device là nvme0n1
        base_dev="${root_dev%p[0-9]*}"
    else
        base_dev="${root_dev%%[0-9]*}"
    fi

    [[ ! -b "/dev/${base_dev}" ]] && {
        warn "Không tìm thấy block device /dev/${base_dev} — bỏ qua I/O tuning"
        return 0
    }

    # Chọn scheduler tối ưu theo loại disk
    # NVMe:     none      — NVMe controller tự quản lý queue, OS scheduler thêm overhead
    # SSD:      mq-deadline — deadline scheduling tối ưu cho random I/O
    # HDD:      bfq       — Budget Fair Queueing tối ưu cho sequential I/O
    local sched="bfq"
    case "$DISK_TYPE" in
        nvme) sched="none"        ;;
        ssd)  sched="mq-deadline" ;;
        hdd)  sched="bfq"         ;;
    esac

    # Apply ngay lập tức
    echo "$sched" > "/sys/block/${base_dev}/queue/scheduler" 2>/dev/null || true

    # Persist qua reboot bằng udev rule
    cat > /etc/udev/rules.d/60-io-scheduler.rules <<EOF
# ModernVPS I/O scheduler — ${DISK_TYPE}
ACTION=="add|change", KERNEL=="sd*",   ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="${sched}"
ACTION=="add|change", KERNEL=="nvme*",                              ATTR{queue/scheduler}="${sched}"
ACTION=="add|change", KERNEL=="sd*",   ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="bfq"
EOF

    log "I/O scheduler: ${sched} (${DISK_TYPE}: /dev/${base_dev})"
}

# ══════════════════════════════════════════════════
# SETUP MVPS AGENT (Web node)
# Nginx server block port 9000 + PHP agent script
# Chỉ lắng nghe trên internal IP, auth bằng Bearer token
# ══════════════════════════════════════════════════

setup_mvps_agent() {
    [[ "$SERVER_TYPE" != "web" ]] && return 0
    log "Cài đặt ModernVPS Cluster Agent (port 9000)..."

    local agent_dir="/var/www/mvps-agent"
    local sock; sock=$(get_php_fpm_sock)
    local nginx_conf="/etc/nginx/sites-available/mvps-agent"
    local token_file="/opt/modernvps/agent-token.json"

    # Tạo thư mục agent
    mkdir -p "$agent_dir"
    chmod 750 "$agent_dir"
    chown root:"$NGINX_USER" "$agent_dir"

    # Copy PHP agent từ installer package
    local agent_src="${SCRIPT_DIR}/agent/index.php"
    if [[ -f "$agent_src" ]]; then
        cp "$agent_src" "${agent_dir}/index.php"
    else
        warn "Không tìm thấy agent/index.php — agent chưa được cài"
        return 1
    fi
    chown root:"$NGINX_USER" "${agent_dir}/index.php"
    chmod 640 "${agent_dir}/index.php"

    # Tạo token ban đầu nếu chưa có
    if [[ ! -f "$token_file" ]]; then
        local init_token; init_token=$(cluster_token_generate "wn")
        cluster_token_write_agent "$init_token"
        warn "Agent token (lưu lại để đăng ký vào LB): ${init_token}"
        printf 'AGENT_TOKEN=%s\n' "$init_token" >> "${INSTALL_DIR}/.credentials"
    fi

    # Nginx server block — chỉ lắng nghe internal IP
    # LB_INTERNAL_IP: đọc từ config nếu có, fallback về 127.0.0.1
    local listen_ip="${LB_INTERNAL_IP:-127.0.0.1}"
    cat > "$nginx_conf" <<EOF
# ModernVPS Cluster Agent
# Chỉ lắng nghe trên internal IP: ${listen_ip}
# Không bao giờ expose ra public interface

server {
    listen ${listen_ip}:9000;
    server_name _;

    root ${agent_dir};
    index index.php;

    # Chỉ cho phép /mvps/* endpoints
    location /mvps/ {
        try_files \$uri /index.php\$is_args\$args;
    }
    location = /index.php {
        fastcgi_pass unix:${sock};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        include fastcgi_params;

        # Tăng timeout cho deploy (upload tarball lớn)
        fastcgi_read_timeout 600;
        fastcgi_send_timeout 600;

        # Tăng upload size cho tarball
        client_max_body_size 500M;
        client_body_buffer_size 128k;
        # Lưu body ra disk tránh timeout khi upload lớn
        client_body_temp_path /tmp/nginx-agent-upload;
    }

    # Block tất cả truy cập khác
    location / { return 404; }

    access_log /var/log/nginx/agent-access.log;
    error_log  /var/log/nginx/agent-error.log warn;
}
EOF

    mkdir -p /tmp/nginx-agent-upload
    chown "$NGINX_USER":"$NGINX_USER" /tmp/nginx-agent-upload
    chmod 700 /tmp/nginx-agent-upload

    ln -sf "$nginx_conf" /etc/nginx/sites-enabled/mvps-agent

    # Bug fix #4: nginx -t fail nếu PHP-FPM socket chưa tồn tại lúc test config
    # Đảm bảo PHP-FPM đang chạy và socket có trước khi reload nginx
    local fpm_svc; fpm_svc=$(get_php_fpm_svc)
    if ! systemctl is-active "$fpm_svc" &>/dev/null; then
        systemctl start "$fpm_svc" 2>/dev/null || true
        sleep 2  # chờ socket được tạo
    fi

    # Verify socket tồn tại trước khi nginx reload
    if [[ ! -S "$sock" ]]; then
        warn "PHP-FPM socket chưa có tại ${sock} — agent vhost tạm disable"
        rm -f /etc/nginx/sites-enabled/mvps-agent
        warn "Sau khi PHP-FPM chạy: ln -sf ${nginx_conf} /etc/nginx/sites-enabled/mvps-agent && nginx -s reload"
        return 0
    fi

    nginx_safe_reload
    log "Cluster Agent: http://${listen_ip}:9000/mvps/ — token tại ${token_file}"
}

# Cập nhật nftables để mở port 9000 cho LB IP mới
# Gọi sau khi có LB_INTERNAL_IP
update_agent_firewall() {
    local lb_ip="$1"
    [[ -z "$lb_ip" ]] && return 1

    # Validate IP format
    if ! echo "$lb_ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
        warn "IP không hợp lệ: $lb_ip"
        return 1
    fi

    # Thêm rule vào nftables (thêm vào table đang chạy + persist)
    nft add rule inet modernvps input \
        ip saddr "$lb_ip" tcp dport 9000 ct state new accept 2>/dev/null || true

    # Persist vào nftables.conf
    if grep -q "Agent port 9000" /etc/nftables.conf 2>/dev/null; then
        # Đã có rule cũ → update IP
        sed -i "s|ip saddr [0-9.]* tcp dport 9000|ip saddr ${lb_ip} tcp dport 9000|g" \
            /etc/nftables.conf
    else
        # Thêm rule mới trước dòng cuối của chain input
        sed -i "/# Log và drop mọi thứ còn lại/i\\
        # Agent port 9000 — LB internal IP only\\
        ip saddr ${lb_ip} tcp dport 9000 ct state new accept" \
            /etc/nftables.conf
    fi

    # Reload nginx server block với IP mới
    local nginx_conf="/etc/nginx/sites-available/mvps-agent"
    if [[ -f "$nginx_conf" ]]; then
        sed -i "s|listen [0-9.]*:9000|listen ${lb_ip}:9000|g" "$nginx_conf"
        sed -i "s|# Chỉ lắng nghe trên internal IP:.*|# Chỉ lắng nghe trên internal IP: ${lb_ip}|" "$nginx_conf"
        nginx_safe_reload
    fi

    log "Firewall đã cập nhật: LB ${lb_ip} → port 9000"
}
