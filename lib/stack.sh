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
    # Backend servers sẽ được thêm qua menu mvps
    # Ví dụ: server 10.0.0.1:80 weight=1 max_fails=3 fail_timeout=30s max_conns=100;

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

events {
    worker_connections ${worker_conn};
    multi_accept on;
    use epoll;
}

http {
    # Load dynamic modules — Ubuntu nginx cần dòng này
    # Không có → limit_conn_zone size=0 (Ubuntu nginx 1.18 shared memory bug)
    include /etc/nginx/modules-enabled/*.conf;

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

events {
    worker_connections ${worker_conn};
    multi_accept on;
    use epoll;
}

http {
    # Load dynamic modules (Ubuntu nginx cần include này)
    # Phải có trước các directive khác để tránh shared memory zone bug
    include /etc/nginx/modules-enabled/*.conf;

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
# Fix: _build_modsecurity_from_source() implement thực,
# không còn là placeholder return 0 ảo
# ══════════════════════════════════════════════════

_build_modsecurity_from_source() {
    log "Build ModSecurity từ source (10-20 phút)..."

    # Cài build dependencies
    local build_deps=(
        git build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev
        libssl-dev libgeoip-dev libtool libxml2 libxml2-dev
        libcurl4-openssl-dev libyajl-dev pkgconf
    )
    pkg_install "${build_deps[@]}" 2>/dev/null || true

    local src_dir="/usr/local/src"

    # Clone ModSecurity v3
    if [[ ! -d "${src_dir}/ModSecurity" ]]; then
        log "Clone ModSecurity v3..."
        git clone --depth 1 --recurse-submodules \
            https://github.com/SpiderLabs/ModSecurity \
            "${src_dir}/ModSecurity" 2>/dev/null || {
            warn "Clone ModSecurity thất bại — kiểm tra kết nối"
            return 1
        }
    fi

    cd "${src_dir}/ModSecurity" || return 1
    log "Build ModSecurity (có thể mất 10-15 phút)..."
    ./build.sh > /dev/null 2>&1 || true
    ./configure --prefix=/usr --with-pcre \
        > /dev/null 2>&1 || { warn "ModSecurity configure thất bại"; return 1; }
    make -j"$(nproc)" > /dev/null 2>&1 || { warn "ModSecurity make thất bại"; return 1; }
    make install > /dev/null 2>&1 || { warn "ModSecurity install thất bại"; return 1; }

    # Clone nginx-connector
    if [[ ! -d "${src_dir}/ModSecurity-nginx" ]]; then
        git clone --depth 1 \
            https://github.com/SpiderLabs/ModSecurity-nginx \
            "${src_dir}/ModSecurity-nginx" 2>/dev/null || {
            warn "Clone ModSecurity-nginx connector thất bại"
            return 1
        }
    fi

    # Build nginx dynamic module — cần đúng version nginx đang cài
    local nginx_ver; nginx_ver=$(nginx -v 2>&1 | grep -oP 'nginx/\K[\d.]+')
    if [[ -z "$nginx_ver" ]]; then
        warn "Không xác định được Nginx version"
        return 1
    fi

    local nginx_src="${src_dir}/nginx-${nginx_ver}"
    if [[ ! -d "$nginx_src" ]]; then
        log "Download Nginx source ${nginx_ver} để build module..."
        wget -q "http://nginx.org/download/nginx-${nginx_ver}.tar.gz" \
            -O "/tmp/nginx-${nginx_ver}.tar.gz" || {
            warn "Download Nginx source thất bại"
            return 1
        }
        tar -xzf "/tmp/nginx-${nginx_ver}.tar.gz" -C "$src_dir"
        rm -f "/tmp/nginx-${nginx_ver}.tar.gz"
    fi

    cd "$nginx_src" || return 1
    log "Configure Nginx dynamic module..."
    ./configure --with-compat \
        --add-dynamic-module="${src_dir}/ModSecurity-nginx" \
        > /dev/null 2>&1 || { warn "Nginx configure thất bại"; return 1; }
    make modules > /dev/null 2>&1 || { warn "Nginx make modules thất bại"; return 1; }

    # Copy module vào đúng vị trí
    mkdir -p /usr/lib/nginx/modules
    cp objs/ngx_http_modsecurity_module.so /usr/lib/nginx/modules/ 2>/dev/null || {
        warn "Copy module thất bại"
        return 1
    }
    chmod 644 /usr/lib/nginx/modules/ngx_http_modsecurity_module.so

    log "ModSecurity build từ source thành công!"
    return 0
}

setup_modsecurity() {
    log "Cấu hình ModSecurity WAF..."
    local modsec_ready=false

    # Kiểm tra module đã có chưa (qua apt hoặc build trước đó)
    if nginx -V 2>&1 | grep -qi modsecurity \
        || [[ -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ]]; then
        modsec_ready=true
        log "ModSecurity module đã có sẵn"
    fi

    # Thử cài qua apt trước (nhanh hơn build từ source)
    # Bug fix: package name thay đổi theo Ubuntu version
    # Ubuntu 20.04: libnginx-mod-http-modsecurity
    # Ubuntu 22.04+: package bị remove → dùng nginx.org repo hoặc build từ source
    if [[ "$modsec_ready" == "false" && "$OS_FAMILY" == "debian" ]]; then
        log "Thử cài ModSecurity qua apt..."
        apt-get update -y -qq 2>/dev/null || true

        # Thử lần lượt các package name khác nhau theo distro version
        local modsec_pkg=""
        for _pkg in libnginx-mod-http-modsecurity libmodsecurity3; do
            if apt-cache show "$_pkg" &>/dev/null 2>&1; then
                modsec_pkg="$_pkg"
                break
            fi
        done

        if [[ -n "$modsec_pkg" ]] \
            && pkg_install libmodsecurity3 "$modsec_pkg" 2>/dev/null \
            && ( [[ -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ]] \
                 || dpkg -l "$modsec_pkg" 2>/dev/null | grep -q '^ii' ); then
            modsec_ready=true
            log "ModSecurity đã cài qua apt ($modsec_pkg)"
        else
            warn "ModSecurity không có trong apt repos (Ubuntu 22.04+ đã remove package)"
        fi
    fi

    # Fallback: build từ source nếu apt không có
    if [[ "$modsec_ready" == "false" && "$OS_FAMILY" == "debian" ]]; then
        warn "ModSecurity không có trong apt repos — build từ source (10-20 phút)..."
        if _build_modsecurity_from_source; then
            modsec_ready=true
        else
            warn "Build ModSecurity thất bại — bỏ qua WAF"
            return 0
        fi
    fi

    if [[ "$modsec_ready" == "false" ]]; then
        warn "ModSecurity không khả dụng trên hệ thống này — bỏ qua WAF"
        return 0
    fi

    # Kích hoạt module trong nginx.conf
    if [[ -f /usr/share/nginx/modules-available/mod-modsecurity.conf ]]; then
        ln -sf /usr/share/nginx/modules-available/mod-modsecurity.conf \
               /etc/nginx/modules-enabled/50-mod-modsecurity.conf 2>/dev/null || true
    elif [[ -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ]] \
        && ! grep -rq 'ngx_http_modsecurity_module' \
               /etc/nginx/modules-enabled/ /etc/nginx/nginx.conf 2>/dev/null; then
        # Fix C3: absolute path — relative 'modules/' resolve từ nginx prefix
        # /usr/share/nginx/modules/ KHÔNG tồn tại; module thật ở /usr/lib/nginx/modules/
        sed -i '1i load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;' \
            /etc/nginx/nginx.conf
    fi

    # Validate sau khi load module
    if ! nginx -t 2>/dev/null; then
        warn "ModSecurity module load thất bại — revert"
        rm -f /etc/nginx/modules-enabled/50-mod-modsecurity.conf
        sed -i '/ngx_http_modsecurity_module/d' /etc/nginx/nginx.conf 2>/dev/null || true
        nginx_safe_reload
        return 0
    fi

    mkdir -p /etc/nginx/modsec

    # Tìm và copy modsecurity.conf-recommended từ nhiều nguồn khác nhau
    local modsec_conf_src=""
    for path in \
        /usr/local/src/ModSecurity/modsecurity.conf-recommended \
        /usr/share/modsecurity-crs/modsecurity.conf-recommended \
        /etc/modsecurity/modsecurity.conf-recommended; do
        [[ -f "$path" ]] && { modsec_conf_src="$path"; break; }
    done

    if [[ -n "$modsec_conf_src" ]]; then
        cp "$modsec_conf_src" /etc/nginx/modsec/modsecurity.conf
        # Bật enforcement mode (mặc định là DetectionOnly)
        sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' \
            /etc/nginx/modsec/modsecurity.conf
        # Copy unicode mapping nếu có
        local unicode_src="${modsec_conf_src%/*}/unicode.mapping"
        [[ -f "$unicode_src" ]] && cp "$unicode_src" /etc/nginx/modsec/ 2>/dev/null || true
    else
        # Tạo config tối thiểu nếu không tìm thấy recommended config
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

    # Clone OWASP CRS nếu chưa có
    if [[ ! -d "/etc/nginx/modsec/crs" ]]; then
        log "Clone OWASP Core Rule Set..."
        git clone --quiet --depth 1 \
            https://github.com/coreruleset/coreruleset.git \
            /etc/nginx/modsec/crs 2>/dev/null || true
        [[ -f /etc/nginx/modsec/crs/crs-setup.conf.example ]] && \
            cp /etc/nginx/modsec/crs/crs-setup.conf.example \
               /etc/nginx/modsec/crs/crs-setup.conf
    fi

    # Tạo main.conf include tất cả
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

    # Inject vào nginx.conf nếu chưa có
    if ! grep -q 'modsecurity on' /etc/nginx/nginx.conf 2>/dev/null; then
        sed -i '/include \/etc\/nginx\/conf\.d\/\*\.conf;/i\
    modsecurity on;\
    modsecurity_rules_file /etc/nginx/modsec/main.conf;' \
            /etc/nginx/nginx.conf 2>/dev/null || true
    fi

    # Final validation
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
