#!/bin/bash
# =====================================================
# security.sh - Các hàm hardening bảo mật
# ModernVPS v3.2.1 - FIX #1: Blacklist persist
# =====================================================

[[ -f "${SCRIPT_DIR}/lib/ai.sh" ]] && source "${SCRIPT_DIR}/lib/ai.sh"

# ══════════════════════════════════════════════════
# SSH KEY SETUP
# ══════════════════════════════════════════════════

setup_ssh_keys() {
    log "SSH Key Setup..."
    local DEPLOYER_PASS=""

    # Tạo user deployer nếu chưa tồn tại
    if ! id deployer &>/dev/null; then
        useradd -m -s /bin/bash deployer
        case "$OS_FAMILY" in
            debian) usermod -aG sudo deployer ;;
            rhel)   usermod -aG wheel deployer ;;
        esac
        DEPLOYER_PASS=$(openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c16)
        echo "deployer:${DEPLOYER_PASS}" | chpasswd
        log "User 'deployer' đã tạo"
    fi

    mkdir -p /home/deployer/.ssh
    chmod 700 /home/deployer/.ssh
    chown deployer:deployer /home/deployer/.ssh

    echo ""
    warn "══════════════════════════════════════════"
    warn "  Thêm SSH public key TRƯỚC khi harden!"
    warn "══════════════════════════════════════════"
    echo "Paste public key cho 'deployer' (Enter để bỏ qua):"
    read -rp "Public key: " PUBKEY

    if [[ -n "$PUBKEY" ]]; then
        echo "$PUBKEY" >> /home/deployer/.ssh/authorized_keys
        chmod 600 /home/deployer/.ssh/authorized_keys
        chown deployer:deployer /home/deployer/.ssh/authorized_keys
        log "SSH key đã thêm!"
        SKIP_KEY=false
    else
        warn "Bỏ qua SSH key — bật xác thực password tạm thời"
        SKIP_KEY=true

        # Tạo SSH key tạm cho deployer để có thể login ngay
        if command -v ssh-keygen &>/dev/null; then
            warn "Tạo SSH key tạm tại /home/deployer/.ssh/id_ed25519 ..."
            sudo -u deployer ssh-keygen -t ed25519 \
                -f /home/deployer/.ssh/id_ed25519 -N "" -q 2>/dev/null || true

            if [[ -f /home/deployer/.ssh/id_ed25519.pub ]]; then
                cat /home/deployer/.ssh/id_ed25519.pub >> /home/deployer/.ssh/authorized_keys
                chmod 600 /home/deployer/.ssh/authorized_keys
                chown deployer:deployer /home/deployer/.ssh/authorized_keys

                # Lên lịch tự xóa private key sau 24h để tránh bị bỏ quên trên server
                # Đây là rủi ro bảo mật nếu private key còn trên server sau khi đã copy ra ngoài
                local del_script="/tmp/mvps-del-tmpkey.sh"
                cat > "$del_script" <<DELEOF
#!/bin/bash
# Tự xóa SSH private key tạm sau 24h
sleep 86400
if [[ -f /home/deployer/.ssh/id_ed25519 ]]; then
    shred -u /home/deployer/.ssh/id_ed25519 2>/dev/null || \
        rm -f /home/deployer/.ssh/id_ed25519
    echo "$(date): SSH temp private key đã xóa tự động" >> /var/log/modernvps/install.log
fi
rm -f "$del_script"
DELEOF
                chmod +x "$del_script"
                nohup bash "$del_script" >/dev/null 2>&1 &

                warn "Private key: /home/deployer/.ssh/id_ed25519"
                warn "⚠️  Copy ra máy local NGAY rồi xóa thủ công:"
                warn "    scp -P2222 deployer@IP:/home/deployer/.ssh/id_ed25519 ~/.ssh/"
                warn "    (Tự xóa sau 24h nếu bạn quên)"
            fi
        fi
    fi

    # Lưu credentials vào file bảo mật
    mkdir -p "$INSTALL_DIR"
    if [[ -n "$DEPLOYER_PASS" ]]; then
        printf 'DEPLOYER_USER=deployer\nDEPLOYER_PASS=%s\n' "$DEPLOYER_PASS" \
            >> "$INSTALL_DIR/.credentials"
        chmod 600 "$INSTALL_DIR/.credentials"
    fi
}

# ══════════════════════════════════════════════════
# SSH HARDENING
# ══════════════════════════════════════════════════

harden_ssh() {
    log "Hardening SSH..."
    cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.bak.$(date +%s)"

    local PASS_AUTH="no"
    [[ "$SKIP_KEY" == "true" ]] && PASS_AUTH="yes"

    # Dùng drop-in config thay vì sửa trực tiếp sshd_config chính
    # Lý do: dễ revert, không conflict với package update
    mkdir -p /etc/ssh/sshd_config.d
    grep -q "^Include.*/etc/ssh/sshd_config.d/" /etc/ssh/sshd_config 2>/dev/null || \
        sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config

    # Xóa các directive cũ trong sshd_config gốc tránh conflict với drop-in
    for directive in Port PermitRootLogin PasswordAuthentication \
                     AuthenticationMethods AllowUsers; do
        sed -i "/^${directive}[[:space:]]/d" /etc/ssh/sshd_config 2>/dev/null || true
    done

    # Ubuntu 22.04+ dùng ssh.socket thay vì sshd.service để quản lý port
    # Phải override socket unit để đổi port, không chỉ sửa sshd_config
    if systemctl cat ssh.socket &>/dev/null; then
        mkdir -p /etc/systemd/system/ssh.socket.d
        printf '[Socket]\nListenStream=\nListenStream=2222\n' \
            > /etc/systemd/system/ssh.socket.d/override.conf
        systemctl daemon-reload
    fi

    # Build AuthenticationMethods dựa trên PASS_AUTH
    local auth_methods="publickey"
    [[ "$PASS_AUTH" == "yes" ]] && auth_methods="publickey password"

    cat > /etc/ssh/sshd_config.d/99-modernvps.conf <<EOF
# ModernVPS SSH Hardening
Port 2222
PermitRootLogin no
PasswordAuthentication ${PASS_AUTH}
PubkeyAuthentication yes
AuthenticationMethods ${auth_methods}
X11Forwarding no
MaxAuthTries 3
MaxSessions 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
AllowAgentForwarding no
AllowUsers deployer
LoginGraceTime 30
HostKey /etc/ssh/ssh_host_ed25519_key
# Chỉ dùng thuật toán hiện đại, loại bỏ legacy
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com
HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com
RekeyLimit 512M 1h
LogLevel VERBOSE
Banner /etc/ssh/banner
EOF

    cat > /etc/ssh/banner <<'EOF'
***********************************************************
  UNAUTHORIZED ACCESS PROHIBITED. All connections monitored.
***********************************************************
EOF

    # Tạo host key ed25519 nếu chưa có
    [[ ! -f /etc/ssh/ssh_host_ed25519_key ]] && \
        ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N "" 2>/dev/null

    # Validate config trước khi apply — tránh lock out
    if sshd -t 2>/dev/null; then
        restart_ssh
        if [[ "$PASS_AUTH" == "yes" ]]; then
            warn "SSH: port 2222, password TẠM BẬT — hãy thêm SSH key sớm!"
        else
            log "SSH: port 2222, key-only (an toàn)"
        fi
    else
        warn "sshd config không hợp lệ — đang revert..."
        rm -f /etc/ssh/sshd_config.d/99-modernvps.conf
        return 1
    fi
}

# ══════════════════════════════════════════════════
# NFTABLES FIREWALL
# ══════════════════════════════════════════════════

setup_nftables() {
    log "Setup nftables (IPv4 + IPv6, SERVER_TYPE=${SERVER_TYPE})..."

    # Đảm bảo PANEL_PORT đã được finalize trước khi ghi vào rules
    # PANEL_PORT được set từ common.sh và có thể bị thay đổi bởi check_prerequisites()
    # Dùng giá trị hiện tại tại thời điểm hàm này được gọi
    local panel_port="${PANEL_PORT:-8080}"

    systemctl disable --now iptables 2>/dev/null || true
    systemctl disable --now netfilter-persistent 2>/dev/null || true

    # Web server và Load Balancer dùng chung ruleset cơ bản
    # Sự khác biệt: LB không cần mở PANEL_PORT (không có web panel)
    local panel_rule=""
    if [[ "$SERVER_TYPE" == "web" ]]; then
        panel_rule="        tcp dport ${panel_port} ct state new accept"
    fi

    # Agent port 9000: chỉ mở cho web node, chỉ từ LB internal IP
    # LB_INTERNAL_IP được set khi join cluster (mvps-cluster add-node)
    # Mặc định rỗng = không mở port → an toàn khi chưa join cluster
    local agent_rule=""
    if [[ "$SERVER_TYPE" == "web" && -n "${LB_INTERNAL_IP:-}" ]]; then
        agent_rule="        ip saddr ${LB_INTERNAL_IP} tcp dport 9000 ct state new accept"
    fi

    cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
# ModernVPS nftables ruleset
# Generated: $(date)
# Server type: ${SERVER_TYPE}

flush ruleset

table inet modernvps {

    # Blacklist sets — hỗ trợ cả IPv4 và IPv6
    # timeout 24h: IP bị ban tự động mở sau 24h
    set blacklist_v4 {
        type ipv4_addr
        flags timeout
        timeout 24h
    }
    set blacklist_v6 {
        type ipv6_addr
        flags timeout
        timeout 24h
    }

    chain input {
        type filter hook input priority filter; policy drop;

        # Cho phép established connections — không re-inspect
        ct state established,related accept
        ct state invalid drop

        # Loopback luôn cho phép
        iif "lo" accept

        # Drop blacklisted IPs ngay đầu
        ip  saddr @blacklist_v4 drop
        ip6 saddr @blacklist_v6 drop

        # Drop các TCP flag combinations bất thường (NULL scan, XMAS scan, SYN-RST)
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop
        tcp flags & (syn|rst) == syn|rst drop

        # ICMP giới hạn rate — tránh flood nhưng vẫn cho phép ping bình thường
        icmp   type echo-request limit rate 2/second burst 4 packets accept
        icmpv6 type { echo-request, nd-neighbor-solicit,
                      nd-router-advert, nd-neighbor-advert } accept

        # SSH: rate limit theo IP nguồn
        # meter: track từng IP riêng, không dùng chung counter
        tcp dport 2222 ct state new \
            meter ssh_limit { ip saddr limit rate 4/minute burst 4 packets } accept
        tcp dport 2222 ct state new log prefix "SSH_BRUTE: " drop

        # HTTP/HTTPS: rate limit cao hơn để phục vụ web traffic thực
        tcp dport { 80, 443 } ct state new \
            meter http_limit { ip saddr limit rate 50/second burst 100 packets } accept
        tcp dport { 80, 443 } ct state new drop

        # Panel port — chỉ mở cho web server
${panel_rule}

        # Agent port 9000 — chỉ từ LB internal IP (web node only)
        # Biến agent_rule rỗng nếu LB_INTERNAL_IP chưa set → không mở port
${agent_rule}

        # Log và drop mọi thứ còn lại (rate limit log để tránh flood disk)
        limit rate 5/minute log prefix "NFT_DROP: " level warn
    }

    chain forward {
        # Load balancer hoạt động ở layer 7 (Nginx reverse proxy)
        # Không cần forward ở layer 3/4 → drop tất cả
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
        # Block các port thường dùng bởi backdoor/C2 phổ biến
        tcp dport { 3333, 4444, 5555, 14444, 14433 } \
            log prefix "OUTBOUND_SUSPECT: " drop
    }
}
EOF

    if nft -c -f /etc/nftables.conf 2>/dev/null; then
        systemctl enable --now nftables 2>/dev/null || true
        nft -f /etc/nftables.conf 2>/dev/null || true
        if [[ "$SERVER_TYPE" == "web" ]]; then
            log "nftables: DROP policy | ports: 2222/80/443/${panel_port} (IPv6 ready)"
        else
            log "nftables: DROP policy | ports: 2222/80/443 (LB mode, IPv6 ready)"
        fi
    else
        warn "nftables config không hợp lệ — bỏ qua"
        return 1
    fi

    # FIX #1: Setup blacklist persist qua reboot
    setup_blacklist_persist
}

# ══════════════════════════════════════════════════
# FIX #1: BLACKLIST PERSIST QUA REBOOT
# ROOT CAUSE: nftables set blacklist_v4/v6 chỉ tồn tại trong RAM
#             Reboot server → mất hết IPs đã ban → attacker quay lại
# GIẢI PHÁP: Script save/restore + systemd service + auto-save timer
# ══════════════════════════════════════════════════

setup_blacklist_persist() {
    log "Setup blacklist persist..."

    mkdir -p /opt/modernvps /var/log/modernvps

    # Cài script mvps-blacklist
    cat > /usr/local/bin/mvps-blacklist <<'BLEOF'
#!/bin/bash
# mvps-blacklist - Persist nftables blacklist qua reboot
# ModernVPS v3.2.1 - FIX #1
set -uo pipefail

readonly INSTALL_DIR="/opt/modernvps"
readonly BLACKLIST_V4="${INSTALL_DIR}/blacklist-v4.txt"
readonly BLACKLIST_V6="${INSTALL_DIR}/blacklist-v6.txt"
readonly LOCK_FILE="/run/mvps-blacklist.lock"
readonly LOG_FILE="/var/log/modernvps/blacklist.log"

log() { echo "[INFO] $1"; echo "$(date -Iseconds) [INFO] $1" >> "$LOG_FILE" 2>/dev/null; }
err() { echo "[ERROR] $1" >&2; echo "$(date -Iseconds) [ERROR] $1" >> "$LOG_FILE" 2>/dev/null; }

is_ipv4() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || return 1
    local IFS='./'; read -ra p <<< "$1"
    for i in 0 1 2 3; do (( p[i] > 255 )) && return 1; done; return 0
}

is_ipv6() { [[ "$1" =~ ^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(/[0-9]{1,3})?$ ]]; }

get_blacklist() {
    nft list set inet modernvps "$1" 2>/dev/null \
        | grep -oP '(?<=elements = \{ ).*(?= \})' \
        | tr ',' '\n' | awk '{print $1}' | grep -v '^$' | sort -u
}

cmd_save() {
    mkdir -p "$INSTALL_DIR"
    local v4=0 v6=0
    : > "$BLACKLIST_V4.tmp"
    while IFS= read -r ip; do [[ -n "$ip" ]] && { echo "$ip" >> "$BLACKLIST_V4.tmp"; ((v4++)); }; done < <(get_blacklist "blacklist_v4")
    mv "$BLACKLIST_V4.tmp" "$BLACKLIST_V4"; chmod 600 "$BLACKLIST_V4"

    : > "$BLACKLIST_V6.tmp"
    while IFS= read -r ip; do [[ -n "$ip" ]] && { echo "$ip" >> "$BLACKLIST_V6.tmp"; ((v6++)); }; done < <(get_blacklist "blacklist_v6")
    mv "$BLACKLIST_V6.tmp" "$BLACKLIST_V6"; chmod 600 "$BLACKLIST_V6"

    log "Saved: ${v4} IPv4, ${v6} IPv6"
}

cmd_restore() {
    local r4=0 r6=0 fail=0 wait=0
    while ! nft list table inet modernvps &>/dev/null; do
        sleep 1; ((wait++)); ((wait > 30)) && { err "nftables không ready"; return 1; }
    done

    [[ -f "$BLACKLIST_V4" ]] && while IFS= read -r ip; do
        [[ -z "$ip" || "$ip" =~ ^# ]] && continue; is_ipv4 "$ip" || continue
        nft add element inet modernvps blacklist_v4 "{ $ip timeout 24h }" 2>/dev/null && ((r4++)) || ((fail++))
    done < "$BLACKLIST_V4"

    [[ -f "$BLACKLIST_V6" ]] && while IFS= read -r ip; do
        [[ -z "$ip" || "$ip" =~ ^# ]] && continue; is_ipv6 "$ip" || continue
        nft add element inet modernvps blacklist_v6 "{ $ip timeout 24h }" 2>/dev/null && ((r6++)) || ((fail++))
    done < "$BLACKLIST_V6"

    log "Restored: ${r4} IPv4, ${r6} IPv6 (${fail} failed)"
}

cmd_add() {
    local ip="$1" timeout="${2:-24h}"
    if is_ipv4 "$ip"; then
        nft add element inet modernvps blacklist_v4 "{ $ip timeout $timeout }" 2>/dev/null || { err "Failed: $ip"; return 1; }
        grep -qxF "$ip" "$BLACKLIST_V4" 2>/dev/null || echo "$ip" >> "$BLACKLIST_V4"
        log "Blocked IPv4: $ip"
    elif is_ipv6 "$ip"; then
        nft add element inet modernvps blacklist_v6 "{ $ip timeout $timeout }" 2>/dev/null || { err "Failed: $ip"; return 1; }
        grep -qxF "$ip" "$BLACKLIST_V6" 2>/dev/null || echo "$ip" >> "$BLACKLIST_V6"
        log "Blocked IPv6: $ip"
    else
        err "Invalid IP: $ip"; return 1
    fi
}

cmd_del() {
    local ip="$1"
    if is_ipv4 "$ip"; then
        nft delete element inet modernvps blacklist_v4 "{ $ip }" 2>/dev/null || true
        [[ -f "$BLACKLIST_V4" ]] && { grep -vxF "$ip" "$BLACKLIST_V4" > "$BLACKLIST_V4.tmp" 2>/dev/null; mv "$BLACKLIST_V4.tmp" "$BLACKLIST_V4"; }
        log "Unblocked: $ip"
    elif is_ipv6 "$ip"; then
        nft delete element inet modernvps blacklist_v6 "{ $ip }" 2>/dev/null || true
        [[ -f "$BLACKLIST_V6" ]] && { grep -vxF "$ip" "$BLACKLIST_V6" > "$BLACKLIST_V6.tmp" 2>/dev/null; mv "$BLACKLIST_V6.tmp" "$BLACKLIST_V6"; }
        log "Unblocked: $ip"
    else
        err "Invalid IP: $ip"; return 1
    fi
}

cmd_list() {
    echo "═══ IPv4 Blacklist ═══"; echo "Runtime:"; get_blacklist "blacklist_v4" | awk '{printf "  %s\n",$0}'
    echo "Persisted:"; [[ -f "$BLACKLIST_V4" ]] && awk '{printf "  %s\n",$0}' "$BLACKLIST_V4" || echo "  (none)"
    echo ""; echo "═══ IPv6 Blacklist ═══"; echo "Runtime:"; get_blacklist "blacklist_v6" | awk '{printf "  %s\n",$0}'
    echo "Persisted:"; [[ -f "$BLACKLIST_V6" ]] && awk '{printf "  %s\n",$0}' "$BLACKLIST_V6" || echo "  (none)"
}

CMD="${1:-help}"; shift || true
exec 200>"$LOCK_FILE"; flock -n 200 || { err "Another instance running"; exit 1; }
case "$CMD" in
    save) cmd_save ;; restore) cmd_restore ;; add) cmd_add "${1:-}" "${2:-24h}" ;;
    del) cmd_del "${1:-}" ;; list) cmd_list ;;
    *) echo "Usage: mvps-blacklist <save|restore|add IP|del IP|list>" ;;
esac
BLEOF
    chmod +x /usr/local/bin/mvps-blacklist

    # Systemd service: restore khi boot
    cat > /etc/systemd/system/mvps-blacklist.service <<'SVCEOF'
[Unit]
Description=ModernVPS Restore nftables Blacklist
After=nftables.service
Requires=nftables.service
Before=fail2ban.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mvps-blacklist restore
ExecStop=/usr/local/bin/mvps-blacklist save
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVCEOF

    # Timer: auto-save mỗi 30 phút
    cat > /etc/systemd/system/mvps-blacklist-save.timer <<'TMREOF'
[Unit]
Description=ModernVPS Blacklist Periodic Save

[Timer]
OnBootSec=5min
OnUnitActiveSec=30min
Persistent=true

[Install]
WantedBy=timers.target
TMREOF

    cat > /etc/systemd/system/mvps-blacklist-save.service <<'SSVCEOF'
[Unit]
Description=ModernVPS Blacklist Periodic Save
After=nftables.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/mvps-blacklist save
SSVCEOF

    systemctl daemon-reload
    systemctl enable mvps-blacklist.service 2>/dev/null || true
    systemctl enable mvps-blacklist-save.timer 2>/dev/null || true
    systemctl start mvps-blacklist-save.timer 2>/dev/null || true

    log "Blacklist persist: OK (systemd service + timer)"
}

# ══════════════════════════════════════════════════
# FAIL2BAN
# ══════════════════════════════════════════════════

# Tạo filter sshd-aggressive nếu chưa có
# Filter này không có sẵn trên Ubuntu 22/24 → tự tạo thay vì bỏ qua
_ensure_sshd_aggressive_filter() {
    local filter_file="/etc/fail2ban/filter.d/sshd-aggressive.conf"
    [[ -f "$filter_file" ]] && return 0

    log "Tạo filter sshd-aggressive (không có sẵn trên distro này)..."
    cat > "$filter_file" <<'EOF'
# sshd-aggressive filter cho ModernVPS
# Ban nhanh hơn sshd thông thường — dành cho IP cố tình bruteforce
[INCLUDES]
before = common.conf

[Definition]
_daemon = sshd
failregex = ^%(__prefix_line)s(?:error: PAM: )?[aA]uthentication (?:failure|error|failed) for .* from <HOST>( via \S+)?\s*$
            ^%(__prefix_line)s(?:error: PAM: )?User not known to the underlying authentication module for .* from <HOST>\s*$
            ^%(__prefix_line)sFailed \S+ for (?:invalid user )?(?P<cond_user>\S+) from <HOST>(?: port \d+)?(?: ssh\d*)?(?(cond_user): |$)
            ^%(__prefix_line)sROOT LOGIN REFUSED from <HOST>
            ^%(__prefix_line)s[iI](?:llegal|nvalid) user .+ from <HOST>
ignoreregex =
EOF
    log "Filter sshd-aggressive đã tạo"
}

setup_fail2ban() {
    log "Cấu hình Fail2ban..."

    # Đảm bảo filter sshd-aggressive tồn tại trước khi check
    _ensure_sshd_aggressive_filter

    # Xây dựng danh sách jail dựa trên filter thực sự tồn tại
    # Tránh enable jail với filter không có → fail2ban crash khi start
    local JAILS=()
    [[ -f /etc/fail2ban/filter.d/sshd.conf            ]] && JAILS+=("sshd")
    [[ -f /etc/fail2ban/filter.d/sshd-aggressive.conf ]] && JAILS+=("sshd-aggressive")

    # Nginx jails chỉ enable trên web server
    if [[ "$SERVER_TYPE" == "web" ]]; then
        [[ -f /etc/fail2ban/filter.d/nginx-http-auth.conf ]] && JAILS+=("nginx-http-auth")
        [[ -f /etc/fail2ban/filter.d/nginx-botsearch.conf ]] && JAILS+=("nginx-botsearch")
        [[ -f /etc/fail2ban/filter.d/nginx-limit-req.conf ]] && JAILS+=("nginx-limit-req")
    fi

    # recidive: ban IP đã bị ban nhiều lần → ban dài hơn (1 tuần)
    [[ -f /etc/fail2ban/filter.d/recidive.conf ]] && JAILS+=("recidive")

    # Ghi cấu hình dạng heredoc thay vì nhiều lần echo >> (gọn hơn, ít lỗi hơn)
    {
        cat <<EOF
[DEFAULT]
banaction        = nftables-multiport
banaction_allports = nftables-allports
ignoreip         = 127.0.0.1/8 ::1
EOF

        for jail in "${JAILS[@]}"; do
            printf '\n[%s]\nenabled = true\n' "$jail"
            case "$jail" in
                sshd)
                    cat <<EOF
port      = 2222
maxretry  = 3
findtime  = 600
bantime   = 3600
EOF
                    ;;
                sshd-aggressive)
                    cat <<EOF
port      = 2222
maxretry  = 2
findtime  = 3600
bantime   = 86400
EOF
                    ;;
                nginx-http-auth)
                    cat <<EOF
port      = http,https
logpath   = /var/log/nginx/error.log
maxretry  = 3
bantime   = 3600
EOF
                    ;;
                nginx-botsearch)
                    cat <<EOF
port      = http,https
logpath   = /var/log/nginx/access.log
maxretry  = 3
findtime  = 300
bantime   = 86400
EOF
                    ;;
                nginx-limit-req)
                    cat <<EOF
port      = http,https
logpath   = /var/log/nginx/error.log
maxretry  = 5
findtime  = 60
bantime   = 7200
EOF
                    ;;
                recidive)
                    cat <<EOF
logpath   = /var/log/fail2ban.log
banaction = nftables-allports
maxretry  = 3
findtime  = 86400
bantime   = 604800
EOF
                    ;;
            esac
        done
    } > /etc/fail2ban/jail.d/modernvps.conf

    # Fix: tạo nginx log files trống TRƯỚC khi restart fail2ban
    # setup_security() chạy TRƯỚC nginx → log chưa tồn tại
    # Fail2ban crash: "Have not found any log file for nginx-http-auth jail"
    if [[ "$SERVER_TYPE" == "web" ]]; then
        mkdir -p /var/log/nginx
        for _log in /var/log/nginx/error.log /var/log/nginx/access.log; do
            [[ ! -f "$_log" ]] && touch "$_log" \
                && chown www-data:adm "$_log" 2>/dev/null \
                && chmod 640 "$_log" || true
        done
    fi

    systemctl restart fail2ban 2>/dev/null || {
        warn "Fail2ban restart thất bại"
        return 1
    }
    log "Fail2ban: jails đã bật: ${JAILS[*]:-none}"
}

# ══════════════════════════════════════════════════
# SYSCTL KERNEL TUNING
# Tách thành 2 profile: web vs loadbalancer
# Guard bằng is_sysctl_writable() để skip trên LXC/OpenVZ
# ══════════════════════════════════════════════════

setup_sysctl() {
    log "Kernel tuning (SERVER_TYPE=${SERVER_TYPE}, VIRT=${VIRT_TYPE})..."

    # Kiểm tra có thể ghi sysctl không (LXC/OpenVZ không cho phép)
    if ! is_sysctl_writable; then
        warn "Bỏ qua sysctl — môi trường ${VIRT_TYPE} không hỗ trợ thay đổi kernel params"
        warn "Liên hệ provider để yêu cầu các kernel params cần thiết"
        return 0
    fi

    local sysctl_file="/etc/sysctl.d/99-modernvps.conf"

    # Params dùng CHUNG cho cả web và lb
    cat > "$sysctl_file" <<'EOF'
# ── ModernVPS Kernel Hardening ─────────────────
# Bảo vệ network
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0

# Kernel hardening
kernel.randomize_va_space=2
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.yama.ptrace_scope=1

# Filesystem hardening
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.file-max=2097152

# TCP performance — BBR congestion control
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.ipv4.tcp_fastopen=3
net.ipv4.tcp_fin_timeout=10
net.ipv4.tcp_tw_reuse=1

# Connection queues
net.core.somaxconn=65535
net.ipv4.tcp_max_syn_backlog=65535

# Memory
vm.swappiness=10
EOF

    # Params BỔ SUNG cho Load Balancer
    # LB xử lý nhiều connection đồng thời hơn web server nhiều
    # → Cần mở rộng ephemeral port range và NIC queue
    if [[ "$SERVER_TYPE" == "loadbalancer" ]]; then
        cat >> "$sysctl_file" <<'EOF'

# ── Load Balancer specific ──────────────────────
# Mở rộng ephemeral port range: LB tạo nhiều connection đến backend
# Mặc định 32768-60999 → chỉ ~28K ports, quá ít khi traffic cao
net.ipv4.ip_local_port_range=1024 65535

# NIC receive queue — tránh drop packet khi burst traffic cao
# trước khi kernel kịp xử lý
net.core.netdev_max_backlog=65535

# Giới hạn orphaned TCP sockets — tránh memory exhaustion
# khi client đột ngột ngắt kết nối hàng loạt
net.ipv4.tcp_max_orphans=65535

# Tăng số lượng file descriptors tối đa cho Nginx LB
# worker_connections 65535 × 2 (read+write) × workers
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 65536 16777216
EOF
    else
        # Web server: ưu tiên disk write performance cho logs và uploads
        cat >> "$sysctl_file" <<'EOF'

# ── Web Server specific ─────────────────────────
# dirty_ratio: % RAM có thể là dirty pages trước khi buộc flush
# 15% phù hợp cho web server có nhiều disk write (logs, sessions)
vm.dirty_ratio=15
vm.dirty_background_ratio=5
EOF
    fi

    # Apply sysctl — ignore lỗi vì một số param không tồn tại trên kernel cũ
    sysctl --system > /dev/null 2>&1 || true

    log "Sysctl: profile ${SERVER_TYPE} đã apply"
}

# ══════════════════════════════════════════════════
# AUDITD
# ══════════════════════════════════════════════════

setup_auditd() {
    command -v auditctl &>/dev/null || return 0
    log "Cấu hình auditd..."
    cat > /etc/audit/rules.d/99-modernvps.rules <<'EOF'
# ModernVPS audit rules
-D
-b 8192
-f 1

# Thay đổi thời gian hệ thống
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change

# Thay đổi identity (user/group/sudo)
-w /etc/passwd  -p wa -k identity
-w /etc/shadow  -p wa -k identity
-w /etc/group   -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/sudoers.d/ -p wa -k identity

# Thay đổi SSH config
-w /etc/ssh/sshd_config    -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd

# Thay đổi Nginx config
-w /etc/nginx/ -p wa -k webserver

# Thay đổi ModernVPS config
-w /opt/modernvps/ -p wa -k modernvps

# Lock audit config (phải là dòng cuối)
-e 2
EOF
    augenrules --load 2>/dev/null || service auditd restart 2>/dev/null || true
    log "Auditd: rules đã load"
}

# ══════════════════════════════════════════════════
# EXTRA HARDENING
# ══════════════════════════════════════════════════

setup_extra_hardening() {
    log "Extra hardening..."

    # Blacklist kernel modules không cần thiết
    # Giảm attack surface — các protocol/filesystem ít dùng nhưng có CVE lịch sử
    cat > /etc/modprobe.d/modernvps-blacklist.conf <<'EOF'
# ModernVPS — Blacklist unused/risky kernel modules
blacklist dccp
blacklist sctp
blacklist rds
blacklist tipc
blacklist cramfs
blacklist hfs
blacklist hfsplus
blacklist firewire-core
blacklist thunderbolt
EOF

    # Giới hạn cron chỉ cho root và deployer
    printf 'root\ndeployer\n' > /etc/cron.allow
    chmod 640 /etc/cron.allow
    rm -f /etc/cron.deny

    # Giới hạn resource limits — tránh fork bomb và core dump
    cat > /etc/security/limits.d/99-modernvps.conf <<'EOF'
# ModernVPS resource limits
* hard core    0
* soft core    0
* hard nofile  65536
* soft nofile  65536
* hard nproc   65536
* soft nproc   65536
EOF

    # Disable core dump qua systemd
    mkdir -p /etc/systemd/coredump.conf.d
    printf '[Coredump]\nStorage=none\nProcessSizeMax=0\n' \
        > /etc/systemd/coredump.conf.d/disable.conf

    # AppArmor enforce cho nginx (chỉ Debian/Ubuntu)
    if [[ "$OS_FAMILY" == "debian" ]]; then
        aa-enforce /etc/apparmor.d/usr.sbin.nginx 2>/dev/null || true
    fi

    log "Extra hardening hoàn tất"
}

# ══════════════════════════════════════════════════
# SETUP SFTP JAIL (dùng bởi menu web)
# Tạo SFTP user bị chroot vào webroot của domain
# ══════════════════════════════════════════════════

setup_sftp_jail_config() {
    # Thêm Match block cho sftp-users group vào sshd config drop-in
    # Chỉ gọi 1 lần khi setup server, không gọi lại mỗi khi tạo user
    local sftp_conf="/etc/ssh/sshd_config.d/98-sftp-jail.conf"
    [[ -f "$sftp_conf" ]] && return 0

    log "Cấu hình SFTP chroot jail..."

    # Tạo group sftp-users nếu chưa có
    getent group sftp-users &>/dev/null || groupadd sftp-users

    cat > "$sftp_conf" <<'EOF'
# ModernVPS SFTP Jail — chroot user vào webroot
Match Group sftp-users
    ChrootDirectory %h
    ForceCommand internal-sftp -l INFO
    AllowTcpForwarding no
    X11Forwarding no
    PasswordAuthentication yes
EOF

    if sshd -t 2>/dev/null; then
        restart_ssh
        log "SFTP chroot jail đã cấu hình (group: sftp-users)"
    else
        warn "SFTP config không hợp lệ — revert"
        rm -f "$sftp_conf"
        return 1
    fi
}

# ══════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════

setup_security() {
    setup_ssh_keys
    harden_ssh          || warn "SSH hardening chưa hoàn tất"
    setup_nftables      || warn "nftables chưa hoàn tất"
    setup_fail2ban      || warn "Fail2ban chưa hoàn tất"
    setup_sysctl
    setup_auditd        || true
    setup_extra_hardening

    # Setup SFTP jail config chỉ cho web server
    if [[ "$SERVER_TYPE" == "web" ]]; then
        setup_sftp_jail_config || warn "SFTP jail config chưa hoàn tất"
    fi
    ai_hook_post_security_setup || true
}
