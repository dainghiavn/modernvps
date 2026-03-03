#!/bin/bash
# ══════════════════════════════════════════════════
# lib/ai.sh — ModernVPS AI Hooks
# Source bởi stack.sh và security.sh
# Không chạy trực tiếp
#
# Nguyên tắc:
#   1. Mọi hook đều ASYNC (nohup background) — không block installer
#   2. Wrap trong ai_enabled() — server chạy bình thường dù AI down
#   3. Chỉ gọi trên web node (agent chạy tại đây)
#   4. Kết quả ghi vào /var/log/modernvps/ai-hooks.log
# ══════════════════════════════════════════════════

AI_CONF="/etc/modernvps/ai.conf"
AI_HOOK_LOG="/var/log/modernvps/ai-hooks.log"
AI_AGENT_TOKEN_FILE="/opt/modernvps/agent-token.json"
AI_AGENT_PORT=9000
AI_HOOK_TIMEOUT=25   # Claude API cần thời gian, dài hơn timeout thường

# ── Helpers ────────────────────────────────────────────────────

# Kiểm tra AI layer có sẵn sàng không
# Return 0 = OK, 1 = không dùng được (không log lỗi — im lặng)
ai_enabled() {
    # Chỉ chạy hook trên web node
    [[ "${SERVER_TYPE:-}" != "web" ]] && return 1

    # File config phải tồn tại
    [[ ! -f "$AI_CONF" ]] && return 1

    # Đọc AI_ENABLED
    local enabled
    enabled=$(grep -m1 '^AI_ENABLED=' "$AI_CONF" 2>/dev/null | cut -d'"' -f2)
    [[ "$enabled" != "true" ]] && return 1

    # API key phải có
    local key
    key=$(grep -m1 '^ANTHROPIC_API_KEY=' "$AI_CONF" 2>/dev/null | cut -d'"' -f2)
    [[ -z "$key" ]] && return 1

    # agent/ai/client.php phải có
    [[ ! -f "${SCRIPT_DIR}/agent/ai/client.php" ]] && return 1

    return 0
}

# Lấy agent token local (web node)
_ai_hook_get_token() {
    [[ ! -f "$AI_AGENT_TOKEN_FILE" ]] && return 1
    python3 -c "
import json, sys
try:
    d = json.load(open('$AI_AGENT_TOKEN_FILE'))
    print(d.get('token',''))
except:
    sys.exit(1)
" 2>/dev/null || \
    grep -o '"token":"[^"]*"' "$AI_AGENT_TOKEN_FILE" 2>/dev/null \
        | cut -d'"' -f4
}

# Ghi log hook
_ai_hook_log() {
    local level="$1"; shift
    mkdir -p "$(dirname "$AI_HOOK_LOG")"
    echo "$(date -Iseconds) [AI-HOOK] [$level] $*" >> "$AI_HOOK_LOG"
}

# Gọi agent AI endpoint (POST JSON)
_ai_hook_call() {
    local endpoint="$1" body="${2:-{}}"
    local token; token=$(_ai_hook_get_token) || return 1
    [[ -z "$token" ]] && return 1

    curl -sf \
        --max-time "$AI_HOOK_TIMEOUT" \
        -X POST \
        -H "Authorization: Bearer ${token}" \
        -H "Content-Type: application/json" \
        -d "$body" \
        "http://127.0.0.1:${AI_AGENT_PORT}${endpoint}" 2>/dev/null
}

# Format và log kết quả AI — không print ra stdout (không làm bẩn installer output)
_ai_hook_log_result() {
    local hook_name="$1" result="$2"

    if [[ -z "$result" ]]; then
        _ai_hook_log "WARN" "${hook_name}: Không nhận được response từ agent"
        return
    fi

    local err; err=$(echo "$result" | grep -o '"error":"[^"]*"' | cut -d'"' -f4 2>/dev/null)
    if [[ -n "$err" ]]; then
        _ai_hook_log "WARN" "${hook_name}: $err"
        return
    fi

    local severity diagnosis
    severity=$(echo "$result" | grep -o '"severity":"[^"]*"' | cut -d'"' -f4 2>/dev/null)
    diagnosis=$(echo "$result" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    # Chỉ lấy 3 dòng đầu để log không quá dài
    lines=d.get('diagnosis','').strip().split('\n')[:3]
    print(' | '.join(l.strip() for l in lines if l.strip()))
except:
    pass
" 2>/dev/null || echo "")

    _ai_hook_log "INFO" "${hook_name}: severity=${severity} | ${diagnosis}"

    # Cảnh báo nếu HIGH/CRITICAL — ghi riêng để dễ grep
    case "$severity" in
        HIGH|CRITICAL)
            _ai_hook_log "ALERT" "${hook_name}: MỨC ĐỘ ${severity} — xem chi tiết: cat ${AI_HOOK_LOG}"
            ;;
    esac
}


# ══════════════════════════════════════════════════
# HOOK 1: Post-deploy AI verify
# Gọi từ: stack.sh → setup_mvps_agent() khi xong
#
# Mục đích: Sau khi agent được cài, gọi AI kiểm tra
#   - Nginx + PHP-FPM + MariaDB có chạy không
#   - Error log có gì bất thường không
#   - Kết quả ghi vào ai-hooks.log
# ══════════════════════════════════════════════════

ai_hook_post_stack_install() {
    ai_enabled || return 0   # Im lặng nếu AI không khả dụng

    _ai_hook_log "INFO" "post_stack_install: Bắt đầu AI verify sau cài stack..."

    # Chờ agent sẵn sàng (PHP-FPM + nginx cần khởi động)
    local max_wait=30 waited=0
    while (( waited < max_wait )); do
        if curl -sf --max-time 2 \
            -H "Authorization: Bearer $(_ai_hook_get_token 2>/dev/null)" \
            "http://127.0.0.1:${AI_AGENT_PORT}/mvps/health" &>/dev/null; then
            break
        fi
        sleep 2
        (( waited += 2 ))
    done

    if (( waited >= max_wait )); then
        _ai_hook_log "WARN" "post_stack_install: Agent chưa sẵn sàng sau ${max_wait}s — bỏ qua AI verify"
        return 0
    fi

    # Gọi AI analyze logs (background — không block installer)
    nohup bash -c '
        sleep 3  # Chờ services ổn định
        result=$( '"'$(declare -f _ai_hook_call)'
        _ai_hook_call /mvps/ai-analyze/logs '"'"'{"lines":30}'"'"
        ')
        '"_ai_hook_log_result post_stack_install \"\$result\""'
    ' >> "$AI_HOOK_LOG" 2>&1 &

    _ai_hook_log "INFO" "post_stack_install: AI verify đang chạy background (PID: $!)"
}

# ══════════════════════════════════════════════════
# HOOK 2: Post-security AI review
# Gọi từ: security.sh → cuối setup_security()
#
# Mục đích: Sau khi cấu hình nftables + Fail2ban xong
#   - AI review security posture
#   - Phát hiện gap nếu có
#   - Kết quả ghi vào ai-hooks.log
# ══════════════════════════════════════════════════

ai_hook_post_security_setup() {
    ai_enabled || return 0

    _ai_hook_log "INFO" "post_security_setup: Bắt đầu AI security review..."

    # Hook này không cần agent sẵn sàng ngay (security setup chạy TRƯỚC stack)
    # → Delay 60s để chờ agent khởi động sau khi stack xong
    nohup bash -c "
        sleep 60  # Chờ agent khởi động sau khi stack cài xong

        # Kiểm tra agent có sẵn sàng không
        token_file='${AI_AGENT_TOKEN_FILE}'
        if [[ ! -f \"\$token_file\" ]]; then
            echo \"\$(date -Iseconds) [AI-HOOK] [WARN] post_security_setup: token chưa có sau 60s\"
            exit 0
        fi

        token=\$(grep -o '\"token\":\"[^\"]*\"' \"\$token_file\" | cut -d'\"' -f4 2>/dev/null)
        [[ -z \"\$token\" ]] && exit 0

        result=\$(curl -sf --max-time ${AI_HOOK_TIMEOUT} \\
            -X POST \\
            -H \"Authorization: Bearer \${token}\" \\
            -H 'Content-Type: application/json' \\
            -d '{\"lines\":20}' \\
            'http://127.0.0.1:${AI_AGENT_PORT}/mvps/ai-analyze/security' 2>/dev/null)

        if [[ -z \"\$result\" ]]; then
            echo \"\$(date -Iseconds) [AI-HOOK] [WARN] post_security_setup: agent không response\"
            exit 0
        fi

        severity=\$(echo \"\$result\" | grep -o '\"severity\":\"[^\"]*\"' | cut -d'\"' -f4)
        echo \"\$(date -Iseconds) [AI-HOOK] [INFO] post_security_setup: severity=\${severity}\"

        case \"\$severity\" in
            HIGH|CRITICAL)
                echo \"\$(date -Iseconds) [AI-HOOK] [ALERT] Security review: MỨC ĐỘ \${severity}\"
                echo \"\$(date -Iseconds) [AI-HOOK] [ALERT] Xem chi tiết: sudo mvps-ai security\"
                ;;
        esac
    " >> "$AI_HOOK_LOG" 2>&1 &

    _ai_hook_log "INFO" "post_security_setup: AI security review sẽ chạy sau 60s (PID: $!)"
}

# ══════════════════════════════════════════════════
# HOOK 3: Post-deploy site verify
# Gọi từ: tools.sh → sau khi rolling deploy xong
# Hoặc gọi thủ công: ai_hook_post_site_deploy <site_url> <site_name>
#
# Mục đích: Sau khi deploy site cụ thể
#   - HTTP probe site_url
#   - Check health
#   - AI đánh giá kết quả deploy
# ══════════════════════════════════════════════════

ai_hook_post_site_deploy() {
    local site_url="${1:-}"
    local site_name="${2:-}"

    ai_enabled || return 0
    [[ -z "$site_url" ]] && return 0

    _ai_hook_log "INFO" "post_site_deploy: Verify deploy ${site_url}..."

    local body
    body=$(printf '{"site_url":"%s","site_name":"%s"}' "$site_url" "$site_name")

    nohup bash -c "
        sleep 5  # Chờ services reload

        token_file='${AI_AGENT_TOKEN_FILE}'
        token=\$(grep -o '\"token\":\"[^\"]*\"' \"\$token_file\" 2>/dev/null | cut -d'\"' -f4)
        [[ -z \"\$token\" ]] && exit 0

        result=\$(curl -sf --max-time ${AI_HOOK_TIMEOUT} \\
            -X POST \\
            -H \"Authorization: Bearer \${token}\" \\
            -H 'Content-Type: application/json' \\
            -d '${body}' \\
            'http://127.0.0.1:${AI_AGENT_PORT}/mvps/ai-analyze/deploy' 2>/dev/null)

        [[ -z \"\$result\" ]] && exit 0

        severity=\$(echo \"\$result\" | grep -o '\"severity\":\"[^\"]*\"' | cut -d'\"' -f4)
        http_code=\$(echo \"\$result\" | grep -o '\"http_code\":[0-9]*' | grep -o '[0-9]*$')

        echo \"\$(date -Iseconds) [AI-HOOK] [INFO] post_site_deploy: ${site_url} severity=\${severity} http=\${http_code}\"

        case \"\$severity\" in
            HIGH|CRITICAL)
                echo \"\$(date -Iseconds) [AI-HOOK] [ALERT] Deploy ${site_url}: MỨC ĐỘ \${severity} — kiểm tra ngay!\"
                ;;
        esac
    " >> "$AI_HOOK_LOG" 2>&1 &

    _ai_hook_log "INFO" "post_site_deploy: AI verify background (PID: $!)"
}
