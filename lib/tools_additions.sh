################################################################################
# GĐ4 — Thêm vào lib/tools.sh
# Hướng dẫn: Copy 3 phần dưới đây vào đúng vị trí trong tools.sh
################################################################################

# ════════════════════════════════════════════════════════════════
# PHẦN 1: Thêm hàm _install_mvps_ai() vào cuối tools.sh
# Vị trí: sau hàm _setup_token_rotation_cron()
# ════════════════════════════════════════════════════════════════

_install_mvps_ai() {
    # Chỉ cài trên web node (AI agent chạy tại đây)
    # LB gọi AI qua mvps-ai --node <id> → không cần agent local
    # Nhưng mvps-ai binary cần có trên cả hai để CLI hoạt động
    log "Cài mvps-ai CLI..."

    local ai_script="${SCRIPT_DIR}/agent/ai/mvps-ai"

    if [[ ! -f "$ai_script" ]]; then
        warn "Không tìm thấy agent/ai/mvps-ai — bỏ qua"
        return 0
    fi

    install -m 755 "$ai_script" /usr/local/bin/mvps-ai
    log "mvps-ai CLI đã cài: sudo mvps-ai help"
}

# ════════════════════════════════════════════════════════════════
# PHẦN 2: Thêm vào _create_menu_web() — trong heredoc MENUEOF
# Vị trí: thêm vào TRƯỚC dòng "0)  exit 0 ;;" của web menu
# ════════════════════════════════════════════════════════════════
#
# Thêm option 20-24 vào case statement trong _create_menu_web:
#
#        # ── AI ANALYSIS ──────────────────────────────
#        20) /usr/local/bin/mvps-ai status ;;
#        21) read -rp "Số dòng log [50]: " _LINES
#            _LINES="${_LINES:-50}"
#            /usr/local/bin/mvps-ai logs --lines "$_LINES" ;;
#        22) /usr/local/bin/mvps-ai metrics ;;
#        23) read -rp "Số dòng log [30]: " _LINES
#            _LINES="${_LINES:-30}"
#            /usr/local/bin/mvps-ai security --lines "$_LINES" ;;
#        24) read -rp "Site URL (vd: https://example.com): " _URL
#            read -rp "Site name (vd: example.com): " _SITE
#            /usr/local/bin/mvps-ai deploy --url "$_URL" --site "$_SITE" ;;
#        0)  exit 0 ;;
#
# Thêm vào phần render menu (phần echo options):
#
#    echo -e " ${CYAN}[AI]${NC}        20) AI status       21) Phân tích log"
#    echo -e "              22) Metrics tune    23) Security check"
#    echo -e "              24) Verify deploy"

# ════════════════════════════════════════════════════════════════
# PHẦN 3: Thêm vào _create_menu_lb() — trong heredoc MENUEOF
# Vị trí: thêm vào TRƯỚC dòng "0)  exit 0 ;;" của lb menu
# ════════════════════════════════════════════════════════════════
#
# Thêm option 29-33 vào case statement trong _create_menu_lb:
#
#        # ── AI ANALYSIS ──────────────────────────────
#        29) read -rp "Node ID (hoặc 'all'): " _NID
#            /usr/local/bin/mvps-ai status --node "$_NID" ;;
#        30) read -rp "Node ID (hoặc 'all'): " _NID
#            read -rp "Số dòng log [50]: " _LINES
#            _LINES="${_LINES:-50}"
#            /usr/local/bin/mvps-ai logs --node "$_NID" --lines "$_LINES" ;;
#        31) read -rp "Node ID (hoặc 'all'): " _NID
#            /usr/local/bin/mvps-ai metrics --node "$_NID" ;;
#        32) read -rp "Node ID (hoặc 'all'): " _NID
#            read -rp "Số dòng log [30]: " _LINES
#            _LINES="${_LINES:-30}"
#            /usr/local/bin/mvps-ai security --node "$_NID" --lines "$_LINES" ;;
#        33) read -rp "Node ID: " _NID
#            read -rp "Site URL: " _URL
#            read -rp "Site name: " _SITE
#            /usr/local/bin/mvps-ai deploy --node "$_NID" --url "$_URL" --site "$_SITE" ;;
#        0)  exit 0 ;;
#
# Thêm vào phần render menu:
#
#    echo -e " ${CYAN}[AI]${NC}        29) AI status       30) Phân tích log"
#    echo -e "              31) Metrics tune    32) Security check"
#    echo -e "              33) Verify deploy"

# ════════════════════════════════════════════════════════════════
# PHẦN 4: Thêm _install_mvps_ai vào setup_mvps_service()
# Vị trí: sau dòng gọi _setup_token_rotation_cron
# ════════════════════════════════════════════════════════════════
#
#    # Token rotation cron (cả LB và Web node)
#    _setup_token_rotation_cron
#
#    # AI CLI (cả web và LB)      ← THÊM DÒNG NÀY
#    _install_mvps_ai
