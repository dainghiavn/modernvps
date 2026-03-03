<?php
/**
 * ModernVPS AI Layer — Prompt Templates
 * Path: /opt/modernvps/agent/ai/prompt.php
 *
 * Mỗi hàm trả về:
 *   ['system' => string, 'user' => string]
 * → Truyền thẳng vào ai_call()
 */

declare(strict_types=1);

// ══════════════════════════════════════════════════
// SYSTEM PROMPT CHUNG
// ══════════════════════════════════════════════════

const AI_SYSTEM_BASE = <<<SYS
You are a senior Linux/DevOps engineer specializing in Nginx, PHP-FPM, MariaDB, and server security.
You are analyzing a production VPS running ModernVPS stack.
Always respond in Vietnamese.
Be concise: max 5 bullet points per section.
Format: use plain text, no markdown headers, no code blocks unless showing a specific command.
Structure your response as:
1. CHẨN ĐOÁN: (1-2 câu tóm tắt vấn đề)
2. NGUYÊN NHÂN: (bullet points, tối đa 3)
3. ĐỀ XUẤT: (bullet points, tối đa 3, kèm lệnh cụ thể nếu có)
4. MỨC ĐỘ: (LOW / MEDIUM / HIGH / CRITICAL)
SYS;

// ══════════════════════════════════════════════════
// PROMPT: LOG ANALYSIS
// ══════════════════════════════════════════════════

/**
 * Phân tích nginx error log + php-fpm log
 *
 * @param string $nginx_log   Nội dung nginx error.log (50 dòng cuối)
 * @param string $phpfpm_log  Nội dung php-fpm error log (50 dòng cuối)
 * @param string $server_type web | loadbalancer
 */
function prompt_logs(string $nginx_log, string $phpfpm_log, string $server_type): array
{
    $system = AI_SYSTEM_BASE;

    $user = <<<MSG
Server type: {$server_type}
Timestamp: {$_SERVER['REQUEST_TIME']}

=== NGINX ERROR LOG (50 dòng cuối) ===
{$nginx_log}

=== PHP-FPM ERROR LOG (50 dòng cuối) ===
{$phpfpm_log}

Hãy phân tích các lỗi trên và đưa ra chẩn đoán, nguyên nhân, đề xuất khắc phục.
MSG;

    return ['system' => $system, 'user' => $user];
}

// ══════════════════════════════════════════════════
// PROMPT: METRICS ANALYSIS
// ══════════════════════════════════════════════════

/**
 * Phân tích metrics hiện tại và đề xuất tune
 *
 * @param array $metrics  Từ ai_sanitize_metrics()
 * @param array $config   PHP-FPM pool config hiện tại
 */
function prompt_metrics(array $metrics, array $pool_config = []): array
{
    $system = AI_SYSTEM_BASE . "\nFocus on performance tuning and resource optimization.";

    $metrics_str    = json_encode($metrics, JSON_PRETTY_PRINT);
    $pool_str       = !empty($pool_config)
        ? json_encode($pool_config, JSON_PRETTY_PRINT)
        : 'N/A';

    $user = <<<MSG
=== CURRENT METRICS ===
{$metrics_str}

=== PHP-FPM POOL CONFIG ===
{$pool_str}

Phân tích hiệu suất server, xác định bottleneck nếu có, và đề xuất điều chỉnh config cụ thể.
MSG;

    return ['system' => $system, 'user' => $user];
}

// ══════════════════════════════════════════════════
// PROMPT: SECURITY ANALYSIS
// ══════════════════════════════════════════════════

/**
 * Phân tích security events từ fail2ban + nftables
 *
 * @param string $fail2ban_log  Fail2ban log gần nhất
 * @param array  $banned_ips    Danh sách IP đang bị ban
 * @param int    $ban_count_24h Số lần ban trong 24h
 */
function prompt_security(string $fail2ban_log, array $banned_ips, int $ban_count_24h): array
{
    $system = AI_SYSTEM_BASE . "\nFocus on threat identification and security hardening.";

    $banned_str = implode(', ', array_slice($banned_ips, 0, 20)); // Giới hạn 20 IPs
    $ip_count   = count($banned_ips);

    $user = <<<MSG
=== FAIL2BAN LOG (30 dòng cuối) ===
{$fail2ban_log}

=== THỐNG KÊ ===
Tổng IP đang bị ban: {$ip_count}
Số lần ban trong 24h: {$ban_count_24h}
Mẫu IP bị ban: {$banned_str}

Phân tích mức độ tấn công, xác định pattern đáng chú ý, đề xuất cải thiện bảo mật.
MSG;

    return ['system' => $system, 'user' => $user];
}

// ══════════════════════════════════════════════════
// PROMPT: DEPLOY VERIFICATION
// ══════════════════════════════════════════════════

/**
 * Verify sau khi deploy xong
 *
 * @param string $site_url    URL của site vừa deploy
 * @param array  $health      Kết quả health check
 * @param string $deploy_log  Log của quá trình deploy
 */
function prompt_deploy(string $site_url, array $health, string $deploy_log): array
{
    $system = AI_SYSTEM_BASE . "\nFocus on deployment verification and post-deploy issues.";

    $health_str = json_encode($health, JSON_PRETTY_PRINT);

    $user = <<<MSG
=== DEPLOY TARGET ===
Site: {$site_url}

=== HEALTH CHECK RESULT ===
{$health_str}

=== DEPLOY LOG (30 dòng cuối) ===
{$deploy_log}

Đánh giá kết quả deploy: thành công/thất bại, vấn đề tiềm ẩn nếu có, bước kiểm tra tiếp theo.
MSG;

    return ['system' => $system, 'user' => $user];
}
