<?php
/**
 * ModernVPS AI Layer — Data Sanitizer
 * Path: /opt/modernvps/agent/ai/sanitize.php
 *
 * Strip thông tin nhạy cảm trước khi gửi lên Claude API.
 * Không sensitive data → vẫn nên sanitize để giảm token cost.
 */

declare(strict_types=1);

/**
 * Sanitize chuỗi log/text trước khi gửi AI
 */
function ai_sanitize(string $input): string
{
    $out = $input;

    // ── Giới hạn độ dài ────────────────────────────────────
    // Cắt bớt nếu quá dài → giảm token cost
    $max_chars = 8000;
    if (mb_strlen($out) > $max_chars) {
        $out = mb_substr($out, 0, $max_chars) . "\n[...truncated...]";
    }

    // ── Strip path tuyệt đối có username/domain ─────────────
    // /home/username/... → /home/***/...
    $out = preg_replace('#/home/[^/\s]+/#', '/home/***/', $out);

    // ── Strip IPv4 private (giữ lại public để AI có context) ─
    // Chỉ ẩn internal IP: 10.x, 172.16-31.x, 192.168.x
    $out = preg_replace(
        '/\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/',
        '10.x.x.x',
        $out
    );
    $out = preg_replace(
        '/\b(172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/',
        '172.x.x.x',
        $out
    );
    $out = preg_replace(
        '/\b(192\.168\.\d{1,3}\.\d{1,3})\b/',
        '192.168.x.x',
        $out
    );

    // ── Strip Bearer token nếu lọt vào log ──────────────────
    $out = preg_replace('/Bearer\s+[A-Za-z0-9\-_\.]+/', 'Bearer [REDACTED]', $out);

    // ── Strip password pattern thường gặp trong log ─────────
    $out = preg_replace('/password[=:\s]+\S+/i', 'password=[REDACTED]', $out);
    $out = preg_replace('/passwd[=:\s]+\S+/i',   'passwd=[REDACTED]',   $out);
    $out = preg_replace('/secret[=:\s]+\S+/i',   'secret=[REDACTED]',   $out);

    // ── Strip email addresses ────────────────────────────────
    $out = preg_replace('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', '[EMAIL]', $out);

    // ── Normalize whitespace thừa ────────────────────────────
    $out = preg_replace('/\n{3,}/', "\n\n", $out);
    $out = trim($out);

    return $out;
}

/**
 * Sanitize array metrics (key-value)
 * Chỉ giữ lại keys an toàn trong whitelist
 */
function ai_sanitize_metrics(array $metrics): array
{
    // Whitelist keys được phép gửi lên AI
    $allowed = [
        'cpu_usage', 'load1', 'load5', 'load15',
        'mem_total_mb', 'mem_used_mb', 'mem_free_mb',
        'disk_used_pct', 'disk_free_gb',
        'nginx_active_conn', 'nginx_requests_sec',
        'php_fpm_active', 'php_fpm_idle', 'php_fpm_queue',
        'uptime_seconds', 'sites_count',
        'server_type', 'php_version', 'os_name',
    ];

    $safe = [];
    foreach ($allowed as $key) {
        if (isset($metrics[$key])) {
            $safe[$key] = $metrics[$key];
        }
    }

    return $safe;
}
