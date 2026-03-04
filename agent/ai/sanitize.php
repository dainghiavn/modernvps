<?php
/**
 * ModernVPS AI Layer — Data Sanitizer v1.1
 * Path: agent/ai/sanitize.php
 *
 * CHANGELOG v1.1 (GĐ8):
 *   [B1] cpu_cores vào whitelist — thiếu → load_ratio tính sai → AI calibrate sai severity
 *   [B2] php_fpm_max vào whitelist — thiếu → worker capacity luôn "0 max" → vô nghĩa
 *   [B3] mem_used_mb explicit trong whitelist
 *   [B4] os_name vào whitelist — AI đề xuất đúng package manager (apt vs dnf)
 *   [B5] Strip thêm sk-ant- và mvps_wn_ token format
 */

declare(strict_types=1);

/**
 * Sanitize log/text trước khi gửi API
 * Strip: private IP, Bearer token, password, email, home path
 */
function ai_sanitize(string $input): string
{
    $out = $input;

    // Giới hạn độ dài
    $max_chars = 8000;
    if (mb_strlen($out) > $max_chars) {
        $out = mb_substr($out, 0, $max_chars) . "\n[...truncated...]";
    }

    // Strip path có username
    $out = preg_replace('#/home/[^/\s]+/#', '/home/***/', $out);

    // Strip private IPv4 — giữ public để AI có threat context
    $out = preg_replace('/\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/', '10.x.x.x', $out);
    $out = preg_replace('/\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/', '172.x.x.x', $out);
    $out = preg_replace('/\b192\.168\.\d{1,3}\.\d{1,3}\b/', '192.168.x.x', $out);

    // Strip tokens
    $out = preg_replace('/Bearer\s+[A-Za-z0-9\-_\.]+/', 'Bearer [REDACTED]', $out);
    $out = preg_replace('/mvps_wn_[A-Za-z0-9]{16,}/', 'mvps_wn_[REDACTED]', $out);  // [B5]
    $out = preg_replace('/sk-ant-[A-Za-z0-9\-_]+/', 'sk-ant-[REDACTED]', $out);      // [B5]

    // Strip credentials trong log
    $out = preg_replace('/password[=:\s]+\S+/i', 'password=[REDACTED]', $out);
    $out = preg_replace('/passwd[=:\s]+\S+/i',   'passwd=[REDACTED]',   $out);
    $out = preg_replace('/secret[=:\s]+\S+/i',   'secret=[REDACTED]',   $out);
    $out = preg_replace('/api_key[=:\s]+\S+/i',  'api_key=[REDACTED]',  $out);

    // Strip email
    $out = preg_replace('/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/', '[EMAIL]', $out);

    // Normalize whitespace
    $out = preg_replace('/\n{3,}/', "\n\n", $out);

    return trim($out);
}

/**
 * Sanitize metrics array — chỉ pass keys trong whitelist lên AI
 *
 * [B1] THÊM cpu_cores  — _fmt_metrics() dùng để tính load/core ratio
 *                         Thiếu → default cores=1 → ratio sai → severity sai
 * [B2] THÊM php_fpm_max — _fmt_metrics() dùng để tính worker capacity %
 *                          Thiếu → "X active | Y idle | 0 max" → vô nghĩa
 * [B3] THÊM mem_used_mb — explicit để không phụ thuộc caller tính key đúng
 * [B4] THÊM os_name    — AI đề xuất đúng package manager (apt vs dnf)
 */
function ai_sanitize_metrics(array $metrics): array
{
    $allowed = [
        // CPU — [B1] cpu_cores bắt buộc có
        'cpu_cores',
        'cpu_usage',
        'load1',
        'load5',
        'load15',

        // Memory — [B3] mem_used_mb explicit
        'mem_total_mb',
        'mem_used_mb',
        'mem_free_mb',
        'mem_available_mb',

        // Disk
        'disk_used_pct',
        'disk_free_gb',

        // Nginx
        'nginx_active_conn',
        'nginx_requests_sec',

        // PHP-FPM — [B2] php_fpm_max bắt buộc có
        'php_fpm_active',
        'php_fpm_idle',
        'php_fpm_max',
        'php_fpm_queue',

        // System
        'uptime_seconds',
        'sites_count',

        // Context — [B4] os_name để AI biết apt/dnf
        'server_type',
        'php_version',
        'os_name',
    ];

    $safe = [];
    foreach ($allowed as $key) {
        if (array_key_exists($key, $metrics)) {
            $val = $metrics[$key];
            if (is_scalar($val) || is_null($val)) {
                $safe[$key] = $val;
            }
        }
    }

    return $safe;
}
