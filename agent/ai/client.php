<?php
/**
 * ModernVPS AI Layer — Claude API Client
 * Path: /opt/modernvps/agent/ai/client.php
 *
 * Wrapper gọi Anthropic Claude API.
 * Có rate limiting, timeout, error handling.
 */

declare(strict_types=1);

require_once __DIR__ . '/sanitize.php';

// ══════════════════════════════════════════════════
// CONFIG LOADER
// ══════════════════════════════════════════════════

function ai_load_config(): array
{
    $conf_file = '/etc/modernvps/ai.conf';

    if (!file_exists($conf_file)) {
        return ['enabled' => false, 'error' => 'ai.conf not found'];
    }

    // Parse bash-style KEY="VALUE" config
    $raw  = file_get_contents($conf_file);
    $conf = [];
    if (preg_match_all('/^([A-Z_]+)="([^"]*)"$/m', $raw, $matches, PREG_SET_ORDER)) {
        foreach ($matches as $m) {
            $conf[$m[1]] = $m[2];
        }
    }

    return [
        'enabled'         => ($conf['AI_ENABLED']    ?? 'false') === 'true',
        'api_key'         => $conf['ANTHROPIC_API_KEY'] ?? '',
        'model'           => $conf['AI_MODEL']        ?? 'claude-haiku-4-5',
        'timeout'         => (int)($conf['AI_TIMEOUT']    ?? 15),
        'max_tokens'      => (int)($conf['AI_MAX_TOKENS']  ?? 800),
        'log_lines'       => (int)($conf['AI_LOG_LINES']   ?? 50),
        'rate_limit'      => (int)($conf['AI_RATE_LIMIT']  ?? 20),
        'rate_limit_file' => $conf['AI_RATE_LIMIT_FILE'] ?? '/tmp/.modernvps_ai_rl',
    ];
}

// ══════════════════════════════════════════════════
// RATE LIMITER
// ══════════════════════════════════════════════════

function ai_check_rate_limit(array $config): bool
{
    $file  = $config['rate_limit_file'];
    $limit = $config['rate_limit'];
    $now   = time();
    $hour  = 3600;

    // Format file: "timestamp:count"
    $data = @file_get_contents($file);
    if ($data) {
        [$ts, $count] = explode(':', $data) + [0, 0];
        // Reset nếu đã qua 1 giờ
        if (($now - (int)$ts) < $hour) {
            if ((int)$count >= $limit) {
                return false; // Đã đạt giới hạn
            }
            file_put_contents($file, "$ts:" . ((int)$count + 1));
            return true;
        }
    }

    // Bắt đầu window mới
    file_put_contents($file, "$now:1");
    return true;
}

// ══════════════════════════════════════════════════
// CORE API CALLER
// ══════════════════════════════════════════════════

/**
 * Gọi Claude API với prompt đã được build sẵn
 *
 * @param  string $system_prompt  Vai trò của AI (từ prompt.php)
 * @param  string $user_message   Nội dung cần phân tích
 * @param  array  $config         Từ ai_load_config()
 * @return array  ['success' => bool, 'content' => string, 'error' => string]
 */
function ai_call(string $system_prompt, string $user_message, array $config): array
{
    // ── Pre-flight checks ──────────────────────────────────
    if (!$config['enabled']) {
        return ['success' => false, 'error' => 'AI layer disabled'];
    }

    if (empty($config['api_key'])) {
        return ['success' => false, 'error' => 'ANTHROPIC_API_KEY chưa được cấu hình'];
    }

    if (!ai_check_rate_limit($config)) {
        return ['success' => false, 'error' => 'Rate limit exceeded (' . $config['rate_limit'] . ' calls/hour)'];
    }

    // ── Sanitize input ─────────────────────────────────────
    $clean_message = ai_sanitize($user_message);

    // ── Build request payload ──────────────────────────────
    $payload = json_encode([
        'model'      => $config['model'],
        'max_tokens' => $config['max_tokens'],
        'system'     => $system_prompt,
        'messages'   => [
            ['role' => 'user', 'content' => $clean_message]
        ],
    ]);

    // ── cURL call ─────────────────────────────────────────
    $ch = curl_init('https://api.anthropic.com/v1/messages');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_TIMEOUT        => $config['timeout'],
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'x-api-key: ' . $config['api_key'],
            'anthropic-version: 2023-06-01',
        ],
    ]);

    $response  = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_err  = curl_error($ch);
    curl_close($ch);

    // ── Error handling ─────────────────────────────────────
    if ($curl_err) {
        return ['success' => false, 'error' => 'cURL error: ' . $curl_err];
    }

    if ($http_code !== 200) {
        $decoded = json_decode($response, true);
        $msg = $decoded['error']['message'] ?? "HTTP $http_code";
        return ['success' => false, 'error' => "API error: $msg"];
    }

    $decoded = json_decode($response, true);
    $content = $decoded['content'][0]['text'] ?? '';

    if (empty($content)) {
        return ['success' => false, 'error' => 'Empty response từ Claude API'];
    }

    return ['success' => true, 'content' => $content];
}
