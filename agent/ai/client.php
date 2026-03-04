<?php
/**
 * ModernVPS AI Layer — Claude API Client v1.2
 * Path: agent/ai/client.php
 *
 * CHANGELOG v1.2 (GĐ8):
 *   [G4] ai_load_config(): thêm report_max_tokens (AI_REPORT_MAX_TOKENS, default 1500)
 *        mvps-ai-report gửi X-Report-Mode: 1 → index.php dùng report_max_tokens
 *        Tránh truncate → "MỨC ĐỘ:" không xuất hiện → ai_extract_severity()=UNKNOWN
 *   [G4] Tăng default AI_MAX_TOKENS 800 → 1000 (an toàn hơn cho mọi realtime query)
 *   [G4] Parse config: hỗ trợ cả KEY="value" và KEY=value (không nháy đôi)
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

    $raw  = file_get_contents($conf_file);
    $conf = [];
    // Support KEY="value" và KEY=value
    if (preg_match_all('/^([A-Z_]+)="?([^"\n]*)"?$/m', $raw, $matches, PREG_SET_ORDER)) {
        foreach ($matches as $m) {
            $conf[$m[1]] = trim($m[2], '"');
        }
    }

    return [
        'enabled'           => ($conf['AI_ENABLED']              ?? 'false') === 'true',
        'api_key'           => $conf['ANTHROPIC_API_KEY']         ?? '',
        'model'             => $conf['AI_MODEL']                  ?? 'claude-haiku-4-5',
        'timeout'           => (int)($conf['AI_TIMEOUT']          ?? 15),
        'max_tokens'        => (int)($conf['AI_MAX_TOKENS']       ?? 1000), // [G4] 800→1000
        'report_max_tokens' => (int)($conf['AI_REPORT_MAX_TOKENS'] ?? 1500), // [G4] MỚI
        'log_lines'         => (int)($conf['AI_LOG_LINES']        ?? 50),
        'rate_limit'        => (int)($conf['AI_RATE_LIMIT']       ?? 20),
        'rate_limit_file'   => $conf['AI_RATE_LIMIT_FILE']        ?? '/tmp/.modernvps_ai_rl',
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

    $data = @file_get_contents($file);
    if ($data) {
        [$ts, $count] = explode(':', $data) + [0, 0];
        if (($now - (int)$ts) < $hour) {
            if ((int)$count >= $limit) return false;
            file_put_contents($file, "$ts:" . ((int)$count + 1));
            return true;
        }
    }

    file_put_contents($file, "$now:1");
    return true;
}

// ══════════════════════════════════════════════════
// CORE API CALLER
// ══════════════════════════════════════════════════

/**
 * Gọi Claude API
 * max_tokens trong $config đã được _ai_get_max_tokens() override nếu report mode
 *
 * @return array ['success' => bool, 'content' => string, 'error' => string]
 */
function ai_call(string $system_prompt, string $user_message, array $config): array
{
    if (!$config['enabled']) {
        return ['success' => false, 'error' => 'AI layer disabled'];
    }
    if (empty($config['api_key'])) {
        return ['success' => false, 'error' => 'ANTHROPIC_API_KEY chưa được cấu hình'];
    }
    if (!ai_check_rate_limit($config)) {
        return ['success' => false,
                'error'   => 'Rate limit exceeded (' . $config['rate_limit'] . ' calls/hour)'];
    }

    $clean_message = ai_sanitize($user_message);

    $payload = json_encode([
        'model'      => $config['model'],
        'max_tokens' => (int)($config['max_tokens'] ?? 1000),
        'system'     => $system_prompt,
        'messages'   => [['role' => 'user', 'content' => $clean_message]],
    ]);

    $ch = curl_init('https://api.anthropic.com/v1/messages');
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_TIMEOUT        => (int)($config['timeout'] ?? 15),
        CURLOPT_CONNECTTIMEOUT => 5,
        CURLOPT_HTTPHEADER     => [
            'Content-Type: application/json',
            'x-api-key: '          . $config['api_key'],
            'anthropic-version: 2023-06-01',
        ],
    ]);

    $response  = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curl_err  = curl_error($ch);
    curl_close($ch);

    if ($curl_err) {
        return ['success' => false, 'error' => 'cURL error: ' . $curl_err];
    }
    if ($http_code !== 200) {
        $decoded = json_decode($response, true);
        $msg     = $decoded['error']['message'] ?? "HTTP $http_code";
        return ['success' => false, 'error' => "API error: $msg"];
    }

    $decoded = json_decode($response, true);
    $content = $decoded['content'][0]['text'] ?? '';

    if (empty($content)) {
        return ['success' => false, 'error' => 'Empty response từ Claude API'];
    }

    return ['success' => true, 'content' => $content];
}
