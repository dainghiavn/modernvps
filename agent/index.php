<?php
/**
 * ModernVPS Cluster Agent v1.4
 * Chạy trên Web node, lắng nghe port 9000 (internal IP only)
 * Auth: Bearer token rotate mỗi 30 ngày
 *
 * Endpoints:
 *   GET  /mvps/health                  → nginx/php/mariadb status
 *   GET  /mvps/metrics                 → cpu/ram/disk/php/sites
 *   POST /mvps/drain                   → graceful drain traffic
 *   POST /mvps/drain/cancel            → restore traffic
 *   POST /mvps/deploy                  → upload + extract tarball
 *   GET  /mvps/deploy/status           → trạng thái deploy hiện tại
 *   POST /mvps/token/rotate            → rotate token mới từ LB
 *   POST /mvps/ai-analyze/logs         → AI phân tích nginx + php-fpm error log
 *   POST /mvps/ai-analyze/metrics      → [NEW] AI phân tích metrics + đề xuất tune
 *   POST /mvps/ai-analyze/security     → [NEW] AI phân tích fail2ban + threat summary
 *   POST /mvps/ai-analyze/deploy       → [NEW] AI verify kết quả deploy
 *
 * CHANGELOG v1.4:
 *   [AI-4] NEW: POST /mvps/ai-analyze/metrics
 *          → Thu thập cpu/ram/disk/php-fpm pool config
 *          → AI đề xuất tune config theo workload thực tế
 *   [AI-5] NEW: POST /mvps/ai-analyze/security
 *          → Thu thập fail2ban log + danh sách IP bị ban
 *          → AI tóm tắt threat level + đề xuất hardening
 *   [AI-6] NEW: POST /mvps/ai-analyze/deploy
 *          → Nhận site_url + health snapshot + deploy log
 *          → AI verify kết quả deploy: OK / WARNING / FAILED
 *   [AI-7] REFACTOR: ai_bootstrap() + ai_call_and_respond()
 *          → Dùng chung cho mọi endpoint AI — không lặp code
 *
 * CHANGELOG v1.3:
 *   [AI-1] POST /mvps/ai-analyze/logs
 *   [AI-2] ai_enabled() guard  [AI-3] Lazy load AI layer
 *
 * CHANGELOG v1.2:
 *   [B1-B9] Bug fixes deploy/token/proc
 */

declare(strict_types=1);
error_reporting(0);

// ── Constants ──────────────────────────────────────────────────
define('CONFIG_ENV',       '/opt/modernvps/config.env');
define('TOKEN_FILE',       '/opt/modernvps/agent-token.json');
define('DRAIN_FLAG',       '/run/mvps-draining');
define('DEPLOY_LOG',       '/var/log/modernvps/deploy.log');
define('DEPLOY_STATE',     '/run/mvps-deploy-state');
define('DEPLOY_DONE_MARK', '/run/mvps-deploy-done-mark');
define('DEPLOY_DIR',       '/var/www');
define('VERSION',          '1.4');
define('AI_DIR',           __DIR__ . '/ai');

// ── Bootstrap ──────────────────────────────────────────────────
$config = parse_config_env(CONFIG_ENV);
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri    = strtok($_SERVER['REQUEST_URI'] ?? '/', '?');
$uri    = rtrim($uri, '/') ?: '/';

// ── Auth ───────────────────────────────────────────────────────
$auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if (!preg_match('/^Bearer\s+(.+)$/', $auth_header, $m)) {
    http_response_code(401);
    json_out(['error' => 'Missing Bearer token']);
}
$provided_token = $m[1];
if (!verify_token($provided_token)) {
    http_response_code(403);
    json_out(['error' => 'Invalid or expired token']);
}

// ── Router ─────────────────────────────────────────────────────
header('Content-Type: application/json');
header('X-ModernVPS-Agent: ' . VERSION);

switch (true) {
    // ── Endpoints gốc — không thay đổi ────────────────────────
    case $uri === '/mvps/health'              && $method === 'GET':
        handle_health($config);   break;
    case $uri === '/mvps/metrics'             && $method === 'GET':
        handle_metrics($config);  break;
    case $uri === '/mvps/drain'               && $method === 'POST':
        handle_drain();           break;
    case $uri === '/mvps/drain/cancel'        && $method === 'POST':
        handle_drain_cancel();    break;
    case $uri === '/mvps/deploy'              && $method === 'POST':
        handle_deploy($config);   break;
    case $uri === '/mvps/deploy/status'       && $method === 'GET':
        handle_deploy_status();   break;
    case $uri === '/mvps/token/rotate'        && $method === 'POST':
        handle_token_rotate($provided_token); break;

    // ── AI endpoints ───────────────────────────────────────────
    case $uri === '/mvps/ai-analyze/logs'     && $method === 'POST':
        handle_ai_analyze_logs($config);     break;
    case $uri === '/mvps/ai-analyze/metrics'  && $method === 'POST': // [AI-4]
        handle_ai_analyze_metrics($config);  break;
    case $uri === '/mvps/ai-analyze/security' && $method === 'POST': // [AI-5]
        handle_ai_analyze_security($config); break;
    case $uri === '/mvps/ai-analyze/deploy'   && $method === 'POST': // [AI-6]
        handle_ai_analyze_deploy($config);   break;

    default:
        http_response_code(404);
        json_out(['error' => 'Unknown endpoint']); // [B8] no URI leak
}


// ══════════════════════════════════════════════════════════════
// HANDLERS — GỐC
// ══════════════════════════════════════════════════════════════

function handle_health(array $config): void
{
    $php_svc = get_php_fpm_svc($config);
    $status  = [
        'nginx'    => service_active('nginx'),
        'php_fpm'  => service_active($php_svc),
        'mariadb'  => service_active('mariadb'),
        'draining' => file_exists(DRAIN_FLAG),
    ];

    $all_up            = $status['nginx'] && $status['php_fpm'] && $status['mariadb'];
    $status['overall'] = $all_up ? 'UP' : 'DEGRADED';

    if ($status['draining']) {
        http_response_code(503);
        $status['overall'] = 'DRAINING';
    }

    $status['timestamp'] = date('c');
    json_out($status);
}

function handle_metrics(array $config): void
{
    // [B5] Guard null khi /proc không mount
    $loadavg_raw = @file_get_contents('/proc/loadavg');
    [$load1, $load5, $load15] = $loadavg_raw !== false
        ? explode(' ', $loadavg_raw) : ['0', '0', '0'];

    $cpuinfo   = @file_get_contents('/proc/cpuinfo');
    $cpu_cores = $cpuinfo !== false ? substr_count($cpuinfo, 'processor') : 1;

    $meminfo_raw = @file_get_contents('/proc/meminfo');
    $mem = [];
    if ($meminfo_raw !== false) {
        preg_match_all('/^(\w+):\s+(\d+)/m', $meminfo_raw, $mm, PREG_SET_ORDER);
        foreach ($mm as $row) $mem[$row[1]] = (int)$row[2];
    }
    $ram_total_mb = (int)(($mem['MemTotal']    ?? 0) / 1024);
    $ram_avail_mb = (int)(($mem['MemAvailable'] ?? 0) / 1024);
    $ram_used_mb  = $ram_total_mb - $ram_avail_mb;

    $df            = @disk_free_space('/var/www') ?: 0;
    $dt            = @disk_total_space('/var/www') ?: 0;
    $disk_used_pct = $dt > 0 ? round(($dt - $df) / $dt * 100, 1) : 0;

    $uptime_raw = @file_get_contents('/proc/uptime');
    $uptime_sec = $uptime_raw !== false ? (int)explode(' ', $uptime_raw)[0] : 0;
    $sites      = count(glob('/var/www/*/') ?: []);

    json_out([
        'node_id'   => gethostname(),
        'timestamp' => date('c'),
        'cpu'  => ['cores' => $cpu_cores, 'load1' => (float)$load1,
                   'load5' => (float)$load5, 'load15' => (float)$load15],
        'ram'  => ['total_mb' => $ram_total_mb, 'used_mb' => $ram_used_mb,
                   'avail_mb' => $ram_avail_mb,
                   'used_pct' => $ram_total_mb > 0
                       ? round($ram_used_mb / $ram_total_mb * 100, 1) : 0],
        'disk' => ['used_pct' => $disk_used_pct,
                   'free_gb'  => round($df / 1073741824, 1),
                   'total_gb' => round($dt / 1073741824, 1)],
        'uptime_sec'   => $uptime_sec,
        'sites'        => $sites,
        'php_workers'  => get_php_workers($config),
        'nginx_conn'   => get_nginx_connections(),
        'ssl_expiring' => get_ssl_expiring(),
        'draining'     => file_exists(DRAIN_FLAG),
    ]);
}

function handle_drain(): void
{
    if (file_exists(DRAIN_FLAG)) {
        json_out(['status' => 'already_draining', 'since' => filemtime(DRAIN_FLAG)]);
        return;
    }
    touch(DRAIN_FLAG);
    chmod(DRAIN_FLAG, 0644);
    log_event("DRAIN started");
    json_out(['status' => 'draining', 'started_at' => date('c'),
              'message' => 'Node is now draining. LB should detect via /mvps/health returning 503.']);
}

function handle_drain_cancel(): void
{
    if (!file_exists(DRAIN_FLAG)) { json_out(['status' => 'not_draining']); return; }
    unlink(DRAIN_FLAG);
    log_event("DRAIN cancelled");
    json_out(['status' => 'active', 'restored_at' => date('c')]);
}

function handle_deploy(array $config): void
{
    if (file_exists(DEPLOY_STATE)) {
        $state = json_decode(file_get_contents(DEPLOY_STATE), true) ?? [];
        if (($state['status'] ?? '') === 'running') {
            http_response_code(409);
            json_out(['error' => 'Deploy already in progress', 'state' => $state]);
            return;
        }
    }

    // [B1] Checksum bắt buộc
    $checksum = $_POST['checksum'] ?? '';
    if (empty($checksum)) {
        http_response_code(400);
        json_out(['error' => 'checksum (SHA256) is required for deploy']);
        return;
    }

    $target = $_POST['target'] ?? '';
    if (!preg_match('/^[a-zA-Z0-9][a-zA-Z0-9.\-_]{0,63}$/', $target)) {
        http_response_code(400);
        json_out(['error' => 'Invalid target site name']);
        return;
    }

    if (empty($_FILES['tarball']['tmp_name'])) {
        http_response_code(400);
        json_out(['error' => 'tarball file is required']);
        return;
    }

    $actual_sha = hash_file('sha256', $_FILES['tarball']['tmp_name']);
    if (!hash_equals(strtolower($checksum), $actual_sha)) {
        http_response_code(400);
        json_out(['error' => "SHA256 mismatch: got $actual_sha"]);
        return;
    }

    // [B3] staging random
    $staging = '/tmp/mvps-deploy-' . bin2hex(random_bytes(8)) . '.tar.gz';
    if (!move_uploaded_file($_FILES['tarball']['tmp_name'], $staging)) {
        http_response_code(500);
        json_out(['error' => 'Failed to move tarball to staging']);
        return;
    }

    $target_path = DEPLOY_DIR . '/' . $target;
    if (!is_dir($target_path)) mkdir($target_path, 0755, true);

    // [B4] realpath symlink guard
    $real_target = realpath($target_path);
    $real_base   = realpath(DEPLOY_DIR);
    if ($real_target === false || $real_base === false ||
        strpos($real_target, $real_base . '/') !== 0) {
        @unlink($staging);
        http_response_code(400);
        json_out(['error' => 'Path traversal detected']);
        return;
    }

    @unlink(DEPLOY_DONE_MARK);
    $nginx_user = $config['NGINX_USER'] ?? 'www-data';

    $cmd = sprintf(
        'nohup bash -c %s >> %s 2>&1',
        escapeshellarg(
            "backup_dir=/tmp/mvps-deploy-bak-$(date +%s); mkdir -p \$backup_dir; " .
            "cp -a " . escapeshellarg($real_target) . "/. \$backup_dir/ 2>/dev/null || true; " .
            "tar -xzf " . escapeshellarg($staging) . " -C " . escapeshellarg($real_target) . " --strip-components=1; " .
            "chown -R " . escapeshellarg($nginx_user . ':' . $nginx_user) . " " . escapeshellarg($real_target) . "; " .
            "find " . escapeshellarg($real_target) . " -type d -exec chmod 755 {} \\;; " .
            "find " . escapeshellarg($real_target) . " -type f -exec chmod 644 {} \\;; " .
            "systemctl reload " . escapeshellarg(get_php_fpm_svc($config)) . " 2>/dev/null || true; " .
            "rm -f " . escapeshellarg($staging) . "; " .
            "touch " . escapeshellarg(DEPLOY_DONE_MARK)
        ),
        escapeshellarg(DEPLOY_LOG)
    );

    $pid = shell_exec("($cmd) & echo \$!");

    // [B9] Check write state
    if (!write_deploy_state('running', 'Deploy in progress', trim($pid ?: ''))) {
        http_response_code(500);
        @unlink($staging);
        json_out(['error' => 'Failed to write deploy state']);
        return;
    }

    log_event("DEPLOY started: target=$target, checksum=$actual_sha");

    // [B2] Watcher dùng marker file
    shell_exec(sprintf(
        'nohup bash -c %s >/dev/null 2>&1 &',
        escapeshellarg(
            "sleep 2; while kill -0 " . escapeshellarg(trim($pid ?: '0')) . " 2>/dev/null; do sleep 2; done; " .
            "if [ -f " . escapeshellarg(DEPLOY_DONE_MARK) . " ]; then " .
            "  echo '{\"status\":\"done\",\"finished_at\":\"$(date -Iseconds)\"}' > " . escapeshellarg(DEPLOY_STATE) . "; " .
            "else echo '{\"status\":\"failed\",\"finished_at\":\"$(date -Iseconds)\"}' > " . escapeshellarg(DEPLOY_STATE) . "; fi"
        )
    ));

    json_out(['status' => 'running', 'target' => $real_target,
              'checksum' => $actual_sha, 'started_at' => date('c'),
              'poll' => '/mvps/deploy/status']);
}

function handle_deploy_status(): void
{
    if (!file_exists(DEPLOY_STATE)) { json_out(['status' => 'idle']); return; }
    $state             = json_decode(file_get_contents(DEPLOY_STATE), true) ?? [];
    $state['log_tail'] = get_log_tail(DEPLOY_LOG, 20);
    json_out($state);
}

function handle_token_rotate(string $old_token): void
{
    $body      = json_decode(file_get_contents('php://input'), true);
    $new_token = $body['new_token'] ?? '';

    if (!preg_match('/^mvps_wn_[a-zA-Z0-9]{32}$/', $new_token)) {
        http_response_code(400);
        json_out(['error' => 'Invalid token format']);
        return;
    }
    if (hash_equals($old_token, $new_token)) {
        http_response_code(400);
        json_out(['error' => 'New token must differ from current token']);
        return;
    }

    $token_data = ['token' => $new_token, 'issued' => date('c'),
                   'expires' => date('c', strtotime('+30 days')), 'rotated_by' => 'lb'];

    // [B7] Atomic write
    $tmp        = TOKEN_FILE . '.tmp.' . bin2hex(random_bytes(4));
    $prev_umask = umask(0177);
    $written    = file_put_contents($tmp, json_encode($token_data, JSON_PRETTY_PRINT));
    umask($prev_umask);

    if ($written === false || !rename($tmp, TOKEN_FILE)) {
        @unlink($tmp);
        http_response_code(500);
        json_out(['error' => 'Failed to write token file']);
        return;
    }

    log_event("TOKEN rotated by LB");
    json_out(['status' => 'rotated', 'expires' => $token_data['expires']]);
}


// ══════════════════════════════════════════════════════════════
// HANDLERS — AI LAYER
// ══════════════════════════════════════════════════════════════

/**
 * POST /mvps/ai-analyze/logs
 */
function handle_ai_analyze_logs(array $config): void
{
    $ai_config = ai_bootstrap();
    if ($ai_config === null) return;

    $body      = json_decode(file_get_contents('php://input'), true) ?? [];
    $req_lines = max(10, min((int)($body['lines'] ?? $ai_config['log_lines']), 200));

    $nginx_log  = ai_read_log_tail(ai_find_nginx_error_log(),         $req_lines);
    $phpfpm_log = ai_read_log_tail(ai_find_phpfpm_error_log($config), $req_lines);

    if (empty(trim($nginx_log)) && empty(trim($phpfpm_log))) {
        json_out(['node_id' => gethostname(), 'analyzed_at' => date('c'),
                  'diagnosis'     => 'Không tìm thấy lỗi nào trong log hiện tại.',
                  'severity'      => 'LOW',
                  'ai_model'      => $ai_config['model'],
                  'log_lines_used'=> 0]);
        return;
    }

    $prompt     = prompt_logs($nginx_log, $phpfpm_log, $config['SERVER_TYPE'] ?? 'web');
    $max_tokens = _ai_get_max_tokens($ai_config);                     // [G4-FIX]
    ai_call_and_respond($prompt, $ai_config, 'logs', $req_lines, [], $max_tokens);
}

/**
 * POST /mvps/ai-analyze/metrics                        [AI-4]
 *
 * Thu thập metrics realtime + php-fpm pool config hiện tại
 * → AI đề xuất tune: pm.max_children, worker_processes, innodb_buffer_pool...
 *
 * Request body: không cần — tự thu thập tại node
 *
 * Response thêm: metrics_snapshot (để client log lại)
 */
function handle_ai_analyze_metrics(array $config): void
{
    $ai_config = ai_bootstrap();
    if ($ai_config === null) return;

    $metrics     = ai_collect_metrics($config);
    $pool_config = ai_read_phpfpm_pool($config);

    $prompt     = prompt_metrics($metrics, $pool_config);
    $max_tokens = _ai_get_max_tokens($ai_config);                     // [G4-FIX]
    ai_call_and_respond($prompt, $ai_config, 'metrics', 0,
                        ['metrics_snapshot' => $metrics], $max_tokens);
}

/**
 * POST /mvps/ai-analyze/security                       [AI-5]
 *
 * Thu thập fail2ban log + IP ban list
 * → AI tóm tắt threat level, attack pattern, đề xuất hardening
 *
 * Request body (optional): { "lines": 30 }
 *
 * Response thêm: banned_ip_count, ban_count_24h
 */
function handle_ai_analyze_security(array $config): void
{
    $ai_config = ai_bootstrap();
    if ($ai_config === null) return;

    $body      = json_decode(file_get_contents('php://input'), true) ?? [];
    $req_lines = max(10, min((int)($body['lines'] ?? 30), 100));

    $f2b_log       = ai_read_fail2ban_log($req_lines);
    $banned_ips    = ai_get_banned_ips();
    $ban_count_24h = ai_get_ban_count_24h();

    if (empty(trim($f2b_log)) && empty($banned_ips)) {
        json_out(['node_id'        => gethostname(),
                  'analyzed_at'   => date('c'),
                  'diagnosis'     => 'Không có hoạt động bảo mật đáng chú ý.',
                  'severity'      => 'LOW',
                  'ai_model'      => $ai_config['model'],
                  'banned_ip_count'=> 0,
                  'ban_count_24h' => 0]);
        return;
    }

    $prompt     = prompt_security($f2b_log, $banned_ips, $ban_count_24h);
    $max_tokens = _ai_get_max_tokens($ai_config);                     // [G4-FIX]
    ai_call_and_respond($prompt, $ai_config, 'security', $req_lines, [
        'banned_ip_count' => count($banned_ips),
        'ban_count_24h'   => $ban_count_24h,
    ], $max_tokens);
}

/**
 * POST /mvps/ai-analyze/deploy                         [AI-6]
 *
 * Verify sau khi deploy xong — AI đánh giá kết quả
 *
 * Request body (bắt buộc):
 *   { "site_url": "https://example.com", "site_name": "example.com" }
 *
 * Response thêm: health_snapshot, http_probe
 */
function handle_ai_analyze_deploy(array $config): void
{
    $ai_config = ai_bootstrap();
    if ($ai_config === null) return;

    $body      = json_decode(file_get_contents('php://input'), true) ?? [];
    $site_url  = trim($body['site_url']  ?? '');
    $site_name = trim($body['site_name'] ?? '');

    if (empty($site_url) || !filter_var($site_url, FILTER_VALIDATE_URL)) {
        http_response_code(400);
        json_out(['error' => 'site_url không hợp lệ hoặc bị thiếu']);
        return;
    }
    if (!empty($site_name) && !preg_match('/^[a-zA-Z0-9][a-zA-Z0-9.\-_]{0,63}$/', $site_name)) {
        http_response_code(400);
        json_out(['error' => 'site_name không hợp lệ']);
        return;
    }

    $php_svc = get_php_fpm_svc($config);
    $health  = [
        'nginx'    => service_active('nginx'),
        'php_fpm'  => service_active($php_svc),
        'mariadb'  => service_active('mariadb'),
        'draining' => file_exists(DRAIN_FLAG),
        'overall'  => 'UP',
    ];
    if (!$health['nginx'] || !$health['php_fpm'] || !$health['mariadb']) {
        $health['overall'] = 'DEGRADED';
    }
    $health['http_probe'] = ai_http_probe($site_url);

    $deploy_log = implode("\n", get_log_tail(DEPLOY_LOG, 30));
    $prompt     = prompt_deploy($site_url, $health, $deploy_log);
    $max_tokens = _ai_get_max_tokens($ai_config);                     // [G4-FIX]
    ai_call_and_respond($prompt, $ai_config, 'deploy', 0, [
        'health_snapshot' => $health,
        'site_url'        => $site_url,
    ], $max_tokens);
}


// ══════════════════════════════════════════════════════════════
// AI BOOTSTRAP + SHARED CALL                          [AI-7]
// ══════════════════════════════════════════════════════════════

/**
 * Load AI layer + validate config
 * Dùng chung cho mọi handle_ai_* — không lặp code
 *
 * @return array|null  AI config nếu OK, null nếu lỗi (đã json_out error)
 */
function ai_bootstrap(): ?array
{
    if (!file_exists(AI_DIR . '/client.php') || !file_exists(AI_DIR . '/prompt.php')) {
        http_response_code(503);
        json_out(['error'  => 'AI layer chưa được cài đặt',
                  'detail' => 'Thiếu agent/ai/client.php hoặc agent/ai/prompt.php']);
        return null;
    }

    require_once AI_DIR . '/client.php';
    require_once AI_DIR . '/prompt.php';

    $ai_config = ai_load_config();

    if (!$ai_config['enabled']) {
        http_response_code(503);
        json_out(['error'  => 'AI layer đang disabled',
                  'detail' => 'Bật AI_ENABLED=true trong /etc/modernvps/ai.conf']);
        return null;
    }

    if (empty($ai_config['api_key'])) {
        http_response_code(503);
        json_out(['error'  => 'ANTHROPIC_API_KEY chưa được cấu hình',
                  'detail' => 'Điền API key vào /etc/modernvps/ai.conf']);
        return null;
    }

    return $ai_config;
}

/**
 * Gọi AI + trả response JSON chuẩn
 * Dùng chung cho mọi endpoint — tránh lặp error handling
 */
function ai_call_and_respond(
    array  $prompt,
    array  $ai_config,
    string $type,
    int    $lines_used       = 0,
    array  $extra            = [],
    int    $max_tokens_override = 0   // [G4-FIX]
): void {
    // [G4-FIX] Override max_tokens nếu được yêu cầu
    if ($max_tokens_override > 0) {
        $ai_config['max_tokens'] = $max_tokens_override;
    }

    $result = ai_call($prompt['system'], $prompt['user'], $ai_config);

    if (!$result['success']) {
        http_response_code(502);
        json_out(['error' => 'Gọi Claude API thất bại', 'detail' => $result['error']]);
        return;
    }

    $severity = ai_extract_severity($result['content']);
    log_event("AI_ANALYZE $type: severity=$severity tokens_max=" . $ai_config['max_tokens']);

    json_out(array_merge(
        [
            'node_id'     => gethostname(),
            'analyzed_at' => date('c'),
            'type'        => $type,
            'diagnosis'   => $result['content'],
            'severity'    => $severity,
            'ai_model'    => $ai_config['model'],
        ],
        $lines_used > 0 ? ['log_lines_used' => $lines_used] : [],
        $extra
    ));
}

function _ai_get_max_tokens(array $ai_config): int
{
    // Report mode: mvps-ai-report gửi header X-Report-Mode: 1
    $report_mode = (($_SERVER['HTTP_X_REPORT_MODE'] ?? '') === '1');
    if ($report_mode && isset($ai_config['report_max_tokens'])) {
        return (int)$ai_config['report_max_tokens'];
    }
    return (int)($ai_config['max_tokens'] ?? 800);
}


// ══════════════════════════════════════════════════════════════
// AI DATA COLLECTORS
// ══════════════════════════════════════════════════════════════

/** Thu thập metrics → gửi AI phân tích */
function ai_collect_metrics(array $config): array
{
    $loadavg_raw = @file_get_contents('/proc/loadavg');
    [$load1, $load5, $load15] = $loadavg_raw !== false
        ? explode(' ', $loadavg_raw) : ['0', '0', '0'];

    $cpuinfo   = @file_get_contents('/proc/cpuinfo');
    $cpu_cores = $cpuinfo !== false ? substr_count($cpuinfo, 'processor') : 1;

    $meminfo_raw = @file_get_contents('/proc/meminfo');
    $mem = [];
    if ($meminfo_raw !== false) {
        preg_match_all('/^(\w+):\s+(\d+)/m', $meminfo_raw, $mm, PREG_SET_ORDER);
        foreach ($mm as $row) $mem[$row[1]] = (int)$row[2];
    }
    $ram_total_mb = (int)(($mem['MemTotal']    ?? 0) / 1024);
    $ram_avail_mb = (int)(($mem['MemAvailable'] ?? 0) / 1024);

    $df      = @disk_free_space('/var/www') ?: 0;
    $dt      = @disk_total_space('/var/www') ?: 0;
    $workers = get_php_workers($config);

    // [B4-FIX] os_name: đọc từ /etc/os-release (không fork process)
    $os_name = 'Linux';
    if (file_exists('/etc/os-release')) {
        $os_raw = @file_get_contents('/etc/os-release');
        if ($os_raw && preg_match('/^PRETTY_NAME="([^"]+)"/m', $os_raw, $om)) {
            $os_name = $om[1];
        }
    }

    return ai_sanitize_metrics([
        // CPU
        'cpu_cores'         => $cpu_cores,
        'load1'             => (float)$load1,
        'load5'             => (float)$load5,
        'load15'            => (float)$load15,

        // Memory
        'mem_total_mb'      => $ram_total_mb,
        'mem_used_mb'       => $ram_total_mb - $ram_avail_mb,
        'mem_free_mb'       => $ram_avail_mb,

        // Disk
        'disk_used_pct'     => $dt > 0 ? round(($dt - $df) / $dt * 100, 1) : 0,
        'disk_free_gb'      => round($df / 1073741824, 1),

        // Nginx
        'nginx_active_conn' => get_nginx_connections(),

        // PHP-FPM — [B2-FIX] thêm php_fpm_max
        'php_fpm_active'    => $workers['active'],
        'php_fpm_idle'      => $workers['idle'],
        'php_fpm_max'       => $workers['max'],   // [B2-FIX] thiếu → "0 max"
        'php_fpm_queue'     => 0,

        // Context — [B4-FIX] thêm os_name
        'sites_count'       => count(glob('/var/www/*/') ?: []),
        'server_type'       => $config['SERVER_TYPE'] ?? 'web',
        'php_version'       => $config['PHP_VERSION'] ?? '8.3',
        'os_name'           => $os_name,           // [B4-FIX]
    ]);
}
/** Đọc php-fpm pool config → array key-value để AI tune */
function ai_read_phpfpm_pool(array $config): array
{
    $version = $config['PHP_VERSION'] ?? '8.3';
    $family  = $config['OS_FAMILY']   ?? 'debian';
    $path    = $family === 'rhel'
        ? '/etc/php-fpm.d/www.conf'
        : "/etc/php/{$version}/fpm/pool.d/www.conf";

    if (!file_exists($path)) return [];

    $result = [];
    $keys   = ['pm', 'pm.max_children', 'pm.start_servers',
               'pm.min_spare_servers', 'pm.max_spare_servers',
               'pm.max_requests', 'request_terminate_timeout'];

    foreach (file($path) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === ';') continue;
        foreach ($keys as $key) {
            if (preg_match('/^' . preg_quote($key, '/') . '\s*=\s*(.+)$/', $line, $m)) {
                $result[$key] = trim($m[1]);
            }
        }
    }
    return $result;
}

/** Đọc fail2ban log */
function ai_read_fail2ban_log(int $lines): string
{
    foreach (['/var/log/fail2ban.log', '/var/log/fail2ban/fail2ban.log'] as $p) {
        if (file_exists($p) && is_readable($p)) return ai_read_log_tail($p, $lines);
    }
    return '';
}

/**
 * Lấy IP đang bị ban từ fail2ban-client
 * Validate jail name trước exec — không inject
 */
function ai_get_banned_ips(): array
{
    $ips = [];
    $out = [];
    exec('fail2ban-client status 2>/dev/null', $out, $code);
    if ($code !== 0) return [];

    $jails_line = '';
    foreach ($out as $line) {
        if (strpos($line, 'Jail list:') !== false) { $jails_line = $line; break; }
    }

    $jails = array_filter(array_map('trim',
        explode(',', preg_replace('/.*Jail list:\s*/i', '', $jails_line))
    ));

    foreach ($jails as $jail) {
        // Validate — chỉ alnum + dash/underscore
        if (!preg_match('/^[a-zA-Z0-9\-_]+$/', $jail)) continue;

        $jout = [];
        exec('fail2ban-client status ' . escapeshellarg($jail) . ' 2>/dev/null', $jout);
        foreach ($jout as $line) {
            if (strpos($line, 'Banned IP list:') !== false) {
                $ip_raw = trim(preg_replace('/.*Banned IP list:\s*/i', '', $line));
                if ($ip_raw !== '') {
                    $ips = array_merge($ips, array_filter(array_map('trim', explode(' ', $ip_raw))));
                }
            }
        }
    }
    return array_values(array_unique($ips));
}

/** Đếm lần ban trong 24h */
function ai_get_ban_count_24h(): int
{
    foreach (['/var/log/fail2ban.log', '/var/log/fail2ban/fail2ban.log'] as $p) {
        if (!file_exists($p) || !is_readable($p)) continue;
        $out = [];
        exec('grep -c ' . escapeshellarg('Ban') . ' ' . escapeshellarg($p) . ' 2>/dev/null || echo 0', $out);
        return (int)($out[0] ?? 0);
    }
    return 0;
}

/**
 * HTTP probe site_url — timeout 5s, follow redirect max 3
 * Không dùng curl để giảm dependency
 */
function ai_http_probe(string $url): array
{
    $ctx = stream_context_create([
        'http' => ['timeout' => 5, 'follow_location' => true, 'max_redirects' => 3,
                   'method' => 'GET', 'ignore_errors' => true,
                   'header' => 'User-Agent: ModernVPS-AI-Probe/1.0'],
        'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
    ]);

    $start    = microtime(true);
    $response = @file_get_contents($url, false, $ctx);
    $elapsed  = round((microtime(true) - $start) * 1000);

    $http_code = 0;
    if (isset($http_response_header)) {
        foreach ($http_response_header as $h) {
            if (preg_match('#HTTP/\S+\s+(\d+)#', $h, $m)) {
                $http_code = (int)$m[1];
                break;
            }
        }
    }

    return ['http_code' => $http_code, 'response_ms' => $elapsed,
            'reachable' => $response !== false];
}

// ── Log path finders ───────────────────────────────────────────

function ai_find_nginx_error_log(): string
{
    $conf = @file_get_contents('/etc/nginx/nginx.conf');
    if ($conf && preg_match('/error_log\s+([^\s;]+)/m', $conf, $m)) {
        $p = trim($m[1]);
        if ($p !== 'stderr' && file_exists($p)) return $p;
    }
    foreach (['/var/log/nginx/error.log', '/var/log/nginx/error.log.1'] as $p) {
        if (file_exists($p)) return $p;
    }
    return '';
}

function ai_find_phpfpm_error_log(array $config): string
{
    $version    = $config['PHP_VERSION'] ?? '8.3';
    $family     = $config['OS_FAMILY']   ?? 'debian';
    $candidates = $family === 'rhel'
        ? ['/var/log/php-fpm/error.log', '/var/log/php-fpm/www-error.log']
        : ["/var/log/php{$version}-fpm.log", '/var/log/php-fpm.log'];
    foreach ($candidates as $p) { if (file_exists($p)) return $p; }
    return '';
}

function ai_read_log_tail(string $path, int $lines): string
{
    if (empty($path) || !file_exists($path) || !is_readable($path)) return '';
    $out = [];
    exec('tail -n ' . (int)$lines . ' ' . escapeshellarg($path) . ' 2>/dev/null', $out);
    return implode("\n", $out);
}

function ai_extract_severity(string $content): string
{
    if (preg_match('/MỨC\s+ĐỘ\s*:\s*(LOW|MEDIUM|HIGH|CRITICAL)/ui', $content, $m)) {
        return strtoupper($m[1]);
    }
    return 'UNKNOWN';
}


// ══════════════════════════════════════════════════════════════
// HELPERS — GỐC
// ══════════════════════════════════════════════════════════════

function verify_token(string $provided): bool
{
    if (!file_exists(TOKEN_FILE)) return false;
    $data = json_decode(file_get_contents(TOKEN_FILE), true);
    if (empty($data['token']) || empty($data['expires'])) return false;
    if (strtotime($data['expires']) < time()) return false;
    return hash_equals($data['token'], $provided);
}

function service_active(string $name): bool
{
    exec("systemctl is-active " . escapeshellarg($name) . " 2>/dev/null", $out, $code);
    return $code === 0;
}

function get_php_fpm_svc(array $config): string
{
    $family  = $config['OS_FAMILY']   ?? 'debian';
    $version = $config['PHP_VERSION'] ?? '8.3';
    return $family === 'debian' ? "php{$version}-fpm" : 'php-fpm';
}

function get_php_workers(array $config): array
{
    $version   = $config['PHP_VERSION'] ?? '8.3';
    $family    = $config['OS_FAMILY']   ?? 'debian';
    $total     = 0;
    $pool_conf = $family === 'rhel'
        ? '/etc/php-fpm.d/www.conf'
        : "/etc/php/{$version}/fpm/pool.d/www.conf";

    if (file_exists($pool_conf)) {
        foreach (file($pool_conf) as $line) {
            if (preg_match('/^pm\.max_children\s*=\s*(\d+)/', $line, $m)) {
                $total = (int)$m[1]; break;
            }
        }
    }

    $active = 0; $idle = 0;
    $fpm_name = $family === 'rhel' ? 'php-fpm' : "php-fpm{$version}";

    if (is_dir('/proc')) {
        foreach (glob('/proc/[0-9]*/status') ?: [] as $sf) {
            $c = @file_get_contents($sf);
            if (!$c) continue;
            if (!preg_match('/^Name:\s*(.+)/m', $c, $nm)) continue;
            if (trim($nm[1]) !== $fpm_name) continue;
            preg_match('/^PPid:\s*(\d+)/m', $c, $pm);
            if ((int)($pm[1] ?? 0) <= 1) continue;
            preg_match('/^State:\s*(\S)/m', $c, $sm);
            ($sm[1] ?? 'S') === 'R' ? $active++ : $idle++;
        }
    }

    return ['active' => $active, 'idle' => $idle, 'max' => $total, 'source' => 'proc'];
}

function get_nginx_connections(): int
{
    $ctx  = stream_context_create(['http' => ['timeout' => 1]]);
    $stub = @file_get_contents('http://127.0.0.1/nginx_status', false, $ctx);
    if ($stub && preg_match('/Active connections:\s*(\d+)/', $stub, $m)) return (int)$m[1];
    return -1;
}

function get_ssl_expiring(): array
{
    $expiring = [];
    foreach (glob('/etc/letsencrypt/live/*/fullchain.pem') ?: [] as $cert) {
        $domain = basename(dirname($cert));
        $end    = exec("openssl x509 -noout -enddate -in " . escapeshellarg($cert) . " 2>/dev/null | cut -d= -f2");
        if (!$end) continue;
        $days = (int)((strtotime($end) - time()) / 86400);
        if ($days <= 30) $expiring[] = ['domain' => $domain, 'days_left' => $days];
    }
    return $expiring;
}

function write_deploy_state(string $status, string $message = '', string $pid = ''): bool
{
    $state   = ['status' => $status, 'message' => $message,
                'pid' => $pid, 'updated_at' => date('c')];
    $written = @file_put_contents(DEPLOY_STATE, json_encode($state, JSON_PRETTY_PRINT), LOCK_EX);
    if ($written === false) {
        log_event("ERROR: Failed to write deploy state: " . (error_get_last()['message'] ?? 'unknown'));
        return false;
    }
    $verify  = @file_get_contents(DEPLOY_STATE);
    $decoded = $verify !== false ? json_decode($verify, true) : null;
    if ($decoded === null || ($decoded['status'] ?? '') !== $status) {
        log_event("ERROR: Deploy state verification failed");
        return false;
    }
    return true;
}

function get_log_tail(string $file, int $lines = 20): array
{
    if (!file_exists($file)) return [];
    $out = [];
    exec("tail -n " . (int)$lines . " " . escapeshellarg($file) . " 2>/dev/null", $out);
    return $out;
}

function parse_config_env(string $path): array
{
    $config = [];
    if (!file_exists($path)) return $config;
    foreach (file($path) as $line) {
        $line = trim($line);
        if ($line === '' || $line[0] === '#') continue;
        if (preg_match('/^([A-Z_]+)=(.*)$/', $line, $m)) {
            $config[$m[1]] = trim($m[2], '"\'');
        }
    }
    return $config;
}

function log_event(string $msg): void
{
    $line = date('c') . ' [AGENT] ' . $msg . ' (from: ' . ($_SERVER['REMOTE_ADDR'] ?? '?') . ')';
    file_put_contents(DEPLOY_LOG, $line . PHP_EOL, FILE_APPEND | LOCK_EX);
}

function json_out(array $data): never
{
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}
