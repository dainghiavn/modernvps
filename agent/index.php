<?php
/**
 * ModernVPS Cluster Agent v1.3
 * Chạy trên Web node, lắng nghe port 9000 (internal IP only)
 * Auth: Bearer token rotate mỗi 30 ngày
 *
 * Endpoints:
 *   GET  /mvps/health              → nginx/php/mariadb status
 *   GET  /mvps/metrics             → cpu/ram/disk/php/sites
 *   POST /mvps/drain               → graceful drain traffic
 *   POST /mvps/drain/cancel        → restore traffic
 *   POST /mvps/deploy              → upload + extract tarball
 *   GET  /mvps/deploy/status       → trạng thái deploy hiện tại
 *   POST /mvps/token/rotate        → rotate token mới từ LB
 *   POST /mvps/ai-analyze/logs     → [NEW] AI phân tích nginx + php-fpm error log
 *
 * CHANGELOG v1.3:
 *   [AI-1] NEW: Endpoint POST /mvps/ai-analyze/logs
 *          → Thu thập nginx error.log + php-fpm error log
 *          → Gửi lên Claude API qua agent/ai/client.php
 *          → Trả về diagnosis, root_cause, suggestions, severity
 *   [AI-2] NEW: Wrap toàn bộ AI logic trong ai_enabled() guard
 *          → Agent hoạt động bình thường khi AI disabled hoặc API down
 *   [AI-3] NEW: require_once ai layer chỉ khi cần — không load nếu không dùng AI
 *
 * CHANGELOG v1.2:
 *   [B1] FIX CRITICAL: Checksum bắt buộc — không cho phép deploy không có SHA256
 *   [B2] FIX CRITICAL: Watcher dùng marker file riêng thay vì grep DONE trong log tích lũy
 *   [B3] FIX HIGH: staging filename dùng random_bytes() thay vì time() — tránh collision
 *   [B4] FIX HIGH: target_abs validate bằng realpath() sau mkdir — chặn symlink escape
 *   [B5] FIX HIGH: /proc/* đọc có guard null — không crash trong container/thiếu /proc
 *   [B6] FIX MED: write_deploy_state thêm LOCK_EX — tránh concurrent write corrupt
 *   [B7] FIX MED: TOKEN_FILE write atomic qua tmp file + rename — tránh race chmod
 *   [B8] FIX LOW: 404 không leak URI vào response
 *   [B9] FIX HIGH: write_deploy_state() check kết quả ghi — báo lỗi đúng cho LB
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
define('VERSION',          '1.3');
// [AI-3] Path đến AI layer — lazy load, chỉ require khi endpoint AI được gọi
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
    // ── Endpoints gốc (không thay đổi) ────────────────────────
    case $uri === '/mvps/health'              && $method === 'GET':
        handle_health($config);
        break;
    case $uri === '/mvps/metrics'             && $method === 'GET':
        handle_metrics($config);
        break;
    case $uri === '/mvps/drain'               && $method === 'POST':
        handle_drain();
        break;
    case $uri === '/mvps/drain/cancel'        && $method === 'POST':
        handle_drain_cancel();
        break;
    case $uri === '/mvps/deploy'              && $method === 'POST':
        handle_deploy($config);
        break;
    case $uri === '/mvps/deploy/status'       && $method === 'GET':
        handle_deploy_status();
        break;
    case $uri === '/mvps/token/rotate'        && $method === 'POST':
        handle_token_rotate($provided_token);
        break;

    // ── [AI-1] AI Analysis endpoints ──────────────────────────
    case $uri === '/mvps/ai-analyze/logs'     && $method === 'POST':
        handle_ai_analyze_logs($config);
        break;

    default:
        http_response_code(404);
        json_out(['error' => 'Unknown endpoint']);
}


// ══════════════════════════════════════════════════════════════
// HANDLERS — GỐC (giữ nguyên)
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

    $all_up = $status['nginx'] && $status['php_fpm'] && $status['mariadb'];
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
    // [B5] FIX: Guard null khi /proc không mount (container, mock env)
    $loadavg_raw = @file_get_contents('/proc/loadavg');
    [$load1, $load5, $load15] = $loadavg_raw !== false
        ? explode(' ', $loadavg_raw)
        : ['0', '0', '0'];

    // CPU cores
    $cpuinfo  = @file_get_contents('/proc/cpuinfo');
    $cpu_cores = $cpuinfo !== false
        ? substr_count($cpuinfo, 'processor')
        : 1;

    // RAM — đọc /proc/meminfo
    $meminfo_raw = @file_get_contents('/proc/meminfo');
    $mem = [];
    if ($meminfo_raw !== false) {
        preg_match_all('/^(\w+):\s+(\d+)/m', $meminfo_raw, $mm, PREG_SET_ORDER);
        foreach ($mm as $row) {
            $mem[$row[1]] = (int)$row[2];
        }
    }
    $ram_total_mb = (int)(($mem['MemTotal']     ?? 0) / 1024);
    $ram_avail_mb = (int)(($mem['MemAvailable']  ?? 0) / 1024);
    $ram_used_mb  = $ram_total_mb - $ram_avail_mb;

    // Disk
    $df            = @disk_free_space('/var/www') ?: 0;
    $dt            = @disk_total_space('/var/www') ?: 0;
    $disk_used_pct = $dt > 0 ? round(($dt - $df) / $dt * 100, 1) : 0;

    // Uptime
    $uptime_raw = @file_get_contents('/proc/uptime');
    $uptime_sec = $uptime_raw !== false ? (int)explode(' ', $uptime_raw)[0] : 0;

    // Sites count
    $sites = count(glob('/var/www/*/') ?: []);

    json_out([
        'node_id'      => gethostname(),
        'timestamp'    => date('c'),
        'cpu' => [
            'cores'  => $cpu_cores,
            'load1'  => (float)$load1,
            'load5'  => (float)$load5,
            'load15' => (float)$load15,
        ],
        'ram' => [
            'total_mb'  => $ram_total_mb,
            'used_mb'   => $ram_used_mb,
            'avail_mb'  => $ram_avail_mb,
            'used_pct'  => $ram_total_mb > 0
                ? round($ram_used_mb / $ram_total_mb * 100, 1) : 0,
        ],
        'disk' => [
            'used_pct' => $disk_used_pct,
            'free_gb'  => round($df / 1073741824, 1),
            'total_gb' => round($dt / 1073741824, 1),
        ],
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
    json_out([
        'status'     => 'draining',
        'started_at' => date('c'),
        'message'    => 'Node is now draining. LB should detect via /mvps/health returning 503.',
    ]);
}

function handle_drain_cancel(): void
{
    if (!file_exists(DRAIN_FLAG)) {
        json_out(['status' => 'not_draining']);
        return;
    }

    unlink(DRAIN_FLAG);
    log_event("DRAIN cancelled");
    json_out([
        'status'      => 'active',
        'restored_at' => date('c'),
    ]);
}

function handle_deploy(array $config): void
{
    // Chỉ 1 deploy tại một thời điểm
    if (file_exists(DEPLOY_STATE)) {
        $state = json_decode(file_get_contents(DEPLOY_STATE), true) ?? [];
        if (($state['status'] ?? '') === 'running') {
            http_response_code(409);
            json_out(['error' => 'Deploy already in progress', 'state' => $state]);
            return;
        }
    }

    // [B1] FIX CRITICAL: Checksum bắt buộc
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

    // [B3] staging filename dùng random_bytes() — tránh collision
    $staging = '/tmp/mvps-deploy-' . bin2hex(random_bytes(8)) . '.tar.gz';
    if (!move_uploaded_file($_FILES['tarball']['tmp_name'], $staging)) {
        http_response_code(500);
        json_out(['error' => 'Failed to move tarball to staging']);
        return;
    }

    $target_path = DEPLOY_DIR . '/' . $target;

    // [B4] Validate realpath sau mkdir — chặn symlink escape
    if (!is_dir($target_path)) {
        mkdir($target_path, 0755, true);
    }
    $real_target = realpath($target_path);
    $real_base   = realpath(DEPLOY_DIR);

    if ($real_target === false || $real_base === false ||
        strpos($real_target, $real_base . '/') !== 0) {
        @unlink($staging);
        http_response_code(400);
        json_out(['error' => 'Path traversal detected']);
        return;
    }

    // Xóa done-mark cũ trước deploy mới
    @unlink(DEPLOY_DONE_MARK);

    $nginx_user = $config['NGINX_USER'] ?? 'www-data';

    $cmd = sprintf(
        'nohup bash -c %s >> %s 2>&1',
        escapeshellarg(
            "backup_dir=/tmp/mvps-deploy-bak-$(date +%s); " .
            "mkdir -p \$backup_dir; " .
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

    // [B9] FIX: Check kết quả write_deploy_state
    if (!write_deploy_state('running', 'Deploy in progress', trim($pid ?: ''))) {
        http_response_code(500);
        @unlink($staging);
        json_out(['error' => 'Failed to write deploy state']);
        return;
    }

    log_event("DEPLOY started: target=$target, checksum=$actual_sha");

    // [B2] Background watcher — check DEPLOY_DONE_MARK
    shell_exec(sprintf(
        'nohup bash -c %s >/dev/null 2>&1 &',
        escapeshellarg(
            "sleep 2; " .
            "while kill -0 " . escapeshellarg(trim($pid ?: '0')) . " 2>/dev/null; do sleep 2; done; " .
            "if [ -f " . escapeshellarg(DEPLOY_DONE_MARK) . " ]; then " .
            "  echo '{\"status\":\"done\",\"finished_at\":\"$(date -Iseconds)\"}' > " . escapeshellarg(DEPLOY_STATE) . "; " .
            "else " .
            "  echo '{\"status\":\"failed\",\"finished_at\":\"$(date -Iseconds)\"}' > " . escapeshellarg(DEPLOY_STATE) . "; " .
            "fi"
        )
    ));

    json_out([
        'status'     => 'running',
        'target'     => $real_target,
        'checksum'   => $actual_sha,
        'started_at' => date('c'),
        'poll'       => '/mvps/deploy/status',
    ]);
}

function handle_deploy_status(): void
{
    if (!file_exists(DEPLOY_STATE)) {
        json_out(['status' => 'idle']);
        return;
    }

    $state = json_decode(file_get_contents(DEPLOY_STATE), true) ?? [];
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

    $token_data = [
        'token'      => $new_token,
        'issued'     => date('c'),
        'expires'    => date('c', strtotime('+30 days')),
        'rotated_by' => 'lb',
    ];

    // [B7] FIX MED: Write atomic qua tmp file + rename
    $tmp_token  = TOKEN_FILE . '.tmp.' . bin2hex(random_bytes(4));
    $prev_umask = umask(0177);
    $written    = file_put_contents($tmp_token, json_encode($token_data, JSON_PRETTY_PRINT));
    umask($prev_umask);

    if ($written === false || !rename($tmp_token, TOKEN_FILE)) {
        @unlink($tmp_token);
        http_response_code(500);
        json_out(['error' => 'Failed to write token file']);
        return;
    }

    log_event("TOKEN rotated by LB");
    json_out([
        'status'  => 'rotated',
        'expires' => $token_data['expires'],
    ]);
}


// ══════════════════════════════════════════════════════════════
// HANDLERS — AI LAYER [v1.3]
// ══════════════════════════════════════════════════════════════

/**
 * POST /mvps/ai-analyze/logs
 *
 * Thu thập nginx error.log + php-fpm error log → gửi Claude API → trả diagnosis.
 *
 * [AI-2] Wrap trong ai_enabled() guard:
 *   → Nếu AI disabled hoặc API key chưa cấu hình → trả 503 với lý do rõ
 *   → Agent gốc không bị ảnh hưởng
 *
 * Request body (JSON, optional):
 *   { "lines": 50 }   ← số dòng log muốn phân tích (default: 50, max: 200)
 *
 * Response:
 *   {
 *     "node_id":    "hostname",
 *     "analyzed_at": "ISO8601",
 *     "diagnosis":  "...",   ← tóm tắt vấn đề
 *     "severity":   "LOW|MEDIUM|HIGH|CRITICAL",
 *     "ai_model":   "claude-haiku-4-5",
 *     "log_lines_used": 50
 *   }
 */
function handle_ai_analyze_logs(array $config): void
{
    // [AI-3] Lazy load AI layer — chỉ require khi endpoint này được gọi
    $ai_client  = AI_DIR . '/client.php';
    $ai_prompt  = AI_DIR . '/prompt.php';

    if (!file_exists($ai_client) || !file_exists($ai_prompt)) {
        http_response_code(503);
        json_out([
            'error'  => 'AI layer chưa được cài đặt',
            'detail' => 'Thiếu agent/ai/client.php hoặc agent/ai/prompt.php',
        ]);
        return;
    }

    require_once $ai_client;
    require_once $ai_prompt;

    // Load AI config
    $ai_config = ai_load_config();

    // [AI-2] Guard: AI disabled
    if (!$ai_config['enabled']) {
        http_response_code(503);
        json_out([
            'error'  => 'AI layer đang disabled',
            'detail' => 'Bật AI_ENABLED=true trong /etc/modernvps/ai.conf',
        ]);
        return;
    }

    // Guard: API key chưa cấu hình
    if (empty($ai_config['api_key'])) {
        http_response_code(503);
        json_out([
            'error'  => 'ANTHROPIC_API_KEY chưa được cấu hình',
            'detail' => 'Điền API key vào /etc/modernvps/ai.conf',
        ]);
        return;
    }

    // Đọc số dòng từ request body (optional)
    $body      = json_decode(file_get_contents('php://input'), true) ?? [];
    $req_lines = min((int)($body['lines'] ?? $ai_config['log_lines']), 200);
    $req_lines = max($req_lines, 10); // tối thiểu 10 dòng

    // Thu thập nginx error log
    $nginx_log_path = ai_find_nginx_error_log($config);
    $nginx_log      = ai_read_log_tail($nginx_log_path, $req_lines);

    // Thu thập php-fpm error log
    $phpfpm_log_path = ai_find_phpfpm_error_log($config);
    $phpfpm_log      = ai_read_log_tail($phpfpm_log_path, $req_lines);

    // Nếu cả 2 log đều trống → không cần gọi AI
    if (empty(trim($nginx_log)) && empty(trim($phpfpm_log))) {
        json_out([
            'node_id'        => gethostname(),
            'analyzed_at'    => date('c'),
            'diagnosis'      => 'Không tìm thấy lỗi nào trong log hiện tại.',
            'severity'       => 'LOW',
            'ai_model'       => $ai_config['model'],
            'log_lines_used' => 0,
            'note'           => 'Log trống hoặc không tìm thấy file log',
        ]);
        return;
    }

    // Build prompt + gọi Claude API
    $server_type = $config['SERVER_TYPE'] ?? 'web';
    $prompt      = prompt_logs($nginx_log, $phpfpm_log, $server_type);
    $result      = ai_call($prompt['system'], $prompt['user'], $ai_config);

    if (!$result['success']) {
        http_response_code(502);
        json_out([
            'error'  => 'Gọi Claude API thất bại',
            'detail' => $result['error'],
        ]);
        return;
    }

    // Parse severity từ response của AI
    $severity = ai_extract_severity($result['content']);

    log_event("AI_ANALYZE logs: severity=$severity, lines=$req_lines");

    json_out([
        'node_id'        => gethostname(),
        'analyzed_at'    => date('c'),
        'diagnosis'      => $result['content'],
        'severity'       => $severity,
        'ai_model'       => $ai_config['model'],
        'log_lines_used' => $req_lines,
    ]);
}


// ══════════════════════════════════════════════════════════════
// AI HELPERS — Dùng nội bộ bởi handle_ai_analyze_*
// ══════════════════════════════════════════════════════════════

/**
 * Tìm đường dẫn nginx error log
 * Ưu tiên: nginx.conf → fallback default path
 */
function ai_find_nginx_error_log(array $config): string
{
    // Thử đọc từ nginx.conf
    $nginx_conf = @file_get_contents('/etc/nginx/nginx.conf');
    if ($nginx_conf && preg_match('/error_log\s+([^\s;]+)/m', $nginx_conf, $m)) {
        $path = trim($m[1]);
        if ($path !== 'stderr' && file_exists($path)) {
            return $path;
        }
    }

    // Fallback paths phổ biến
    $fallbacks = [
        '/var/log/nginx/error.log',
        '/var/log/nginx/error.log.1',
    ];
    foreach ($fallbacks as $path) {
        if (file_exists($path)) return $path;
    }

    return '';
}

/**
 * Tìm đường dẫn php-fpm error log
 */
function ai_find_phpfpm_error_log(array $config): string
{
    $version = $config['PHP_VERSION'] ?? '8.3';
    $family  = $config['OS_FAMILY']   ?? 'debian';

    $candidates = $family === 'rhel'
        ? ['/var/log/php-fpm/error.log', '/var/log/php-fpm/www-error.log']
        : [
            "/var/log/php{$version}-fpm.log",
            '/var/log/php-fpm.log',
        ];

    foreach ($candidates as $path) {
        if (file_exists($path)) return $path;
    }

    return '';
}

/**
 * Đọc N dòng cuối của file log — an toàn, không shell injection
 */
function ai_read_log_tail(string $path, int $lines): string
{
    if (empty($path) || !file_exists($path) || !is_readable($path)) {
        return '';
    }

    $out = [];
    exec('tail -n ' . (int)$lines . ' ' . escapeshellarg($path) . ' 2>/dev/null', $out);
    return implode("\n", $out);
}

/**
 * Extract severity từ nội dung response AI
 * AI được yêu cầu (trong prompt) kết thúc bằng "MỨC ĐỘ: LOW/MEDIUM/HIGH/CRITICAL"
 */
function ai_extract_severity(string $content): string
{
    if (preg_match('/MỨC\s+ĐỘ\s*:\s*(LOW|MEDIUM|HIGH|CRITICAL)/ui', $content, $m)) {
        return strtoupper($m[1]);
    }
    return 'UNKNOWN';
}


// ══════════════════════════════════════════════════════════════
// HELPERS — GỐC (giữ nguyên)
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
                $total = (int)$m[1];
                break;
            }
        }
    }

    $active   = 0;
    $idle     = 0;
    $fpm_name = $family === 'rhel' ? 'php-fpm' : "php-fpm{$version}";

    if (is_dir('/proc')) {
        foreach (glob('/proc/[0-9]*/status') ?: [] as $status_file) {
            $content = @file_get_contents($status_file);
            if (!$content) continue;
            if (!preg_match('/^Name:\s*(.+)/m', $content, $nm)) continue;
            if (trim($nm[1]) !== $fpm_name) continue;
            preg_match('/^PPid:\s*(\d+)/m', $content, $pm);
            if ((int)($pm[1] ?? 0) <= 1) continue;
            preg_match('/^State:\s*(\S)/m', $content, $sm);
            ($sm[1] ?? 'S') === 'R' ? $active++ : $idle++;
        }
    }

    return ['active' => $active, 'idle' => $idle, 'max' => $total, 'source' => 'proc'];
}

function get_nginx_connections(): int
{
    $ctx  = stream_context_create(['http' => ['timeout' => 1]]);
    $stub = @file_get_contents('http://127.0.0.1/nginx_status', false, $ctx);
    if ($stub && preg_match('/Active connections:\s*(\d+)/', $stub, $m)) {
        return (int)$m[1];
    }
    return -1;
}

function get_ssl_expiring(): array
{
    $expiring = [];
    $certs    = glob('/etc/letsencrypt/live/*/fullchain.pem') ?: [];
    foreach ($certs as $cert) {
        $domain = basename(dirname($cert));
        $end    = exec("openssl x509 -noout -enddate -in " . escapeshellarg($cert) . " 2>/dev/null | cut -d= -f2");
        if (!$end) continue;
        $days = (int)((strtotime($end) - time()) / 86400);
        if ($days <= 30) {
            $expiring[] = ['domain' => $domain, 'days_left' => $days];
        }
    }
    return $expiring;
}

function write_deploy_state(string $status, string $message = '', string $pid = ''): bool
{
    $state = [
        'status'     => $status,
        'message'    => $message,
        'pid'        => $pid,
        'updated_at' => date('c'),
    ];

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