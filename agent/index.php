<?php
/**
 * ModernVPS Cluster Agent v1.1
 * Chạy trên Web node, lắng nghe port 9000 (internal IP only)
 * Auth: Bearer token rotate mỗi 30 ngày
 *
 * Endpoints:
 *   GET  /mvps/health         → nginx/php/mariadb status
 *   GET  /mvps/metrics        → cpu/ram/disk/php/sites
 *   POST /mvps/drain          → graceful drain traffic
 *   POST /mvps/drain/cancel   → restore traffic
 *   POST /mvps/deploy         → upload + extract tarball
 *   GET  /mvps/deploy/status  → trạng thái deploy hiện tại
 *   POST /mvps/token/rotate   → rotate token mới từ LB
 *
 * CHANGELOG v1.1:
 *   [B1] FIX CRITICAL: Checksum bắt buộc — không cho phép deploy không có SHA256
 *   [B2] FIX CRITICAL: Watcher dùng marker file riêng thay vì grep DONE trong log tích lũy
 *   [B3] FIX HIGH: staging filename dùng random_bytes() thay vì time() — tránh collision
 *   [B4] FIX HIGH: target_abs validate bằng realpath() sau mkdir — chặn symlink escape
 *   [B5] FIX HIGH: /proc/* đọc có guard null — không crash trong container/thiếu /proc
 *   [B6] FIX MED: write_deploy_state thêm LOCK_EX — tránh concurrent write corrupt
 *   [B7] FIX MED: TOKEN_FILE write atomic qua tmp file + rename — tránh race chmod
 *   [B8] FIX LOW: 404 không leak URI vào response
 */

declare(strict_types=1);
error_reporting(0);

// ── Constants ──────────────────────────────────────────────────
define('CONFIG_ENV',       '/opt/modernvps/config.env');
define('TOKEN_FILE',       '/opt/modernvps/agent-token.json');
define('DRAIN_FLAG',       '/run/mvps-draining');
define('DEPLOY_LOG',       '/var/log/modernvps/deploy.log');
define('DEPLOY_STATE',     '/run/mvps-deploy-state');
// [B2] Marker file riêng — tránh grep DONE trong log tích lũy từ các deploy cũ
define('DEPLOY_DONE_MARK', '/run/mvps-deploy-done-mark');
define('DEPLOY_DIR',       '/var/www');
define('VERSION',          '1.1');

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
    case $uri === '/mvps/health'        && $method === 'GET':
        handle_health($config);
        break;
    case $uri === '/mvps/metrics'       && $method === 'GET':
        handle_metrics($config);
        break;
    case $uri === '/mvps/drain'         && $method === 'POST':
        handle_drain();
        break;
    case $uri === '/mvps/drain/cancel'  && $method === 'POST':
        handle_drain_cancel();
        break;
    case $uri === '/mvps/deploy'        && $method === 'POST':
        handle_deploy($config);
        break;
    case $uri === '/mvps/deploy/status' && $method === 'GET':
        handle_deploy_status();
        break;
    case $uri === '/mvps/token/rotate'  && $method === 'POST':
        handle_token_rotate($provided_token);
        break;
    default:
        http_response_code(404);
        // [B8] FIX: Không leak $uri vào response — information disclosure không cần thiết
        json_out(['error' => 'Unknown endpoint']);
}


// ══════════════════════════════════════════════════════════════
// HANDLERS
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
    // Đọc CPU load
    $loadavg_raw = @file_get_contents('/proc/loadavg');
    [$load1, $load5, $load15] = $loadavg_raw !== false
        ? array_slice(explode(' ', $loadavg_raw), 0, 3)
        : ['0', '0', '0'];

    // RAM
    $meminfo      = [];
    $meminfo_raw  = @file('/proc/meminfo');
    if ($meminfo_raw !== false) {
        foreach ($meminfo_raw as $line) {
            if (preg_match('/^(\w+):\s+(\d+)/', $line, $m)) {
                $meminfo[$m[1]] = (int)$m[2];
            }
        }
    }
    $ram_total_mb = isset($meminfo['MemTotal'])     ? (int)($meminfo['MemTotal']     / 1024) : 0;
    $ram_avail_mb = isset($meminfo['MemAvailable']) ? (int)($meminfo['MemAvailable'] / 1024) : 0;
    $ram_used_mb  = $ram_total_mb - $ram_avail_mb;

    // Disk
    $df = disk_free_space('/') ?: 0;
    $dt = disk_total_space('/') ?: 0;
    $disk_used_pct = $dt > 0 ? round((($dt - $df) / $dt) * 100, 1) : 0;

    // CPU cores
    $cpu_cores   = 0;
    $cpuinfo_raw = @file('/proc/cpuinfo');
    if ($cpuinfo_raw !== false) {
        foreach ($cpuinfo_raw as $line) {
            if (str_starts_with($line, 'processor')) $cpu_cores++;
        }
    }

    // Uptime
    $uptime_raw = @file_get_contents('/proc/uptime');
    $uptime_sec = $uptime_raw !== false
        ? (int)explode(' ', $uptime_raw)[0]
        : 0;

    // Sites count
    $sites = count(glob('/etc/nginx/sites-enabled/*') ?: []);

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

    // [B1] FIX CRITICAL: Checksum bắt buộc — bỏ !empty() guard
    // Không có checksum → deploy bị từ chối hoàn toàn
    // Trước: if (!empty($checksum) && !hash_equals(...)) → checksum optional → upload webshell không cần SHA256
    $checksum = $_POST['checksum'] ?? '';
    if (empty($checksum)) {
        http_response_code(400);
        json_out(['error' => 'checksum (SHA256) is required for deploy']);
        return;
    }

    $target = $_POST['target'] ?? 'html';

    // Sanitize target path — chặn path traversal
    $target = preg_replace('/[^a-zA-Z0-9_\-\/]/', '', $target);
    $target = ltrim($target, '/');
    if (str_contains($target, '..') || empty($target)) {
        http_response_code(400);
        json_out(['error' => 'Invalid target path']);
        return;
    }

    $target_abs = DEPLOY_DIR . '/' . $target;

    if (empty($_FILES['tarball']['tmp_name']) || !is_uploaded_file($_FILES['tarball']['tmp_name'])) {
        http_response_code(400);
        json_out(['error' => 'Missing tarball file']);
        return;
    }

    $tmp = $_FILES['tarball']['tmp_name'];

    // Verify SHA256 checksum — bắt buộc, không còn optional
    $actual_sha = hash_file('sha256', $tmp);
    if (!hash_equals($checksum, $actual_sha)) {
        http_response_code(400);
        json_out(['error' => 'Checksum mismatch', 'expected' => $checksum, 'actual' => $actual_sha]);
        @unlink($tmp);
        return;
    }

    // [B3] FIX HIGH: random_bytes() thay vì time() — tránh collision 2 request/giây
    // Trước: '/tmp/mvps-deploy-' . time() . '.tar.gz' → cùng tên nếu 2 request trong 1 giây
    $staging = '/tmp/mvps-deploy-' . bin2hex(random_bytes(8)) . '.tar.gz';
    move_uploaded_file($tmp, $staging);

    // [B4] FIX HIGH: realpath() verify sau mkdir — chặn symlink escape khỏi DEPLOY_DIR
    // Trước: chỉ dùng string concat, symlink trỏ ra ngoài /var/www bypass được
    @mkdir($target_abs, 0755, true);
    $real_target = realpath($target_abs);
    $real_base   = realpath(DEPLOY_DIR);
    if ($real_target === false || $real_base === false
        || !str_starts_with($real_target . '/', $real_base . '/')) {
        http_response_code(400);
        @unlink($staging);
        json_out(['error' => 'Invalid target: resolves outside deploy directory']);
        return;
    }

    // [B2] FIX CRITICAL: Xóa marker file cũ trước deploy mới
    // Trước: grep -q DONE <DEPLOY_LOG> — log tích lũy nhiều deploys → "DONE" cũ → false positive
    // Fix: dùng DEPLOY_DONE_MARK riêng, xóa trước mỗi deploy
    @unlink(DEPLOY_DONE_MARK);

    $nginx_user = $config['NGINX_USER'] ?? 'www-data';
    $cmd = sprintf(
        'nohup bash -c %s >%s 2>&1 &',
        escapeshellarg(
            "set -e; " .
            "backup_dir=/tmp/mvps-deploy-bak-$(date +%s); " .
            "mkdir -p \$backup_dir; " .
            "cp -a " . escapeshellarg($real_target) . "/. \$backup_dir/ 2>/dev/null || true; " .
            "tar -xzf " . escapeshellarg($staging) . " -C " . escapeshellarg($real_target) . " --strip-components=1; " .
            "chown -R " . escapeshellarg($nginx_user . ':' . $nginx_user) . " " . escapeshellarg($real_target) . "; " .
            "find " . escapeshellarg($real_target) . " -type d -exec chmod 755 {} \\;; " .
            "find " . escapeshellarg($real_target) . " -type f -exec chmod 644 {} \\;; " .
            "systemctl reload " . escapeshellarg(get_php_fpm_svc($config)) . " 2>/dev/null || true; " .
            "rm -f " . escapeshellarg($staging) . "; " .
            // [B2] Ghi marker file riêng thay vì echo DONE vào log tích lũy
            "touch " . escapeshellarg(DEPLOY_DONE_MARK)
        ),
        escapeshellarg(DEPLOY_LOG)
    );

    $pid = shell_exec("($cmd) & echo \$!");
    write_deploy_state('running', 'Deploy in progress', trim($pid ?: ''));
    log_event("DEPLOY started: target=$target, checksum=$actual_sha");

    // [B2] Background watcher — check DEPLOY_DONE_MARK thay vì grep DONE trong log
    shell_exec(sprintf(
        'nohup bash -c %s >/dev/null 2>&1 &',
        escapeshellarg(
            "sleep 2; " .
            "while kill -0 " . escapeshellarg(trim($pid ?: '0')) . " 2>/dev/null; do sleep 2; done; " .
            // Dùng marker file riêng — không bị nhiễu bởi log từ deploy cũ
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
    // Trước: file_put_contents() → chmod() — khoảng trống giữa 2 lệnh file có perm 644
    // Fix: write vào tmp với umask 0177 (→ 0600) rồi rename() atomic
    $tmp_token = TOKEN_FILE . '.tmp.' . bin2hex(random_bytes(4));
    $prev_umask = umask(0177); // tmp file tạo ra với 0600
    $written = file_put_contents($tmp_token, json_encode($token_data, JSON_PRETTY_PRINT));
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
// HELPERS
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
    $version = $config['PHP_VERSION'] ?? '8.3';
    $family  = $config['OS_FAMILY']   ?? 'debian';

    // Đọc max_children từ pool config
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

    // Đọc active/idle workers từ /proc — 0 forks, 0 dependencies
    $active   = 0;
    $idle     = 0;
    $fpm_name = $family === 'rhel' ? 'php-fpm' : "php-fpm{$version}";

    if (is_dir('/proc')) {
        foreach (glob('/proc/[0-9]*/status') ?: [] as $status_file) {
            $content = @file_get_contents($status_file);
            if (!$content) continue;

            // Tên process
            if (!preg_match('/^Name:\s*(.+)/m', $content, $nm)) continue;
            if (trim($nm[1]) !== $fpm_name) continue;

            // Bỏ qua master process (PPid ≤ 1)
            preg_match('/^PPid:\s*(\d+)/m', $content, $pm);
            if ((int)($pm[1] ?? 0) <= 1) continue;

            // R = running (active), S/D/... = idle
            preg_match('/^State:\s*(\S)/m', $content, $sm);
            ($sm[1] ?? 'S') === 'R' ? $active++ : $idle++;
        }
    }

    return [
        'active' => $active,
        'idle'   => $idle,
        'max'    => $total,
        'source' => 'proc',
    ];
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

function write_deploy_state(string $status, string $message = '', string $pid = ''): void
{
    // [B6] FIX MED: Thêm LOCK_EX — tránh concurrent write từ watcher + PHP request
    // Trước: file_put_contents không có lock → watcher và request cùng ghi → state corrupt
    file_put_contents(DEPLOY_STATE, json_encode([
        'status'     => $status,
        'message'    => $message,
        'pid'        => $pid,
        'updated_at' => date('c'),
    ]), LOCK_EX);
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
