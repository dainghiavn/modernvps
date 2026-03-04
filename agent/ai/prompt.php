<?php
/**
 * ModernVPS AI Layer — Prompt Templates v2.0
 * Path: agent/ai/prompt.php
 *
 * CHANGELOG v2.0 (GĐ7):
 *   [P1] System prompt riêng cho từng loại — không dùng chung 1 const
 *   [P2] Output format RIGID: 4 section cố định, ai_extract_severity() không bao giờ fail
 *   [P3] Severity calibration với ngưỡng số cụ thể từng domain
 *   [P4] Token-efficient: format data gọn, không dump JSON thô
 *   [P5] Context injection: derived metrics → AI calibrate đúng workload
 *   [P6] Negative space: AI được hướng dẫn rõ khi KHÔNG có vấn đề
 *   [P7] Xóa $_SERVER['REQUEST_TIME'] leak — dùng date() trong PHP thay thế
 *   [P8] Helper _filter_log() + _filter_fail2ban_log() lọc noise trước khi gửi
 *   [P9] _count_subnets() phát hiện distributed attack pattern trước khi gửi AI
 *
 * Output format bắt buộc (mọi prompt đều enforce):
 *   CHẨN ĐOÁN: ...
 *   NGUYÊN NHÂN: ...
 *   ĐỀ XUẤT: ...
 *   MỨC ĐỘ: LOW|MEDIUM|HIGH|CRITICAL
 *
 * ai_extract_severity() trong index.php parse "MỨC ĐỘ:" ở dòng cuối — luôn có.
 */

declare(strict_types=1);

// ══════════════════════════════════════════════════════════════
// SHARED OUTPUT CONTRACT — nhúng vào MỌI system prompt
// ══════════════════════════════════════════════════════════════

/**
 * [P2] Output contract cứng
 * Đảm bảo AI luôn trả đúng 4 section, "MỨC ĐỘ:" luôn là dòng cuối.
 * ai_extract_severity() dùng regex: /MỨC\s+ĐỘ\s*:\s*(LOW|MEDIUM|HIGH|CRITICAL)/ui
 */
const AI_OUTPUT_CONTRACT = <<<'CONTRACT'

━━━ ĐỊNH DẠNG PHẢN HỒI BẮT BUỘC ━━━
Tuân thủ chính xác 4 section dưới đây, không thêm section khác, không dùng markdown:

CHẨN ĐOÁN: (1-2 câu. Nếu bình thường: "Hệ thống hoạt động bình thường.")
NGUYÊN NHÂN:
- điểm 1 (nếu không có vấn đề: "- Không phát hiện nguyên nhân bất thường.")
- điểm 2 (tối đa 3 điểm)
ĐỀ XUẤT:
- điểm 1 kèm lệnh cụ thể nếu có (nếu không cần: "- Không cần hành động.")
- điểm 2 (tối đa 3 điểm)
MỨC ĐỘ: LOW

Thay "LOW" bằng mức phù hợp: LOW | MEDIUM | HIGH | CRITICAL
Dòng "MỨC ĐỘ:" PHẢI là dòng cuối cùng tuyệt đối.
Phản hồi bằng tiếng Việt. Không dùng **, ##, hay lời mở đầu/kết thúc.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONTRACT;


// ══════════════════════════════════════════════════════════════
// PRIVATE HELPERS
// ══════════════════════════════════════════════════════════════

/**
 * [P4] Format metrics → text ngắn (~40% ít token hơn JSON thô)
 */
function _fmt_metrics(array $m): string
{
    $cores      = max(1, (int)($m['cpu_cores'] ?? 1));
    $load1      = (float)($m['load1'] ?? 0);
    $load_ratio = round($load1 / $cores, 2);

    $ram_total = max(1, (int)($m['mem_total_mb'] ?? 1));
    $ram_used  = (int)($m['mem_used_mb'] ?? 0);
    $ram_pct   = (int)round($ram_used / $ram_total * 100);

    $php_active = (int)($m['php_fpm_active'] ?? 0);
    $php_idle   = (int)($m['php_fpm_idle']   ?? 0);
    $php_max    = (int)($m['php_fpm_max']     ?? ($php_active + $php_idle));

    $nginx_conn = (int)($m['nginx_active_conn'] ?? -1);

    return implode("\n", [
        sprintf('CPU: %d cores | load1=%.2f | load5=%.2f | load15=%.2f | load/core=%.2f',
            $cores, $load1,
            (float)($m['load5']  ?? 0),
            (float)($m['load15'] ?? 0),
            $load_ratio),
        sprintf('RAM: %dMB total | %dMB used (%d%%) | %dMB free',
            $ram_total, $ram_used, $ram_pct,
            (int)($m['mem_free_mb'] ?? ($ram_total - $ram_used))),
        sprintf('Disk /var/www: %.1fGB free | %.1f%% used',
            (float)($m['disk_free_gb']  ?? 0),
            (float)($m['disk_used_pct'] ?? 0)),
        sprintf('Nginx active conn: %s',
            $nginx_conn >= 0 ? (string)$nginx_conn : 'n/a'),
        sprintf('PHP-FPM: %d active | %d idle | %d max',
            $php_active, $php_idle, $php_max),
        sprintf('Sites: %d | PHP %s | Server type: %s',
            (int)($m['sites_count'] ?? 0),
            (string)($m['php_version'] ?? '?'),
            (string)($m['server_type'] ?? 'web')),
    ]);
}

/**
 * Format PHP-FPM pool config → text
 */
function _fmt_pool(array $p): string
{
    if (empty($p)) return '(Không đọc được pool config)';
    return implode("\n", array_map(
        fn($k, $v) => "  {$k} = {$v}",
        array_keys($p),
        $p
    ));
}

/**
 * [P8] Lọc log — giữ lại dòng có từ khoá lỗi
 * Tránh gửi hàng trăm dòng info lên API tốn token vô ích
 *
 * @param string $raw  Nội dung log thô
 * @param int    $max  Số dòng tối đa sau lọc
 */
function _filter_log(string $raw, int $max = 60): string
{
    if (empty(trim($raw))) return '';

    $keywords = [
        'error', 'crit', 'alert', 'emerg', 'warn',
        'failed', 'failure', 'refused', 'timeout',
        'cannot', 'unable', 'denied', 'killed',
        'exception', 'fatal', 'panic', 'oom',
        '502', '503', '504',
    ];

    $lines    = explode("\n", $raw);
    $filtered = [];

    foreach ($lines as $line) {
        $ll = strtolower($line);
        foreach ($keywords as $kw) {
            if (str_contains($ll, $kw)) {
                $filtered[] = rtrim($line);
                break;
            }
        }
    }

    // Nếu lọc quá strict → giữ nguyên
    if (empty($filtered)) {
        $filtered = array_values(array_filter(array_map('rtrim', $lines)));
    }

    // Giữ $max dòng cuối
    if (count($filtered) > $max) {
        $filtered = array_slice($filtered, -$max);
    }

    return implode("\n", $filtered);
}

/**
 * [P8] Lọc fail2ban log — chỉ giữ dòng Ban/Unban/Found/WARNING/ERROR
 */
function _filter_fail2ban_log(string $raw, int $max = 50): string
{
    if (empty(trim($raw))) return '(Không có log)';

    $keywords = ['Ban ', 'Unban ', 'Found ', 'WARNING', 'ERROR',
                 'already banned', 'Restore Ban'];
    $lines    = explode("\n", $raw);
    $filtered = [];

    foreach ($lines as $line) {
        $line = rtrim($line);
        if (empty($line)) continue;
        foreach ($keywords as $kw) {
            if (str_contains($line, $kw)) {
                $filtered[] = $line;
                break;
            }
        }
    }

    if (empty($filtered)) {
        $filtered = array_values(array_filter(array_map('rtrim', $lines)));
    }

    if (count($filtered) > $max) {
        $filtered = array_slice($filtered, -$max);
    }

    return implode("\n", $filtered);
}

/**
 * [P9] Đếm IPs theo /24 subnet — phát hiện distributed attack
 *
 * @param  array $ips  ['1.2.3.4', ...]
 * @return array       ['1.2.3' => 5, ...] sorted desc
 */
function _count_subnets(array $ips): array
{
    $subnets = [];
    foreach ($ips as $ip) {
        $parts = explode('.', (string)$ip);
        if (count($parts) >= 3) {
            $s = "{$parts[0]}.{$parts[1]}.{$parts[2]}";
            $subnets[$s] = ($subnets[$s] ?? 0) + 1;
        }
    }
    arsort($subnets);
    return $subnets;
}

/**
 * Format services status → text
 */
function _fmt_services(array $health): string
{
    $map = [
        'nginx'   => 'Nginx',
        'php_fpm' => 'PHP-FPM',
        'mariadb' => 'MariaDB',
    ];
    $lines = [];
    foreach ($map as $key => $label) {
        if (!array_key_exists($key, $health)) continue;
        $up      = (bool)$health[$key];
        $lines[] = "  {$label}: " . ($up ? 'UP' : 'DOWN ⚠');
    }
    $draining = (bool)($health['draining'] ?? false);
    $lines[]  = '  Drain mode: ' . ($draining ? 'YES (đang drain)' : 'NO');
    $lines[]  = '  Overall: ' . ($health['overall'] ?? 'UNKNOWN');
    return implode("\n", $lines);
}


// ══════════════════════════════════════════════════════════════
// PROMPT 1: LOG ANALYSIS
// ══════════════════════════════════════════════════════════════

/**
 * Phân tích nginx error log + php-fpm log
 *
 * [P3] Severity calibration log:
 *   LOW      = Vài warning lẻ tẻ, không lặp lại, không ảnh hưởng user
 *   MEDIUM   = Lỗi >10 lần/giờ, 502/504 xuất hiện, PHP notice lặp lại
 *   HIGH     = Lỗi liên tục, upstream timeout thường xuyên, worker killed/OOM
 *   CRITICAL = nginx crash/không start, PHP-FPM pool cạn kiệt, disk full
 *
 * @param string $nginx_log    50 dòng cuối nginx error.log
 * @param string $phpfpm_log   50 dòng cuối php-fpm error log
 * @param string $server_type  web | loadbalancer
 */
function prompt_logs(string $nginx_log, string $phpfpm_log, string $server_type): array
{
    // [P8] Lọc noise trước khi gửi
    $nginx_clean  = _filter_log($nginx_log,  50);
    $phpfpm_clean = _filter_log($phpfpm_log, 30);

    $nginx_section = !empty(trim($nginx_clean))
        ? "=== NGINX ERROR LOG (đã lọc, ≤50 dòng) ===\n{$nginx_clean}"
        : "=== NGINX ERROR LOG ===\n(Không có lỗi nào được phát hiện)";

    if ($server_type === 'web') {
        $phpfpm_section = !empty(trim($phpfpm_clean))
            ? "=== PHP-FPM ERROR LOG (đã lọc, ≤30 dòng) ===\n{$phpfpm_clean}"
            : "=== PHP-FPM ERROR LOG ===\n(Không có lỗi nào được phát hiện)";
    } else {
        $phpfpm_section = "=== PHP-FPM ===\n(Load Balancer — không có PHP-FPM)";
    }

    // ── System prompt ─────────────────────────────────────
    $system = <<<SYS
Bạn là kỹ sư Linux/DevOps senior chuyên Nginx và PHP-FPM production.
Đang phân tích error log từ VPS chạy ModernVPS stack (server type: {$server_type}).

NHIỆM VỤ: Đọc log, bỏ qua noise bình thường, xác định vấn đề thực sự, chẩn đoán nguyên nhân gốc.

THANG MỨC ĐỘ (LOG):
LOW      = Vài warning lẻ, không lặp lại, không ảnh hưởng user
MEDIUM   = Lỗi lặp >10 lần/giờ, có 502/504, PHP notice liên tục
HIGH     = Lỗi liên tục, upstream timeout, worker killed/OOM
CRITICAL = nginx crash, PHP-FPM pool cạn kiệt, disk full, service không start
SYS;

    $system .= AI_OUTPUT_CONTRACT;

    // ── User prompt ───────────────────────────────────────
    $ts   = date('Y-m-d H:i:s T');
    $user = <<<MSG
Thời điểm phân tích: {$ts}
Server type: {$server_type}

{$nginx_section}

{$phpfpm_section}

Phân tích theo định dạng bắt buộc. Nếu log sạch, nói rõ và giữ MỨC ĐỘ: LOW.
MSG;

    return ['system' => $system, 'user' => $user];
}


// ══════════════════════════════════════════════════════════════
// PROMPT 2: METRICS + TUNING
// ══════════════════════════════════════════════════════════════

/**
 * Phân tích metrics + đề xuất tune config
 *
 * [P3] Severity calibration metrics:
 *   LOW      = Tất cả chỉ số trong ngưỡng, không cần hành động
 *   MEDIUM   = RAM>75% hoặc load/core>1.5 — theo dõi, tune nhẹ
 *   HIGH     = RAM>90% hoặc load/core>2.5 hoặc PHP workers>90% capacity
 *   CRITICAL = RAM>95%, load/core>4, disk>95%, PHP queue>0 — nguy cơ down
 *
 * @param array $metrics     Từ ai_collect_metrics() trong index.php
 * @param array $pool_config PHP-FPM pool config hiện tại
 */
function prompt_metrics(array $metrics, array $pool_config = []): array
{
    // [P4] Format gọn
    $metrics_text = _fmt_metrics($metrics);
    $pool_text    = _fmt_pool($pool_config);

    // [P5] Tính derived metrics, inject vào prompt để AI không tự tính sai
    $cores     = max(1, (int)($metrics['cpu_cores'] ?? 1));
    $load1     = (float)($metrics['load1'] ?? 0);
    $load_ratio = round($load1 / $cores, 2);

    $ram_total = max(1, (int)($metrics['mem_total_mb'] ?? 1));
    $ram_used  = (int)($metrics['mem_used_mb'] ?? 0);
    $ram_pct   = (int)round($ram_used / $ram_total * 100);

    $php_active = (int)($metrics['php_fpm_active'] ?? 0);
    $php_max_cfg = (int)($pool_config['pm.max_children'] ?? 0);
    $php_cap_pct = $php_max_cfg > 0
        ? (int)round($php_active / $php_max_cfg * 100)
        : -1;

    $derived = sprintf(
        "load/core=%.2f | RAM=%d%% used | Disk=%.1f%% used | PHP workers: %d active%s",
        $load_ratio,
        $ram_pct,
        (float)($metrics['disk_used_pct'] ?? 0),
        $php_active,
        $php_cap_pct >= 0 ? " ({$php_cap_pct}% of pm.max_children={$php_max_cfg})" : ''
    );

    // ── System prompt ─────────────────────────────────────
    $system = <<<SYS
Bạn là kỹ sư Linux/DevOps senior chuyên performance tuning cho Nginx, PHP-FPM, MariaDB.
Đang phân tích metrics realtime của VPS production chạy ModernVPS stack.

NHIỆM VỤ: Xác định bottleneck nếu có. Đề xuất điều chỉnh config cụ thể, có thể áp dụng ngay.

THANG MỨC ĐỘ (METRICS):
LOW      = Tất cả chỉ số bình thường — không cần hành động
MEDIUM   = RAM>75% hoặc load/core>1.5 — tune nhẹ, theo dõi thêm
HIGH     = RAM>90% hoặc load/core>2.5 hoặc PHP workers>90% max — tune ngay
CRITICAL = RAM>95%, load/core>4, disk>95%, PHP queue>0 — nguy cơ down ngay

ĐỀ XUẤT TUNING PHẢI CỤ THỂ VÀ ĐẦY ĐỦ:
- Tên directive, giá trị cũ → giá trị mới (vd: pm.max_children = 15 → 25)
- Đường dẫn file cần sửa (vd: /etc/php/8.3/fpm/pool.d/www.conf)
- Lệnh áp dụng (vd: systemctl reload php8.3-fpm)
SYS;

    $system .= AI_OUTPUT_CONTRACT;

    // ── User prompt ───────────────────────────────────────
    $ts   = date('Y-m-d H:i:s T');
    $user = <<<MSG
Thời điểm phân tích: {$ts}

=== METRICS THỰC TẾ ===
{$metrics_text}

=== CHỈ SỐ DẪN XUẤT ===
{$derived}

=== PHP-FPM POOL CONFIG HIỆN TẠI ===
{$pool_text}

Phân tích theo định dạng bắt buộc.
Nếu hệ thống đang tốt, nói rõ và đề xuất 1 preventive action cho tương lai (MỨC ĐỘ: LOW).
MSG;

    return ['system' => $system, 'user' => $user];
}


// ══════════════════════════════════════════════════════════════
// PROMPT 3: SECURITY ANALYSIS
// ══════════════════════════════════════════════════════════════

/**
 * Phân tích fail2ban log + IP ban list
 *
 * [P3] Severity calibration security:
 *   LOW      = <10 ban/24h, SSH scan nhỏ, không có pattern đáng ngờ
 *   MEDIUM   = 10-50 ban/24h, có pattern nhắm mục tiêu
 *   HIGH     = >50 ban/24h, DDoS pattern, nhiều jails bị kích hoạt đồng thời
 *   CRITICAL = >200 ban/24h, bypass attempt, brute force thành công, APT pattern
 *
 * @param string $fail2ban_log   Fail2ban log gần nhất
 * @param array  $banned_ips     Danh sách IP đang bị ban
 * @param int    $ban_count_24h  Số lần ban trong 24h
 */
function prompt_security(string $fail2ban_log, array $banned_ips, int $ban_count_24h): array
{
    // [P8] Lọc log
    $f2b_clean = _filter_fail2ban_log($fail2ban_log, 50);

    // [P4] Giới hạn IP list gửi lên (tối đa 15)
    $ip_count     = count($banned_ips);
    $ip_sample    = array_slice($banned_ips, 0, 15);
    $ip_str       = !empty($ip_sample)
        ? implode(', ', $ip_sample) . ($ip_count > 15 ? " ... (+".($ip_count-15)." more)" : '')
        : 'Không có IP nào đang bị ban';

    // [P9] Phân tích subnet pattern trước khi gửi AI
    $subnets    = _count_subnets($banned_ips);
    $top3       = array_slice($subnets, 0, 3, true);
    $subnet_str = !empty($top3)
        ? implode(', ', array_map(
            fn($s, $c) => "{$s}.x ({$c} IPs)",
            array_keys($top3),
            $top3
          ))
        : 'Không có pattern subnet';

    // Tự động classify dựa trên số ban (giúp AI không bị anchored sai)
    $auto_level = match(true) {
        $ban_count_24h === 0  => 'Không có hoạt động',
        $ban_count_24h < 10   => 'Thấp (<10 ban)',
        $ban_count_24h < 50   => 'Trung bình (10-50 ban)',
        $ban_count_24h < 200  => 'Cao (50-200 ban)',
        default               => 'Rất cao (>200 ban)',
    };

    // ── System prompt ─────────────────────────────────────
    $system = <<<SYS
Bạn là kỹ sư bảo mật Linux senior chuyên threat analysis và server hardening.
Đang phân tích security events từ VPS production chạy ModernVPS + Fail2ban + nftables.

NHIỆM VỤ: Xác định pattern tấn công, đánh giá mức độ threat, đề xuất hardening khả thi ngay.

THANG MỨC ĐỘ (SECURITY):
LOW      = <10 ban/24h, SSH scan thông thường, không có pattern đáng ngờ
MEDIUM   = 10-50 ban/24h, có pattern nhắm mục tiêu cụ thể
HIGH     = >50 ban/24h, DDoS pattern, nhiều jails cùng bị kích hoạt
CRITICAL = >200 ban/24h, bypass fail2ban, credential stuffing, APT indicator

ĐỀ XUẤT PHẢI KHẢ THI NGAY:
- Lệnh nftables cụ thể nếu cần block thêm
- Điều chỉnh fail2ban (bantime, maxretry, findtime) với giá trị cụ thể
- Log nào cần monitor thêm để phát hiện sớm hơn
SYS;

    $system .= AI_OUTPUT_CONTRACT;

    // ── User prompt ───────────────────────────────────────
    $ts   = date('Y-m-d H:i:s T');
    $user = <<<MSG
Thời điểm phân tích: {$ts}

=== THỐNG KÊ BAN ===
Tổng IP đang bị ban: {$ip_count}
Lần ban trong 24h: {$ban_count_24h} (mức: {$auto_level})
Mẫu IP bị ban: {$ip_str}
Top subnets: {$subnet_str}

=== FAIL2BAN LOG (đã lọc, ≤50 dòng) ===
{$f2b_clean}

Phân tích theo định dạng bắt buộc.
Nếu không có bất thường, nói rõ và giữ MỨC ĐỘ: LOW.
MSG;

    return ['system' => $system, 'user' => $user];
}


// ══════════════════════════════════════════════════════════════
// PROMPT 4: DEPLOY VERIFICATION
// ══════════════════════════════════════════════════════════════

/**
 * Verify kết quả deploy
 *
 * [P3] Severity calibration deploy:
 *   LOW      = HTTP 2xx, tất cả services UP, response <1s, log sạch
 *   MEDIUM   = Deploy xong nhưng response >2s hoặc có warning trong log
 *   HIGH     = HTTP 4xx/5xx, service DEGRADED, log có lỗi mới sau deploy
 *   CRITICAL = Site không reach được, service DOWN, deploy log có lỗi nghiêm trọng
 *
 * @param string $site_url    URL cần verify
 * @param array  $health      Health snapshot từ handle_ai_analyze_deploy()
 * @param string $deploy_log  30 dòng cuối deploy.log
 */
function prompt_deploy(string $site_url, array $health, string $deploy_log): array
{
    // [P4] Format services
    $svc_str = _fmt_services($health);

    // HTTP probe
    $probe     = $health['http_probe'] ?? [];
    $http_code = (int)($probe['http_code']  ?? 0);
    $resp_ms   = (int)($probe['response_ms'] ?? 0);
    $reachable = (bool)($probe['reachable']  ?? false);

    $probe_status = match(true) {
        !$reachable           => 'KHÔNG REACH ĐƯỢC ⚠',
        $http_code >= 500     => "HTTP {$http_code} — Server Error ⚠",
        $http_code >= 400     => "HTTP {$http_code} — Client Error",
        $http_code >= 200
          && $http_code < 300 => "HTTP {$http_code} — OK",
        $http_code === 0      => 'Không nhận được response',
        default               => "HTTP {$http_code}",
    };

    $probe_str = sprintf('%s | %dms', $probe_status, $resp_ms);

    // Tự động classify response time
    $perf_hint = match(true) {
        $resp_ms === 0    => '',
        $resp_ms < 500    => ' (nhanh)',
        $resp_ms < 2000   => ' (chấp nhận được)',
        $resp_ms < 5000   => ' (chậm — cần kiểm tra)',
        default           => ' (rất chậm — có vấn đề)',
    };
    if (!empty($perf_hint)) $probe_str .= $perf_hint;

    // [P8] Lọc deploy log
    $deploy_clean = _filter_log($deploy_log, 30);
    $deploy_section = !empty(trim($deploy_clean))
        ? $deploy_clean
        : '(Deploy log sạch — không có lỗi)';

    // ── System prompt ─────────────────────────────────────
    $system = <<<SYS
Bạn là kỹ sư DevOps senior chuyên deploy web application và post-deploy verification.
Đang verify kết quả deploy lên VPS production chạy ModernVPS stack.

NHIỆM VỤ: Đánh giá deploy có thành công không, phát hiện vấn đề tiềm ẩn, đề xuất bước tiếp theo.

THANG MỨC ĐỘ (DEPLOY):
LOW      = HTTP 2xx, services UP, response <1s, log sạch — thành công hoàn toàn
MEDIUM   = Deploy xong nhưng response >2s hoặc warning trong log — cần monitor
HIGH     = HTTP 4xx/5xx, service DEGRADED, lỗi mới trong log — cần xử lý ngay
CRITICAL = Site không reach được, service DOWN, lỗi nghiêm trọng trong log

ĐỀ XUẤT RÕ RÀNG:
- Nếu OK: bước smoke test bổ sung nếu cần
- Nếu lỗi: lệnh diagnose cụ thể (journalctl, nginx -t, tail log...)
- Nếu CRITICAL: lệnh rollback cụ thể
SYS;

    $system .= AI_OUTPUT_CONTRACT;

    // ── User prompt ───────────────────────────────────────
    $ts   = date('Y-m-d H:i:s T');
    $user = <<<MSG
Thời điểm verify: {$ts}
Site URL: {$site_url}

=== SERVICES STATUS ===
{$svc_str}

=== HTTP PROBE ===
{$probe_str}

=== DEPLOY LOG (đã lọc, ≤30 dòng) ===
{$deploy_section}

Đánh giá theo định dạng bắt buộc.
MSG;

    return ['system' => $system, 'user' => $user];
}
