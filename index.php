<?php
/**
 * client-diagnostics.php
 * 
 * A self-contained PHP diagnostic page you can send to users.
 * It shows and logs: client IP (with proxy awareness), reverse DNS, user agent,
 * parsed browser + version, OS, languages, referrer, TLS info, cookies enabled,
 * and various request/server details.
 * 
 * Usage:
 *  - Upload this file to a URL you can share (e.g., https://example.com/diag.php)
 *  - Optional: add ?json=1 for raw JSON output (no HTML)
 *  - Optional: set $logFile to a writable path (default: same directory)
 */
 
// Strong no-cache for Cloudflare + browsers
header('Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache'); // legacy HTTP/1.0 clients
header('Expires: Thu, 01 Jan 1970 00:00:00 GMT');
header('Surrogate-Control: no-store');   // extra hint for CDNs
header('CDN-Cache-Control: no-store');   // some CDNs honor this (harmless if ignored)

// Optional: set a cookie to trip any "Bypass cache on cookie" rule you create in Cloudflare
setcookie('nocache', '1', 0, '/', '', true, true); 

// ====== CONFIG ======
$logFile = __DIR__ . '/client-diagnostics.log'; // Make sure the web server can write here
$logJson  = true;         // Write a JSON line to the log
$logHuman = true;         // Also write a human-readable block to the log
$resolveReverseDNS = true; // set true if you want reverse DNS (can be slow)
$setTestCookie = true;    // tries to detect cookies enabled on refresh
$showAllHeaders = true;   // show HTTP request headers in output
$trustedProxyHeaders = [
    'HTTP_CF_CONNECTING_IP',
    'HTTP_X_FORWARDED_FOR',
    'HTTP_X_REAL_IP',
];

// ====== Helpers ======
function is_valid_ip($ip) {
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) ||
           filter_var($ip, FILTER_VALIDATE_IP);
}

function pick_forwarded_ip($xff) {
    // Choose the first *public-looking* IP from X-Forwarded-For list
    $parts = array_map('trim', explode(',', $xff));
    foreach ($parts as $p) {
        if (filter_var($p, FILTER_VALIDATE_IP)) {
            return $p;
        }
    }
    // fallback to the first if none validated (still better than nothing)
    return trim($parts[0] ?? '');
}

function get_client_ip($trustedProxyHeaders) {
    foreach ($trustedProxyHeaders as $h) {
        if (!empty($_SERVER[$h])) {
            if ($h === 'HTTP_X_FORWARDED_FOR') {
                $candidate = pick_forwarded_ip($_SERVER[$h]);
            } else {
                $candidate = trim($_SERVER[$h]);
            }
            if (is_valid_ip($candidate)) {
                return $candidate;
            }
        }
    }
    // Fallback
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    return is_valid_ip($remote) ? $remote : $remote;
}

function parse_os_from_ua($ua) {
    $os_list = [
        'Windows 11' => '/Windows NT 10\.0; Win64; x64/',
        'Windows 10' => '/Windows NT 10\.0/',
        'Windows 8.1' => '/Windows NT 6\.3/',
        'Windows 8' => '/Windows NT 6\.2/',
        'Windows 7' => '/Windows NT 6\.1/',
        'Windows Vista' => '/Windows NT 6\.0/',
        'Windows XP' => '/Windows NT 5\.1|Windows XP/',
        'macOS' => '/Mac OS X/',
        'iOS' => '/iPhone|iPad|iPod/',
        'Android' => '/Android/',
        'Linux' => '/Linux/',
        'ChromeOS' => '/CrOS/',
    ];
    foreach ($os_list as $name => $pattern) {
        if (preg_match($pattern, $ua)) {
            return $name;
        }
    }
    return 'Unknown';
}

function parse_browser_from_ua($ua) {
    // Simple (not exhaustive) parser
    $browsers = [
        'Edge' => '/EdgA?\/([\d\.]+)/',             // Edge (Chromium + Android)
        'Chrome' => '/Chrome\/([\d\.]+)/',
        'Firefox' => '/Firefox\/([\d\.]+)/',
        'Safari' => '/Version\/([\d\.]+)\s+Safari/',
        'Opera' => '/OPR\/([\d\.]+)/',
        'IE' => '/MSIE\s([\d\.]+)|Trident\/.*rv:([\d\.]+)/',
    ];
    foreach ($browsers as $name => $pattern) {
        if (preg_match($pattern, $ua, $m)) {
            $ver = $m[1] ?? ($m[2] ?? '');
            return [$name, $ver];
        }
    }
    return ['Unknown', ''];
}

function get_tls_info() {
    // Works on Apache with mod_ssl variables; Nginx via fastcgi_param may differ.
    $tls = [];
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        $tls['https'] = true;
        if (!empty($_SERVER['SSL_PROTOCOL'])) $tls['protocol'] = $_SERVER['SSL_PROTOCOL'];
        if (!empty($_SERVER['SSL_CIPHER'])) $tls['cipher'] = $_SERVER['SSL_CIPHER'];
        if (!empty($_SERVER['SSL_CIPHER_USEKEYSIZE'])) $tls['key_size'] = $_SERVER['SSL_CIPHER_USEKEYSIZE'];
    } else {
        $tls['https'] = false;
    }
    return $tls;
}

function bool_to_str($b) { return $b ? 'yes' : 'no'; }

function write_log_lines($logFile, $lines) {
    $fh = @fopen($logFile, 'ab');
    if (!$fh) return false;
    if (flock($fh, LOCK_EX)) {
        foreach ($lines as $line) {
            fwrite($fh, $line . PHP_EOL);
        }
        fflush($fh);
        flock($fh, LOCK_UN);
    }
    fclose($fh);
    return true;
}

function redacted($str) {
    // Feel free to implement masking here if you plan to share logs broadly
    return $str;
}

// ====== Gather data ======
$now = gmdate('c');
$ua  = $_SERVER['HTTP_USER_AGENT'] ?? '';
$ip  = get_client_ip($trustedProxyHeaders);

$reverse = null;
if ($resolveReverseDNS && filter_var($ip, FILTER_VALIDATE_IP)) {
    // This can be slow; disabled by default.
    $reverse = @gethostbyaddr($ip);
    if ($reverse === $ip) $reverse = null;
}

// basic UA parsing
list($browserName, $browserVersion) = parse_browser_from_ua($ua);
$osName = parse_os_from_ua($ua);

$acceptLang = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
$referer    = $_SERVER['HTTP_REFERER'] ?? '';
$accept     = $_SERVER['HTTP_ACCEPT'] ?? '';
$encoding   = $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '';
$connection = $_SERVER['HTTP_CONNECTION'] ?? '';

$serverSoftware = $_SERVER['SERVER_SOFTWARE'] ?? '';
$serverName     = $_SERVER['SERVER_NAME'] ?? '';
$serverAddr     = $_SERVER['SERVER_ADDR'] ?? '';
$serverPort     = $_SERVER['SERVER_PORT'] ?? '';
$requestUri     = $_SERVER['REQUEST_URI'] ?? '';
$requestMethod  = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$remotePort     = $_SERVER['REMOTE_PORT'] ?? '';

$cfRay       = $_SERVER['HTTP_CF_RAY'] ?? '';
$cfIPCountry = $_SERVER['HTTP_CF_IPCOUNTRY'] ?? '';

$tls = get_tls_info();

// Cookie test
$cookieStatus = 'unknown';
if ($setTestCookie) {
    if (!isset($_COOKIE['diag_cookie'])) {
        setcookie('diag_cookie', '1', time() + 3600, '/');
        $cookieStatus = 'testing (reload to confirm)';
    } else {
        $cookieStatus = 'enabled (cookie received)';
    }
}

// Build structured data
$data = [
    'timestamp_utc' => $now,
    'client_ip' => $ip,
    'reverse_dns' => $reverse,
    'user_agent' => $ua,
    'browser' => [
        'name' => $browserName,
        'version' => $browserVersion,
    ],
    'os' => $osName,
    'languages' => $acceptLang,
    'referer' => $referer,
    'headers' => [
        'accept' => $accept,
        'accept_encoding' => $encoding,
        'connection' => $connection,
    ],
    'cloudflare' => [
        'cf_ray' => $cfRay,
        'cf_ipcountry' => $cfIPCountry,
    ],
    'tls' => $tls,
    'request' => [
        'method' => $requestMethod,
        'uri'    => $requestUri,
        'remote_port' => $remotePort,
    ],
    'server' => [
        'software' => $serverSoftware,
        'name' => $serverName,
        'addr' => $serverAddr,
        'port' => $serverPort,
        'php_version' => PHP_VERSION,
    ],
    'cookies' => [
        'diag_cookie' => isset($_COOKIE['diag_cookie']),
        'status' => $cookieStatus,
    ],
];

if ($showAllHeaders) {
    $allHeaders = [];
    foreach ($_SERVER as $k => $v) {
        if (strpos($k, 'HTTP_') === 0 || in_array($k, ['CONTENT_TYPE', 'CONTENT_LENGTH'])) {
            $allHeaders[$k] = $v;
        }
    }
    $data['all_request_headers'] = $allHeaders;
}

// ====== Logging ======
$logLines = [];
if ($logJson) {
    $logLines[] = json_encode($data, JSON_UNESCAPED_SLASHES);
}
if ($logHuman) {
    $human = "=== Client Diagnostics @ {$now} ===\n"
        . "IP: " . redacted($ip) . "\n"
        . ($reverse ? "Reverse DNS: {$reverse}\n" : '')
        . "UA: {$ua}\n"
        . "Browser: {$browserName} {$browserVersion}\n"
        . "OS: {$osName}\n"
        . "Languages: {$acceptLang}\n"
        . ($referer ? "Referrer: {$referer}\n" : '')
        . "TLS: " . ($tls['https'] ? 'HTTPS' : 'HTTP') 
            . (isset($tls['protocol']) ? " {$tls['protocol']}" : '')
            . (isset($tls['cipher']) ? " {$tls['cipher']}" : '')
            . "\n"
        . "Cookie test: {$cookieStatus}\n"
        . "Cloudflare: " . ($cfRay ? "cf-ray={$cfRay} " : "") . ($cfIPCountry ? "cf-ipcountry={$cfIPCountry}" : "") . "\n"
        . "Request: {$requestMethod} {$requestUri} (remote port {$remotePort})\n"
        . "Server: {$serverSoftware} on {$serverName} ({$serverAddr}:{$serverPort}) PHP " . PHP_VERSION . "\n";
    $logLines[] = $human;
}
if ($logJson || $logHuman) {
    @write_log_lines($logFile, $logLines);
}

// ====== Output ======
if (isset($_GET['json'])) {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// Simple HTML UI
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Client Diagnostics</title>
<style>
  body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; padding: 16px; line-height: 1.5; }
  .wrap { max-width: 1000px; margin: 0 auto; }
  pre { background: #0b1020; color: #e8ecf1; padding: 16px; border-radius: 8px; overflow-x: auto; }
  .btns { margin: 12px 0; display: flex; gap: 8px; flex-wrap: wrap; }
  button { padding: 8px 12px; border: 1px solid #ccc; border-radius: 8px; background: #f7f7f7; cursor: pointer; }
  code { background: #f1f5f9; padding: 0 4px; border-radius: 4px; }
  .note { color: #555; font-size: 0.95em; }
</style>
</head>
<body>
<div class="wrap">
  <h1>Client Diagnostics</h1>
  <p>Copy the details below and send them to support, or click the copy button.</p>
  <div class="btns">
    <button id="copyBtn">Copy details</button>
    <a href="?json=1"><button type="button">View JSON</button></a>
  </div>
  <pre id="out"><?php echo htmlspecialchars(
"Timestamp (UTC): {$data['timestamp_utc']}
IP: {$data['client_ip']}" . ($data['reverse_dns'] ? "\nReverse DNS: {$data['reverse_dns']}" : "") . "
UA: {$data['user_agent']}
Browser: {$data['browser']['name']} {$data['browser']['version']}
OS: {$data['os']}
Languages: {$data['languages']}" .
($data['referer'] ? "\nReferrer: {$data['referer']}" : "") . "
TLS: " . ($data['tls']['https'] ? 'HTTPS' : 'HTTP') .
(isset($data['tls']['protocol']) ? " {$data['tls']['protocol']}" : "") .
(isset($data['tls']['cipher']) ? " {$data['tls']['cipher']}" : "") .
"\nCookie test: {$data['cookies']['status']}
Cloudflare: " .
($data['cloudflare']['cf_ray'] ? "cf-ray={$data['cloudflare']['cf_ray']} " : "") .
($data['cloudflare']['cf_ipcountry'] ? "cf-ipcountry={$data['cloudflare']['cf_ipcountry']}" : "") .
"\nRequest: {$data['request']['method']} {$data['request']['uri']} (remote port {$data['request']['remote_port']})
Server: {$data['server']['software']} on {$data['server']['name']} ({$data['server']['addr']}:{$data['server']['port']}) PHP {$data['server']['php_version']}
"
, ENT_QUOTES, 'UTF-8'); ?></pre>

<?php if (!empty($data['all_request_headers'])): ?>
  <h3>All Request Headers</h3>
  <pre><?php echo htmlspecialchars(print_r($data['all_request_headers'], true), ENT_QUOTES, 'UTF-8'); ?></pre>
<?php endif; ?>

  <p class="note">
    A log entry was written to <code><?php echo htmlspecialchars($logFile, ENT_QUOTES, 'UTF-8'); ?></code>
    (if writable). You can tail this file on the server for incoming diagnostics.
  </p>
</div>

<script>
document.getElementById('copyBtn').addEventListener('click', function() {
  const text = document.getElementById('out').innerText;
  navigator.clipboard.writeText(text).then(() => {
    alert('Copied!');
  }, () => {
    alert('Copy failed — please select and copy manually.');
  });
});
</script>
</body>
</html>
