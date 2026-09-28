#!/usr/bin/env php
<?php
/**
 * webcli.php — generic HTTP client for interacting with web applications.
 *
 * Usage (CLI only, no webserver needed):
 *   php webcli.php get  https://example.com/path
 *   php webcli.php post https://example.com/login  -d "user=alice&pass=123" -H "Origin: https://example.com"
 *   php webcli.php upload https://example.com/upload -f ./evidence/payload.txt -F "file"
 *   php webcli.php json https://example.com/api/users  -d '{"role":"admin"}'
 *   php webcli.php follow https://example.com/redirect -c cookies.txt -S
 *
 * What it is: a thin wrapper around PHP's stream / cURL transports for poking
 * web endpoints, inspecting responses, and uploading files — for authorized
 * testing of apps you own or have permission to test.
 *
 * What it is NOT: an exploit delivery system, a webshell, or a tool that
 * operates on systems you have not authorized. Scope and authorization are on
 * the operator. No code execution on the target occurs; this speaks HTTP.
 *
 * Transport: prefers curl if available, falls back to PHP stream context.
 * Output: status, headers, body (optionally saved to file).
 */

declare(strict_types=1);

// ─── usage / help ─────────────────────────────────────────────────────────────
function usage(): void {
    $h = <<<'HELP'
webcli.php — authorized HTTP client for web application interaction

Usage:
  php webcli.php METHOD URL [options]

Methods:
  get      GET       URL
  post     POST      URL
  put      PUT       URL
  patch    PATCH     URL
  delete   DELETE    URL
  head     HEAD      URL
  upload   POST (multipart file upload)  URL
  json     POST/PUT  URL   with JSON body + Accept: application/json
  options  OPTIONS   URL
  follow   GET and follow redirects, saving cookies

Common options:
  -d, --data STRING      request body / form data / JSON string
  -H, --header STRING    custom header  (repeatable)
  -F, --field STRING     multipart field description
                          for upload:  -F "fieldname=@/path/to/file"
                          for json:    ignored
  -f, --file PATH        file to upload (upload method only; alternative to -F)
  -T, --target-field STR field name for -f upload (default: "file")
  -c, --cookie FILE      load cookies from file (Netscape format if possible)
  -J, --cookie-jar FILE  save cookies to file after request
  -o, --output FILE      save response body to file
  -i, --include          include response headers in stdout
  -v, --verbose          show request + response headers
  -L, --follow           follow redirects (default: false for post/put/patch)
  -X, --max-redirs N     max redirects to follow (default: 5)
  -m, --method METHOD    override method for raw requests
  -n, --no-headers       suppress status line
  --timeout SEC          connect + read timeout (default: 30)
  -u, --user-pass STR    "user:password" for HTTP Basic Auth
  -e, --encode-url       URL-encode the data value (for form-urlencoded bodies)
  --dump                 dump full response as PHP var_export (debug)

Examples:
  php webcli.php get https://localhost:8080/panel.php
  php webcli.php post https://localhost:8080/api/login -d "user=admin&pass=x" -H "Content-Type: application/x-www-form-urlencoded"
  php webcli.php upload https://localhost:8080/upload -F "doc=@./sandbox/report.pdf"
  php webcli.php json https://localhost:8080/api/me -d '{"id":1}'
  php webcli.php follow https://localhost:8080/some-redirect -c cookies.txt
  php webcli.php get https://localhost:8080/panel.php -c cookies.txt -v

Authorization reminder:
  Only use this against systems you own or have explicit written permission to
  test. Keep scope documented. This tool makes network requests; it does not
  execute anything on the target.

HELP;
    fwrite(STDOUT, $h);

}

// ─── transport detection ──────────────────────────────────────────────────────
function has_curl(): bool {
    return extension_loaded('curl');
}

function build_curl_options(array $opts): array {
    $ch = [
        CURLOPT_URL            => $opts['url'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER         => $opts['include_headers'],
        CURLOPT_FOLLOWLOCATION => $opts['follow'],
        CURLOPT_MAXREDIRS      => $opts['max_redirs'],
        CURLOPT_TIMEOUT        => $opts['timeout'],
        CURLOPT_CONNECTTIMEOUT => $opts['timeout'],
        CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
        CURLOPT_USERAGENT      => 'webcli/1.0 (authorized testing)',
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
    ];

    if ($opts['method'] !== 'GET') {
        $ch[CURLOPT_CUSTOMREQUEST] = strtoupper($opts['method']);
    }

    if ($opts['body'] !== null) {
        $ch[CURLOPT_POSTFIELDS] = $opts['body'];
        if ($opts['content_type']) {
            $ch[CURLOPT_HTTPHEADER][] = 'Content-Type: ' . $opts['content_type'];
        }
    } elseif ($opts['method'] === 'POST' && empty($opts['multipart'])) {
        // POST with no body is valid but unusual; leave empty.
    }

    // Headers.
    if (!empty($opts['headers'])) {
        foreach ($opts['headers'] as $h) {
            $ch[CURLOPT_HTTPHEADER][] = $h;
        }
    }

    // Basic auth.
    if ($opts['user'] && $opts['pass']) {
        $ch[CURLOPT_USERPWD] = $opts['user'] . ':' . $opts['pass'];
    }

    // Cookies — load.
    if ($opts['cookie_file']) {
        $ch[CURLOPT_COOKIEFILE] = $opts['cookie_file'];
    }
    if ($opts['cookie_jar']) {
        $ch[CURLOPT_COOKIEJAR] = $opts['cookie_jar'];
    }

    // Multipart upload.
    if (!empty($opts['multipart'])) {
        $ch[CURLOPT_POSTFIELDS] = $opts['multipart'];
        // curl handles multipart automatically with array values.
    }

    $ch[CURLOPT_VERBOSE] = $opts['verbose'];
    if ($opts['verbose']) {
        $stderr = fopen('php://stderr', 'w');
        $ch[CURLOPT_STDERR] = $stderr;
    }

    return $ch;
}

function run_curl(array $opts): array {
    $ch = curl_init();
    curl_setopt_array($ch, build_curl_options($opts));
    $start = microtime(true);
    $body  = curl_exec($ch);
    $errno = curl_errno($ch);
    $error = curl_error($ch);
    $info  = curl_getinfo($ch);
    $elapsed = round((microtime(true) - $start) * 1000, 1);
    curl_close($ch);

    $headers = [];
    if (isset($info['header_size']) && $info['header_size'] > 0 && $body !== false) {
        $raw_headers = substr($body, 0, $info['header_size']);
        $body = substr($body, $info['header_size']);
        // Parse headers: split on \r\n\r\n first line.
        $parts = explode("\r\n\r\n", $raw_headers, 2);
        $header_lines = explode("\r\n", $parts[0]);
        foreach ($header_lines as $line) {
            if ($line === '') continue;
            $pos = strpos($line, ':');
            if ($pos === false) {
                // status line: HTTP/1.1 200 OK
                $headers['_status_line'] = $line;
            } else {
                $key = substr($line, 0, $pos);
                $val = ltrim(substr($line, $pos + 1));
                $headers[$key][] = $val;
            }
        }
    }

    $status = (int) ($info['http_code'] ?? 0);

    return [
        'status'    => $status,
        'headers'   => $headers,
        'body'      => $body === false ? '' : $body,
        'error'     => $errno ? $error : null,
        'time_ms'   => $elapsed,
        'redirects' => (int) ($info['redirect_count'] ?? 0),
        'size'      => strlen($body === false ? '' : $body),
        'transport' => 'curl',
    ];
}

function build_stream_context(array $opts): array {
    $context = [
        'http' => [
            'method'           => strtoupper($opts['method']),
            'timeout'          => $opts['timeout'],
            'follow_location'  => $opts['follow'],
            'max_redirects'    => $opts['max_redirs'],
            'ignore_errors'    => true,        // we want to read error responses too
            'user_agent'       => 'webcli/1.0 (authorized testing)',
        ],
    ];

    if ($opts['body'] !== null) {
        $context['http']['content'] = $opts['body'];
    }

    if ($opts['headers']) {
        $context['http']['header'] = implode("\r\n", $opts['headers']) . "\r\n";
    }

    if ($opts['user'] && $opts['pass']) {
        $encoded = base64_encode($opts['user'] . ':' . $opts['pass']);
        $context['http']['header'] .= "Authorization: Basic {$encoded}\r\n";
    }

    if ($opts['cookie_file'] || $opts['cookie_jar']) {
        // stream context supports reading cookies; writing is harder.
        // We support reading only with streams.
        if (function_exists('stream_context_set_option')) {
            if ($opts['cookie_file']) {
                $context['http']['header'] .= "Cookie: " . file_get_contents($opts['cookie_file']) . "\r\n";
            }
        }
    }

    // Multipart via streams is painful; for upload we require curl. Fall back
    // to an explicit multipart builder only if curl unavailable and user insists.
    if (!empty($opts['multipart'])) {
        // Build multipart body manually.
        $boundary = '----WebcliMixed_' . uniqid('', true);
        $body = '';
        foreach ($opts['multipart'] as $name => $spec) {
            $body .= "--{$boundary}\r\n";
            if (is_array($spec) && isset($spec['file'])) {
                $body .= "Content-Disposition: form-data; name=\"{$name}\"; filename=\"" . basename($spec['file']) . "\"\r\n";
                $body .= "Content-Type: application/octet-stream\r\n\r\n";
                $body .= file_get_contents($spec['file']) . "\r\n";
            } else {
                $body .= "Content-Disposition: form-data; name=\"{$name}\"\r\n\r\n";
                $body .= $spec . "\r\n";
            }
        }
        $body .= "--{$boundary}--\r\n";
        $context['http']['content'] = $body;
        $context['http']['header'] .= "Content-Type: multipart/form-data; boundary={$boundary}\r\n";
    }

    return $context;
}

function run_stream(array $opts): array {
    $url = $opts['url'];
    $ctx = stream_context_create(build_stream_context($opts));
    $start = microtime(true);
    $fh = @fopen($url, 'r', false, $ctx);
    $error = $fh === false ? error_get_last() : null;
    if ($fh === false) {
        return [
            'status'  => 0,
            'headers' => [],
            'body'    => '',
            'error'   => $error['message'] ?? 'stream open failed',
            'time_ms' => 0,
            'redirects' => 0,
            'size'    => 0,
            'transport' => 'stream',
        ];
    }
    $body = stream_get_contents($fh);
    fclose($fh);
    $info = stream_get_meta_data($fh); // not useful post-close; approximate.
    $elapsed = round((microtime(true) - $start) * 1000, 1);

    // Parse headers from $http_response_headers (set by stream wrapper).
    $headers = [];
    if (isset($http_response_headers) && is_array($http_response_headers)) {
        foreach ($http_response_headers as $line) {
            $pos = strpos($line, ':');
            if ($pos === false) {
                $headers['_status_line'] = trim($line);
            } else {
                $key = substr($line, 0, $pos);
                $val = ltrim(substr($line, $pos + 1));
                $headers[$key][] = $val;
            }
        }
    }

    // Attempt to extract status from status line or default.
    $status = 0;
    if (isset($headers['_status_line'])) {
        if (preg_match('#\s(\d{3})\s#', $headers['_status_line'], $m)) {
            $status = (int) $m[1];
        }
    }

    return [
        'status'    => $status,
        'headers'   => $headers,
        'body'      => $body === false ? '' : $body,
        'error'     => $error ? ($error['message'] ?? 'stream error') : null,
        'time_ms'   => $elapsed,
        'redirects' => 0,
        'size'      => strlen($body === false ? '' : $body),
        'transport' => 'stream',
    ];
}

function run_request(array $opts): array {
    if (has_curl()) {
        return run_curl($opts);
    }
    return run_stream($opts);
}

// ─── multipart parsing ────────────────────────────────────────────────────────
function parse_upload_spec(string $spec): array {
    // Accepts: fieldname=@/abs/path   or   fieldname=@./relative/path
    // Also:   fieldname=value
    if (preg_match('#^([^\s=]+)\s*=\s*@(.+)$#', $spec, $m)) {
        $field = trim($m[1]);
        $path  = trim($m[2]);
        if (!file_exists($path)) {
            fwrite(STDERR, "webcli: upload file not found: {$path}\n");
            exit(2);
        }
        return ['field' => $field, 'file' => $path];
    }
    if (preg_match('#^([^\s=]+)\s*=\s*(.+)$#', $spec, $m)) {
        return ['field' => trim($m[1]), 'value' => trim($m[2]), 'file' => null];
    }
    // Bare path with -f takes field name from --target-field.
    return ['field' => null, 'file' => $spec, 'value' => null];
}

// ─── option parsing ───────────────────────────────────────────────────────────
function parse_args(array $argv): array {
    $args = array_slice($argv, 1);
    $opts = [
        'method'         => 'GET',
        'url'            => null,
        'body'           => null,
        'headers'        => [],
        'multipart'      => [],
        'upload_file'    => null,
        'upload_field'   => 'file',
        'cookie_file'    => null,
        'cookie_jar'     => null,
        'output'         => null,
        'include_headers'=> false,
        'verbose'        => false,
        'follow'         => false,
        'max_redirs'     => 5,
        'timeout'        => 30,
        'user'           => null,
        'pass'           => null,
        'encode_url'     => false,
        'dump'           => false,
    ];

    $i = 0;
    while ($i < count($args)) {
        $a = $args[$i];
        if ($a === '-h' || $a === '--help') {
            usage();
            exit(0);
        }
        if ($a === '--dump') { $opts['dump'] = true; $i++; continue; }
        if ($a === '-v' || $a === '--verbose') { $opts['verbose'] = true; $i++; continue; }
        if ($a === '-i' || $a === '--include') { $opts['include_headers'] = true; $i++; continue; }
        if ($a === '-L' || $a === '--follow') { $opts['follow'] = true; $i++; continue; }
        if ($a === '-n' || $a === '--no-headers') { $opts['include_headers'] = false; $i++; continue; }
        if ($a === '--timeout' && isset($args[$i+1])) { $opts['timeout'] = (int) $args[++$i]; $i++; continue; }
        if ($a === '-X' || $a === '--max-redirs') { if (isset($args[$i+1])) { $opts['max_redirs'] = (int) $args[++$i]; } $i++; continue; }
        if ($a === '-u' || $a === '--user-pass') {
            if (isset($args[$i+1])) {
                $up = explode(':', $args[++$i], 2);
                $opts['user'] = $up[0] ?? '';
                $opts['pass'] = $up[1] ?? '';
            }
            $i++;
            continue;
        }
        if ($a === '-c' || $a === '--cookie') {
            if (isset($args[$i+1])) { $opts['cookie_file'] = $args[++$i]; }
            $i++; continue;
        }
        if ($a === '-J' || $a === '--cookie-jar') {
            if (isset($args[$i+1])) { $opts['cookie_jar'] = $args[++$i]; }
            $i++; continue;
        }
        if ($a === '-o' || $a === '--output') {
            if (isset($args[$i+1])) { $opts['output'] = $args[++$i]; }
            $i++; continue;
        }
        if ($a === '-e' || $a === '--encode-url') { $opts['encode_url'] = true; $i++; continue; }
        if (($a === '-d' || $a === '--data') && isset($args[$i+1])) {
            $opts['body'] = $args[++$i];
            $i++; continue;
        }
        if (($a === '-H' || $a === '--header') && isset($args[$i+1])) {
            $opts['headers'][] = $args[++$i];
            $i++; continue;
        }
        if (($a === '-F' || $a === '--field') && isset($args[$i+1])) {
            $spec = parse_upload_spec($args[++$i]);
            if ($spec['file']) {
                $opts['multipart'][$spec['field'] ?? $opts['upload_field']] = ['file' => $spec['file']];
            } elseif ($spec['value'] !== null) {
                $opts['multipart'][$spec['field']] = $spec['value'];
            }
            $i++; continue;
        }
        if (($a === '-f' || $a === '--file') && isset($args[$i+1])) {
            $path = $args[++$i];
            if (!file_exists($path)) {
                fwrite(STDERR, "webcli: upload file not found: {$path}\n");
                exit(2);
            }
            $opts['upload_file'] = $path;
            $i++; continue;
        }
        if ($a === '-T' || $a === '--target-field') {
            if (isset($args[$i+1])) { $opts['upload_field'] = $args[++$i]; }
            $i++; continue;
        }
        if ($a === '-m' || $a === '--method') {
            if (isset($args[$i+1])) { $opts['method'] = strtoupper($args[++$i]); }
            $i++; continue;
        }
        // Positional: first non-option is method wrapper hint if method not yet
        // determined by subcommands below; second is URL.
        if ($opts['method'] === 'GET' && !in_array($a, array_keys(get_defined_constants(true)['curl'] ?? []))) {
            // This block is a fallback; real method selection is done by caller.
        }
        // Anything else that looks like a URL, or a method keyword used positionally.
        if (str_contains($a, '://') || str_starts_with($a, '/')) {
            if ($opts['url'] === null) {
                $opts['url'] = $a;
            } else {
                fwrite(STDERR, "webcli: unexpected second URL argument: {$a}\n");
                exit(2);
            }
        } elseif (in_array(strtoupper($a), ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','UPLOAD','JSON','FOLLOW'], true)) {
            // Method keyword used as the first positional (URL slot). The caller
            // (main()) will reinterpret it and leave the real URL for the next arg.
            if ($opts['url'] === null) {
                $opts['url'] = $a;
            } else {
                fwrite(STDERR, "webcli: unexpected second URL argument: {$a}\n");
                exit(2);
            }
        } else {
            fwrite(STDERR, "webcli: unrecognized argument: {$a}\n");
            exit(2);
        }
        $i++;
    }

    return $opts;
}

// ─── helpers ──────────────────────────────────────────────────────────────────
function guess_method_from_positional(string $first): string {
    $first = strtoupper($first);
    $methods = ['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','UPLOAD','JSON','FOLLOW'];
    if (in_array($first, $methods, true)) {
        return $first;
    }
    return 'GET';
}

function normalize_method(string $subcommand, string $explicit): string {
    if ($explicit) return strtoupper($explicit);
    return match (strtoupper($subcommand)) {
        'GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS' => strtoupper($subcommand),
        'UPLOAD','JSON','FOLLOW' => 'POST',
        default => 'GET',
    };
}

function render_response(array $resp, array $opts): void {
    if ($opts['dump']) {
        var_export($resp);
        echo "\n";
        return;
    }

    $status = $resp['status'];
    $headers = $resp['headers'];
    $body = $resp['body'];
    $transport = $resp['transport'];
    $time = $resp['time_ms'];
    $size = $resp['size'];
    $redirects = $resp['redirects'];

    if ($opts['verbose']) {
        $method = strtoupper($opts['method']);
        $url = $opts['url'];
        $req_headers = $opts['headers'];
        fwrite(STDERR, "==> {$method} {$url}\n");
        if ($opts['body'] !== null && $opts['method'] !== 'UPLOAD') {
            $preview = strlen($opts['body']) > 512 ? substr($opts['body'], 0, 512) . '...' : $opts['body'];
            fwrite(STDERR, "     body: " . $preview . "\n");
        }
        if ($opts['body'] === null && $opts['method'] === 'POST' && empty($opts['multipart'])) {
            fwrite(STDERR, "     body: (empty)\n");
        }
        fwrite(STDERR, "     headers:\n");
        foreach ($req_headers as $h) fwrite(STDERR, "       {$h}\n");
        fwrite(STDERR, "\n");
    }

    if (!$opts['no_headers']) {
        $status_line = $headers['_status_line'] ?? "HTTP/1.1 {$status}";
        echo "{$status_line}\n";
        echo "transport: {$transport} | time: {$time}ms | size: {$size}B | redirects: {$redirects}\n";
        echo str_repeat('-', 70) . "\n";
        foreach ($headers as $key => $vals) {
            if ($key === '_status_line') continue;
            foreach ((array)$vals as $v) {
                echo "{$key}: {$v}\n";
            }
        }
        echo str_repeat('-', 70) . "\n";
    }

    if ($opts['include_headers']) {
        // Already printed above; body follows.
    }

    if ($body !== '') {
        echo $body;
    } elseif ($opts['verbose'] || $opts['include_headers']) {
        echo "(empty body)\n";
    }

    if ($resp['error']) {
        fwrite(STDERR, "\nwebcli: transport error: {$resp['error']}\n");
    }
}

function save_output(string $body, string $path): void {
    if (file_put_contents($path, $body) === false) {
        fwrite(STDERR, "webcli: failed to write output to {$path}\n");
        exit(3);
    }
    fwrite(STDERR, "webcli: saved response body to {$path} ({$size} bytes)\n");
}

// ─── main ─────────────────────────────────────────────────────────────────────
function main(array $cli_argv): int {
    $args = parse_args($cli_argv);

    // Subcommand detection: first positional arg may be method keyword.
    $positional_method = null;
    $url = null;
    foreach (['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS','UPLOAD','JSON','FOLLOW'] as $kw) {
        if (strtoupper($args['url'] ?? '') === $kw) {
            $positional_method = strtoupper($args['url']);
            $url = null;
            break;
        }
    }
    // If URL arg is actually a method keyword, shift it.
    if ($positional_method && isset($args['url'])) {
        // Re-parse: move method keyword out of url.
        $targs = [];
        $seen_url = false;
        foreach ($args as $k => $v) {
            if ($k === 'url' && strtoupper($v) === $positional_method) {
                $seen_url = true;
                continue;
            }
            $targs[$k] = $v;
        }
        if (!$seen_url) {
            fwrite(STDERR, "webcli: missing URL after subcommand\n");
            exit(2);
        }
        $args = $targs;
    }

    $method = normalize_method($positional_method ?? '', $args['method'] ?? '');
    $url    = $args['url'];

    if ($url === null) {
        fwrite(STDERR, "webcli: missing URL\n");
        usage();
        return 2;
    }

    // URL validation: must have scheme.
    if (!preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*://#', $url)) {
        fwrite(STDERR, "webcli: URL must include a scheme (http:// or https://): {$url}\n");
        return 2;
    }

    // Upload method special handling.
    if (strtoupper($positional_method ?? '') === 'UPLOAD' || ($method === 'POST' && ($args['upload_file'] || !empty($args['multipart'])))) {
        $method = 'POST';
        // Build multipart from -F / -f.
        if ($args['upload_file']) {
            $args['multipart'][$args['upload_field']] = ['file' => $args['upload_file']];
        }
        $opts = $args;
        $opts['method'] = $method;
        $opts['url'] = $url;
        $resp = run_request($opts);
        render_response($resp, $opts);
        if ($args['output']) save_output($resp['body'], $args['output']);
        return $resp['status'] >= 400 ? 1 : 0;
    }

    // JSON method: set body + headers.
    $body = $args['body'];
    $content_type = null;
    if (strtoupper($positional_method ?? '') === 'JSON' || ($method === 'POST' && stripos($url, 'json') === false && !empty($args['body']) && strpos($args['body'], '{') !== false)) {
        // Only auto-detect JSON if user didn't explicitly set method to JSON.
        if (strtoupper($positional_method ?? '') !== 'JSON') {
            // Heuristic: if -d starts with { and no content-type header set, treat as JSON.
            if (preg_match('#^\s*[\{\[]#', $body ?? '') && !array_reduce($args['headers'] ?? [], fn($c,$h) => $c or (stripos($h,'content-type: application/json')!==false), false)) {
                $method = $args['method'] === 'GET' ? 'POST' : $method;
                $content_type = 'application/json';
                $args['headers'][] = 'Accept: application/json';
                if (!in_array('Content-Type: application/json', $args['headers'], true)) {
                    $args['headers'][] = 'Content-Type: application/json';
                }
            }
        }
    }

    if ($content_type) {
        $args['body'] = $body;
    } elseif ($args['body'] !== null && $args['encode_url']) {
        $args['body'] = urlencode($args['body']);
    }

    // Default Content-Type for form data if not set and body present and not JSON.
    if ($args['body'] !== null && !$content_type) {
        $has_ct = array_reduce($args['headers'] ?? [], fn($c,$h) => $c or stripos($h,'content-type:')!==false, false);
        if (!$has_ct && !empty($args['multipart'])) {
            // multipart already sets its own content-type in curl/stream builder.
        } elseif (!$has_ct) {
            $args['headers'][] = 'Content-Type: application/x-www-form-urlencoded';
        }
    }

    $opts = $args;
    $opts['method'] = $method;
    $opts['url'] = $url;
    $opts['content_type'] = $content_type;

    // Follow defaults.
    if ($method === 'GET') {
        $opts['follow'] = $opts['follow'] ?? true;
    }

    $resp = run_request($opts);
    render_response($resp, $opts);
    if ($opts['output']) save_output($resp['body'], $opts['output']);

    return $resp['status'] >= 400 ? 1 : 0;
}

exit(main($argv));
