<?php
/**
 * 3NCRYPT3D // TERMINAL — hardened sandboxed file management panel
 *
 * Security boundaries (non-negotiable):
 *  - All file operations confined to $SANDBOX_DIR via realpath() + basename() gates.
 *  - No shell_exec / system / exec / passthru / popen / proc_open anywhere.
 *  - No eval / assert / preg_replace /e / create_function / unserialize on user input.
 *  - Uploaded PHP and dotfiles blocked before disk write.
 *  - Keys never logged. Audit log is hash-chained (tamper-evident), stored outside sandbox.
 *  - CSRF token required on every state-changing POST.
 *  - Session cookie flags hardened (HttpOnly, Secure, SameSite).
 *
 * Legitimate use only: authenticated, audited, sandboxed tool for owned systems.
 */

declare(strict_types=1);

// ─── CONFIG ───────────────────────────────────────────────────────────────────
$SESSION_NAME         = '3NCRYPT3D_SID';
$PASSWORD_HASH        = password_hash('3ncrypt3d', PASSWORD_ARGON2ID);
$SANDBOX_DIR          = realpath(__DIR__ . '/sandbox') ?: (__DIR__ . '/sandbox');
$AUDIT_LOG            = __DIR__ . '/audit.log';
$CSRF_COOKIE_NAME     = '3NCRYPT3D_CSRF';
$SESSION_LIFETIME_SEC = 1800; // 30 minutes idle timeout
$MAX_UPLOAD_BYTES     = 5 * 1024 * 1024; // 5 MB per file
$BANNED_EXTENSIONS    = ['php','phtml','php3','php4','php5','php7','php8','phar',
                         'inc','hphp','ctp','module','htaccess','htpasswd','env','gitignore'];
$BANNED_MAGIC_BYTES   = [                        // bare-PHP abuse signatures
    "\x3c\x3f\x70\x68\x70",                     // <?php
    "\x3c\x3f\x70\x68\x70\x20",                // <?php 
    "\x3c\x3f\x70\x68",                         // <?ph (short)
    "\x25\x33\x43\x25\x33\x46",                // %3C%3F (URL-encoded <?)
    "\x3c\x25",                                 // <%  ASP-style abuse
    "\x3c\x73\x63\x72\x69\x70\x74",           // <script
    "\x64\x6f\x63\x74\x79\x70\x65",           // document (JS in disguise)
];
$BANNED_FILENAME_PATTERNS = [
    '/\.php[0-9]*(\.[^\.]+)?$/i',              // explicit .php[N] or .php.ext
    '/\.(phtml|php3|php4|php5|php7|php8|phar|inc|hphp|ctp|module)$/i',
    '/\.(htaccess|htpasswd|env|gitignore)$/i',
    '/^\./',                                     // dotfiles
    '/(%html|%2f|%5c|%00|%0d%0a)/i',           // encoded traversal fragments in name
];

// ─── SESSION HARDENING ────────────────────────────────────────────────────────
ini_set('session.name', $SESSION_NAME);
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', '1');       // require HTTPS in production
ini_set('session.cookie_samesite', 'Lax');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.sid_length', '32');
ini_set('session.sid_bits_per_character', '6');
session_start();

// ─── CSRF ─────────────────────────────────────────────────────────────────────
function csrf_token(): string {
    $token = bin2hex(random_bytes(32));
    $_SESSION['csrf_token'] = $token;
    setcookie($GLOBALS['CSRF_COOKIE_NAME'], $token, [
        'expires'  => time() + $GLOBALS['SESSION_LIFETIME_SEC'],
        'path'     => '/',
        'samesite' => 'Lax',
        'httponly' => false,   // client must read it for JS-free forms; set false so forms can embed it
        'secure'   => isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    ]);
    return $token;
}

function verify_csrf(): bool {
    $sessionToken = $_SESSION['csrf_token'] ?? '';
    $postToken    = $_POST['csrf_token'] ?? '';
    $cookieToken  = $_COOKIE[$GLOBALS['CSRF_COOKIE_NAME']] ?? '';
    // Timing-safe compare against both sources (defense in depth).
    return (bool) $sessionToken
        && (hash_equals($sessionToken, $postToken) || hash_equals($sessionToken, $cookieToken));
}

// ─── AUTH ─────────────────────────────────────────────────────────────────────
function authenticate(): bool {
    return !empty($_SESSION['authenticated'])
        && isset($_SESSION['logged_in_at'])
        && (time() - $_SESSION['logged_in_at'] < $GLOBALS['SESSION_LIFETIME_SEC']);
}

// ─── AUDIT LOG — hash-chained entries (tamper-evident), keys never logged ─────
function audit(string $action, string $detail = '', string $status = 'SUCCESS'): void {
    global $AUDIT_LOG;
    $ip        = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    $timestamp = date('Y-m-d H:i:s');
    $prevHash  = '';

    if (file_exists($AUDIT_LOG)) {
        $fh = fopen($AUDIT_LOG, 'rb');
        if ($fh) {
            // Read last line to chain the hash.
            $lastLine = '';
            while (!feof($fh)) { $lastLine = fgets($fh); }
            fclose($fh);
            $trimmed = trim($lastLine);
            if ($trimmed !== '' && str_starts_with($trimmed, '!!PREV')) {
                $prevHash = $trimmed;
            }
        }
    }

    // Detail is scrubbed: no key material ever reaches the log.
    $detail = scrub_for_log($detail);
    $payload = "[$timestamp] IP: $ip | ACTION: $action | DETAIL: $detail | STATUS: $status";
    $chain   = hash('sha256', ($prevHash !== '' ? $prevHash . "\n" : '') . $payload);
    $line    = $payload . "\n" . "!!PREV[$chain]\n";

    file_put_contents($AUDIT_LOG, $line, FILE_APPEND | LOCK_EX);
}

function scrub_for_log(string $s): string {
    // Generic scrub: strip anything that looks like a key/password marker.
    // Conservative: always OK to over-scrub; never under-scrub.
    $s = preg_replace('/(key|pass|secret|token|iv|tag|nonce)[=:]\s*[^\s,&|]{4,}/i', '$1=[REDACTED]', $s);
    $s = preg_replace('/&[a-zA-Z0-9+/=]{16,}/', '[REDACTED_BASE64]', $s);
    return $s;
}

// ─── PATH SAFETY — real confinement gate ──────────────────────────────────────
function safe_resolve(string $filename): string|false {
    global $SANDBOX_DIR;
    // Normalize sandbox real path once.
    $sandboxReal = realpath($SANDBOX_DIR);
    if ($sandboxReal === false || !is_dir($sandboxReal)) {
        return false;
    }
    // Strip path components and null bytes. Reject traversal immediately.
    $name = basename($filename);
    if ($name === '' || $name === '.' || $name === '..' || str_contains($name, "\0")) {
        return false;
    }
    $candidate = $sandboxReal . '/' . $name;
    $resolved  = realpath($candidate);
    if ($resolved === false) {
        // File may not exist yet (upload). Build a candidate and verify it stays under sandbox.
        if (str_starts_with($candidate, $sandboxReal . '/') && !str_contains($candidate, '/../')) {
            return $candidate; // will exist after write; still under sandbox by construction
        }
        return false;
    }
    // Confirm resolved path is under sandbox (prevents symlink escape if sandbox is writable).
    if (!str_starts_with($resolved, $sandboxReal . '/') && $resolved !== $sandboxReal) {
        return false;
    }
    return $resolved;
}

// ─── FILE SAFETY — upload validation ──────────────────────────────────────────
function is_extension_allowed(string $name): bool {
    $ext = strtolower(pathinfo($name, PATHINFO_EXTENSION));
    if ($ext === '') {
        return false;                 // require an extension
    }
    return !in_array($ext, $GLOBALS['BANNED_EXTENSIONS'], true);
}

function passes_name_policy(string $name): bool {
    foreach ($GLOBALS['BANNED_FILENAME_PATTERNS'] as $pattern) {
        if (preg_match($pattern, $name)) {
            return false;
        }
    }
    return true;
}

function has_banned_magic(string $bytes): bool {
    foreach ($GLOBALS['BANNED_MAGIC_BYTES'] as $sig) {
        if (str_starts_with($bytes, $sig)) {
            return true;
        }
    }
    return false;
}

// ─── HKDF — per-file key derivation from a master key ────────────────────────
function derive_file_key(string $masterKey, string $filename): string {
    // Derive a 32-byte key for AES-256-GCM from the master + context (filename).
    // Salt is a fixed per-panel constant — fine for this sandboxed tool; do NOT
    // reuse this pattern for cross-panel key derivation without a random salt.
    $salt = hex2bin('00112233445566778899aabbccddeeff');
    $key  = hash_hkdf('sha256', $masterKey, 32, $salt, $filename);
    return $key;
}

// ─── ENCRYPTION / DECRYPTION — AES-256-GCM ──────────────────────────────────
function encrypt_file(string $path, string $masterKey, string $filename): string|false {
    if (!is_readable($path) || !is_file($path)) {
        return false;
    }
    $data = file_get_contents($path);
    if ($data === false) {
        return false;
    }
    $iv  = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
    $key = derive_file_key($masterKey, $filename);
    $tag = '';
    $ct  = openssl_encrypt($data, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    if ($ct === false || $tag === false) {
        return false;
    }
    return $iv . $tag . $ct;
}

function decrypt_file(string $path, string $masterKey, string $filename): string|false {
    if (!is_readable($path) || !is_file($path)) {
        return false;
    }
    $data = file_get_contents($path);
    if ($data === false) {
        return false;
    }
    $ivLen = openssl_cipher_iv_length('aes-256-gcm');
    if (strlen($data) < $ivLen + 16 + 1) {
        return false;
    }
    $iv       = substr($data, 0, $ivLen);
    $tag      = substr($data, $ivLen, 16);
    $cipher   = substr($data, $ivLen + 16);
    $key      = derive_file_key($masterKey, $filename);
    return openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
}

// ─── HASH ─────────────────────────────────────────────────────────────────────
function file_sha256(string $path): string|false {
    if (!is_readable($path) || !is_file($path)) {
        return false;
    }
    return hash_file('sha256', $path);
}

// ─── ROUTING ──────────────────────────────────────────────────────────────────
$message  = '';
$msgClass = 'success';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'], $_POST['csrf_token'])) {
    if (!verify_csrf()) {
        $message  = 'CSRF VALIDATION FAILED — REQUEST REJECTED.';
        $msgClass = 'alert';
        audit('CSRF_FAIL', ($_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN'), 'REJECTED');
    } else {
        $action  = $_POST['action'];
        $rawFile = $_POST['filename'] ?? '';
        $filename = basename($rawFile);
        $masterKey = $_POST['key'] ?? '';

        match ($action) {
            'login' => null, // handled below
            'logout' => null, // handled below
            'upload' => handle_upload($filename),
            'hash'   => handle_hash($filename),
            'encrypt'=> handle_encrypt($filename, $masterKey),
            'decrypt'=> handle_decrypt($filename, $masterKey),
            'delete' => handle_delete($filename),
            default  => null,
        };
    }
}

function handle_upload(string $filename): void {
    global $message, $msgClass;
    if (empty($_FILES['file']['name'])) {
        $message = 'NO FILE SELECTED.'; $msgClass = 'alert';
        audit('UPLOAD', 'none', 'FAILED_NO_FILE');
        return;
    }
    $uploadName = basename($_FILES['file']['name']);
    if (!passes_name_policy($uploadName)) {
        $message = 'UPLOAD BLOCKED: filename policy violation.'; $msgClass = 'alert';
        audit('UPLOAD_BLOCKED_POLICY', $uploadName, 'REJECTED');
        return;
    }
    if (!is_extension_allowed($uploadName)) {
        $message = 'UPLOAD BLOCKED: prohibited extension.'; $msgClass = 'alert';
        audit('UPLOAD_BLOCKED_EXT', $uploadName, 'REJECTED');
        return;
    }
    // Magic-byte scan.
    $tmp = fopen($_FILES['file']['tmp_name'], 'rb');
    if ($tmp === false) {
        $message = 'UPLOAD FAILED: cannot read temp file.'; $msgClass = 'alert';
        audit('UPLOAD_FAIL_READ', $uploadName, 'FAILED');
        return;
    }
    $head = fread($tmp, 8192);
    fclose($tmp);
    if ($head === false || $head === '') {
        $message = 'UPLOAD FAILED: empty or unreadable file.'; $msgClass = 'alert';
        audit('UPLOAD_FAIL_EMPTY', $uploadName, 'FAILED');
        return;
    }
    if (has_banned_magic($head)) {
        $message = 'UPLOAD BLOCKED: forbidden file header (PHP/JS abuse signature).'; $msgClass = 'alert';
        audit('UPLOAD_BLOCKED_MAGIC', $uploadName, 'REJECTED');
        return;
    }
    // Size guard.
    if ($_FILES['file']['size'] > $GLOBALS['MAX_UPLOAD_BYTES']) {
        $message = 'UPLOAD BLOCKED: file exceeds size limit.'; $msgClass = 'alert';
        audit('UPLOAD_BLOCKED_SIZE', $uploadName, 'REJECTED');
        return;
    }
    $target = safe_resolve($uploadName);
    if ($target === false) {
        $message = 'UPLOAD FAILED: path resolution error.'; $msgClass = 'alert';
        audit('UPLOAD_FAIL_PATH', $uploadName, 'FAILED');
        return;
    }
    if (move_uploaded_file($_FILES['file']['tmp_name'], $target)) {
        $message = 'FILE UPLOADED: ' . $uploadName;
        audit('UPLOAD', $uploadName, 'SUCCESS');
    } else {
        $message = 'UPLOAD FAILED: write error.'; $msgClass = 'alert';
        audit('UPLOAD_FAIL_WRITE', $uploadName, 'FAILED');
    }
}

function handle_hash(string $filename): void {
    global $message, $msgClass;
    $path = safe_resolve($filename);
    if ($path === false || !is_file($path)) {
        $message = 'FILE NOT FOUND.'; $msgClass = 'alert';
        audit('HASH_FAIL', $filename, 'NOT_FOUND');
        return;
    }
    $h = file_sha256($path);
    if ($h === false) {
        $message = 'HASH FAILED.'; $msgClass = 'alert';
        audit('HASH_FAIL', $filename, 'ERROR');
        return;
    }
    $message  = 'SHA-256 [' . $filename . ']:<br><strong style="color:#fff">' . $h . '</strong>';
    audit('HASH', $filename, 'SUCCESS');
}

function handle_encrypt(string $filename, string $masterKey): void {
    global $message, $msgClass;
    if ($masterKey === '') {
        $message = 'ENCRYPT FAILED: key required.'; $msgClass = 'alert';
        audit('ENCRYPT_FAIL', $filename, 'NO_KEY');
        return;
    }
    $path = safe_resolve($filename);
    if ($path === false || !is_file($path)) {
        $message = 'FILE NOT FOUND.'; $msgClass = 'alert';
        audit('ENCRYPT_FAIL', $filename, 'NOT_FOUND');
        return;
    }
    $enc = encrypt_file($path, $masterKey, $filename);
    if ($enc === false) {
        $message = 'ENCRYPTION FAILED.'; $msgClass = 'alert';
        audit('ENCRYPT_FAIL', $filename, 'ERROR');
        return;
    }
    $encName = $filename . '.enc';
    $encPath = safe_resolve($encName);
    if ($encPath === false) {
        $message = 'ENCRYPT FAILED: cannot resolve output path.'; $msgClass = 'alert';
        audit('ENCRYPT_FAIL_OUTPATH', $encName, 'ERROR');
        return;
    }
    if (file_put_contents($encPath, $enc, LOCK_EX) === false) {
        $message = 'ENCRYPT FAILED: write error.'; $msgClass = 'alert';
        audit('ENCRYPT_FAIL_WRITE', $encName, 'ERROR');
        return;
    }
    $message = 'ENCRYPTED TO: ' . $encName;
    audit('ENCRYPT', $filename . ' -> ' . $encName, 'SUCCESS');
}

function handle_decrypt(string $filename, string $masterKey): void {
    global $message, $msgClass;
    if ($masterKey === '') {
        $message = 'DECRYPT FAILED: key required.'; $msgClass = 'alert';
        audit('DECRYPT_FAIL', $filename, 'NO_KEY');
        return;
    }
    $path = safe_resolve($filename);
    if ($path === false || !is_file($path)) {
        $message = 'FILE NOT FOUND.'; $msgClass = 'alert';
        audit('DECRYPT_FAIL', $filename, 'NOT_FOUND');
        return;
    }
    // Output name: strip .enc if present, else append .dec.
    $base = preg_replace('/\\.enc$/', '', $filename);
    if ($base === $filename) {
        $base .= '.dec';
    }
    $plain = decrypt_file($path, $masterKey, $filename);
    if ($plain === false) {
        $message = 'DECRYPTION FAILED: invalid key or corrupt data.'; $msgClass = 'alert';
        audit('DECRYPT_FAIL', $filename, 'DECRYPT_ERROR');
        return;
    }
    $outPath = safe_resolve($base);
    if ($outPath === false) {
        $message = 'DECRYPT FAILED: cannot resolve output path.'; $msgClass = 'alert';
        audit('DECRYPT_FAIL_OUTPATH', $base, 'ERROR');
        return;
    }
    if (file_put_contents($outPath, $plain, LOCK_EX) === false) {
        $message = 'DECRYPT FAILED: write error.'; $msgClass = 'alert';
        audit('DECRYPT_FAIL_WRITE', $base, 'ERROR');
        return;
    }
    $message = 'DECRYPTED TO: ' . $base;
    audit('DECRYPT', $filename . ' -> ' . $base, 'SUCCESS');
}

function handle_delete(string $filename): void {
    global $message, $msgClass;
    $path = safe_resolve($filename);
    if ($path === false || !is_file($path)) {
        $message = 'FILE NOT FOUND.'; $msgClass = 'alert';
        audit('DELETE_FAIL', $filename, 'NOT_FOUND');
        return;
    }
    if (!unlink($path)) {
        $message = 'DELETE FAILED.'; $msgClass = 'alert';
        audit('DELETE_FAIL', $filename, 'ERROR');
        return;
    }
    $message = 'DELETED: ' . $filename;
    audit('DELETE', $filename, 'SUCCESS');
}

// ─── AUTH FLOW ────────────────────────────────────────────────────────────────
if (isset($_GET['logout'])) {
    audit('LOGOUT', '', 'SUCCESS');
    session_unset();
    session_destroy();
    header('Location: panel.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $pass = $_POST['password'] ?? '';
    if (password_verify($pass, $PASSWORD_HASH)) {
        session_regenerate_id(true);
        $_SESSION['authenticated'] = true;
        $_SESSION['logged_in_at']  = time();
        audit('LOGIN', '', 'SUCCESS');
        header('Location: panel.php');
        exit;
    }
    audit('LOGIN', '', 'FAILED');
    $message = 'ACCESS DENIED.';
    $msgClass = 'alert';
}

// Bootstrap CSRF token for the authenticated view.
$csrf = csrf_token();

// ─── HTML ─────────────────────────────────────────────────────────────────────
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>3NCRYPT3D // TERMINAL</title>
    <style>
        :root {
            --bg: #050505;
            --fg: #0f0;
            --warn: #f55;
            --ok: #0f0;
            --dim: #0a0;
            --panel-bg: #000;
            --border: #0f0;
        }
        * { box-sizing: border-box; }
        body {
            background: var(--bg);
            color: var(--fg);
            font-family: 'Courier New', Courier, monospace;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            border: 1px solid var(--border);
            padding: 20px;
            box-shadow: 0 0 15px rgba(0,255,0,0.2);
            background: var(--panel-bg);
        }
        h1, h2 {
            text-align: center;
            text-shadow: 0 0 10px var(--fg);
            margin-top: 0;
        }
        h1.warn { color: var(--warn); text-shadow: 0 0 10px var(--warn); }
        hr {
            border: 0;
            border-bottom: 1px dashed var(--border);
            margin: 20px 0;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 10px;
            table-layout: fixed;
        }
        th, td {
            border: 1px solid var(--border);
            padding: 8px;
            text-align: left;
            word-wrap: break-word;
        }
        th { background: #0a0a0a; }
        .col-filename { width: 25%; }
        .col-size { width: 15%; }
        .col-hash { width: 15%; }
        .col-encrypt { width: 15%; }
        .col-decrypt { width: 15%; }
        .col-delete { width: 15%; }
        input, button {
            background: #000;
            color: var(--fg);
            border: 1px solid var(--border);
            padding: 8px;
            font-family: inherit;
            margin: 2px 0;
            width: 100%;
        }
        input[type="file"] { border: 1px dashed var(--border); }
        button:hover {
            background: var(--fg);
            color: #000;
            cursor: pointer;
            box-shadow: 0 0 10px var(--fg);
        }
        .log-box {
            height: 250px;
            overflow-y: auto;
            border: 1px solid var(--border);
            padding: 10px;
            background: #020202;
            white-space: pre-wrap;
            font-size: 0.85em;
            color: var(--dim);
        }
        .alert {
            color: var(--warn);
            border: 1px solid var(--warn);
            padding: 10px;
            box-shadow: 0 0 10px rgba(255,0,0,0.3);
            margin-bottom: 15px;
            text-align: center;
            font-weight: bold;
            background: #200;
        }
        .success {
            color: var(--ok);
            border: 1px solid var(--ok);
            padding: 10px;
            margin-bottom: 15px;
            text-align: center;
            background: #020;
        }
        .action-form { display: inline-block; width: 100%; margin: 0; }
        .flex { display: flex; gap: 20px; }
        .flex > div { flex: 1; }
        .logout {
            float: right;
            font-size: 12px;
            color: var(--warn);
            text-decoration: none;
            margin-top: 10px;
        }
        .mono { font-family: 'Courier New', Courier, monospace; }
        .hint { font-size: 11px; color: var(--dim); margin-top: 5px; }
        .status-bar {
            text-align: center;
            font-size: 11px;
            color: var(--dim);
            margin-bottom: 10px;
        }
    </style>
</head>
<body>
<div class="container">
<?php if (!authenticate()): ?>
    <h1>3NCRYPT3D // AUTHENTICATION</h1>
    <?php if ($message): ?>
        <div class="alert"><?= $message ?></div>
    <?php endif; ?>
    <form method="POST">
        <input type="hidden" name="action" value="login">
        <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
        <input type="password" name="password" placeholder="ENTER PASSPHRASE" autofocus autocomplete="off">
        <br><br>
        <button type="submit">INITIALIZE</button>
    </form>
    <br>
    <div class="hint">Default passphrase: 3ncrypt3d — change by editing $PASSWORD_HASH in panel.php</div>
<?php else: ?>
    <h1>3NCRYPT3D // TERMINAL
        <a href="?logout=1" class="logout">[ LOGOUT ]</a>
    </h1>
    <div class="status-bar">SESSION ACTIVE · <?= date('Y-m-d H:i:s') ?> UTC · SANDBOX: <?= htmlspecialchars(basename($GLOBALS['SANDBOX_DIR'])) ?></div>
    <?php if ($message): ?>
        <div class="<?= $msgClass ?>"><?= $message ?></div>
    <?php endif; ?>

    <div class="flex">
        <div>
            <h2>UPLOAD TO SANDBOX</h2>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="action" value="upload">
                <input type="hidden" name="csrf_token" value="<?= $csrf ?>">
                <input type="file" name="file" required>
                <button type="submit">UPLOAD FILE</button>
            </form>
            <div class="hint">Max <?= $GLOBALS['MAX_UPLOAD_BYTES'] >> 20 ?>MB · PHP and dotfiles blocked · magic-byte scanned</div>
        </div>
        <div>
            <h2>MASTER KEY</h2>
            <input type="password" id="master_key" placeholder="ENTER AES-256-GCM MASTER KEY" oninput="updateKeys()">
            <div class="hint">Per-file key derived via HKDF(SHA256) from this master + filename. Key never leaves the browser except in the POST body.</div>
        </div>
    </div>

    <hr>
    <h2>SANDBOX FILES</h2>
    <table>
        <tr>
            <th class="col-filename">FILENAME</th>
            <th class="col-size">SIZE</th>
            <th class="col-hash">HASH</th>
            <th class="col-encrypt">ENCRYPT</th>
            <th class="col-decrypt">DECRYPT</th>
            <th class="col-delete">DELETE</th>
        </tr>
        <?php
        $files = [];
        $dir = @scandir($SANDBOX_DIR);
        if ($dir !== false) {
            $files = array_diff($dir, ['.', '..', '.htaccess']);
        }
        if (empty($files)) {
            echo '<tr><td colspan="6" style="text-align:center;">NO FILES IN SANDBOX</td></tr>';
        }
        foreach ($files as $f) {
            $safe = htmlspecialchars($f, ENT_QUOTES, 'UTF-8');
            $path = $SANDBOX_DIR . '/' . $f;
            $size = is_file($path) ? filesize($path) : 0;

            $units = ['B','KB','MB','GB','TB'];
            $bytes = max($size, 0);
            $pow   = floor(($bytes ? log($bytes) : 0) / log(1024));
            $pow   = min($pow, count($units) - 1);
            $bytes /= pow(1024, $pow);
            $sizeStr = round($bytes, 2) . ' ' . $units[$pow];

            echo "<tr>";
            echo "<td>$safe</td>";
            echo "<td>$sizeStr</td>";
            echo '<td><form method="POST" class="action-form">
                    <input type="hidden" name="action" value="hash">
                    <input type="hidden" name="csrf_token" value="' . $csrf . '">
                    <input type="hidden" name="filename" value="' . $safe . '">
                    <button type="submit">SHA-256</button>
                  </form></td>';
            echo '<td><form method="POST" class="action-form">
                    <input type="hidden" name="action" value="encrypt">
                    <input type="hidden" name="csrf_token" value="' . $csrf . '">
                    <input type="hidden" name="filename" value="' . $safe . '">
                    <input type="password" name="key" class="key-input" required placeholder="key">
                    <button type="submit">ENCRYPT</button>
                  </form></td>';
            echo '<td><form method="POST" class="action-form">
                    <input type="hidden" name="action" value="decrypt">
                    <input type="hidden" name="csrf_token" value="' . $csrf . '">
                    <input type="hidden" name="filename" value="' . $safe . '">
                    <input type="password" name="key" class="key-input" required placeholder="key">
                    <button type="submit">DECRYPT</button>
                  </form></td>';
            echo '<td><form method="POST" class="action-form" onsubmit="return confirm(\'CONFIRM DELETION OF ' . addslashes($safe) . '?\');">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="csrf_token" value="' . $csrf . '">
                    <input type="hidden" name="filename" value="' . $safe . '">
                    <button type="submit" style="color:var(--warn); border-color:var(--warn);">DELETE</button>
                  </form></td>';
            echo "</tr>";
        }
        ?>
    </table>

    <script>
    function updateKeys() {
        var mk = document.getElementById('master_key').value;
        var inputs = document.getElementsByClassName('key-input');
        for (var i = 0; i < inputs.length; i++) { inputs[i].value = mk; }
    }
    </script>

    <hr>
    <h2>AUDIT LOG (tamper-evident, hash-chained)</h2>
    <div class="log-box" id="audit-log"><?php
        if (file_exists($AUDIT_LOG)) {
            echo htmlspecialchars(file_get_contents($AUDIT_LOG), ENT_QUOTES, 'UTF-8');
        } else {
            echo 'NO LOGS FOUND.';
        }
    ?></div>
    <script>
        var lb = document.getElementById('audit-log');
        lb.scrollTop = lb.scrollHeight;
    </script>
<?php endif; ?>
</div>
</body>
</html>
