# php.panel

3NCRYPT3D // TERMINAL — hardened sandboxed file management panel (PHP).

## What it is

Authenticated web panel for uploading, hashing, encrypting, decrypting, and
deleting files — **confined to `./sandbox/` only**.

## Security model (non-negotiable boundaries)

- All file ops are restricted to `$SANDBOX_DIR` via `realpath()` + `basename()`
  resolution. Path traversal is rejected by construction.
- No shell execution functions anywhere: `shell_exec`, `system`, `exec`,
  `passthru`, `popen`, `proc_open` are all absent.
- No code-evaluation surface: no `eval`, `assert`, `preg_replace` `/e`,
  `create_function`, `unserialize` on user input.
- Uploaded PHP is blocked by extension, filename policy, and magic-byte scan
  before the file is written to disk. Dotfiles are blocked too.
- `.htaccess` inside `sandbox/` disables the PHP engine for that directory,
  denies execution extensions, blocks dotfiles, and forces every served file
  as a download attachment with `nosniff` + `X-Frame-Options: DENY`.
- Authentication via `password_hash` / `password_verify` (Argon2id).
- CSRF token required on every state-changing POST.
- Session cookie hardened: `HttpOnly`, `Secure`, `SameSite=Lax`, strict mode,
  cookie-only sessions.
- Audit log is hash-chained (each line references the previous line's hash)
  so tampering is detectable. Key material is **never** written to the log.
- Encryption: AES-256-GCM with per-file key derivation via HKDF(SHA256) from a
  master key + filename context. Unique IV per file. GCM tag stored inline.
- Default session idle timeout: 30 minutes.

## What it does NOT do

- It cannot write or read outside `./sandbox/`.
- It cannot execute uploaded PHP (blocked at upload + at webserver level).
- It cannot run arbitrary commands on the host.
- It is not a webshell. It is a sandboxed admin tool for owned systems.

## Files

- `panel.php` — main application
- `sandbox/` — confined working directory
- `sandbox/.htaccess` — Apache hardening for the sandbox
- `audit.log` — tamper-evident operation log (created automatically)

## Quick start

```bash
php -S localhost:8080
# then open http://localhost:8080/panel.php
```

Default passphrase: `3ncrypt3d`

Change it by editing `$PASSWORD_HASH` in `panel.php` (recompute with
`password_hash('YOUR_PASSPHRASE', PASSWORD_ARGON2ID)`).

## Requirements

- PHP 7.4+ with `openssl`, `hash_hkdf`, `password_hash` (Argon2id) available.
- Apache with `mod_authz_core` if you want the `.htaccess` rules to apply
  (nginx users should mirror the equivalent directives in server config).

## Local testing

The included `.htaccess` rules require Apache. For a quick local smoke test
with the built-in server, the PHP-level guards still apply (extension block,
magic-byte scan, path confinement) even if the webserver-level rules don't.
