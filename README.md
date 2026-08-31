# TOTP Vault

A production-grade, **zero-dependency** RFC 6238 TOTP authenticator CLI and encrypted security vault. Built entirely with the Node.js standard library — no npm packages, no installs, no external downloads.

Track E submission for the **Zero Dependency Hackathon 2026** (Security & Crypto Utilities).

## Features

- **RFC 6238 TOTP** generation with SHA-1 and SHA-256 support
- **RFC 4226 HOTP** counter-based codes
- **RFC 4648 Base32** decoder written from scratch with bitwise operations, lookup table, and strict trailing-bit validation
- **OTP URI import** — parse `otpauth://totp/...` URIs directly via the `import` command (uses `node:url`)
- **Zero-allocation HMAC** — reuses a module-level 8-byte counter buffer for every OTP calculation
- **Unsigned right-shift fix** — `>>> 0` on the dynamic truncation bin ensures codes never evaluate as negative
- **Timing-safe verification** with configurable ±N window drift tolerance (prevents timing attacks via `crypto.timingSafeEqual`)
- **AES-256-GCM encrypted vault** using PBKDF2 key derivation (100,000 iterations, SHA-256)
- **Live hacker terminal mode** with phosphor-green ANSI telemetry, crypto debug output, and countdown progress bars
- **Interactive vault challenge mode** — type rolling codes against the clock with rate limiting
- **Tamper detection** via GCM authentication tags (ciphertext, IV, and auth tag all verified)
- **Password entropy meter** displayed during vault creation
- **JSON output mode** for scripting and automation (`--json` flag)

## Installation

None required. This project has zero runtime dependencies. You only need Node.js 16+.

```bash
# Verify zero dependencies
cat package.json  # "dependencies": {}
```

## Quick Start

```bash
# Add an account (Base32 secret from your service provider)
node index.js add github JBSWY3DPEHPK3PXP

# Import an account from an otpauth:// URI (e.g. from a QR code)
node index.js import "otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30"

# Generate the current 6-digit code
node index.js generate github

# Verify a code (accepts ±1 time window by default)
node index.js verify github 123456

# List all stored accounts
node index.js list

# Live watch mode — overview of all accounts
node index.js watch

# Live watch mode — single account with full crypto telemetry
node index.js watch github

# Interactive challenge — type codes against the clock
node index.js challenge github

# Remove an account
node index.js remove github

# Export vault as plain JSON (requires password)
node index.js export
```

## Commands

| Command | Description |
|---|---|
| `add <name> <secret> [--digits 6\|8] [--step 30\|60] [--algo sha1\|sha256]` | Add a new account |
| `import <otpauth-uri>` | Import an account from an `otpauth://totp/...` URI |
| `generate <name> [--json]` | Generate the current TOTP code |
| `verify <name> <code> [--drift N]` | Verify a code with N-window drift tolerance |
| `list [--json]` | List all stored accounts |
| `watch [<account>] [--interval N]` | Live watch mode (single account shows crypto telemetry) |
| `challenge <account>` | Interactive vault challenge — type codes against the clock |
| `remove <name>` | Remove an account from the vault |
| `export` | Export vault as plain JSON |
| `help` | Show help message |

### Options

| Flag | Description | Default |
|---|---|---|
| `--digits 6\|8` | OTP digit count | 6 |
| `--step 30\|60` | Time step in seconds | 30 |
| `--algo sha1\|sha256` | HMAC algorithm | sha1 |
| `--drift N` | Drift tolerance windows | 1 |
| `--interval N` | Watch refresh interval (seconds) | 1 |
| `--json` | Machine-readable JSON output | off |

### Environment Variables

- `TOTP_VAULT_PASSWORD` — Provide the vault password non-interactively (useful for scripting)

## OTP URI Import

The `import` command parses standard `otpauth://totp/` URIs (the format encoded in QR codes by authenticator apps):

```bash
node index.js import "otpauth://totp/AWS:admin@corp?secret=JBSWY3DPEHPK3PXP&issuer=AWS&algorithm=SHA256&digits=8&period=60"
```

The parser extracts:
- **Label** — the account path (e.g. `AWS:admin@corp`)
- **Issuer** — from the `issuer` parameter or the label prefix before `:`
- **Secret** — the Base32-encoded shared secret (required)
- **Algorithm** — SHA1 (default), SHA256, or SHA512
- **Digits** — 6 (default) or 8
- **Period** — 30 (default) or 60 seconds

URL parsing uses the native `node:url` module — no external URI parsing library needed.

## Live Hacker Terminal Mode

The `watch` command provides two modes:

**Overview mode** (`node index.js watch`): Displays all accounts with colored progress bars and countdown timers.

**Single-account telemetry mode** (`node index.js watch <account>`): A high-security vault keypad display showing:
- Current Unix timestamp
- Time counter step (T)
- Raw hex HMAC digest
- Dynamic truncation offset byte (0x00–0x0F)
- The computed OTP code
- A visual countdown progress bar that turns red in the final 5 seconds

Uses phosphor green and amber ANSI colors on a black background for a classic terminal aesthetic.

## Interactive Vault Challenge Mode

```bash
node index.js challenge github
```

Prompts you to type the current rolling code before the time step expires. Features:
- Tracks successful consecutive entries (streak counter)
- Reports drift offset for each successful verification
- Locks out after 3 failed attempts (rate limiting)
- Displays a session summary on exit

## Testing

```bash
node --test test.js
```

The test suite verifies:
- Official RFC 6238 and RFC 4226 test vectors (SHA-1 and SHA-256)
- Unsigned right-shift fix (bin is always non-negative across 1000 counters)
- Base32 edge cases (padding, lowercase, whitespace, invalid characters, non-ASCII, non-zero trailing bits)
- OTP URI parsing (standard URIs, defaults, issuer extraction, URL-encoded labels, error cases)
- AES-256-GCM encryption/decryption roundtrips and tamper detection (ciphertext, IV, auth tag)
- Time-drift tolerance (±1, ±2, custom drift, drift=0)
- Password entropy estimation
- Performance benchmarks (HMAC-SHA1 vs HMAC-SHA256 throughput)

## Security Architecture

### Vault Encryption

1. **Key Derivation:** The vault password is processed through PBKDF2 with SHA-256, 100,000 iterations, and a random 32-byte salt to produce a 256-bit encryption key.
2. **Encryption:** Vault contents are encrypted with AES-256-GCM using a random 12-byte IV. The GCM mode provides both confidentiality and integrity.
3. **Authentication:** A 128-bit GCM authentication tag is stored alongside the ciphertext. Any tampering with the ciphertext, IV, or auth tag causes decryption to fail.
4. **File Permissions:** The vault file is written with mode `0600` (owner read/write only).

### TOTP Verification

- Codes are compared using `crypto.timingSafeEqual` to prevent timing side-channel attacks.
- Verification accepts codes from configurable time windows (±N drift) to accommodate clock skew.
- Both the candidate and expected codes are converted to equal-length buffers before comparison.
- The drift offset is reported on success, enabling callers to detect and log clock skew.

### Unsigned Right-Shift Fix

The dynamic truncation step in HOTP computes a 31-bit integer from 4 HMAC bytes. Without `>>> 0`, JavaScript's signed 32-bit arithmetic can produce a negative value when bit 31 is set (the mask `& 0x7f` clears bit 31 of the first byte, but intermediate `<<` operations can still trigger sign extension in edge cases). The `>>> 0` unsigned right shift coerces the result to a non-negative 32-bit unsigned integer, guaranteeing correct modulo arithmetic for all possible HMAC outputs.

### Zero-Allocation Buffer Optimization

The `hotp` function reuses a module-level 8-byte `Buffer` (`HOTP_COUNTER_BUF`) for the HMAC counter input instead of allocating new memory on each call. This eliminates GC pressure during high-frequency OTP generation (e.g., watch mode refreshing every second, benchmark runs of 10,000+ iterations).

## Threat Model

### Assets

| Asset | Description |
|---|---|
| TOTP secrets | Base32-encoded shared secrets stored in the encrypted vault |
| Vault password | Master password used to derive the AES-256-GCM encryption key |
| Vault file | `.totp_vault.json` containing encrypted ciphertext, salt, IV, and auth tag |
| OTP codes | Transient 6/8-digit codes displayed in terminal or transmitted over verification |

### Attacker Capabilities

| Capability | Description |
|---|---|
| File system access | Attacker can read/copy the vault file from disk |
| Network interception | Attacker can observe network traffic (if codes are transmitted) |
| Timing observation | Attacker can measure response times of verification operations |
| Vault tampering | Attacker can modify the vault file on disk |
| Brute-force password | Attacker can attempt many passwords against the vault file |
| Replay attack | Attacker can reuse a previously observed valid code |

### Side-Channel Mitigations

| Vector | Mitigation |
|---|---|
| Timing attack on verification | `crypto.timingSafeEqual` provides constant-time buffer comparison; no early-exit on character mismatch |
| Memory allocation patterns | Zero-allocation buffer reuse in `hotp` eliminates allocation timing variance |
| Error message leakage | Decryption failures return a generic error message regardless of failure cause (wrong password vs corrupted data) |

### Replay Window Management

| Aspect | Implementation |
|---|---|
| Time step | Configurable 30s or 60s windows; default 30s per RFC 6238 |
| Drift tolerance | Configurable ±N windows; default ±1 (accepts T-1, T, T+1) |
| Replay prevention | Each time step produces a unique code; a code from step T is invalid at step T+2 or beyond |
| Challenge rate limiting | Interactive challenge mode locks out after 3 consecutive failed attempts |

## Performance Benchmarks

Benchmarks run via `node --test test.js` on the test hardware. Results are printed to test stdout.

| Operation | Algorithm | Throughput (ops/sec) |
|---|---|---|
| HOTP generation | HMAC-SHA1 | ~15,000–25,000 |
| HOTP generation | HMAC-SHA256 | ~12,000–20,000 |
| Buffer reuse (hotp) | HMAC-SHA1 | Faster than per-call alloc |
| Per-call alloc (baseline) | HMAC-SHA1 | Slower than reuse |
| Vault encryption | AES-256-GCM + PBKDF2 | ~7–10 ops/sec (PBKDF2-bound) |
| Vault decryption | AES-256-GCM + PBKDF2 | ~7–10 ops/sec (PBKDF2-bound) |

Note: PBKDF2 with 100,000 iterations is intentionally slow to resist brute-force. The HMAC throughput numbers reflect the OTP calculation only, excluding key derivation. Actual numbers vary by hardware.

## Zero-Dependency Mapping

Every npm package that a conventional project would use is replaced by native Node.js standard-library APIs:

| npm Package | Node.js Standard Library Replacement |
|---|---|
| `otplib` / `speakeasy` | `node:crypto.createHmac()` + `Buffer.writeBigUInt64BE()` — HOTP/TOTP from scratch |
| `crypto-js` | `node:crypto` — `createCipheriv('aes-256-gcm')`, `pbkdf2Sync()`, `randomBytes()` |
| `base32.js` / `hi-base32` | Bitwise shift & buffer operations with `Int8Array` lookup table |
| `chalk` / `kleur` | Raw ANSI escape sequences (`\x1b[...]m`) |
| `commander` / `yargs` | Manual `process.argv` parsing with `parseFlags()` |
| `dotenv-vault` / `bcrypt` | `node:crypto.pbkdf2Sync()` (100K iterations, SHA-256) |
| `cli-progress` | ANSI redraw loop with `setInterval` + `\x1b[H\x1b[2J` |
| `jest` / `mocha` | `node:test` + `node:assert` |
| `lowdb` / `keyv` | `node:fs.readFileSync` / `writeFileSync` with JSON |
| `secure-compare` | `node:crypto.timingSafeEqual()` |
| `moment` / `date-fns` | `Date.now()` + `Math.floor()` epoch arithmetic |
| `inquirer` / `prompts` | `node:readline` + raw-mode stdin for silent password input |
| `uuid` | `node:crypto.randomUUID()` |
| `zxcvbn` | Custom entropy estimation via charset size × length |
| `otpauth-uri` / `query-string` | `node:url` — `new URL()` + `URLSearchParams` for otpauth:// parsing |

See [STDLIB.md](STDLIB.md) for detailed implementation notes on each mapping.

## License

MIT
