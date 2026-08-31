# STDLIB.md — Standard Library Mapping

This document maps popular third-party npm packages to the native Node.js standard-library functionality used to replace them in this zero-dependency project.

## 1. `otplib` / `speakeasy` → `node:crypto` HMAC + BigUInt64BE

**Replaced by:** `node:crypto.createHmac('sha1' | 'sha256', key)` combined with a module-level `Buffer.alloc(8)` and `buf.writeBigUInt64BE(BigInt(counter))`.

The HOTP/TOTP algorithm is implemented from scratch per RFC 4226 and RFC 6238. A big-endian 8-byte counter buffer is fed into an HMAC, the result is dynamically truncated using the last nibble as an offset, and the 31-bit binary value is reduced modulo `10^digits`.

**Unsigned right-shift fix:** The dynamic truncation computation uses `>>> 0` to coerce the result to an unsigned 32-bit integer, preventing negative values when bit 31 is set in the HMAC bytes. Without this fix, certain HMAC outputs would produce negative `bin` values, causing incorrect OTP codes.

**Zero-allocation optimization:** The 8-byte counter buffer (`HOTP_COUNTER_BUF`) is allocated once at module load and reused for every `hotp()` call. This eliminates per-call `Buffer.alloc(8)` overhead and reduces GC pressure during high-frequency OTP generation.

## 2. `base32.js` / `hi-base32` → Native bitwise shift & buffer operations

**Replaced by:** A hand-written RFC 4648 Base32 decoder using the alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`. An `Int8Array(128)` lookup table maps ASCII codes directly to 5-bit values (-1 for invalid), avoiding per-character `String.indexOf()` calls. Each character maps to 5 bits; bits accumulate in a shift register and are flushed 8 at a time into a `Buffer`. Lowercase normalization, padding (`=`) stripping, and whitespace handling are all native string operations. Invalid and non-ASCII characters are rejected with a thrown error.

**Strict trailing-bit validation (RFC 4648 §3.3):** After decoding, any remaining bits (fewer than 8) are checked for non-zero values. If the trailing bits are non-zero, the input is rejected as invalid padding. This prevents silently accepting malformed Base32 strings that would produce incorrect key material.

## 3. `chalk` / `kleur` → Standard ANSI escape sequences

**Replaced by:** Direct ANSI escape codes such as `\x1b[32m` (green), `\x1b[33m` (yellow), `\x1b[31m` (red), `\x1b[36m` (cyan), `\x1b[1m` (bold), and `\x1b[0m` (reset). A small `paint(color, text)` helper wraps strings with color codes. Terminals interpret these sequences natively without any runtime library overhead.

## 4. `commander` / `yargs` → Native `process.argv` parsing

**Replaced by:** Manual parsing of `process.argv.slice(2)`. Positional arguments and sub-commands (`add`, `generate`, `watch`, `list`) are dispatched directly via a standard `switch` dispatcher, keeping execution instantaneous with no parser abstraction.

## 5. `crypto-js` / `dotenv-vault` / `bcrypt` → `node:crypto.pbkdf2Sync` + AES-256-GCM

**Replaced by:** `node:crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')` for key derivation and `node:crypto.createCipheriv('aes-256-gcm', key, iv)` for authenticated encryption. The vault file stores base64-encoded salt, IV, ciphertext, and GCM authentication tag. Key material and decrypted buffers are wiped immediately with `buf.fill(0)` after use.

## 6. `cli-progress` / `ora` → `node:readline` In-Place Single-Line Cursor Buffer Control

**Replaced by:** `readline.cursorTo(process.stdout, 0)` combined with `readline.clearLine(process.stdout, 0)` and carriage return (`\r\x1b[2K`) rewrites.

Instead of redrawing entire screen blocks or causing line-wrapping scroll artifacts in PowerShell, watch mode locks to a single terminal line. The progress bar (`█` and `░`) and countdown timer update strictly in place, dynamically transitioning colors from Green to Yellow to Red as the window reaches expiration.

## 7. `jest` / `mocha` → `node:test` + `node:assert`

**Replaced by:** Node's built-in test runner invoked via `node --test`. Tests use `test(name, fn)` from `node:test` and assertions from `node:assert`. No test framework installation, configuration files, or build transpilation is required.

## 8. `lowdb` / `keyv` → `node:fs` synchronous JSON file read/write

**Replaced by:** `node:fs.readFileSync` and `node:fs.writeFileSync` with `JSON.parse` / `JSON.stringify`. The vault is a single JSON file (`.totp_vault.json`) written with POSIX mode `0o600` (owner read/write only).

## 9. `secure-compare` → `node:crypto.timingSafeEqual`

**Replaced by:** `node:crypto.timingSafeEqual(a, b)` for constant-time comparison during TOTP verification. Both buffers are length-checked first to prevent side-channel timing leaks.

## 10. `moment` / `date-fns` → Native `Date.now()` and Math epoch logic

**Replaced by:** Direct integer arithmetic on epoch time (`Math.floor(Date.now() / 1000 / step)`). An optional software offset environment variable (`TOTP_TIME_OFFSET`) is included to adjust for hardware clock drift without altering operating system clock settings.

## 11. `inquirer` / `prompts` → `node:readline` + raw mode stdin

**Replaced by:** A custom `readPassword()` helper using `process.stdin.setRawMode(true)` that reads keystrokes one at a time, suppresses terminal echo, and handles Enter, Backspace, and termination signals natively.

## 12. `uuid` → `node:crypto.randomUUID`

**Replaced by:** `node:crypto.randomUUID()` when unique identifiers are required, available natively via Node standard library.

## 13. `zxcvbn` → Custom entropy estimation

**Replaced by:** A lightweight `estimatePasswordEntropy()` helper calculating Shannon entropy via character set diversity ($\text{length} \times \log_2(\text{charsetSize})$) to score password strength during vault initialization without pulling in external dictionary packages.
