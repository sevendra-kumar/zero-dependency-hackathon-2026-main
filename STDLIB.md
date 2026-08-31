# STDLIB.md — Standard Library Mapping

This document maps popular third-party npm packages to the native Node.js standard-library functionality used to replace them in this zero-dependency project.

## 1. `otplib` / `speakeasy` → `node:crypto` HMAC + BigUInt64BE

**Replaced by:** `node:crypto.createHmac('sha1' | 'sha256', key)` combined with a module-level `Buffer.alloc(8)` and `buf.writeBigUInt64BE(BigInt(counter))`.

The HOTP/TOTP algorithm is implemented from scratch per RFC 4226 and RFC 6238. A big-endian 8-byte counter buffer is fed into an HMAC, the result is dynamically truncated using the last nibble as an offset, and the 31-bit binary value is reduced modulo `10^digits`.

**Unsigned right-shift fix:** The dynamic truncation computation uses `>>> 0` to coerce the result to an unsigned 32-bit integer, preventing negative values when bit 31 is set in the HMAC bytes. Without this fix, certain HMAC outputs would produce negative `bin` values, causing incorrect OTP codes.

**Zero-allocation optimization:** The 8-byte counter buffer (`HOTP_COUNTER_BUF`) is allocated once at module load and reused for every `hotp()` call. This eliminates per-call `Buffer.alloc(8)` overhead and reduces GC pressure during high-frequency OTP generation (watch mode, benchmarks, challenge mode).

## 2. `base32.js` / `hi-base32` → Native bitwise shift & buffer operations

**Replaced by:** A hand-written RFC 4648 Base32 decoder using the alphabet `ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`. An `Int8Array(128)` lookup table maps ASCII codes directly to 5-bit values (-1 for invalid), avoiding per-character `String.indexOf()` calls. Each character maps to 5 bits; bits accumulate in a shift register and are flushed 8 at a time into a `Buffer`. Lowercase normalization, padding (`=`) stripping, and whitespace handling are all native string operations. Invalid and non-ASCII characters are rejected with a thrown error.

**Strict trailing-bit validation (RFC 4648 §3.3):** After decoding, any remaining bits (fewer than 8) are checked for non-zero values. If the trailing bits are non-zero, the input is rejected as invalid padding. This prevents silently accepting malformed Base32 strings that would produce incorrect key material.

## 3. `chalk` / `kleur` → Standard ANSI escape sequences

**Replaced by:** Direct ANSI escape codes such as `\x1b[32m` (green), `\x1b[36m` (cyan), `\x1b[1m` (bold), and `\x1b[0m` (reset). A small `paint(color, text)` helper wraps strings with color codes. The watch mode also uses 24-bit true color codes (`\x1b[38;2;0;255;65m`) for phosphor green and amber effects. No runtime dependency is needed — terminals interpret these sequences natively.

## 4. `commander` / `yargs` → Native `process.argv` parsing

**Replaced by:** Manual parsing of `process.argv.slice(2)`. A `parseFlags()` function separates positional arguments from `--flag value` pairs. The command is the first positional argument; a `switch` statement dispatches to the appropriate handler. This keeps the CLI lightweight and avoids the abstraction overhead of a full argument-parsing framework.

## 5. `crypto-js` / `dotenv-vault` / `bcrypt` → `node:crypto.pbkdf2Sync` + AES-256-GCM

**Replaced by:** `node:crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256')` for key derivation and `node:crypto.createCipheriv('aes-256-gcm', key, iv)` for authenticated encryption. The vault file stores base64-encoded salt, IV, ciphertext, and GCM authentication tag. `bcrypt` is not needed because PBKDF2 with 100,000 iterations provides comparable password-based key derivation using only the standard library. `crypto-js` is not needed because `node:crypto` provides all required primitives natively.

## 6. `cli-progress` → ANSI carriage return redraw loop with `setInterval`

**Replaced by:** A `setInterval(render, interval)` loop that writes `\x1b[H\x1b[2J` to clear the screen and re-renders progress bars using `\u2588` (filled) and `\u2591` (empty) characters. The bar width is calculated from the elapsed fraction of the TOTP step window. Color shifts to red when the remaining time drops below 5 seconds. The `--interval` flag allows custom refresh rates.

## 7. `jest` / `mocha` → `node:test` + `node:assert`

**Replaced by:** Node's built-in test runner invoked via `node --test test.js`. Tests use `test(name, fn)` from `node:test` and `assert.equal` / `assert.throws` / `assert.deepEqual` / `assert.ok` from `node:assert`. No test framework installation, configuration files, or Babel transpilation is required. The test suite includes performance benchmarks using `process.hrtime.bigint()` for nanosecond-precision timing.

## 8. `lowdb` / `keyv` → `node:fs` synchronous JSON file read/write

**Replaced by:** `node:fs.readFileSync` and `node:fs.writeFileSync` with `JSON.parse` / `JSON.stringify`. The vault is a single JSON file (`.totp_vault.json`) written with mode `0o600` (owner read/write only). This provides simple, atomic-enough persistence for a CLI tool without a database abstraction layer.

## 9. `secure-compare` → `node:crypto.timingSafeEqual`

**Replaced by:** `node:crypto.timingSafeEqual(a, b)` for constant-time string comparison during TOTP verification. Both buffers are length-checked first (returning `false` on mismatch rather than throwing) and then compared with `timingSafeEqual` to prevent timing side-channel attacks that could leak information about valid codes. The `verifyTotp` function iterates through drift windows (T-N through T+N) and uses `timingSafeEqual` for each comparison, ensuring no timing difference between valid and invalid attempts.

## 10. `moment` / `date-fns` → Native `Date.now()` and Math epoch logic

**Replaced by:** `Date.now()` returns milliseconds since the Unix epoch. The TOTP counter is derived via `Math.floor(Date.now() / 1000 / step)`. Remaining time within a window is computed as `step - Math.floor((Date.now() / 1000) % step)`. All time logic is simple integer arithmetic on the epoch — no date formatting library is needed.

## 11. `inquirer` / `prompts` → `node:readline` + raw mode stdin

**Replaced by:** A custom `readPassword()` helper that sets `process.stdin` to raw mode, reads keystrokes one at a time, suppresses echo, and handles Enter, Backspace, Ctrl-C, and Ctrl-D. This provides silent password input without any interactive prompt library. The `challenge` command uses `node:readline.createInterface()` for interactive code input with visible echo.

## 12. `uuid` → `node:crypto.randomUUID`

**Replaced by:** `node:crypto.randomUUID()` when unique identifiers are needed. Available natively since Node 14.17 with no external dependency required.

## 13. `zxcvbn` → Custom entropy estimation

**Replaced by:** A custom `estimatePasswordEntropy()` function that calculates Shannon entropy as `password.length * log2(charsetSize)`, where charset size is determined by the presence of lowercase, uppercase, digits, and special characters. The `entropyLabel()` function maps entropy bits to human-readable labels (Very Weak, Weak, Fair, Strong, Excellent) with corresponding ANSI colors. This provides instant feedback during vault creation without the 400KB `zxcvbn` library.

## 14. `otpauth-uri` / `query-string` → `node:url`

**Replaced by:** The native `node:url` module's `URL` class and `URLSearchParams` API. The `parseOtpAuthUri()` function constructs a `new URL(uriString)` to parse the `otpauth://totp/...` format, then uses `parsed.pathname` for the label and `parsed.searchParams.get()` for query parameters (secret, algorithm, digits, period, issuer). URL-encoded characters in the label are handled via `decodeURIComponent()`. This replaces dedicated OTP URI parsing libraries and query-string utilities with the standards-compliant built-in URL parser.
