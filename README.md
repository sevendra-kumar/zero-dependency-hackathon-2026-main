Here is the updated **`README.md`** with all multi-account references (such as `AWS` and side-by-side display) completely removed, focusing solely on the strict single-line, single-account watch mode:

```markdown
# TOTP Vault

A production-grade, **zero-dependency** RFC 6238 TOTP authenticator CLI and encrypted security vault[cite: 1]. Built entirely with the Node.js standard library — no npm packages, no installs, no external downloads[cite: 1].

Track E submission for the **Zero Dependency Hackathon 2026** (Security & Crypto Utilities)[cite: 1].

## Features

- **RFC 6238 TOTP** generation with SHA-1 and SHA-256 support[cite: 1]
- **RFC 4226 HOTP** counter-based codes[cite: 1]
- **RFC 4648 Base32** decoder written from scratch with bitwise operations, lookup table, and strict trailing-bit validation[cite: 1]
- **Zero-allocation HMAC** — reuses a module-level 8-byte counter buffer for every OTP calculation[cite: 1]
- **Unsigned right-shift fix** — `>>> 0` on the dynamic truncation bin ensures codes never evaluate as negative[cite: 1]
- **Timing-safe verification** with configurable ±N window drift tolerance (prevents timing attacks via `crypto.timingSafeEqual`)[cite: 1]
- **AES-256-GCM encrypted vault** using PBKDF2 key derivation (100,000 iterations, SHA-256)[cite: 1]
- **Stationary Single-Line Watch HUD** — locked, in-place live countdown with native console buffer control (`readline.cursorTo`) and smooth dynamic color transitions (Green $\rightarrow$ Yellow $\rightarrow$ Red) without terminal line wrapping or scroll spam
- **Software Time Offset Compensation** — millisecond-accurate visual alignment via `TOTP_TIME_OFFSET`
- **Tamper detection** via GCM authentication tags (ciphertext, IV, and auth tag all verified)[cite: 1]
- **Password entropy meter** displayed during vault creation[cite: 1]

## Installation

None required[cite: 1]. This project has zero runtime dependencies[cite: 1]. You only need Node.js 16+[cite: 1].

```bash
# Verify zero dependencies
npm list --depth=0
cat package.json  # "dependencies": {}

```

## Quick Start

```bash
# Add an account (Base32 secret from your service provider)
node index.js add github JBSWY3DPEHPK3PXP

# Generate the current 6-digit code
node index.js generate github

# List all stored accounts
node index.js list

# Live watch mode — single-line in-place countdown
node index.js watch github

```

## Commands

| Command | Description |
| --- | --- |
| `add <name> <secret> [--digits 6|8] [--step 30|60] [--algo sha1|sha256]` | Add a new account |
| `generate <name>` | Generate the current TOTP code |
| `list` | List all stored accounts |
| `watch [<account>]` | Locked single-line in-place live monitoring HUD |
| `help` | Show help message |

### Environment Variables

* `TOTP_VAULT_PASSWORD` — Provide the vault password non-interactively (useful for scripting)


* `TOTP_TIME_OFFSET` — Adjust internal clock calculation by $\pm N$ milliseconds to align perfectly with hardware drift or external authenticator apps

## Single-Line Live Watch HUD

The `watch` command operates strictly in-place on a **single stationary terminal line**:

```text
GITHUB 652 683 [██████░░] 18s

```

* **No Terminal Scroll:** Uses `readline.cursorTo(0)` and `readline.clearLine(0)` to overwrite the exact same console buffer line, completely preventing duplicate output lines down the screen.
* **Dynamic Color Transitions:** The code, time indicator, and progress bar dynamically shift from **Green** ($\ge 11\text{s}$) to **Yellow** ($6\text{s} - 10\text{s}$) and **Red** ($\le 5\text{s}$).

## Security Architecture

### Vault Encryption

1. **Key Derivation:** The vault password is processed through PBKDF2 with SHA-256, 100,000 iterations, and a random 32-byte salt to produce a 256-bit encryption key.


2. **Encryption:** Vault contents are encrypted with AES-256-GCM using a random 12-byte IV. The GCM mode provides both confidentiality and integrity.


3. **Authentication:** A 128-bit GCM authentication tag is stored alongside the ciphertext. Any tampering with the ciphertext, IV, or auth tag causes decryption to fail.


4. **Memory Hygiene:** Ephemeral key buffers and plaintext records are wiped immediately with `buf.fill(0)` after cryptographic operations.
5. **File Permissions:** The vault file is written with mode `0600` (owner read/write only).



### TOTP Verification

* Codes are compared using `crypto.timingSafeEqual` to prevent timing side-channel attacks.


* Verification accepts codes from configurable time windows (±N drift) to accommodate clock skew.


* Both the candidate and expected codes are converted to equal-length buffers before comparison.



### Unsigned Right-Shift Fix

The dynamic truncation step in HOTP computes a 31-bit integer from 4 HMAC bytes. Without `>>> 0`, JavaScript's signed 32-bit arithmetic can produce a negative value when bit 31 is set. The `>>> 0` unsigned right shift coerces the result to a non-negative 32-bit unsigned integer, guaranteeing correct modulo arithmetic for all possible HMAC outputs.

### Zero-Allocation Buffer Optimization

The `hotp` function reuses a module-level 8-byte `Buffer` (`HOTP_COUNTER_BUF`) for the HMAC counter input instead of allocating new memory on each call. This eliminates GC pressure during high-frequency OTP generation.

## Zero-Dependency Mapping

Every npm package that a conventional project would use is replaced by native Node.js standard-library APIs:

| npm Package | Node.js Standard Library Replacement |
| --- | --- |
| `otplib` / `speakeasy` | `node:crypto.createHmac()` + `Buffer.writeBigUInt64BE()` — HOTP/TOTP from scratch

 |
| `crypto-js` | `node:crypto` — `createCipheriv('aes-256-gcm')`, `pbkdf2Sync()`, `randomBytes()`<br> |
| `base32.js` / `hi-base32` | Bitwise shift & buffer operations with `Int8Array` lookup table

 |
| `chalk` / `kleur` | Raw ANSI escape sequences (`\x1b[...]m`)

 |
| `commander` / `yargs` | Standard `process.argv` parsing dispatcher |
| `cli-progress` / `ora` | `node:readline` (`cursorTo`, `clearLine`) + Unicode progress blocks

 |
| `secure-compare` | `node:crypto.timingSafeEqual()`<br> |
| `inquirer` / `prompts` | `node:readline` + raw-mode stdin for silent password input

 |
| `zxcvbn` | Custom entropy estimation via charset size $\times$ length

 |

See [STDLIB.md](https://www.google.com/search?q=STDLIB.md) for detailed implementation notes on each mapping.

## License

MIT

```

```
