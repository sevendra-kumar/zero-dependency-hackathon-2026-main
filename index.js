#!/usr/bin/env node
'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const readline = require('node:readline');
const url = require('node:url');

const VAULT_FILE = path.join(process.cwd(), '.totp_vault.json');
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_KEYLEN = 32;
const PBKDF2_DIGEST = 'sha256';
const CHALLENGE_MAX_FAILURES = 3;

// ---------------------------------------------------------------------------
// Zero-allocation reusable buffers for HMAC counter computation
// ---------------------------------------------------------------------------
const HOTP_COUNTER_BUF = Buffer.alloc(8);

// ---------------------------------------------------------------------------
// ANSI helpers (replaces chalk/kleur)
// ---------------------------------------------------------------------------
const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  underline: '\x1b[4m',
  blink: '\x1b[5m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  phosphorGreen: '\x1b[38;2;0;255;65m',
  phosphorAmber: '\x1b[38;2;255;176;0m',
  bgBlack: '\x1b[40m',
  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
};

function paint(color, text) {
  return `${ANSI[color]}${text}${ANSI.reset}`;
}

// ---------------------------------------------------------------------------
// Base32 decoder (RFC 4648) — replaces base32.js / hi-base32
// ---------------------------------------------------------------------------
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE32_LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0; i < BASE32_ALPHABET.length; i++) {
  BASE32_LOOKUP[BASE32_ALPHABET.charCodeAt(i)] = i;
}

function base32Decode(input) {
  if (typeof input !== 'string') {
    throw new TypeError('Base32 input must be a string');
  }
  const clean = input.toUpperCase().replace(/[\s=]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i);
    if (code >= 128) {
      throw new Error(`Invalid Base32 character: '${clean[i]}'`);
    }
    const idx = BASE32_LOOKUP[code];
    if (idx === -1) {
      throw new Error(`Invalid Base32 character: '${clean[i]}'`);
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  // RFC 4648 §3.3: trailing padding bits must be zero
  if (bits > 0) {
    const mask = (1 << bits) - 1;
    if ((value & mask) !== 0) {
      throw new Error('Non-zero trailing bits in Base32 input (invalid padding per RFC 4648)');
    }
  }
  return Buffer.from(out);
}

function base32Encode(buffer) {
  const bytes = Buffer.from(buffer);
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(value >> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }
  return out;
}

// ---------------------------------------------------------------------------
// HOTP / TOTP (RFC 4226 / RFC 6238) — replaces otplib / speakeasy
// Zero-allocation: reuses HOTP_COUNTER_BUF for the 8-byte counter
// ---------------------------------------------------------------------------
function hotpRaw(secret, counter, digits = 6, algo = 'sha1') {
  if (!Buffer.isBuffer(secret)) {
    throw new TypeError('secret must be a Buffer');
  }
  if (!Number.isInteger(counter) || counter < 0) {
    throw new TypeError('counter must be a non-negative integer');
  }
  if (digits !== 6 && digits !== 8) {
    throw new RangeError('digits must be 6 or 8');
  }
  // Reuse module-level buffer instead of allocating per call
  HOTP_COUNTER_BUF.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac(algo, secret).update(HOTP_COUNTER_BUF).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    (((hmac[offset] & 0x7f) << 24) |
      (hmac[offset + 1] << 16) |
      (hmac[offset + 2] << 8) |
      hmac[offset + 3]) >>> 0;
  const otp = bin % 10 ** digits;
  return {
    code: otp.toString().padStart(digits, '0'),
    hmac,
    offset,
    bin,
  };
}

function hotp(secret, counter, digits = 6, algo = 'sha1') {
  return hotpRaw(secret, counter, digits, algo).code;
}

function totp(secret, opts = {}) {
  const {
    digits = 6,
    step = 30,
    algo = 'sha1',
    time = Date.now(),
  } = opts;
  if (step <= 0) throw new RangeError('step must be positive');
  const counter = Math.floor(time / 1000 / step);
  return hotp(secret, counter, digits, algo);
}

function totpRaw(secret, opts = {}) {
  const {
    digits = 6,
    step = 30,
    algo = 'sha1',
    time = Date.now(),
  } = opts;
  if (step <= 0) throw new RangeError('step must be positive');
  const counter = Math.floor(time / 1000 / step);
  return { ...hotpRaw(secret, counter, digits, algo), counter };
}

function verifyTotp(secret, code, opts = {}) {
  const {
    digits = 6,
    step = 30,
    algo = 'sha1',
    time = Date.now(),
    drift = 1,
  } = opts;
  if (!/^\d+$/.test(code) || code.length !== digits) {
    return { valid: false, driftOffset: null };
  }
  const counter = Math.floor(time / 1000 / step);
  const expected = Buffer.from(code, 'utf8');
  for (let d = -drift; d <= drift; d++) {
    const candidate = hotp(secret, counter + d, digits, algo);
    const candBuf = Buffer.from(candidate, 'utf8');
    if (
      candBuf.length === expected.length &&
      crypto.timingSafeEqual(candBuf, expected)
    ) {
      return { valid: true, driftOffset: d };
    }
  }
  return { valid: false, driftOffset: null };
}

// ---------------------------------------------------------------------------
// OTP URI parsing (otpauth://) — replaces qrcode/otpauth-uri parsers
// Uses node:url for standards-compliant URL parsing
// ---------------------------------------------------------------------------
function parseOtpAuthUri(uriString) {
  if (typeof uriString !== 'string') {
    throw new TypeError('URI must be a string');
  }
  let parsed;
  try {
    parsed = new url.URL(uriString);
  } catch (err) {
    throw new Error(`Invalid otpauth URI: ${err.message}`);
  }
  if (parsed.protocol !== 'otpauth:') {
    throw new Error(`Expected otpauth:// protocol, got '${parsed.protocol}'`);
  }
  const type = parsed.host.toLowerCase();
  if (type !== 'totp') {
    throw new Error(`Only 'totp' type is supported, got '${type}'`);
  }

  // Label is the pathname without leading slash; may contain encoded chars
  const label = decodeURIComponent(parsed.pathname.slice(1));
  if (!label) {
    throw new Error('Missing account label in otpauth URI');
  }

  // Extract issuer from label if present (format: Issuer:Account or Issuer/Account)
  let issuer = parsed.searchParams.get('issuer') || '';
  let accountName = label;
  if (label.includes(':')) {
    const colonIdx = label.indexOf(':');
    issuer = label.slice(0, colonIdx).trim();
    accountName = label.slice(colonIdx + 1).trim();
  } else if (issuer && label.startsWith(issuer + '/')) {
    accountName = label.slice(issuer.length + 1).trim();
  }

  const secret = parsed.searchParams.get('secret');
  if (!secret) {
    throw new Error('Missing required parameter: secret');
  }

  const algoParam = (parsed.searchParams.get('algorithm') || 'SHA1').toUpperCase();
  const algoMap = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };
  const algo = algoMap[algoParam];
  if (!algo) {
    throw new Error(`Unsupported algorithm: '${algoParam}' (supported: SHA1, SHA256, SHA512)`);
  }

  const digitsParam = parsed.searchParams.get('digits');
  const digits = digitsParam ? parseInt(digitsParam, 10) : 6;
  if (![6, 8].includes(digits)) {
    throw new Error(`Invalid digits: '${digitsParam}' (must be 6 or 8)`);
  }

  const periodParam = parsed.searchParams.get('period');
  const step = periodParam ? parseInt(periodParam, 10) : 30;
  if (![30, 60].includes(step)) {
    throw new Error(`Invalid period: '${periodParam}' (must be 30 or 60)`);
  }

  return { type, label, accountName, issuer, secret, algo, digits, step };
}

// ---------------------------------------------------------------------------
// Encrypted vault — replaces dotenv-vault / bcrypt / lowdb / keyv
// ---------------------------------------------------------------------------
function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(
    password,
    salt,
    PBKDF2_ITERATIONS,
    PBKDF2_KEYLEN,
    PBKDF2_DIGEST,
  );
}

function encryptVault(data, password) {
  const salt = crypto.randomBytes(32);
  const key = deriveKey(password, salt);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(data), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return {
    version: 1,
    kdf: 'pbkdf2-sha256',
    kdfIterations: PBKDF2_ITERATIONS,
    cipher: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
  };
}

function decryptVault(vault, password) {
  if (!vault || typeof vault !== 'object') {
    throw new Error('Invalid vault structure');
  }
  const salt = Buffer.from(vault.salt, 'base64');
  const key = deriveKey(password, salt);
  const iv = Buffer.from(vault.iv, 'base64');
  const authTag = Buffer.from(vault.authTag, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const encrypted = Buffer.from(vault.ciphertext, 'base64');
  let decrypted;
  try {
    decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (err) {
    throw new Error('Vault decryption failed: wrong password or corrupted data');
  }
  return JSON.parse(decrypted.toString('utf8'));
}

function loadVaultFile() {
  if (!fs.existsSync(VAULT_FILE)) {
    return null;
  }
  try {
    return JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8'));
  } catch (err) {
    throw new Error(`Failed to read vault file: ${err.message}`);
  }
}

function saveVaultFile(vault) {
  fs.writeFileSync(VAULT_FILE, JSON.stringify(vault, null, 2), { mode: 0o600 });
}

// ---------------------------------------------------------------------------
// Account management
// ---------------------------------------------------------------------------
function defaultVaultData() {
  return { accounts: {} };
}

function addAccount(data, name, secret, opts = {}) {
  const { digits = 6, step = 30, algo = 'sha1' } = opts;
  if (data.accounts[name]) {
    throw new Error(`Account '${name}' already exists`);
  }
  let keyBuffer;
  try {
    keyBuffer = base32Decode(secret);
  } catch (err) {
    throw new Error(`Invalid secret: ${err.message}`);
  }
  data.accounts[name] = {
    secret: base32Encode(keyBuffer),
    digits,
    step,
    algo,
    createdAt: new Date().toISOString(),
  };
  return data;
}

function removeAccount(data, name) {
  if (!data.accounts[name]) {
    throw new Error(`Account '${name}' not found`);
  }
  delete data.accounts[name];
  return data;
}

function getAccount(data, name) {
  if (!data.accounts[name]) {
    throw new Error(`Account '${name}' not found`);
  }
  return data.accounts[name];
}

// ---------------------------------------------------------------------------
// Password strength estimation (entropy bits) — replaces zxcvbn-lite
// ---------------------------------------------------------------------------
function estimatePasswordEntropy(password) {
  if (!password) return 0;
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
  const entropy = password.length * Math.log2(charsetSize || 1);
  return Math.round(entropy);
}

function entropyLabel(entropy) {
  if (entropy < 28) return { label: 'Very Weak', color: 'red' };
  if (entropy < 36) return { label: 'Weak', color: 'red' };
  if (entropy < 60) return { label: 'Fair', color: 'yellow' };
  if (entropy < 80) return { label: 'Strong', color: 'green' };
  return { label: 'Excellent', color: 'phosphorGreen' };
}

// ---------------------------------------------------------------------------
// Interactive password input (silent, replaces inquirer-style prompts)
// ---------------------------------------------------------------------------
function readPassword(prompt) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const stdout = process.stdout;
    stdout.write(prompt);
    if (stdin.isTTY) {
      stdin.setRawMode(true);
    }
    stdin.resume();
    let pwd = '';
    const onData = (chunk) => {
      const ch = chunk[0];
      if (ch === 0x0d || ch === 0x0a) {
        stdin.removeListener('data', onData);
        if (stdin.isTTY) stdin.setRawMode(false);
        stdin.pause();
        stdout.write('\n');
        resolve(pwd);
      } else if (ch === 0x03 || ch === 0x04) {
        process.stdout.write('\n');
        process.exit(0);
      } else if (ch === 0x7f || ch === 0x08) {
        if (pwd.length > 0) pwd = pwd.slice(0, -1);
      } else if (ch >= 0x20) {
        pwd += chunk.toString('utf8');
      }
    };
    stdin.on('data', onData);
  });
}

async function getVaultPassword(prompt = 'Vault password: ') {
  if (process.env.TOTP_VAULT_PASSWORD) {
    return process.env.TOTP_VAULT_PASSWORD;
  }
  return readPassword(prompt);
}

async function loadAndDecrypt() {
  const vault = loadVaultFile();
  if (!vault) return null;
  const password = await getVaultPassword();
  return decryptVault(vault, password);
}

async function encryptAndSave(data) {
  let password;
  const existing = loadVaultFile();
  if (existing) {
    password = await getVaultPassword();
  } else {
    password = await getVaultPassword('Create vault password: ');
    const confirm = await getVaultPassword('Confirm password: ');
    if (password !== confirm) {
      throw new Error('Passwords do not match');
    }
    const entropy = estimatePasswordEntropy(password);
    const meta = entropyLabel(entropy);
    process.stdout.write(`  Password strength: ${paint(meta.color, meta.label)} (${entropy} bits entropy)\n`);
  }
  const vault = encryptVault(data, password);
  saveVaultFile(vault);
}

// ---------------------------------------------------------------------------
// CLI argument parsing — replaces commander / yargs
// ---------------------------------------------------------------------------
function parseFlags(args) {
  const flags = {};
  const positional = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith('--')) {
        flags[key] = next;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      positional.push(arg);
    }
  }
  return { flags, positional };
}

function printUsage() {
  const lines = [
    '',
    `${paint('bold', 'TOTP Vault')} ${paint('dim', '— zero-dependency RFC 6238 authenticator')}`,
    '',
    paint('cyan', 'USAGE:'),
    '  node index.js <command> [options]',
    '',
    paint('cyan', 'COMMANDS:'),
    `  ${paint('green', 'add')} <name> <secret> [--digits 6|8] [--step 30|60] [--algo sha1|sha256]`,
    `        Add a new account with a Base32 secret.`,
    `  ${paint('green', 'import')} <otpauth-uri>  Import an account from an otpauth:// URI.`,
    `  ${paint('green', 'generate')} <name> [--json]   Generate the current TOTP code.`,
    `  ${paint('green', 'verify')} <name> <code> [--drift N]   Verify a code with N-window drift tolerance.`,
    `  ${paint('green', 'list')} [--json]             List all stored accounts.`,
    `  ${paint('green', 'watch')} [<account>] [--interval N]  Live watch mode (single account shows crypto telemetry).`,
    `  ${paint('green', 'challenge')} <account>      Interactive vault challenge — type codes against the clock.`,
    `  ${paint('green', 'remove')} <name>            Remove an account from the vault.`,
    `  ${paint('green', 'export')}                   Export vault as plain JSON (requires password).`,
    `  ${paint('green', 'help')}                     Show this help message.`,
    '',
    paint('cyan', 'OPTIONS:'),
    '  --digits 6|8       OTP digit count (default: 6)',
    '  --step 30|60       Time step in seconds (default: 30)',
    '  --algo sha1|sha256 HMAC algorithm (default: sha1)',
    '  --drift N          Drift tolerance windows (default: 1)',
    '  --interval N       Watch refresh interval in seconds (default: 1)',
    '  --json             Machine-readable JSON output',
    '',
    paint('cyan', 'ENVIRONMENT:'),
    '  TOTP_VAULT_PASSWORD    Provide vault password non-interactively.',
    '',
  ];
  process.stdout.write(lines.join('\n') + '\n');
}

// ---------------------------------------------------------------------------
// Progress bar renderer
// ---------------------------------------------------------------------------
function progressBar(elapsed, step, width = 24) {
  const pct = elapsed / step;
  const filled = Math.round(pct * width);
  const bar = '\u2588'.repeat(filled) + '\u2591'.repeat(width - filled);
  return bar;
}

// ---------------------------------------------------------------------------
// Command: import (otpauth:// URI)
// ---------------------------------------------------------------------------
async function cmdImport(positional) {
  if (positional.length < 1) {
    throw new Error('Usage: import <otpauth://totp/...>');
  }
  const uriString = positional[0];
  const parsed = parseOtpAuthUri(uriString);
  const name = parsed.accountName || parsed.label;

  let data;
  const existing = loadVaultFile();
  if (existing) {
    const password = await getVaultPassword();
    data = decryptVault(existing, password);
  } else {
    data = defaultVaultData();
  }
  addAccount(data, name, parsed.secret, {
    digits: parsed.digits,
    step: parsed.step,
    algo: parsed.algo,
  });
  await encryptAndSave(data);
  process.stdout.write(
    `${paint('green', '\u2713')} Account '${paint('cyan', name)}' imported from otpauth URI.
` +
    `  ${paint('dim', `Algorithm: ${parsed.algo.toUpperCase()} | Digits: ${parsed.digits} | Period: ${parsed.step}s`)}\n`
  );
}

// ---------------------------------------------------------------------------
// Command: add
// ---------------------------------------------------------------------------
async function cmdAdd(positional, flags) {
  if (positional.length < 2) {
    throw new Error('Usage: add <name> <secret> [--digits 6|8] [--step 30|60] [--algo sha1|sha256]');
  }
  const [name, secret] = positional;
  const digits = flags.digits ? parseInt(flags.digits, 10) : 6;
  const step = flags.step ? parseInt(flags.step, 10) : 30;
  const algo = flags.algo || 'sha1';
  if (![6, 8].includes(digits)) throw new Error('--digits must be 6 or 8');
  if (![30, 60].includes(step)) throw new Error('--step must be 30 or 60');
  if (!['sha1', 'sha256'].includes(algo)) throw new Error('--algo must be sha1 or sha256');

  let data;
  const existing = loadVaultFile();
  if (existing) {
    const password = await getVaultPassword();
    data = decryptVault(existing, password);
  } else {
    data = defaultVaultData();
  }
  addAccount(data, name, secret, { digits, step, algo });
  await encryptAndSave(data);
  process.stdout.write(`${paint('green', '\u2713')} Account '${paint('cyan', name)}' added.\n`);
}

// ---------------------------------------------------------------------------
// Command: generate
// ---------------------------------------------------------------------------
async function cmdGenerate(positional, flags) {
  if (positional.length < 1) throw new Error('Usage: generate <name> [--json]');
  const [name] = positional;
  const data = await loadAndDecrypt();
  if (!data) throw new Error('No vault found. Add an account first.');
  const acct = getAccount(data, name);
  const key = base32Decode(acct.secret);
  const code = totp(key, { digits: acct.digits, step: acct.step, algo: acct.algo });
  const remaining = acct.step - Math.floor((Date.now() / 1000) % acct.step);

  if (flags.json) {
    process.stdout.write(JSON.stringify({
      account: name,
      code,
      digits: acct.digits,
      step: acct.step,
      algo: acct.algo,
      remaining,
      timestamp: Math.floor(Date.now() / 1000),
    }) + '\n');
  } else {
    process.stdout.write(
      `${paint('bold', code)}  ${paint('dim', `(${remaining}s remaining)`)}\n`,
    );
  }
}

// ---------------------------------------------------------------------------
// Command: verify
// ---------------------------------------------------------------------------
async function cmdVerify(positional, flags) {
  if (positional.length < 2) throw new Error('Usage: verify <name> <code> [--drift N]');
  const [name, code] = positional;
  const drift = flags.drift ? parseInt(flags.drift, 10) : 1;
  if (drift < 0 || drift > 10) throw new Error('--drift must be between 0 and 10');

  const data = await loadAndDecrypt();
  if (!data) throw new Error('No vault found. Add an account first.');
  const acct = getAccount(data, name);
  const key = base32Decode(acct.secret);
  const result = verifyTotp(key, code, {
    digits: acct.digits,
    step: acct.step,
    algo: acct.algo,
    drift,
  });
  if (result.valid) {
    const driftStr = result.driftOffset === 0
      ? 'on time'
      : `drift ${result.driftOffset > 0 ? '+' : ''}${result.driftOffset}`;
    process.stdout.write(`${paint('green', '\u2713 Valid')} code for '${name}' (${driftStr}).\n`);
  } else {
    process.stdout.write(`${paint('red', '\u2717 Invalid')} code for '${name}'.\n`);
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------------------
// Command: list
// ---------------------------------------------------------------------------
async function cmdList(flags) {
  const data = await loadAndDecrypt();
  if (!data) {
    if (flags.json) {
      process.stdout.write(JSON.stringify({ accounts: [] }) + '\n');
    } else {
      process.stdout.write(`${paint('yellow', 'No vault found.')}\n`);
    }
    return;
  }
  const names = Object.keys(data.accounts);
  if (flags.json) {
    const list = names.map((name) => ({
      name,
      digits: data.accounts[name].digits,
      step: data.accounts[name].step,
      algo: data.accounts[name].algo,
      createdAt: data.accounts[name].createdAt,
    }));
    process.stdout.write(JSON.stringify({ accounts: list }) + '\n');
    return;
  }
  if (names.length === 0) {
    process.stdout.write(`${paint('dim', 'No accounts stored.')}\n`);
    return;
  }
  process.stdout.write(`\n${paint('bold', 'Stored accounts:')}\n`);
  for (const name of names) {
    const a = data.accounts[name];
    process.stdout.write(
      `  ${paint('cyan', name)}  ${paint('dim', `${a.digits}d \u00b7 ${a.step}s \u00b7 ${a.algo}`)}\n`,
    );
  }
  process.stdout.write('\n');
}

// ---------------------------------------------------------------------------
// Command: remove
// ---------------------------------------------------------------------------
async function cmdRemove(positional) {
  if (positional.length < 1) throw new Error('Usage: remove <name>');
  const [name] = positional;
  const data = await loadAndDecrypt();
  if (!data) throw new Error('No vault found.');
  removeAccount(data, name);
  await encryptAndSave(data);
  process.stdout.write(`${paint('green', '\u2713')} Account '${paint('cyan', name)}' removed.\n`);
}

// ---------------------------------------------------------------------------
// Command: watch (live hacker terminal mode)
// ---------------------------------------------------------------------------
async function cmdWatch(positional, flags) {
  const data = await loadAndDecrypt();
  if (!data) throw new Error('No vault found. Add an account first.');
  const names = Object.keys(data.accounts);
  if (names.length === 0) {
    process.stdout.write(`${paint('dim', 'No accounts stored.')}\n`);
    return;
  }

  const interval = flags.interval ? parseFloat(flags.interval) * 1000 : 1000;
  if (interval < 100) throw new Error('--interval must be at least 0.1 seconds');

  const accountName = positional[0];

  if (accountName) {
    // Single-account telemetry mode
    const acct = getAccount(data, accountName);
    const key = base32Decode(acct.secret);
    const a = { name: accountName, key, digits: acct.digits, step: acct.step, algo: acct.algo };
    await watchSingle(a, interval);
  } else {
    // Overview mode (all accounts)
    const accounts = names.map((name) => {
      const ac = data.accounts[name];
      return { name, key: base32Decode(ac.secret), digits: ac.digits, step: ac.step, algo: ac.algo };
    });
    await watchOverview(accounts, interval);
  }
}

async function watchSingle(acct, interval) {
  const render = () => {
    const now = Date.now();
    const raw = totpRaw(acct.key, { digits: acct.digits, step: acct.step, algo: acct.algo, time: now });
    const elapsed = Math.floor((now / 1000) % acct.step);
    const remaining = acct.step - elapsed;
    const bar = progressBar(elapsed, acct.step);
    const barColor = remaining <= 5 ? 'red' : 'phosphorGreen';
    const codeColor = remaining <= 5 ? 'red' : 'phosphorGreen';
    const ts = Math.floor(now / 1000);
    const hmacHex = raw.hmac.toString('hex');
    const hmacDisplay = hmacHex.length > 40 ? hmacHex.slice(0, 40) + '...' : hmacHex;

    process.stdout.write('\x1b[H\x1b[2J');
    process.stdout.write(ANSI.bgBlack);
    process.stdout.write(`\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u2554' + '\u2550'.repeat(52) + '\u2557')}\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u2551')}  ${paint('bold', 'TOTP VAULT :: LIVE TELEMETRY')}${' '.repeat(23)}${paint('phosphorGreen', '\u2551')}\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u2551')}  Account: ${paint('phosphorAmber', acct.name.padEnd(44))}${paint('phosphorGreen', '\u2551')}\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u2551')}  ${paint('dim', 'UNIX TIMESTAMP')}  ${paint('phosphorGreen', String(ts).padEnd(34))}${paint('phosphorGreen', '\u2551')}\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u2551')}  ${paint('dim', 'TIME COUNTER (T)')}  ${paint('phosphorGreen', String(raw.counter).padEnd(34))}${paint('phosphorGreen', '\u2551')}\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u2551')}  ${paint('dim', 'HMAC DIGEST')}      ${paint('phosphorAmber', hmacDisplay.padEnd(34))}${paint('phosphorGreen', '\u2551')}\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u2551')}  ${paint('dim', 'TRUNC OFFSET')}     ${paint('phosphorAmber', ('0x' + raw.offset.toString(16).padStart(2, '0')).padEnd(34))}${paint('phosphorGreen', '\u2551')}\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u2551')}  ${paint('dim', 'OTP CODE')}          ${paint(codeColor, paint('bold', raw.code.padEnd(34)))}${paint('phosphorGreen', '\u2551')}\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u2551')}  ${paint('dim', 'ALGORITHM')}        ${paint('phosphorGreen', (acct.algo.toUpperCase() + ' / ' + acct.digits + '-digit').padEnd(34))}${paint('phosphorGreen', '\u2551')}\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u2551')}  ${paint(barColor, '[' + bar + ']')} ${paint(barColor, remaining + 's')}${' '.repeat(4)}${paint('phosphorGreen', '\u2551')}\n`);
    process.stdout.write(`  ${paint('phosphorGreen', '\u255a' + '\u2550'.repeat(52) + '\u255d')}\n`);
    process.stdout.write(`\n  ${paint('dim', 'Press Ctrl+C to exit.')}\n`);
    process.stdout.write(ANSI.reset);
  };

  process.stdout.write('\x1b[?25l');
  render();
  const timer = setInterval(render, interval);
  const cleanup = () => {
    clearInterval(timer);
    process.stdout.write('\x1b[?25h\x1b[0m\n');
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

async function watchOverview(accounts, interval) {
  const render = () => {
    process.stdout.write('\x1b[H\x1b[2J');
    process.stdout.write(ANSI.bgBlack);
    process.stdout.write(`\n  ${paint('bold', '\u23f1  TOTP Watch Mode')}  ${paint('dim', new Date().toISOString())}\n\n`);
    for (const acct of accounts) {
      const code = totp(acct.key, { digits: acct.digits, step: acct.step, algo: acct.algo });
      const elapsed = Math.floor((Date.now() / 1000) % acct.step);
      const remaining = acct.step - elapsed;
      const bar = progressBar(elapsed, acct.step, 20);
      const color = remaining <= 5 ? 'red' : 'green';
      process.stdout.write(
        `  ${paint('cyan', acct.name.padEnd(20))} ${paint('bold', code)}  ${paint(color, '[' + bar + ']')} ${paint('dim', remaining + 's')}\n`,
      );
    }
    process.stdout.write(`\n  ${paint('dim', 'Press Ctrl+C to exit.')}\n`);
    process.stdout.write(ANSI.reset);
  };

  process.stdout.write('\x1b[?25l');
  render();
  const timer = setInterval(render, interval);
  const cleanup = () => {
    clearInterval(timer);
    process.stdout.write('\x1b[?25h\x1b[0m\n');
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

// ---------------------------------------------------------------------------
// Command: challenge (interactive vault challenge mode)
// ---------------------------------------------------------------------------
async function cmdChallenge(positional) {
  if (positional.length < 1) throw new Error('Usage: challenge <account>');
  const [name] = positional;
  const data = await loadAndDecrypt();
  if (!data) throw new Error('No vault found. Add an account first.');
  const acct = getAccount(data, name);
  const key = base32Decode(acct.secret);

  let consecutive = 0;
  let failures = 0;
  let bestStreak = 0;
  let totalAttempts = 0;

  process.stdout.write('\x1b[H\x1b[2J');
  process.stdout.write(`\n  ${paint('bold', '\ud83d\udd12 VAULT CHALLENGE MODE')}\n`);
  process.stdout.write(`  ${paint('dim', 'Type the current rolling code before the time step expires.')}\n`);
  process.stdout.write(`  ${paint('dim', 'Account:')} ${paint('cyan', name)}  ${paint('dim', `${acct.digits}d / ${acct.step}s / ${acct.algo.toUpperCase()}`)}\n\n`);

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  const askCode = () => {
    const now = Date.now();
    const elapsed = Math.floor((now / 1000) % acct.step);
    const remaining = acct.step - elapsed;
    const bar = progressBar(elapsed, acct.step, 20);
    const barColor = remaining <= 5 ? 'red' : 'green';

    process.stdout.write(`\r  ${paint(barColor, '[' + bar + ']')} ${paint('dim', remaining + 's remaining')}\n`);
    rl.question(`  ${paint('bold', 'Enter code> ')}`, (answer) => {
      totalAttempts++;
      const code = answer.trim();
      const result = verifyTotp(key, code, {
        digits: acct.digits,
        step: acct.step,
        algo: acct.algo,
        drift: 1,
      });

      if (result.valid) {
        consecutive++;
        if (consecutive > bestStreak) bestStreak = consecutive;
        const driftStr = result.driftOffset === 0
          ? 'on time'
          : `drift ${result.driftOffset > 0 ? '+' : ''}${result.driftOffset}`;
        process.stdout.write(`  ${paint('green', '\u2713 ACCESS GRANTED')} ${paint('dim', '(' + driftStr + ')')}  ${paint('green', 'Streak: ' + consecutive)}\n\n`);
        askCode();
      } else {
        consecutive = 0;
        failures++;
        if (failures >= CHALLENGE_MAX_FAILURES) {
          process.stdout.write(`\n  ${paint('red', '\ud83d\udeab LOCKED OUT')}\n`);
          process.stdout.write(`  ${paint('dim', 'Too many failed attempts.')}\n\n`);
          process.stdout.write(`  ${paint('bold', 'Session summary:')}\n`);
          process.stdout.write(`    Total attempts:  ${totalAttempts}\n`);
          process.stdout.write(`    Best streak:     ${bestStreak}\n`);
          process.stdout.write(`    Failed attempts: ${failures}\n\n`);
          rl.close();
          process.exit(1);
        } else {
          process.stdout.write(`  ${paint('red', '\u2717 ACCESS DENIED')}  ${paint('dim', 'Failed: ' + failures + '/' + CHALLENGE_MAX_FAILURES)}\n\n`);
          askCode();
        }
      }
    });
  };

  askCode();
}

// ---------------------------------------------------------------------------
// Command: export
// ---------------------------------------------------------------------------
async function cmdExport() {
  const data = await loadAndDecrypt();
  if (!data) throw new Error('No vault found.');
  process.stdout.write(JSON.stringify(data, null, 2) + '\n');
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    printUsage();
    return;
  }
  const command = args[0];
  const rest = args.slice(1);
  const { flags, positional } = parseFlags(rest);

  try {
    switch (command) {
      case 'add':
        await cmdAdd(positional, flags);
        break;
      case 'import':
        await cmdImport(positional);
        break;
      case 'generate':
        await cmdGenerate(positional, flags);
        break;
      case 'verify':
        await cmdVerify(positional, flags);
        break;
      case 'list':
        await cmdList(flags);
        break;
      case 'watch':
        await cmdWatch(positional, flags);
        break;
      case 'challenge':
        await cmdChallenge(positional);
        break;
      case 'remove':
        await cmdRemove(positional);
        break;
      case 'export':
        await cmdExport();
        break;
      case 'help':
      case '--help':
      case '-h':
        printUsage();
        break;
      default:
        process.stdout.write(`${paint('red', 'Unknown command:')} ${command}\n`);
        printUsage();
        process.exitCode = 1;
    }
  } catch (err) {
    process.stdout.write(`${paint('red', 'Error:')} ${err.message}\n`);
    process.exitCode = 1;
  }
}

// Export internals for testing
module.exports = {
  base32Decode,
  base32Encode,
  hotp,
  hotpRaw,
  totp,
  totpRaw,
  verifyTotp,
  deriveKey,
  encryptVault,
  decryptVault,
  addAccount,
  removeAccount,
  getAccount,
  defaultVaultData,
  estimatePasswordEntropy,
  entropyLabel,
  progressBar,
  parseOtpAuthUri,
  VAULT_FILE,
  PBKDF2_ITERATIONS,
  CHALLENGE_MAX_FAILURES,
};

// Run CLI only when invoked directly (not required as a module)
if (require.main === module) {
  main();
}
