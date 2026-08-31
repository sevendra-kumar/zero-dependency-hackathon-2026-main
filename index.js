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

let GLOBAL_TIME_OFFSET_MS = parseInt(process.env.TOTP_TIME_OFFSET || '0', 10);
const HOTP_COUNTER_BUF = Buffer.alloc(8);

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  cyan: '\x1b[36m',
  phosphorGreen: '\x1b[38;2;0;255;65m',
  phosphorAmber: '\x1b[38;2;255;176;0m',
};

function paint(color, text) {
  return `${ANSI[color] || ''}${text}${ANSI.reset}`;
}

function wipeBuffer(buf) {
  if (Buffer.isBuffer(buf)) buf.fill(0);
}

// ---------------------------------------------------------------------------
// Base32 Codec (RFC 4648)
// ---------------------------------------------------------------------------
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE32_LOOKUP = new Int8Array(128).fill(-1);
for (let i = 0; i < BASE32_ALPHABET.length; i++) {
  BASE32_LOOKUP[BASE32_ALPHABET.charCodeAt(i)] = i;
}

function base32Decode(input) {
  if (typeof input !== 'string') throw new TypeError('Base32 input must be a string');
  const clean = input.toUpperCase().replace(/[\s=]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (let i = 0; i < clean.length; i++) {
    const code = clean.charCodeAt(i);
    if (code >= 128 || BASE32_LOOKUP[code] === -1) {
      throw new Error(`Invalid Base32 character: '${clean[i]}'`);
    }
    value = (value << 5) | BASE32_LOOKUP[code];
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >> bits) & 0xff);
    }
  }
  if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) {
    throw new Error('Non-zero trailing bits in Base32 input (invalid padding per RFC 4648)');
  }
  return Buffer.from(out);
}

function base32Encode(buffer) {
  const bytes = Buffer.from(buffer);
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(value >> bits) & 0x1f];
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  return out;
}

// ---------------------------------------------------------------------------
// HOTP / TOTP Engine (RFC 4226 / RFC 6238)
// ---------------------------------------------------------------------------
function hotpRaw(secret, counter, digits = 6, algo = 'sha1') {
  if (!Buffer.isBuffer(secret)) throw new TypeError('secret must be a Buffer');
  if (!Number.isInteger(counter) || counter < 0) throw new TypeError('counter must be a non-negative integer');
  if (digits !== 6 && digits !== 8) throw new RangeError('digits must be 6 or 8');

  HOTP_COUNTER_BUF.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac(algo.toLowerCase(), secret).update(HOTP_COUNTER_BUF).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const bin =
    (((hmac[offset] & 0x7f) << 24) |
      (hmac[offset + 1] << 16) |
      (hmac[offset + 2] << 8) |
      hmac[offset + 3]) >>> 0;
  const otp = bin % 10 ** digits;
  return { code: otp.toString().padStart(digits, '0'), hmac, offset, bin };
}

function hotp(secret, counter, digits = 6, algo = 'sha1') {
  return hotpRaw(secret, counter, digits, algo).code;
}

function totp(secret, opts = {}) {
  const { digits = 6, step = 30, algo = 'sha1', time = Date.now() + GLOBAL_TIME_OFFSET_MS } = opts;
  if (step <= 0) throw new RangeError('step must be positive');
  const counter = Math.floor(time / 1000 / step);
  return hotp(secret, counter, digits, algo);
}

function totpRaw(secret, opts = {}) {
  const { digits = 6, step = 30, algo = 'sha1', time = Date.now() + GLOBAL_TIME_OFFSET_MS } = opts;
  if (step <= 0) throw new RangeError('step must be positive');
  const counter = Math.floor(time / 1000 / step);
  return { ...hotpRaw(secret, counter, digits, algo), counter };
}

function verifyTotp(secret, code, opts = {}) {
  const { digits = 6, step = 30, algo = 'sha1', time = Date.now() + GLOBAL_TIME_OFFSET_MS, drift = 1 } = opts;
  if (!/^\d+$/.test(code) || code.length !== digits) return { valid: false, driftOffset: null };
  const currentCounter = Math.floor(time / 1000 / step);
  const expected = Buffer.from(code, 'utf8');

  for (let d = -drift; d <= drift; d++) {
    const candidate = Buffer.from(hotp(secret, currentCounter + d, digits, algo), 'utf8');
    if (candidate.length === expected.length && crypto.timingSafeEqual(candidate, expected)) {
      return { valid: true, driftOffset: d };
    }
  }
  return { valid: false, driftOffset: null };
}

function parseOtpAuthUri(uriString) {
  if (typeof uriString !== 'string') throw new TypeError('URI must be a string');
  let parsed;
  try {
    parsed = new url.URL(uriString);
  } catch (err) {
    throw new Error(`Invalid otpauth URI: ${err.message}`);
  }
  if (parsed.protocol !== 'otpauth:') throw new Error(`Expected otpauth:// protocol, got '${parsed.protocol}'`);
  const type = parsed.host.toLowerCase();
  if (type !== 'totp') throw new Error(`Only 'totp' type is supported, got '${type}'`);

  const label = decodeURIComponent(parsed.pathname.slice(1));
  if (!label) throw new Error('Missing account label in otpauth URI');

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
  if (!secret) throw new Error('Missing required parameter: secret');

  const algoParam = (parsed.searchParams.get('algorithm') || 'SHA1').toUpperCase();
  const algoMap = { SHA1: 'sha1', SHA256: 'sha256', SHA512: 'sha512' };
  const algo = algoMap[algoParam];
  if (!algo) throw new Error(`Unsupported algorithm: '${algoParam}' (supported: SHA1, SHA256, SHA512)`);

  const digitsParam = parsed.searchParams.get('digits');
  const digits = digitsParam ? parseInt(digitsParam, 10) : 6;
  if (![6, 8].includes(digits)) throw new Error(`Invalid digits: '${digitsParam}' (must be 6 or 8)`);

  const periodParam = parsed.searchParams.get('period');
  const step = periodParam ? parseInt(periodParam, 10) : 30;
  if (![30, 60].includes(step)) throw new Error(`Invalid period: '${periodParam}' (must be 30 or 60)`);

  return { type, label, accountName, issuer, secret, algo, digits, step };
}

// ---------------------------------------------------------------------------
// Vault & Cryptography
// ---------------------------------------------------------------------------
function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, PBKDF2_DIGEST);
}

function encryptVault(data, password) {
  const salt = crypto.randomBytes(32);
  const key = deriveKey(password, salt);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(data), 'utf8');
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();

  wipeBuffer(key);
  wipeBuffer(plaintext);

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
  if (!vault || typeof vault !== 'object') throw new Error('Invalid vault structure');
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
    wipeBuffer(key);
    throw new Error('Vault decryption failed: wrong password or corrupted data');
  }

  wipeBuffer(key);
  const result = JSON.parse(decrypted.toString('utf8'));
  wipeBuffer(decrypted);
  return result;
}

function loadVaultFile() {
  if (!fs.existsSync(VAULT_FILE)) return null;
  return JSON.parse(fs.readFileSync(VAULT_FILE, 'utf8'));
}

function saveVaultFile(vault) {
  fs.writeFileSync(VAULT_FILE, JSON.stringify(vault, null, 2), { mode: 0o600 });
}

function defaultVaultData() {
  return { accounts: {} };
}

function addAccount(data, name, secret, opts = {}) {
  const { digits = 6, step = 30, algo = 'sha1' } = opts;
  if (data.accounts[name]) throw new Error(`Account '${name}' already exists`);
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
  if (!data.accounts[name]) throw new Error(`Account '${name}' not found`);
  delete data.accounts[name];
  return data;
}

function getAccount(data, name) {
  if (!data.accounts[name]) throw new Error(`Account '${name}' not found`);
  return data.accounts[name];
}

function estimatePasswordEntropy(password) {
  if (!password) return 0;
  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) charsetSize += 32;
  return Math.round(password.length * Math.log2(charsetSize || 1));
}

function entropyLabel(entropy) {
  if (entropy < 28) return { label: 'Very Weak', color: 'red' };
  if (entropy < 36) return { label: 'Weak', color: 'red' };
  if (entropy < 60) return { label: 'Fair', color: 'yellow' };
  if (entropy < 80) return { label: 'Strong', color: 'green' };
  return { label: 'Excellent', color: 'green' };
}

function readPassword(prompt) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const stdout = process.stdout;
    stdout.write(prompt);
    if (stdin.isTTY) stdin.setRawMode(true);
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
  if (process.env.TOTP_VAULT_PASSWORD) return process.env.TOTP_VAULT_PASSWORD;
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
    if (password !== confirm) throw new Error('Passwords do not match');
    const entropy = estimatePasswordEntropy(password);
    const meta = entropyLabel(entropy);
    process.stdout.write(`  Password strength: ${paint(meta.color, meta.label)} (${entropy} bits entropy)\n`);
  }
  const vault = encryptVault(data, password);
  saveVaultFile(vault);
}

function progressBar(elapsed, step, width = 8) {
  const pct = Math.min(1, Math.max(0, elapsed / step));
  const filled = Math.round(pct * width);
  return '█'.repeat(filled) + '░'.repeat(Math.max(0, width - filled));
}

// ---------------------------------------------------------------------------
// Single-Line Locked Watch HUD
// ---------------------------------------------------------------------------
async function cmdWatch(positional) {
  const data = await loadAndDecrypt();
  if (!data) throw new Error('No vault found.');
  const names = Object.keys(data.accounts);
  if (names.length === 0) return process.stdout.write('No accounts found.\n');

  const selectedName = positional[0] || names[0];
  if (!data.accounts[selectedName]) throw new Error(`Account '${selectedName}' not found`);

  const acct = {
    name: selectedName,
    key: base32Decode(data.accounts[selectedName].secret),
    ...data.accounts[selectedName],
  };

  if (process.stdout.isTTY) process.stdout.write('\x1b[?25l');

  const render = () => {
    const now = Date.now() + GLOBAL_TIME_OFFSET_MS;
    const code = totp(acct.key, { digits: acct.digits, step: acct.step, algo: acct.algo, time: now });
    const formattedCode = code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code;
    const elapsed = Math.floor((now / 1000) % acct.step);
    const remaining = acct.step - elapsed;
    const bar = progressBar(elapsed, acct.step, 8);

    let color = 'green';
    if (remaining <= 5) color = 'red';
    else if (remaining <= 10) color = 'yellow';

    const output = `${paint('bold', acct.name.toUpperCase())} ${paint(color, formattedCode)} ${paint(color, `[${bar}] ${remaining}s`)}`;

    if (process.stdout.isTTY) {
      readline.cursorTo(process.stdout, 0);
      readline.clearLine(process.stdout, 0);
    }
    process.stdout.write(`\r\x1b[2K${output}`);
  };

  render();
  const timer = setInterval(render, 1000);

  const cleanup = () => {
    clearInterval(timer);
    if (process.stdout.isTTY) {
      readline.cursorTo(process.stdout, 0);
      process.stdout.write('\x1b[?25h');
    }
    process.stdout.write('\n');
    process.exit(0);
  };
  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
}

// ---------------------------------------------------------------------------
// CLI Handlers
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

async function cmdAdd(positional, flags) {
  if (positional.length < 2) throw new Error('Usage: add <name> <secret> [--digits 6|8] [--step 30|60] [--algo sha1|sha256]');
  const [name, secret] = positional;
  const digits = flags.digits ? parseInt(flags.digits, 10) : 6;
  const step = flags.step ? parseInt(flags.step, 10) : 30;
  const algo = flags.algo || 'sha1';
  let data = (await loadAndDecrypt()) || defaultVaultData();
  addAccount(data, name, secret, { digits, step, algo });
  await encryptAndSave(data);
  process.stdout.write(`${paint('green', '\u2713')} Account '${paint('cyan', name)}' added.\n`);
}

async function cmdGenerate(positional, flags) {
  if (positional.length < 1) throw new Error('Usage: generate <name> [--json]');
  const [name] = positional;
  const data = await loadAndDecrypt();
  if (!data) throw new Error('No vault found.');
  const acct = getAccount(data, name);
  const code = totp(base32Decode(acct.secret), { digits: acct.digits, step: acct.step, algo: acct.algo });
  if (flags.json) {
    process.stdout.write(JSON.stringify({ account: name, code }) + '\n');
  } else {
    process.stdout.write(`${code}\n`);
  }
}

async function cmdList(flags) {
  const data = await loadAndDecrypt();
  if (!data) return process.stdout.write('No vault found.\n');
  const names = Object.keys(data.accounts);
  if (flags.json) {
    process.stdout.write(JSON.stringify({ accounts: names }) + '\n');
    return;
  }
  for (const name of names) {
    const a = data.accounts[name];
    process.stdout.write(`  ${paint('cyan', name)}  ${paint('dim', `${a.digits}d · ${a.step}s · ${a.algo}`)}\n`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];
  const { flags, positional } = parseFlags(args.slice(1));

  try {
    switch (command) {
      case 'add': await cmdAdd(positional, flags); break;
      case 'generate': await cmdGenerate(positional, flags); break;
      case 'watch': await cmdWatch(positional); break;
      case 'list': await cmdList(flags); break;
      default:
        process.stdout.write('Usage: node index.js [add|generate|watch|list]\n');
    }
  } catch (err) {
    process.stdout.write(`${paint('red', 'Error:')} ${err.message}\n`);
    process.exitCode = 1;
  }
}

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
  wipeBuffer,
  VAULT_FILE,
  PBKDF2_ITERATIONS,
  CHALLENGE_MAX_FAILURES,
};

if (require.main === module) {
  main();
}
