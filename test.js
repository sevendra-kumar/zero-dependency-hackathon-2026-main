'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const {
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
  CHALLENGE_MAX_FAILURES,
} = require('./index.js');

// ---------------------------------------------------------------------------
// RFC 4226 / RFC 6238 reference test vectors
// ---------------------------------------------------------------------------
const ASCII_SECRET_SHA1 = Buffer.from('12345678901234567890', 'ascii');
const ASCII_SECRET_SHA256 = Buffer.from('12345678901234567890123456789012', 'ascii');
const BASE32_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

// RFC 6238 Appendix B test vectors: [time, 8-digit SHA1, 8-digit SHA256]
const RFC6238_VECTORS = [
  [59, '94287082', '46119246'],
  [1111111109, '07081804', '68084774'],
  [1111111111, '14050471', '67062674'],
  [1234567890, '89005924', '91819424'],
  [2000000000, '69279037', '90698825'],
  [20000000000, '65353130', '77737706'],
];

test('RFC 6238 SHA1 vectors match (8-digit)', () => {
  for (const [t, expected] of RFC6238_VECTORS) {
    const code = totp(ASCII_SECRET_SHA1, { digits: 8, step: 30, algo: 'sha1', time: t * 1000 });
    assert.equal(code, expected, `SHA1 T=${t}`);
  }
});

test('RFC 6238 SHA256 vectors match (8-digit)', () => {
  for (const [t, , expected] of RFC6238_VECTORS) {
    const code = totp(ASCII_SECRET_SHA256, { digits: 8, step: 30, algo: 'sha256', time: t * 1000 });
    assert.equal(code, expected, `SHA256 T=${t}`);
  }
});

test('RFC 6238 6-digit truncation matches last 6 of 8-digit', () => {
  for (const [t, expected8] of RFC6238_VECTORS) {
    const code6 = totp(ASCII_SECRET_SHA1, { digits: 6, step: 30, algo: 'sha1', time: t * 1000 });
    assert.equal(code6, expected8.slice(2), `6-digit T=${t}`);
  }
});

test('RFC 4226 HOTP counter 0 produces 755224', () => {
  const code = hotp(ASCII_SECRET_SHA1, 0, 6, 'sha1');
  assert.equal(code, '755224');
});

test('RFC 4226 HOTP counter 1 produces 287082', () => {
  const code = hotp(ASCII_SECRET_SHA1, 1, 6, 'sha1');
  assert.equal(code, '287082');
});

test('RFC 4226 HOTP counter 5 produces 254676', () => {
  const code = hotp(ASCII_SECRET_SHA1, 5, 6, 'sha1');
  assert.equal(code, '254676');
});

// ---------------------------------------------------------------------------
// Unsigned right shift fix (32-bit signed integer bug)
// ---------------------------------------------------------------------------
test('hotpRaw bin is always non-negative (unsigned right shift)', () => {
  // Test with secrets/counters that produce high-bit-set HMAC bytes
  // The >>> 0 ensures bin never goes negative even when bit 31 is set
  for (let counter = 0; counter < 1000; counter++) {
    const result = hotpRaw(ASCII_SECRET_SHA1, counter, 6, 'sha1');
    assert.ok(result.bin >= 0, `bin negative at counter ${counter}: ${result.bin}`);
    assert.ok(result.bin <= 0x7fffffff, `bin exceeds 31-bit range at counter ${counter}: ${result.bin}`);
  }
});

test('hotpRaw bin is non-negative with SHA-256', () => {
  for (let counter = 0; counter < 1000; counter++) {
    const result = hotpRaw(ASCII_SECRET_SHA256, counter, 6, 'sha256');
    assert.ok(result.bin >= 0, `bin negative at counter ${counter}: ${result.bin}`);
  }
});

test('hotpRaw returns code, hmac, offset, and bin', () => {
  const result = hotpRaw(ASCII_SECRET_SHA1, 0, 6, 'sha1');
  assert.equal(result.code, '755224');
  assert.ok(Buffer.isBuffer(result.hmac));
  assert.equal(result.hmac.length, 20);
  assert.ok(result.offset >= 0 && result.offset <= 15);
  assert.ok(Number.isInteger(result.bin));
});

test('hotpRaw SHA256 produces 32-byte HMAC', () => {
  const result = hotpRaw(ASCII_SECRET_SHA256, 0, 6, 'sha256');
  assert.equal(result.hmac.length, 32);
});

test('totpRaw returns counter and hmac telemetry', () => {
  const result = totpRaw(ASCII_SECRET_SHA1, { time: 59 * 1000, step: 30 });
  assert.equal(result.counter, 1);
  assert.ok(Buffer.isBuffer(result.hmac));
  assert.ok(result.offset >= 0 && result.offset <= 15);
});

test('reused counter buffer does not corrupt across calls', () => {
  const c0 = hotp(ASCII_SECRET_SHA1, 0, 6, 'sha1');
  const c1 = hotp(ASCII_SECRET_SHA1, 1, 6, 'sha1');
  const c0Again = hotp(ASCII_SECRET_SHA1, 0, 6, 'sha1');
  assert.equal(c0, '755224');
  assert.equal(c1, '287082');
  assert.equal(c0Again, '755224');
});

test('rapid sequential calls produce consistent results', () => {
  const results = new Set();
  for (let i = 0; i < 100; i++) {
    results.add(hotp(ASCII_SECRET_SHA1, 42, 6, 'sha1'));
  }
  assert.equal(results.size, 1);
});

// ---------------------------------------------------------------------------
// Base32 decoder tests
// ---------------------------------------------------------------------------
test('Base32 decode matches ASCII secret bytes', () => {
  const decoded = base32Decode(BASE32_SECRET);
  assert.equal(decoded.toString('ascii'), '12345678901234567890');
});

test('Base32 handles lowercase input', () => {
  const lower = base32Decode(BASE32_SECRET.toLowerCase());
  assert.equal(lower.toString('ascii'), '12345678901234567890');
});

test('Base32 handles padding characters', () => {
  const padded = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ====';
  const decoded = base32Decode(padded);
  assert.equal(decoded.toString('ascii'), '12345678901234567890');
});

test('Base32 handles whitespace in input', () => {
  const spaced = 'GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ';
  const decoded = base32Decode(spaced);
  assert.equal(decoded.toString('ascii'), '12345678901234567890');
});

test('Base32 rejects invalid characters', () => {
  assert.throws(() => base32Decode('INVALID!@#$'), /Invalid Base32 character/);
});

test('Base32 rejects 0 and 1 (not in RFC 4648 alphabet)', () => {
  assert.throws(() => base32Decode('0'), /Invalid Base32 character/);
  assert.throws(() => base32Decode('1'), /Invalid Base32 character/);
});

test('Base32 rejects non-ASCII characters', () => {
  assert.throws(() => base32Decode('\u00e9'), /Invalid Base32 character/);
});

test('Base32 encode/decode roundtrip', () => {
  const original = crypto.randomBytes(20);
  const encoded = base32Encode(original);
  const decoded = base32Decode(encoded);
  assert.deepEqual(decoded, original);
});

test('Base32 lookup table is correctly initialized', () => {
  // 'AA' = 00000 00000 = 10 bits, first byte = 00000000 = 0x00
  assert.equal(base32Decode('AA').toString('hex'), '00');
  // 'BA' = 00001 00000 = first byte = 00001000 = 0x08
  assert.equal(base32Decode('BA').toString('hex'), '08');
});

// ---------------------------------------------------------------------------
// Base32 strict trailing-bit validation (RFC 4648 §3.3)
// ---------------------------------------------------------------------------
test('Base32 rejects non-zero trailing padding bits (RFC 4648)', () => {
  // 'AB' = 00000 00001 = 10 bits. First byte = 00000000. Remaining 2 bits = 01 (non-zero).
  // This should be rejected because the trailing bits are non-zero.
  assert.throws(() => base32Decode('AB'), /Non-zero trailing bits/);
});

test('Base32 accepts zero trailing padding bits', () => {
  // 'AA' = 00000 00000 = 10 bits. First byte = 00000000. Remaining 2 bits = 00 (zero).
  // This should be accepted.
  assert.doesNotThrow(() => base32Decode('AA'));
});

test('Base32 rejects non-zero trailing bits in longer strings', () => {
  // 'AAAAAAB' — the last char 'B' leaves 2 trailing bits = 01, non-zero
  assert.throws(() => base32Decode('AAAAAAB'), /Non-zero trailing bits/);
});

test('Base32 accepts valid zero-trailing strings of various lengths', () => {
  // 8 chars = 40 bits = 5 bytes, no trailing bits
  assert.doesNotThrow(() => base32Decode('AAAAAAAA'));
  // 2 chars = 10 bits = 1 byte + 2 trailing bits (zero for 'AA')
  assert.doesNotThrow(() => base32Decode('AA'));
  // 4 chars = 20 bits = 2 bytes + 4 trailing bits (zero for 'AAAA')
  assert.doesNotThrow(() => base32Decode('AAAA'));
});

// ---------------------------------------------------------------------------
// OTP URI parsing (parseOtpAuthUri)
// ---------------------------------------------------------------------------
test('parseOtpAuthUri parses a standard otpauth URI', () => {
  const uri = 'otpauth://totp/GitHub:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30';
  const parsed = parseOtpAuthUri(uri);
  assert.equal(parsed.type, 'totp');
  assert.equal(parsed.accountName, 'user@example.com');
  assert.equal(parsed.issuer, 'GitHub');
  assert.equal(parsed.secret, 'JBSWY3DPEHPK3PXP');
  assert.equal(parsed.algo, 'sha1');
  assert.equal(parsed.digits, 6);
  assert.equal(parsed.step, 30);
});

test('parseOtpAuthUri uses defaults for optional parameters', () => {
  const uri = 'otpauth://totp/myaccount?secret=JBSWY3DPEHPK3PXP';
  const parsed = parseOtpAuthUri(uri);
  assert.equal(parsed.accountName, 'myaccount');
  assert.equal(parsed.algo, 'sha1');
  assert.equal(parsed.digits, 6);
  assert.equal(parsed.step, 30);
  assert.equal(parsed.issuer, '');
});

test('parseOtpAuthUri parses SHA-256 and 8-digit URIs', () => {
  const uri = 'otpauth://totp/secure?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60';
  const parsed = parseOtpAuthUri(uri);
  assert.equal(parsed.algo, 'sha256');
  assert.equal(parsed.digits, 8);
  assert.equal(parsed.step, 60);
});

test('parseOtpAuthUri extracts issuer from label when not in params', () => {
  const uri = 'otpauth://totp/AWS:user@example.com?secret=JBSWY3DPEHPK3PXP';
  const parsed = parseOtpAuthUri(uri);
  assert.equal(parsed.issuer, 'AWS');
  assert.equal(parsed.accountName, 'user@example.com');
});

test('parseOtpAuthUri rejects non-otpauth protocol', () => {
  assert.throws(() => parseOtpAuthUri('https://example.com'), /Expected otpauth/);
});

test('parseOtpAuthUri rejects non-totp type', () => {
  assert.throws(() => parseOtpAuthUri('otpauth://hotp/account?secret=ABC'), /Only 'totp' type/);
});

test('parseOtpAuthUri rejects missing secret', () => {
  assert.throws(() => parseOtpAuthUri('otpauth://totp/account'), /Missing required parameter: secret/);
});

test('parseOtpAuthUri rejects missing label', () => {
  assert.throws(() => parseOtpAuthUri('otpauth://totp/?secret=ABC'), /Missing account label/);
});

test('parseOtpAuthUri rejects unsupported algorithm', () => {
  assert.throws(
    () => parseOtpAuthUri('otpauth://totp/acct?secret=ABC&algorithm=MD5'),
    /Unsupported algorithm/,
  );
});

test('parseOtpAuthUri rejects invalid digits', () => {
  assert.throws(
    () => parseOtpAuthUri('otpauth://totp/acct?secret=ABC&digits=7'),
    /Invalid digits/,
  );
});

test('parseOtpAuthUri rejects invalid period', () => {
  assert.throws(
    () => parseOtpAuthUri('otpauth://totp/acct?secret=ABC&period=45'),
    /Invalid period/,
  );
});

test('parseOtpAuthUri rejects malformed URI', () => {
  assert.throws(() => parseOtpAuthUri('not a url at all'), /Invalid otpauth URI/);
});

test('parseOtpAuthUri handles URL-encoded characters in label', () => {
  const uri = 'otpauth://totp/Acme%20Co%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP';
  const parsed = parseOtpAuthUri(uri);
  assert.equal(parsed.issuer, 'Acme Co');
  assert.equal(parsed.accountName, 'user@example.com');
});

// ---------------------------------------------------------------------------
// TOTP verification and drift tolerance
// ---------------------------------------------------------------------------
test('verifyTotp accepts current code', () => {
  const now = Date.now();
  const code = totp(ASCII_SECRET_SHA1, { time: now });
  const result = verifyTotp(ASCII_SECRET_SHA1, code, { time: now });
  assert.equal(result.valid, true);
  assert.equal(result.driftOffset, 0);
});

test('verifyTotp accepts code from previous window (T-1)', () => {
  const now = Date.now();
  const prevTime = now - 30 * 1000;
  const code = totp(ASCII_SECRET_SHA1, { time: prevTime });
  const result = verifyTotp(ASCII_SECRET_SHA1, code, { time: now });
  assert.equal(result.valid, true);
  assert.equal(result.driftOffset, -1);
});

test('verifyTotp accepts code from next window (T+1)', () => {
  const now = Date.now();
  const nextTime = now + 30 * 1000;
  const code = totp(ASCII_SECRET_SHA1, { time: nextTime });
  const result = verifyTotp(ASCII_SECRET_SHA1, code, { time: now });
  assert.equal(result.valid, true);
  assert.equal(result.driftOffset, 1);
});

test('verifyTotp rejects code outside drift window', () => {
  const now = Date.now();
  const farTime = now + 2 * 30 * 1000;
  const code = totp(ASCII_SECRET_SHA1, { time: farTime });
  const result = verifyTotp(ASCII_SECRET_SHA1, code, { time: now });
  assert.equal(result.valid, false);
  assert.equal(result.driftOffset, null);
});

test('verifyTotp rejects wrong-length code', () => {
  const now = Date.now();
  assert.equal(verifyTotp(ASCII_SECRET_SHA1, '12345', { time: now }).valid, false);
  assert.equal(verifyTotp(ASCII_SECRET_SHA1, '1234567', { time: now }).valid, false);
});

test('verifyTotp rejects non-numeric code', () => {
  const now = Date.now();
  assert.equal(verifyTotp(ASCII_SECRET_SHA1, 'abcdef', { time: now }).valid, false);
});

test('verifyTotp with 8-digit codes', () => {
  const now = Date.now();
  const code = totp(ASCII_SECRET_SHA1, { digits: 8, time: now });
  assert.equal(verifyTotp(ASCII_SECRET_SHA1, code, { digits: 8, time: now }).valid, true);
});

test('verifyTotp respects custom step (60s)', () => {
  const now = Date.now();
  const code = totp(ASCII_SECRET_SHA1, { step: 60, time: now });
  assert.equal(verifyTotp(ASCII_SECRET_SHA1, code, { step: 60, time: now }).valid, true);
  assert.equal(verifyTotp(ASCII_SECRET_SHA1, code, { step: 30, time: now }).valid, false);
});

test('verifyTotp respects custom drift parameter', () => {
  const now = Date.now();
  const farTime = now + 2 * 30 * 1000;
  const code = totp(ASCII_SECRET_SHA1, { time: farTime });
  assert.equal(verifyTotp(ASCII_SECRET_SHA1, code, { time: now, drift: 1 }).valid, false);
  assert.equal(verifyTotp(ASCII_SECRET_SHA1, code, { time: now, drift: 2 }).valid, true);
});

test('verifyTotp drift=0 rejects adjacent windows', () => {
  const now = Date.now();
  const prevTime = now - 30 * 1000;
  const code = totp(ASCII_SECRET_SHA1, { time: prevTime });
  assert.equal(verifyTotp(ASCII_SECRET_SHA1, code, { time: now, drift: 0 }).valid, false);
});

test('verifyTotp reports correct drift offset for T+2', () => {
  const now = Date.now();
  const futureTime = now + 2 * 30 * 1000;
  const code = totp(ASCII_SECRET_SHA1, { time: futureTime });
  const result = verifyTotp(ASCII_SECRET_SHA1, code, { time: now, drift: 3 });
  assert.equal(result.valid, true);
  assert.equal(result.driftOffset, 2);
});

// ---------------------------------------------------------------------------
// Vault encryption (AES-256-GCM + PBKDF2)
// ---------------------------------------------------------------------------
test('encryptVault/decryptVault roundtrip preserves data', () => {
  const data = defaultVaultData();
  addAccount(data, 'test', BASE32_SECRET, { digits: 6, step: 30, algo: 'sha1' });
  const encrypted = encryptVault(data, 'my-password');
  const decrypted = decryptVault(encrypted, 'my-password');
  assert.deepEqual(decrypted, data);
});

test('decryptVault fails with wrong password', () => {
  const data = defaultVaultData();
  addAccount(data, 'test', BASE32_SECRET);
  const encrypted = encryptVault(data, 'correct-password');
  assert.throws(() => decryptVault(encrypted, 'wrong-password'), /decryption failed/);
});

test('decryptVault detects tampered ciphertext', () => {
  const data = defaultVaultData();
  addAccount(data, 'test', BASE32_SECRET);
  const encrypted = encryptVault(data, 'password');
  const tampered = { ...encrypted };
  const buf = Buffer.from(tampered.ciphertext, 'base64');
  buf[0] ^= 0xff;
  tampered.ciphertext = buf.toString('base64');
  assert.throws(() => decryptVault(tampered, 'password'), /decryption failed/);
});

test('decryptVault detects tampered auth tag', () => {
  const data = defaultVaultData();
  addAccount(data, 'test', BASE32_SECRET);
  const encrypted = encryptVault(data, 'password');
  const tampered = { ...encrypted };
  const tag = Buffer.from(tampered.authTag, 'base64');
  tag[0] ^= 0xff;
  tampered.authTag = tag.toString('base64');
  assert.throws(() => decryptVault(tampered, 'password'), /decryption failed/);
});

test('decryptVault detects tampered IV', () => {
  const data = defaultVaultData();
  addAccount(data, 'test', BASE32_SECRET);
  const encrypted = encryptVault(data, 'password');
  const tampered = { ...encrypted };
  const iv = Buffer.from(tampered.iv, 'base64');
  iv[0] ^= 0xff;
  tampered.iv = iv.toString('base64');
  assert.throws(() => decryptVault(tampered, 'password'), /decryption failed/);
});

test('encrypted vault contains required fields', () => {
  const data = defaultVaultData();
  const encrypted = encryptVault(data, 'pw');
  assert.equal(encrypted.cipher, 'aes-256-gcm');
  assert.equal(encrypted.kdf, 'pbkdf2-sha256');
  assert.equal(encrypted.kdfIterations, 100000);
  assert.ok(encrypted.salt);
  assert.ok(encrypted.iv);
  assert.ok(encrypted.authTag);
  assert.ok(encrypted.ciphertext);
});

test('PBKDF2 derives consistent key for same salt', () => {
  const salt = crypto.randomBytes(32);
  const k1 = deriveKey('password', salt);
  const k2 = deriveKey('password', salt);
  assert.deepEqual(k1, k2);
  assert.equal(k1.length, 32);
});

test('PBKDF2 produces different keys for different salts', () => {
  const salt1 = crypto.randomBytes(32);
  const salt2 = crypto.randomBytes(32);
  const k1 = deriveKey('password', salt1);
  const k2 = deriveKey('password', salt2);
  assert.notDeepEqual(k1, k2);
});

test('each encryption uses unique salt and IV', () => {
  const data = defaultVaultData();
  const e1 = encryptVault(data, 'pw');
  const e2 = encryptVault(data, 'pw');
  assert.notEqual(e1.salt, e2.salt);
  assert.notEqual(e1.iv, e2.iv);
});

// ---------------------------------------------------------------------------
// Account management
// ---------------------------------------------------------------------------
test('addAccount stores account with defaults', () => {
  const data = defaultVaultData();
  addAccount(data, 'github', BASE32_SECRET);
  assert.ok(data.accounts.github);
  assert.equal(data.accounts.github.digits, 6);
  assert.equal(data.accounts.github.step, 30);
  assert.equal(data.accounts.github.algo, 'sha1');
});

test('addAccount rejects duplicate name', () => {
  const data = defaultVaultData();
  addAccount(data, 'github', BASE32_SECRET);
  assert.throws(() => addAccount(data, 'github', BASE32_SECRET), /already exists/);
});

test('addAccount rejects invalid secret', () => {
  const data = defaultVaultData();
  assert.throws(() => addAccount(data, 'bad', '!!!invalid!!!'), /Invalid secret/);
});

test('addAccount stores custom options', () => {
  const data = defaultVaultData();
  addAccount(data, 'secure', BASE32_SECRET, { digits: 8, step: 60, algo: 'sha256' });
  assert.equal(data.accounts.secure.digits, 8);
  assert.equal(data.accounts.secure.step, 60);
  assert.equal(data.accounts.secure.algo, 'sha256');
});

test('removeAccount deletes an account', () => {
  const data = defaultVaultData();
  addAccount(data, 'github', BASE32_SECRET);
  removeAccount(data, 'github');
  assert.equal(data.accounts.github, undefined);
});

test('removeAccount throws for non-existent account', () => {
  const data = defaultVaultData();
  assert.throws(() => removeAccount(data, 'nope'), /not found/);
});

test('getAccount returns account data', () => {
  const data = defaultVaultData();
  addAccount(data, 'github', BASE32_SECRET, { digits: 8, step: 60, algo: 'sha256' });
  const acct = getAccount(data, 'github');
  assert.equal(acct.digits, 8);
  assert.equal(acct.step, 60);
  assert.equal(acct.algo, 'sha256');
});

test('getAccount throws for non-existent account', () => {
  const data = defaultVaultData();
  assert.throws(() => getAccount(data, 'nope'), /not found/);
});

// ---------------------------------------------------------------------------
// Password entropy estimation
// ---------------------------------------------------------------------------
test('estimatePasswordEntropy returns 0 for empty password', () => {
  assert.equal(estimatePasswordEntropy(''), 0);
  assert.equal(estimatePasswordEntropy(null), 0);
});

test('estimatePasswordEntropy increases with length and charset', () => {
  const weak = estimatePasswordEntropy('aaaa');
  const medium = estimatePasswordEntropy('Abcd1234');
  const strong = estimatePasswordEntropy('Abcd1234!@#$');
  assert.ok(weak < medium);
  assert.ok(medium < strong);
});

test('entropyLabel classifies correctly', () => {
  assert.equal(entropyLabel(20).label, 'Very Weak');
  assert.equal(entropyLabel(30).label, 'Weak');
  assert.equal(entropyLabel(45).label, 'Fair');
  assert.equal(entropyLabel(70).label, 'Strong');
  assert.equal(entropyLabel(100).label, 'Excellent');
});

// ---------------------------------------------------------------------------
// Progress bar
// ---------------------------------------------------------------------------
test('progressBar produces correct width', () => {
  const bar = progressBar(15, 30, 20);
  assert.equal(bar.length, 20);
  assert.ok(bar.includes('\u2588'));
  assert.ok(bar.includes('\u2591'));
});

test('progressBar full at step boundary', () => {
  const bar = progressBar(30, 30, 10);
  assert.equal(bar, '\u2588'.repeat(10));
});

test('progressBar empty at start', () => {
  const bar = progressBar(0, 30, 10);
  assert.equal(bar, '\u2591'.repeat(10));
});

// ---------------------------------------------------------------------------
// Challenge mode constants
// ---------------------------------------------------------------------------
test('CHALLENGE_MAX_FAILURES is 3', () => {
  assert.equal(CHALLENGE_MAX_FAILURES, 3);
});

// ---------------------------------------------------------------------------
// Performance benchmarks
// ---------------------------------------------------------------------------
test('benchmark: HMAC-SHA1 throughput', () => {
  const iterations = 5000;
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    hotp(ASCII_SECRET_SHA1, i, 6, 'sha1');
  }
  const elapsedNs = Number(process.hrtime.bigint() - start);
  const opsPerSec = Math.round((iterations / elapsedNs) * 1e9);
  assert.ok(opsPerSec > 0);
  process.stdout.write(`\n  HMAC-SHA1: ${opsPerSec.toLocaleString()} ops/sec (${iterations} iterations)\n`);
});

test('benchmark: HMAC-SHA256 throughput', () => {
  const iterations = 5000;
  const start = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    hotp(ASCII_SECRET_SHA256, i, 6, 'sha256');
  }
  const elapsedNs = Number(process.hrtime.bigint() - start);
  const opsPerSec = Math.round((iterations / elapsedNs) * 1e9);
  assert.ok(opsPerSec > 0);
  process.stdout.write(`  HMAC-SHA256: ${opsPerSec.toLocaleString()} ops/sec (${iterations} iterations)\n`);
});

test('benchmark: zero-allocation buffer reuse is faster than per-call alloc', () => {
  const iterations = 5000;
  const startReuse = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    hotp(ASCII_SECRET_SHA1, i, 6, 'sha1');
  }
  const reuseNs = Number(process.hrtime.bigint() - startReuse);

  const startAlloc = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) {
    const buf = Buffer.alloc(8);
    buf.writeBigUInt64BE(BigInt(i));
    crypto.createHmac('sha1', ASCII_SECRET_SHA1).update(buf).digest();
  }
  const allocNs = Number(process.hrtime.bigint() - startAlloc);

  process.stdout.write(`  Buffer reuse: ${(iterations / reuseNs * 1e9).toFixed(0)} ops/sec vs alloc: ${(iterations / allocNs * 1e9).toFixed(0)} ops/sec\n`);
  assert.ok(reuseNs <= allocNs * 1.25, 'Buffer reuse should be at least as fast as per-call allocation');
});
