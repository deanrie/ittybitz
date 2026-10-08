/* ── IttyBitz crypto core — container format, key derivation, decrypt ────
   Kept free of DOM references so the project's regression suite can extract
   this exact block and run it against the historical ciphertext fixtures.
   This block is shared by BOTH shipped files: site/index.html carries it
   followed by crypto-encrypt.js (as <script id="ittybitz-crypto-core">), and
   site/ittybitz-recovery.html carries it alone (as
   <script id="ittybitz-decrypt-core">) — one source, assembled by
   scripts/build-app.mjs, so the two can never drift apart again.

   Wire format, identical to src/lib/crypto.ts:
     IBTZ\x01 || salt(16) || iv(12) || AES-256-GCM ciphertext
   Key derivation: PBKDF2-SHA256 @ 1,000,000 iterations over the UTF-8
   password bytes, with the key file bytes (if any) appended after them.
   v0 (headerless) containers from IttyBitz 1.x still decrypt.

   Password Unicode form: the password is NFC-normalized before encryption,
   because "é" can arrive as U+00E9 (NFC) or "e"+U+0301 (NFD) depending on
   platform and input method, and those are different bytes to PBKDF2.
   Decryption tries NFC first, then — only if the typed string was not
   already NFC — the exact typed bytes, which is how ciphertexts made before
   this normalization were keyed. Every older file still opens.

   The PBKDF2/AES output depends only on (password, key file, salt, iv) — never
   on the CryptoKey's declared usages — so a key derived here with ['encrypt']
   interoperates byte-for-byte with the app's ['encrypt','decrypt'] key.

   If you change anything in this block, `npm run test:crypto` must still pass.
   ───────────────────────────────────────────────────────────────────────── */
var ITTYBITZ_PBKDF2_ITERATIONS = 1000000;
var ITTYBITZ_SALT_LENGTH = 16;
var ITTYBITZ_IV_LENGTH = 12;
var ITTYBITZ_MAGIC = [0x49, 0x42, 0x54, 0x5a]; // "IBTZ"
var ITTYBITZ_VERSION = 1;
var ITTYBITZ_MAX_VERSION = 1;
var ITTYBITZ_MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB
var ITTYBITZ_MAX_PASSWORD_LENGTH = 1024;

function ittybitzFormatVersion(bytes) {
  if (bytes.length < 5) return 0;
  for (var i = 0; i < 4; i++) if (bytes[i] !== ITTYBITZ_MAGIC[i]) return 0;
  return bytes[4];
}

function ittybitzValidatePassword(password) {
  if (typeof password !== 'string') throw new Error('Password must be a string.');
  if (password.length > ITTYBITZ_MAX_PASSWORD_LENGTH) throw new Error('Password is too long.');
  if (password.indexOf('\0') >= 0) throw new Error('Password contains invalid characters.');
}

// Password strings to try on decrypt: NFC first, then the exact typed form if
// it differs. No duplicates, so an already-NFC password costs one PBKDF2 run.
function ittybitzPasswordCandidates(password) {
  var nfc = password.normalize('NFC');
  return nfc === password ? [password] : [nfc, password];
}

async function ittybitzDeriveKey(password, salt, keyFileBytes, usages) {
  var pw = new TextEncoder().encode(password);
  var material;
  if (keyFileBytes && keyFileBytes.length) {
    material = new Uint8Array(pw.length + keyFileBytes.length);
    material.set(pw, 0);
    material.set(keyFileBytes, pw.length);
  } else {
    material = pw;
  }
  var base = await crypto.subtle.importKey('raw', material, { name: 'PBKDF2' }, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: ITTYBITZ_PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    usages
  );
}


/**
 * Decrypt an IttyBitz container (v0 legacy or v1).
 * @param {Uint8Array} bytes     raw container bytes
 * @param {string}     password
 * @param {Uint8Array|null} keyFileBytes
 * @returns {Promise<Uint8Array>} plaintext bytes
 */
async function ittybitzDecrypt(bytes, password, keyFileBytes) {
  if (!bytes || !bytes.length) throw new Error('No data to decrypt.');
  ittybitzValidatePassword(password);

  var version = ittybitzFormatVersion(bytes);
  if (version > ITTYBITZ_MAX_VERSION) {
    throw new Error('This file was encrypted with a newer version of IttyBitz than this tool understands.');
  }
  var offset = version >= 1 ? 5 : 0;

  var headerEnd = offset + ITTYBITZ_SALT_LENGTH + ITTYBITZ_IV_LENGTH;
  if (bytes.length <= headerEnd) throw new Error('Invalid encrypted data format — file is too short.');

  var salt = bytes.slice(offset, offset + ITTYBITZ_SALT_LENGTH);
  var iv = bytes.slice(offset + ITTYBITZ_SALT_LENGTH, headerEnd);
  var ciphertext = bytes.slice(headerEnd);

  var candidates = ittybitzPasswordCandidates(password);
  for (var c = 0; c < candidates.length; c++) {
    var key = await ittybitzDeriveKey(candidates[c], salt, keyFileBytes, ['decrypt']);
    try {
      var plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ciphertext);
      return new Uint8Array(plain);
    } catch (e) {
      if (c === candidates.length - 1) throw e; // same DOMException as before
    }
  }
}
