/* ── IttyBitz crypto core — encrypt ──────────────────────────────────────
   Appended after crypto-core.js in site/index.html only; the recovery tool is
   decrypt-only and never carries this. Depends on the constants and
   ittybitzDeriveKey() defined there.
   ───────────────────────────────────────────────────────────────────────── */
/**
 * Encrypt bytes into an IttyBitz v1 container.
 * @param {Uint8Array} bytes     plaintext bytes
 * @param {string}     password
 * @param {Uint8Array|null} keyFileBytes
 * @returns {Promise<Uint8Array>} IBTZ\x01 || salt || iv || ciphertext
 */
async function ittybitzEncrypt(bytes, password, keyFileBytes) {
  if (!bytes || !bytes.length) throw new Error('Cannot process empty data.');
  if (bytes.length > ITTYBITZ_MAX_FILE_SIZE) {
    throw new Error('File is too large. Maximum size is ' + (ITTYBITZ_MAX_FILE_SIZE / 1024 / 1024) + 'MB.');
  }
  if (!password) throw new Error('A password is required for encryption.');
  ittybitzValidatePassword(password);

  var salt = crypto.getRandomValues(new Uint8Array(ITTYBITZ_SALT_LENGTH));
  var iv = crypto.getRandomValues(new Uint8Array(ITTYBITZ_IV_LENGTH));
  var key = await ittybitzDeriveKey(password.normalize('NFC'), salt, keyFileBytes, ['encrypt']);
  var ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, bytes));

  var out = new Uint8Array(5 + salt.length + iv.length + ct.length);
  out[0] = ITTYBITZ_MAGIC[0];
  out[1] = ITTYBITZ_MAGIC[1];
  out[2] = ITTYBITZ_MAGIC[2];
  out[3] = ITTYBITZ_MAGIC[3];
  out[4] = ITTYBITZ_VERSION;
  out.set(salt, 5);
  out.set(iv, 5 + salt.length);
  out.set(ct, 5 + salt.length + iv.length);
  return out;
}
