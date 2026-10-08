# Security Policy

## Reporting a vulnerability

**Please don't open a public issue for a security problem.**

Report it privately:

1. **[Open a private security advisory](https://github.com/seQRets/ittybitz/security/advisories/new)** — preferred
2. Or email **security@seqrets.app**

Machine-readable contact details are published at
[`/.well-known/security.txt`](https://ittybitz.app/.well-known/security.txt),
per [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).

Include what you did, what happened, what you expected instead, and your browser
and version. For a decryption fault, a ciphertext that reproduces it is the most
useful thing you can send — **made with a throwaway password and throwaway data,
never with anything real**.

You should get an acknowledgement within a week.

## Before you report

Check that the copy you loaded matches what was published. Every
[release](https://github.com/seQRets/ittybitz/releases) ships `SHA256SUMS.txt`
beside `ittybitz.html` and `ittybitz-recovery.html`, and the same values are in
this repository's `SHA256SUMS.txt`:

```
shasum -a 256 -c SHA256SUMS.txt
```

If it does not say `OK`, include that — a mismatch is significant on its own,
and tells us whether the fault is in the project or in an altered copy.

Then run `npm run test:crypto` on a clone. It replays real ciphertexts from
every release since v1.0 through the current code; if any of them fails to
decrypt, that is a finding in itself.

## Scope

This project is two self-contained HTML files. There is no backend, no
database, no accounts, no cookies and no network call, so the surface is narrow
and the things that matter are specific.

**In scope**

- Anything that lets a ciphertext be decrypted without the password (and key
  file, if one was used), or weakens AES-256-GCM / PBKDF2 as the page applies
  them
- Anything that weakens the randomness behind the salt, the IV, the password
  generator or the key-file generator
- A ciphertext produced by any released version that the current version, or
  the recovery tool, no longer decrypts
- Anything that causes either page to make a network request
- Anything that causes a password, key file, plaintext or decrypted output to be
  stored, logged, or leave the page
- A wrong BIP-39 validation, SeedQR or master fingerprint — a QR that scans
  cleanly into the **wrong** wallet is silent and unrecoverable
- The QR encoding a different string than the one shown
- A secret readable while the blur reports it hidden (beyond the documented
  limits below)
- Injection through any input field or filename
- A stale or wrong CSP hash that lets an altered inline script run

**Out of scope**

- Browser extensions being able to read the page. This is documented, is true
  of every web page, and cannot be fixed from inside one — it is why the
  guidance is to run the file offline in a browser profile with no extensions.
- A compromised machine, keylogger, or screen recorder
- Memory not being erased after use — JavaScript cannot guarantee that, and
  the README says so; the erasure is best-effort by design
- The clipboard being readable by other programs after Copy — the page warns
  and clears it after 60 seconds, but a clipboard manager has its copy by then
- The blur against determined optics: it is a shoulder-surfing mitigation, not
  encryption
- PBKDF2 rather than a memory-hard KDF — an accepted, documented tradeoff
  ([SECURITY-AUDIT.md](SECURITY-AUDIT.md), Low #1)
- Scanner output about headers that don't apply to a static page under
  `default-src 'none'`
- Denial of service against GitHub Pages

## Supported versions

The [latest release](https://github.com/seQRets/ittybitz/releases/latest), the
published pages at <https://ittybitz.app>, and the current `main` branch; the
three are the same bytes. Older releases stay available for download but are
not patched — a fix ships as a new release with new checksums. Ciphertexts made
with **any** release are supported forever: decrypting them is what the
regression suite exists to guarantee.
