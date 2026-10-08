#!/usr/bin/env node
/**
 * Append this version's ciphertexts to scripts/crypto-fixtures.json.
 *
 * The regression suite's promise — "anything encrypted with any version of
 * IttyBitz still decrypts" — is only as good as the fixtures it replays, and
 * those stopped at v2.7.3 because adding one was a by-hand step. This makes it
 * a command, run as part of cutting a release:
 *
 *     npm run fixtures:add
 *
 * It encrypts two fixed plaintexts (ASCII and non-ASCII), each with and
 * without the suite's key file, using the crypto core extracted from the
 * SHIPPED site/index.html — the bytes users actually run, not src/lib/crypto.ts
 * — under the version in package.json, and appends four entries. It refuses
 * to run twice for one version, never touches an existing entry, and leaves
 * the file byte-identical when there is nothing to add. The release workflow
 * fails if the tagged version has no fixtures, so this cannot be forgotten.
 *
 * The password and key file are the suite's published TEST-ONLY values.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { webcrypto } from "node:crypto";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const FIXTURES_PATH = join(HERE, "crypto-fixtures.json");
const CHECK = process.argv.includes("--check");

const version = "v" + JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
const fixtures = JSON.parse(readFileSync(FIXTURES_PATH, "utf8"));
const have = fixtures.fixtures.filter((f: any) => f.version === version);

if (CHECK) {
  if (have.length) { console.log(`add-release-fixtures: ${have.length} fixture(s) present for ${version}`); process.exit(0); }
  console.error(`add-release-fixtures: no fixtures for ${version} in crypto-fixtures.json — run: npm run fixtures:add`);
  process.exit(1);
}
if (have.length) {
  console.log(`add-release-fixtures: ${version} already has ${have.length} fixture(s); nothing to do`);
  process.exit(0);
}

// The shipped core, exactly as the regression suite extracts it.
const appHtml = readFileSync(join(ROOT, "site", "index.html"), "utf8");
const core = appHtml.match(/<script id="ittybitz-crypto-core">([\s\S]*?)<\/script>/);
if (!core) { console.error("add-release-fixtures: crypto core block not found in site/index.html"); process.exit(1); }
const box: any = { crypto: webcrypto, TextEncoder, TextDecoder, console };
createContext(box);
runInContext(core[1]!, box);
if (typeof box.ittybitzEncrypt !== "function") { console.error("add-release-fixtures: ittybitzEncrypt not exposed"); process.exit(1); }

const hexToBytes = (hex: string) => Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));
const keyFile = hexToBytes(fixtures.keyFileHex);
const enc = new TextEncoder();

const PLAINTEXTS: Array<[string, string]> = [
  ["ascii", "The quick brown fox jumps over the lazy dog 0123456789"],
  ["unicode", "秘密 · émoji 🔐🦖 · Ω≈ç√ · naïve café — “quoted”"],
];

const added: any[] = [];
for (const [payload, plaintext] of PLAINTEXTS) {
  for (const withKey of [false, true]) {
    const ct: Uint8Array = await box.ittybitzEncrypt(enc.encode(plaintext), fixtures.password, withKey ? keyFile : null);
    added.push({
      version,
      format: "v1",
      payload,
      keyFile: withKey,
      plaintext,
      base64: Buffer.from(ct).toString("base64"),
    });
  }
}

fixtures.fixtures.push(...added);
writeFileSync(FIXTURES_PATH, JSON.stringify(fixtures, null, 2) + "\n");
console.log(`add-release-fixtures: appended ${added.length} fixture(s) for ${version}; now run: npm run test:crypto`);
