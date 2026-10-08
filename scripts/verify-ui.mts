#!/usr/bin/env node
/**
 * verify-ui.mts — drives the two shipped pages in headless Chrome and asserts
 * on what a user would see and do. The crypto regression suite proves the
 * core; this proves the page around it: that it loads under its own CSP,
 * makes no request, encrypts and decrypts through the real controls, hides
 * what should be hidden, refuses to be framed, and lays out on a phone.
 *
 *     npm run test:ui
 *
 * Needs Node 22.6+ (native TypeScript stripping, global fetch/WebSocket) and
 * Google Chrome or Chromium; set CHROME if the binary is somewhere unusual.
 * Nothing else — no install step, no dependencies, the same rule as the page.
 *
 * The independent judge is src/lib/crypto.ts running here in Node: what the
 * page encrypts through its UI must open under crypto.ts, and what crypto.ts
 * encrypts must open through the page's UI. The page is never its own judge.
 *
 * Every check here was confirmed to fail against deliberately broken code
 * before being kept.
 */
import { spawn } from "node:child_process";
import { accessSync, constants, mkdtempSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createServer } from "node:http";
import { createHash } from "node:crypto";
import { encryptFile, decryptFile } from "../src/lib/crypto.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..");
const APP = join(ROOT, "site", "index.html");
const RECOVERY = join(ROOT, "site", "ittybitz-recovery.html");
const FIXTURES = JSON.parse(readFileSync(join(HERE, "crypto-fixtures.json"), "utf8"));
const PASSWORD = "Harness-Only-Password-Not-For-Real-Use-2026!";

let count = 0, fails = 0;
const chk = (name: string, ok: boolean, extra = "") => {
  count++; if (!ok) fails++;
  console.log(`  ${ok ? "ok  " : "FAIL"} ${name}${extra ? "  — " + extra : ""}`);
};
const section = (t: string) => console.log(`\n--- ${t} ---`);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/* ---- chrome ---------------------------------------------------------- */
function findChrome(): string | null {
  const candidates = [process.env.CHROME,
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  ].filter(Boolean) as string[];
  for (const c of candidates) { try { accessSync(c, constants.X_OK); return c; } catch {} }
  return null;
}

async function launch(bin: string, port = 9336) {
  const dir = mkdtempSync(join(tmpdir(), "ittybitz-verify-"));
  const proc = spawn(bin, ["--headless=new", `--remote-debugging-port=${port}`,
    `--user-data-dir=${dir}`, "--no-first-run", "--no-default-browser-check",
    "--disable-gpu", "--disable-extensions", "--disable-background-networking",
    "--disable-component-update", "--disable-sync", "--no-pings",
    "--window-size=1280,900", "about:blank"], { stdio: ["ignore", "pipe", "pipe"] });
  let err = ""; proc.stderr.on("data", (d) => (err += d));
  for (let i = 0; i < 100; i++) {
    try {
      const v: any = await fetch(`http://127.0.0.1:${port}/json/version`).then((r) => r.json());
      return { proc, wsUrl: v.webSocketDebuggerUrl as string, version: v.Browser as string };
    } catch { await sleep(100); }
  }
  proc.kill(); throw new Error("Chrome did not start.\n" + err);
}

function connect(wsUrl: string) {
  const ws = new WebSocket(wsUrl);
  let id = 0; const pending = new Map<number, { res: (v: any) => void; rej: (e: Error) => void }>();
  const listeners: Array<(m: any) => void> = [];
  const ready = new Promise<void>((res, rej) => { ws.onopen = () => res(); ws.onerror = () => rej(new Error("ws")); });
  ws.onmessage = (ev) => {
    const m = JSON.parse(String(ev.data));
    if (m.id && pending.has(m.id)) {
      const { res, rej } = pending.get(m.id)!; pending.delete(m.id);
      m.error ? rej(new Error(JSON.stringify(m.error))) : res(m.result);
    } else if (m.method) listeners.forEach((f) => f(m));
  };
  const send = async (method: string, params: any = {}, sessionId?: string) => {
    await ready; const mid = ++id;
    return new Promise<any>((res, rej) => {
      pending.set(mid, { res, rej });
      ws.send(JSON.stringify({ id: mid, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  };
  return { send, on: (f: (m: any) => void) => listeners.push(f) };
}

async function openPage(browser: { wsUrl: string }, url: string) {
  const cdp = connect(browser.wsUrl);
  const { targetId } = await cdp.send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
  const S = (m: string, p?: any, sid?: string) => cdp.send(m, p, sid || sessionId);
  const requests: string[] = [], exceptions: string[] = [];
  const childSessions = new Set<string>();
  cdp.on((m) => {
    if (m.method === "Target.attachedToTarget" && m.params.targetInfo.type === "iframe") {
      childSessions.add(m.params.sessionId);
      cdp.send("Runtime.enable", {}, m.params.sessionId).catch(() => {});
    }
    if (m.method === "Target.detachedFromTarget") childSessions.delete(m.params.sessionId);
    if (m.sessionId !== sessionId) return;
    if (m.method === "Runtime.exceptionThrown")
      exceptions.push(m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text);
    if (m.method === "Network.requestWillBeSent") requests.push(m.params.request.url);
  });
  await S("Runtime.enable"); await S("Network.enable"); await S("Page.enable");
  // A blocked script is reported by the browser, not the page: ask the document.
  await S("Page.addScriptToEvaluateOnNewDocument", { source:
    "window.__csp=[];addEventListener('securitypolicyviolation',"
    + "e=>window.__csp.push(e.violatedDirective+' blocked '+(e.blockedURI||'inline')));"
    // Clipboard: record writes instead of touching the real clipboard, and
    // intercept the one-minute timer so the auto-clear can be fired on demand.
    + "window.__clip=[];navigator.clipboard.writeText=t=>{window.__clip.push(t);return Promise.resolve()};"
    + "window.__fire=null;const __st=window.setTimeout;window.setTimeout=(fn,ms,...a)=>{if(ms===60000){window.__fire=fn;return 1}return __st(fn,ms,...a)};" });
  await S("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true });
  const goto = async (u: string) => {
    await S("Page.navigate", { url: u });
    for (let i = 0; i < 200; i++) {
      const r = await S("Runtime.evaluate", { expression: "document.readyState", returnByValue: true });
      if (r.result.value === "complete") break;
      await sleep(50);
    }
  };
  await goto(url);
  const evalIn = async (expr: string, sid?: string) => {
    const r = await S("Runtime.evaluate",
      { expression: `(async()=>{${expr}})()`, awaitPromise: true, returnByValue: true }, sid);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || r.exceptionDetails.text);
    return r.result.value;
  };
  return {
    requests, exceptions, childSessions, evalIn,
    evaluate: (expr: string) => evalIn(expr),
    setViewport: (width: number, height: number) =>
      S("Emulation.setDeviceMetricsOverride", { width, height, deviceScaleFactor: 1, mobile: false }),
    close: () => cdp.send("Target.closeTarget", { targetId }),
  };
}

/* ---- helpers shared with the page ------------------------------------- */
const b64 = (buf: ArrayBuffer | Uint8Array) => Buffer.from(buf as any).toString("base64");
const fromB64 = (s: string) => { const b = Buffer.from(s, "base64"); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) as ArrayBuffer; };
// Wait until the status box stops saying the key is being derived.
const WAIT_DONE = `
  for (let i = 0; i < 400; i++) {
    const s = document.getElementById('status').textContent;
    if (s && !/Deriving|Encrypting/.test(s)) break;
    await new Promise(r => setTimeout(r, 50));
  }`;

/* ---- static: the files are what they say ------------------------------ */
function staticChecks(file: string, label: string) {
  section(`${label}: the file`);
  const src = readFileSync(file, "utf8");
  const comments = [...src.matchAll(/<!--[\s\S]*?-->/g)].map((m) => [m.index!, m.index! + m[0].length]);
  const inComment = (i: number) => comments.some(([a, b]) => i >= a && i < b);
  const blocks = [...src.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)].filter((b) => !inComment(b.index!));
  const want = blocks.map((b) => `'sha256-${createHash("sha256").update(b[2], "utf8").digest("base64")}'`);
  const meta = src.match(/<meta\s+http-equiv="Content-Security-Policy"[\s\S]*?content="([^"]*)"/i);
  const csp = meta ? meta[1] : "";
  const scriptSrc = (csp.match(/script-src([^;]*)/) || [, ""])[1]!.trim().split(/\s+/).filter(Boolean);
  chk("CSP pins equal the SHA-256 of each inline script, recomputed here",
      scriptSrc.length === want.length && want.every((h) => scriptSrc.includes(h)), `${blocks.length} block(s)`);
  chk("script-src carries no 'unsafe-inline'", !/script-src[^;]*unsafe-inline/.test(csp));
  const bare = csp.replace(/'sha256-[A-Za-z0-9+/=]+'/g, "");
  chk("the CSP names no network source", /default-src 'none'/.test(csp) && /connect-src 'none'/.test(csp) && !/https?:|\/\/|\*/.test(bare));
  const markup = src.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, "").replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "").replace(/<!--[\s\S]*?-->/g, "");
  chk("no inline event handler in the markup", !/<[a-zA-Z][^>]*?\s(on[a-z]+)\s*=/.test(markup));
  chk("no Math.random( anywhere", !/Math\.random\s*\(/.test(src));
  const sums = existsSync(join(ROOT, "SHA256SUMS.txt")) ? readFileSync(join(ROOT, "SHA256SUMS.txt"), "utf8") : "";
  const hash = createHash("sha256").update(readFileSync(file)).digest("hex");
  chk("SHA256SUMS.txt matches the file", sums.includes(hash), hash.slice(0, 16) + "…");
}

/* ---- the app ---------------------------------------------------------- */
async function appLoadChecks(browser: any, url: string, label: string) {
  section(`app ${label}`);
  const p = await openPage(browser, url);
  try {
    const r = await p.evaluate(`return { csp: window.__csp, ok: typeof ittybitzEncrypt === 'function' && typeof ittybitzDecrypt === 'function'
      && typeof ittybitzValidateBip39 === 'function' && typeof masterFingerprint === 'function', version: document.getElementById('version').textContent }`);
    chk("loads with no CSP violation", r.csp.length === 0, r.csp.join("; "));
    chk("every script block ran", r.ok);
    chk("no exception on load", p.exceptions.length === 0, p.exceptions.join(" | "));
    const foreign = p.requests.filter((u) => !u.startsWith(url) && !u.startsWith("data:"));
    chk("requests nothing but itself", foreign.length === 0, foreign.join(", "));
    const pkg = "v" + JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")).version;
    chk("the footer version matches package.json", r.version.startsWith(pkg + " "), r.version);
  } finally { await p.close(); }
}

async function appFlowChecks(browser: any, url: string) {
  const p = await openPage(browser, url);
  try {
    section("encrypt through the UI");
    const secret = "the harness secret — Zürich 🔐 " + Date.now();
    const enc = await p.evaluate(`
      const $ = id => document.getElementById(id);
      $('pill-text').click();
      $('t').value = ${JSON.stringify(secret)}; $('t').dispatchEvent(new Event('input'));
      const blurredWhileTyping = $('t').classList.contains('blurred');
      $('p').value = 'weak'; $('p').dispatchEvent(new Event('input'));
      const weakBorder = $('p').classList.contains('bad-border');
      $('go').click(); await new Promise(r => setTimeout(r, 50));
      const weakStatus = $('status').textContent;
      $('p').value = ${JSON.stringify(PASSWORD)}; $('p').dispatchEvent(new Event('input'));
      const strongBorder = $('p').classList.contains('ok-border');
      // Since the repeat field exists, a mismatch must refuse before anything is derived.
      let mismatchStatus = null;
      if ($('p2')) {
        $('p2').value = ${JSON.stringify(PASSWORD + 'x')}; $('p2').dispatchEvent(new Event('input'));
        $('go').click(); await new Promise(r => setTimeout(r, 50));
        mismatchStatus = $('status').textContent;
        $('p2').value = ${JSON.stringify(PASSWORD)}; $('p2').dispatchEvent(new Event('input'));
      }
      $('go').click();
      ${WAIT_DONE}
      return { blurredWhileTyping, weakBorder, weakStatus, strongBorder, mismatchStatus,
               out: $('out').value, status: $('status').textContent, pwAfter: $('p').value,
               secretAfter: $('t').value, qrOffered: $('out-qr').style.display !== 'none' }`);
    chk("the typed secret is blurred as soon as it has content", enc.blurredWhileTyping);
    chk("a weak password is refused before anything is encrypted", enc.weakBorder && /Weak password/.test(enc.weakStatus), enc.weakStatus.slice(0, 40));
    chk("a strong password turns the border green", enc.strongBorder);
    chk("a mismatched repeat password is refused before anything is encrypted",
        enc.mismatchStatus === null || /do not match/.test(enc.mismatchStatus), enc.mismatchStatus || "(no repeat field on this build)");
    chk("Encrypt produces Base64 that opens under crypto.ts with the same password", await (async () => {
      try { return new TextDecoder().decode(await decryptFile(fromB64(enc.out), PASSWORD, null)) === secret; } catch { return false; }
    })(), `${enc.out.length} chars`);
    chk("the Base64 starts with an IBTZ v1 header", Buffer.from(enc.out, "base64").subarray(0, 5).equals(Buffer.from([0x49, 0x42, 0x54, 0x5a, 1])));
    chk("the password and the secret are cleared from their fields afterwards", enc.pwAfter === "" && enc.secretAfter === "");
    chk("a QR of the result is offered", enc.qrOffered);

    section("decrypt through the UI");
    const tsCt = b64(await encryptFile(new TextEncoder().encode(secret).buffer as ArrayBuffer, PASSWORD, null));
    const dec = await p.evaluate(`
      const $ = id => document.getElementById(id);
      $('tab-dec').click(); $('pill-text').click();
      $('t').value = ${JSON.stringify(tsCt)}; $('t').dispatchEvent(new Event('input'));
      $('p').value = ${JSON.stringify(PASSWORD)}; $('p').dispatchEvent(new Event('input'));
      $('go').click();
      ${WAIT_DONE}
      const blurred = $('out').classList.contains('blurred');
      const revealShown = $('out-reveal').style.display !== 'none';
      $('out-reveal').click();
      return { out: $('out').value, blurred, revealShown, afterReveal: $('out').classList.contains('blurred'),
               status: $('status').textContent, pwAfter: $('p').value }`);
    chk("crypto.ts ciphertext decrypts through the UI to the original text", dec.out === secret);
    chk("the decrypted text is blurred until the eye is pressed", dec.blurred && dec.revealShown && !dec.afterReveal);
    chk("the password is cleared after decrypting", dec.pwAfter === "");

    const bad = await p.evaluate(`
      const $ = id => document.getElementById(id);
      $('t').value = ${JSON.stringify(tsCt)}; $('t').dispatchEvent(new Event('input'));
      $('p').value = ${JSON.stringify(PASSWORD + "x")}; $('p').dispatchEvent(new Event('input'));
      $('go').click();
      ${WAIT_DONE}
      return { out: $('out').value, status: $('status').textContent, cls: $('status').className }`);
    chk("a wrong password shows the generic failure and no output", bad.out === "" && /Decryption failed/.test(bad.status) && /err/.test(bad.cls), bad.status.slice(0, 60));

    // A real historical ciphertext, through the real controls.
    const fx = FIXTURES.fixtures.find((f: any) => f.format === "v0" && !f.keyFile && f.payload === "seed12");
    const legacy = await p.evaluate(`
      const $ = id => document.getElementById(id);
      $('t').value = ${JSON.stringify(fx.base64)}; $('t').dispatchEvent(new Event('input'));
      $('p').value = ${JSON.stringify(FIXTURES.password)}; $('p').dispatchEvent(new Event('input'));
      $('go').click();
      ${WAIT_DONE}
      await new Promise(r => setTimeout(r, 300));
      return { out: $('out').value, seedBorder: $('out').classList.contains('ok-border'),
               fp: document.getElementById('dec-fp-code').textContent, fpShown: document.getElementById('dec-fp').classList.contains('show'),
               qrOffered: $('out-qr').style.display !== 'none' }`);
    chk(`a ${fx.version} headerless ciphertext decrypts through the UI`, legacy.out === fx.plaintext);
    chk("a valid BIP-39 seed is recognised: green border, master fingerprint, SeedQR offered",
        legacy.seedBorder && legacy.fpShown && legacy.fp === "73c5da0a" && legacy.qrOffered, `fingerprint ${legacy.fp}`);

    section("the SeedQR");
    const qr = await p.evaluate(`
      const $ = id => document.getElementById(id);
      $('out-qr').click(); await new Promise(r => setTimeout(r, 100));
      const open = { shown: $('qr-overlay').classList.contains('show'), blurred: $('qr-box').classList.contains('qr-blur'),
                     title: $('qr-title').textContent, dlDisabled: $('qr-download').disabled, drawn: $('qr-canvas').width > 256 };
      $('qr-reveal').click();
      const revealed = { blurred: $('qr-box').classList.contains('qr-blur'), dlDisabled: $('qr-download').disabled };
      $('qr-close').click();
      return { open, revealed, closed: $('qr-overlay').classList.contains('show') }`);
    chk("the SeedQR opens blurred, as a Standard SeedQR, with download disabled",
        qr.open.shown && qr.open.blurred && qr.open.title === "Standard SeedQR" && qr.open.dlDisabled && qr.open.drawn, JSON.stringify(qr.open));
    chk("Reveal unblurs it and enables download; Close closes", !qr.revealed.blurred && !qr.revealed.dlDisabled && !qr.closed);

    section("the clipboard");
    const clip = await p.evaluate(`
      const $ = id => document.getElementById(id);
      window.__clip = []; window.__fire = null;
      $('out-copy').click(); await new Promise(r => setTimeout(r, 50));
      const afterCopy = window.__clip.length, armed = !!window.__fire, hint = $('status').textContent;
      if (window.__fire) window.__fire();
      const afterTimer = window.__clip.slice();
      window.__clip = []; window.__fire = null;
      $('out-copy').click(); await new Promise(r => setTimeout(r, 50));
      document.dispatchEvent(new Event('copy'));
      if (window.__fire) window.__fire();
      return { afterCopy, armed, hint, afterTimer: afterTimer.map(s => s.length), afterForeign: window.__clip.map(s => s.length) }`);
    chk("Copy writes once, warns, and arms a 60 s clear", clip.afterCopy === 1 && clip.armed && /60 seconds/.test(clip.hint));
    chk("the clear overwrites with an empty string when nothing else was copied", clip.afterTimer.length === 2 && clip.afterTimer[1] === 0);
    chk("the clear is skipped if something else was copied in between", clip.afterForeign.length === 1);

    section("the password generator");
    const gen = await p.evaluate(`
      const $ = id => document.getElementById(id);
      $('tab-enc').click();
      const out = [];
      for (let i = 0; i < 20; i++) { $('p-gen').click(); out.push($('p').value); }
      return { out, border: $('p').classList.contains('ok-border') }`);
    const strong = (pw: string) => pw.length >= 24 && /[A-Z]/.test(pw) && /[a-z]/.test(pw) && /\d/.test(pw) && /[!@#$%^&*()_+~`|}{[\]:;?><,./=-]/.test(pw);
    chk("20 generated passwords are 32 chars, all pass the strength rule, all distinct",
        gen.out.every((pw: string) => pw.length === 32 && strong(pw)) && new Set(gen.out).size === 20 && gen.border);

    section("layout");
    for (const w of [320, 390, 1440]) {
      await p.setViewport(w, 800);
      const r = await p.evaluate(`await new Promise(r => setTimeout(r, 100)); return { sw: document.documentElement.scrollWidth, iw: innerWidth }`);
      chk(`${w}px — no sideways scroll`, r.sw <= r.iw, `scrollWidth ${r.sw} of ${r.iw}`);
    }
    await p.setViewport(1280, 900);
    chk("no exception during any of the above", p.exceptions.length === 0, p.exceptions.join(" | "));
    const csp = await p.evaluate(`return window.__csp`);
    chk("still no CSP violation after use", csp.length === 0, csp.join("; "));
  } finally { await p.close(); }
}

/* ---- contrast: every text node vs its composited background --------- */
// WCAG AA: 4.5:1 for normal text, 3:1 for large (>= 24px, or >= 18.66px bold).
// Backgrounds are composited up the ancestor chain over the page colour;
// text over a gradient (the orange buttons) cannot be measured this way and
// is skipped — those are black on orange, about 8:1 by eye.
const CONTRAST_PROBE = `
  document.querySelectorAll('details').forEach(d => d.open = true);
  const parse = c => { const m = c.match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const p = m[1].split(',').map(parseFloat); return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 }; };
  const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
  const lum = c => { const f = v => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const contrast = (a, b) => { const l1 = lum(a), l2 = lum(b); return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05); };
  const bgOf = el => {
    const chain = []; let gradient = false;
    for (let e = el; e; e = e.parentElement) {
      const cs = getComputedStyle(e); const c = parse(cs.backgroundColor); if (c && c.a > 0) chain.push(c);
      // body's faint radial glow over black barely moves the result; a gradient
      // on a closer ancestor (the orange buttons) makes it unmeasurable
      if (e !== document.body && e !== document.documentElement && /gradient/.test(cs.backgroundImage)) gradient = true;
    }
    let bg = parse(getComputedStyle(document.documentElement).backgroundColor); if (!bg || bg.a === 0) bg = parse(getComputedStyle(document.body).backgroundColor) || { r: 0, g: 0, b: 0, a: 1 };
    for (const c of chain.reverse()) bg = over(c, bg);
    return { bg, gradient };
  };
  const out = [], seen = new Set(); let n, checked = 0;
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while ((n = walker.nextNode())) {
    const t = n.textContent.trim(); if (t.length < 2) continue;
    const el = n.parentElement; if (!el || seen.has(el) || ['SCRIPT', 'STYLE'].includes(el.tagName)) continue; seen.add(el);
    const cs = getComputedStyle(el); if (cs.display === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) === 0) continue;
    const r = el.getBoundingClientRect(); if (!r.width || !r.height) continue;
    const fill = parse(cs.webkitTextFillColor); if (fill && fill.a === 0) continue;   // gradient-filled headline
    let fg = parse(cs.color); if (!fg) continue;
    const { bg, gradient } = bgOf(el); if (gradient) continue;
    if (fg.a < 1) fg = over(fg, bg);
    const size = parseFloat(cs.fontSize), bold = parseInt(cs.fontWeight) >= 700;
    const need = size >= 24 || (size >= 18.66 && bold) ? 3 : 4.5; const c = contrast(fg, bg); checked++;
    if (c < need) out.push((el.id ? '#' + el.id : el.tagName.toLowerCase()) + ' ' + c.toFixed(2) + ':1 (' + size + 'px) "' + t.slice(0, 30) + '"');
  }
  return { checked, fails: out };`;

async function contrastChecks(browser: any, url: string, label: string) {
  section(`contrast: ${label}`);
  const p = await openPage(browser, url);
  try {
    const r = await p.evaluate(CONTRAST_PROBE);
    chk(`every text element meets WCAG AA (${r.checked} measured; gradient-backed buttons skipped)`, r.fails.length === 0, r.fails.join(' | '));
  } finally { await p.close(); }
}

/* ---- the recovery tool ------------------------------------------------- */
async function recoveryChecks(browser: any, url: string, label: string) {
  section(`recovery tool ${label}`);
  const p = await openPage(browser, url);
  try {
    const r = await p.evaluate(`return { csp: window.__csp, dec: typeof ittybitzDecrypt === 'function', enc: typeof ittybitzEncrypt }`);
    chk("loads with no CSP violation and its decrypt core ran", r.csp.length === 0 && r.dec, r.csp.join("; "));
    chk("carries no encrypt function (decrypt-only)", r.enc === "undefined");
    const foreign = p.requests.filter((u) => !u.startsWith(url) && !u.startsWith("data:"));
    chk("requests nothing but itself", foreign.length === 0, foreign.join(", "));
    const fx = FIXTURES.fixtures.find((f: any) => f.format === "v1" && !f.keyFile && f.payload === "ascii");
    const d = await p.evaluate(`
      const $ = id => document.getElementById(id);
      $('tab-text').click();
      $('t').value = ${JSON.stringify(fx.base64)}; $('t').dispatchEvent(new Event('input'));
      $('p').value = ${JSON.stringify(FIXTURES.password)}; $('p').dispatchEvent(new Event('input'));
      $('go').click();
      for (let i = 0; i < 400; i++) { const s = $('out').textContent; if (s && !/Deriving/.test(s)) break; await new Promise(r => setTimeout(r, 50)); }
      return { out: $('out').textContent, blurred: $('out').classList.contains('blur'), hint: $('hint').textContent }`);
    chk(`a ${fx.version} ciphertext decrypts through the recovery UI, blurred until clicked`, d.out === fx.plaintext && d.blurred, d.hint);
    chk("no exception", p.exceptions.length === 0, p.exceptions.join(" | "));
  } finally { await p.close(); }
}

/* ---- the frame guard --------------------------------------------------- */
async function guardChecks(browser: any, framerUrl: string, label: string, probe: string) {
  section(`frame guard: ${label}`);
  const p = await openPage(browser, framerUrl);
  try {
    let sid: string | undefined;
    for (let i = 0; i < 60 && !sid; i++) { await sleep(100); sid = [...p.childSessions][0]; }
    chk("a cross-origin frame of the page exists for the test", !!sid);
    if (sid) {
      let r: any = null;
      for (let i = 0; i < 40 && !r; i++) {
        try { r = await p.evalIn(probe, sid); } catch { r = null; }
        if (!r) await sleep(100);
      }
      chk("framed: the tool is withheld and the notice names the real address", !!r && r.refused, JSON.stringify(r));
    }
  } finally { await p.close(); }
}

/* ---- run ------------------------------------------------------------- */
const bin = findChrome();
if (!bin) { console.error("Could not find Chrome. Install it, or set CHROME to the binary."); process.exit(2); }

staticChecks(APP, "app");
staticChecks(RECOVERY, "recovery tool");

const serve = (handler: (req: any, res: any) => void) => new Promise<any>((res) => {
  const s = createServer(handler); s.listen(0, "127.0.0.1", () => res(s));
});
const site = await serve((req, res) => {
  const f = req.url === "/" || req.url === "/index.html" ? APP : req.url === "/ittybitz-recovery.html" ? RECOVERY : null;
  if (!f) { res.writeHead(404); res.end(); return; }
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); res.end(readFileSync(f));
});
const origin = `http://127.0.0.1:${site.address().port}`;
const framer = await serve((req, res) => {
  const target = req.url === "/recovery" ? `${origin}/ittybitz-recovery.html` : `${origin}/index.html`;
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><title>framer</title><iframe src="${target}" width="900" height="700"></iframe>`);
});
const framerOrigin = `http://localhost:${framer.address().port}`;

const browser = await launch(bin);
console.log(`\n${browser.version}`);
try {
  await appLoadChecks(browser, pathToFileURL(APP).href, "over file://");
  await appLoadChecks(browser, `${origin}/index.html`, "over http");
  await appFlowChecks(browser, `${origin}/index.html`);
  await contrastChecks(browser, `${origin}/index.html`, "app");
  await contrastChecks(browser, `${origin}/ittybitz-recovery.html`, "recovery tool");
  await recoveryChecks(browser, pathToFileURL(RECOVERY).href, "over file://");
  await recoveryChecks(browser, `${origin}/ittybitz-recovery.html`, "over http");
  await guardChecks(browser, `${framerOrigin}/app`, "app",
    `if (document.readyState !== 'complete') return null;
     const body = document.body.textContent || '';
     return { refused: /won.t run inside a frame/i.test(body) && /ittybitz\\.app/.test(body) && !document.getElementById('go') }`);
  await guardChecks(browser, `${framerOrigin}/recovery`, "recovery tool",
    `if (document.readyState !== 'complete') return null;
     const body = document.body.textContent || '';
     return { refused: /inside a frame/i.test(body) && !document.getElementById('go') }`);
} finally {
  browser.proc.kill(); site.close(); framer.close();
}
console.log(`\n${fails === 0 ? `all ${count} checks passed` : `${fails} of ${count} checks FAILED`}`);
process.exit(fails === 0 ? 0 : 1);
