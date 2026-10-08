(function () {
  // ---- Anti-framing guard ----
  // The recovery tool is meant to be opened directly, never embedded. A <meta>
  // CSP cannot set frame-ancestors, so enforce it here: if we are inside a
  // frame (cross-origin access to window.top throws, treated as framed), refuse
  // to initialize so a hostile wrapper can never harvest a password or key file.
  var framed;
  try { framed = window.top !== window.self; } catch (e) { framed = true; }
  if (framed) {
    try {
      document.body.innerHTML =
        '<div style="max-width:30rem;margin:14vh auto 0;padding:0 1.5rem;text-align:center;' +
        'color:#f4f4f5;font:16px/1.6 system-ui,-apple-system,sans-serif">' +
        '<h1 style="font-size:1.4rem;font-weight:600;margin:0 0 .75rem">IttyBitz Recovery won\u2019t run inside a frame</h1>' +
        '<p style="color:#a1a1aa;margin:0">For your security it refuses to run embedded in another page. ' +
        'Open this file directly in your browser instead.</p></div>';
    } catch (e) { /* ignore */ }
    return;
  }

  var $ = function (id) { return document.getElementById(id); };
  var mode = 'file';
  var mainFile = null;
  var keyFile = null;

  $('netbadge').textContent = navigator.onLine ? 'online \u2014 but nothing is sent' : 'offline \u2014 working normally';

  // Web Crypto is only exposed in a "secure context". Opening this file
  // directly from disk (file://) qualifies in current Chrome, Firefox, Edge
  // and Safari, but the spec leaves room for variation and some older or
  // restricted browsers do not. If that happens, say so plainly and give a
  // way out - failing with "cannot read property 'importKey' of undefined"
  // at the moment someone is trying to recover their data would be cruel.
  if (!(window.crypto && window.crypto.subtle)) {
    document.querySelector('.card').innerHTML =
      '<div class="out err" style="display:block">' +
      '<strong>This browser will not allow decryption from a local file.</strong>\n\n' +
      'Your data is fine \u2014 this is a browser restriction, not a problem with your file.\n' +
      'Web Crypto is unavailable here because the page is not in a "secure context".\n\n' +
      'Either:\n' +
      '  1. Open this same file in Chrome, Firefox, Edge or Safari, or\n' +
      '  2. Serve the folder locally and open it over http://localhost \u2014 from a\n' +
      '     terminal in the folder containing this file, run:\n\n' +
      '       python3 -m http.server 8000\n\n' +
      '     then visit http://localhost:8000/ittybitz-recovery.html\n\n' +
      'The IttyBitz source and file format are at\n' +
      'https://github.com/seQRets/ittybitz — the data can also be decrypted\n' +
      'with any AES-256-GCM / PBKDF2 implementation.' +
      '</div>';
    return;
  }

  function setMode(m) {
    mode = m;
    $('tab-file').setAttribute('aria-selected', String(m === 'file'));
    $('tab-text').setAttribute('aria-selected', String(m === 'text'));
    $('pane-file').style.display = m === 'file' ? '' : 'none';
    $('pane-text').style.display = m === 'text' ? '' : 'none';
    // The key file is a shared input that applies to whichever mode you
    // decrypt in. Clear it on a tab switch so a key file chosen for one
    // secret is never silently applied to the next.
    if (clearKeyZone) clearKeyZone();
    reset();
  }
  $('tab-file').onclick = function () { setMode('file'); };
  $('tab-text').onclick = function () { setMode('text'); };

  // Mirrors the main app's filename validation: rejects path traversal, null
  // bytes, C0 control characters and Unicode bidi overrides (U+202A-U+202E,
  // U+2066-U+2069), which can disguise a file's real extension when the
  // decrypted result is downloaded.
  var BAD_NAME = /[\u0000-\u001f\u202a-\u202e\u2066-\u2069]/;
  function validName(name) {
    if (name.indexOf('..') >= 0 || name.indexOf('/') >= 0 || name.indexOf('\\') >= 0) return false;
    if (name.length > 255) return false;
    return !BAD_NAME.test(name);
  }

  function wireDrop(zoneId, inputId, descId, clearId, onPick) {
    var zone = $(zoneId), input = $(inputId), desc = $(descId), clear = $(clearId);
    var defaultText = desc.textContent;

    function pick(file) {
      if (!file) return;
      if (!validName(file.name)) {
        show('err', 'That filename contains characters that are not allowed.');
        return;
      }
      // An empty key file adds nothing to the key: the result is the same as
      // using no key file at all, while looking protected by one.
      if (zoneId === 'drop-key' && file.size === 0) {
        show('err', 'That key file is empty (0 bytes), so it would add nothing to the key. Choose the right file.');
        return;
      }
      onPick(file);
      desc.textContent = file.name;
      desc.className = 'picked';
      clear.style.display = '';
    }

    zone.addEventListener('click', function () { input.click(); });
    zone.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); input.click(); }
    });
    input.addEventListener('change', function () { pick(input.files && input.files[0]); });

    ['dragenter', 'dragover'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) {
        e.preventDefault(); e.stopPropagation(); zone.classList.add('dragging');
      });
    });
    ['dragleave', 'drop'].forEach(function (ev) {
      zone.addEventListener(ev, function (e) {
        e.preventDefault(); e.stopPropagation(); zone.classList.remove('dragging');
      });
    });
    zone.addEventListener('drop', function (e) {
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        pick(e.dataTransfer.files[0]);
      }
    });

    function resetZone() {
      onPick(null); input.value = '';
      desc.textContent = defaultText; desc.className = '';
      clear.style.display = 'none';
    }
    clear.querySelector('button').addEventListener('click', function (e) {
      e.stopPropagation();
      resetZone();
    });
    return resetZone;
  }

  wireDrop('drop-main', 'f', 'main-desc', 'main-clear', function (f) { mainFile = f; });
  var clearKeyZone = wireDrop('drop-key', 'k', 'key-desc', 'key-clear', function (f) { keyFile = f; });

  // Swallow drops on the rest of the window so a near-miss does not make the
  // browser navigate away from the page and lose what the user has typed.
  ['dragover', 'drop'].forEach(function (ev) {
    window.addEventListener(ev, function (e) { e.preventDefault(); }, false);
  });

  function readBytes(file) {
    return new Promise(function (resolve, reject) {
      if (!file) return resolve(null);
      var r = new FileReader();
      r.onload = function () { resolve(new Uint8Array(r.result)); };
      r.onerror = function () { reject(new Error('Could not read ' + file.name)); };
      r.readAsArrayBuffer(file);
    });
  }

  function b64ToBytes(s) {
    var bin = atob(String(s).replace(/\s+/g, ''));
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function show(cls, text) { var o = $('out'); o.className = 'out ' + cls; o.textContent = text; }
  function reset() {
    var o = $('out');
    o.className = 'out'; o.textContent = ''; o.title = ''; o.onclick = null;
    $('hint').textContent = '';
  }

  $('go').onclick = async function () {
    var btn = this;
    btn.disabled = true;
    reset();

    try {
      var input = null, outName = 'decrypted';
      if (mode === 'file') {
        if (!mainFile) throw new Error('Drop an encrypted file above, or click to browse.');
        input = await readBytes(mainFile);
        // Match the main app: strip .ibitz, otherwise prefix so the download
        // can never silently carry the encrypted file's own name.
        outName = /\.ibitz$/i.test(mainFile.name)
          ? mainFile.name.replace(/\.ibitz$/i, '')
          : 'decrypted-' + mainFile.name;
        if (!outName) outName = 'decrypted';
      } else {
        var txt = $('t').value.trim();
        if (!txt) throw new Error('Paste the encrypted text first.');
        try { input = b64ToBytes(txt); }
        catch (e) { throw new Error('That does not look like valid Base64 text.'); }
      }

      var pw = $('p').value;
      if (!pw) throw new Error('Enter the password.');

      var kfBytes = await readBytes(keyFile);
      show('ok', 'Deriving key (1,000,000 PBKDF2 iterations \u2014 this takes a moment)\u2026');

      var plain;
      try {
        plain = await ittybitzDecrypt(input, pw, kfBytes);
      } catch (e) {
        // Web Crypto signals a failed AES-GCM authentication (wrong password
        // or key file, or corrupted data) as a DOMException. Our own format
        // checks throw plain Errors with messages worth showing verbatim.
        // Classifying by type means a filename or message text can never
        // accidentally trigger the wrong explanation.
        if (e instanceof DOMException) {
          throw new Error('Decryption failed. The password or key file is wrong, or the data is corrupted.');
        }
        throw e;
      }

      var asText = null, binaryAsText = false;
      if (mode === 'text') {
        // Not UTF-8 means a file's ciphertext was pasted as text: hand the
        // bytes over as a download rather than showing replacement marks.
        try { asText = new TextDecoder('utf-8', { fatal: true }).decode(plain); } catch (eNotText) { asText = null; }
        if (asText === null) { binaryAsText = true; outName = 'decrypted.bin'; }
      }
      if (asText !== null) {
        show('ok', asText);
        $('out').classList.add('blur');
        $('out').title = 'Click to reveal';
        $('out').onclick = function () { this.classList.toggle('blur'); };
        $('hint').textContent = 'Decrypted successfully. Click the result to reveal or hide it.';
      } else {
        var blob = new Blob([plain], { type: 'application/octet-stream' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url; a.download = outName;
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        // Revoke on a delay: Safari can cancel a download whose object URL is
        // revoked before the download has actually started.
        setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
        show('ok', binaryAsText
          ? 'Decrypted successfully, but the result is not text \u2014 it looks like an encrypted file. Downloaded as "decrypted.bin"; rename it to what it was.'
          : 'Decrypted successfully \u2014 downloaded as "' + outName + '".');
      }
      // Best-effort erase now that the plaintext has been handed off (the
      // Blob and TextDecoder both copy). Same posture as the main app.
      plain.fill(0);
    } catch (err) {
      show('err', err && err.message ? err.message : String(err));
    } finally {
      btn.disabled = false;
      // Never leave the password sitting in the field. This tool is meant for
      // borrowed and air-gapped machines — exactly where that matters most.
      $('p').value = '';
    }
  };
})();
