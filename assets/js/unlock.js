(function () {
  'use strict';
  var STORE = 'portfolio_access_v1';
  var TTL = 24 * 60 * 60 * 1000; // stay unlocked for 24 hours on this browser
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  var gate = document.getElementById('lock-gate');
  var form = document.getElementById('lock-form');
  var input = document.getElementById('lock-input');
  var button = document.getElementById('lock-button');
  var errorBox = document.getElementById('lock-error');
  var content = document.getElementById('locked-content');
  var lockLink = document.getElementById('lock-link');
  var payloadEl = document.getElementById('locked-payload');
  if (!form || !content || !payloadEl) return;

  var payload = JSON.parse(payloadEl.textContent);

  function fromB64(s) {
    var bin = atob(s);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function toB64(buf) {
    var bytes = new Uint8Array(buf);
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function deriveKey(passcode) {
    return crypto.subtle.importKey('raw', enc.encode(passcode), 'PBKDF2', false, ['deriveKey']).then(function (base) {
      return crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: fromB64(payload.salt), iterations: payload.iter, hash: 'SHA-256' },
        base,
        { name: 'AES-GCM', length: 256 },
        true,
        ['decrypt']
      );
    });
  }

  function importKey(rawB64) {
    return crypto.subtle.importKey('raw', fromB64(rawB64), { name: 'AES-GCM' }, true, ['decrypt']);
  }

  function decryptPage(key) {
    return crypto.subtle
      .decrypt({ name: 'AES-GCM', iv: fromB64(payload.iv) }, key, fromB64(payload.ct))
      .then(function (buf) { return JSON.parse(dec.decode(buf)); });
  }

  function loadImages(key) {
    var imgs = content.querySelectorAll('img[data-locked]');
    Array.prototype.forEach.call(imgs, function (img) {
      fetch(img.getAttribute('data-locked'))
        .then(function (r) { if (!r.ok) throw new Error('missing'); return r.arrayBuffer(); })
        .then(function (buf) {
          var iv = new Uint8Array(buf, 0, 12);
          return crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, buf.slice(12));
        })
        .then(function (plain) {
          var blob = new Blob([plain], { type: img.getAttribute('data-mime') || 'image/png' });
          img.src = URL.createObjectURL(blob);
        })
        .catch(function () { /* leave the placeholder if one image fails */ });
    });
  }

  function reveal(page, key) {
    content.innerHTML = page.html;
    content.hidden = false;
    gate.hidden = true;
    if (lockLink) lockLink.hidden = false;
    if (page.title) document.title = page.title;
    loadImages(key);
    window.scrollTo(0, 0);
  }

  function remember(key) {
    crypto.subtle.exportKey('raw', key).then(function (raw) {
      try {
        localStorage.setItem(STORE, JSON.stringify({ k: toB64(raw), exp: Date.now() + TTL }));
      } catch (e) { /* storage blocked: the visitor will be asked on each page */ }
    });
  }

  function forget() {
    try { localStorage.removeItem(STORE); } catch (e) {}
  }

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.hidden = false;
  }

  if (lockLink) {
    lockLink.addEventListener('click', function (e) {
      e.preventDefault();
      forget();
      window.location.href = 'projects.html';
    });
  }

  // already unlocked on this browser: open straight away
  var saved = null;
  try { saved = JSON.parse(localStorage.getItem(STORE) || 'null'); } catch (e) {}
  if (saved && saved.exp > Date.now() && saved.k) {
    importKey(saved.k)
      .then(function (key) {
        return decryptPage(key).then(function (page) { reveal(page, key); });
      })
      .catch(function () {
        forget(); // passcode changed since it was saved
        input.focus();
      });
  } else {
    forget();
    input.focus();
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    errorBox.hidden = true;
    var passcode = input.value.trim();
    if (!passcode) return;
    if (!window.crypto || !crypto.subtle) {
      showError('This browser cannot unlock the page. Please use a current browser over https.');
      return;
    }
    button.disabled = true;
    button.textContent = 'Unlocking…';
    deriveKey(passcode)
      .then(function (key) {
        return decryptPage(key).then(function (page) {
          remember(key);
          reveal(page, key);
        });
      })
      .catch(function () {
        showError('That passcode is not correct. Please try again.');
        input.select();
      })
      .then(function () {
        button.disabled = false;
        button.textContent = 'Unlock';
      });
  });
})();
