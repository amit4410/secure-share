const API = '/api';
let token = localStorage.getItem('token');
let myPrivateKey = null;
const fileMetadata = {};
const selectedOwned = new Set();
const selectedShared = new Set();
let ownedCache = [];
let sharedCache = [];
let currentSharesFileId = null;

/* ============================================================
   HELPERS
   ============================================================ */

function bufToB64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, function(c) {
    return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];
  });
}
function escapeAttr(s) {
  return String(s).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}
function formatSize(bytes) {
  if (!bytes) return '0 B';
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1024 * 1024 * 1024) return (bytes / 1024 / 1024).toFixed(1) + ' MB';
  return (bytes / 1024 / 1024 / 1024).toFixed(2) + ' GB';
}
function formatTime(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  const diff = Date.now() - d.getTime();
  const min = Math.floor(diff / 60000);
  if (min < 1) return 'just now';
  if (min < 60) return min + 'm ago';
  const hr = Math.floor(min / 60);
  if (hr < 24) return hr + 'h ago';
  const days = Math.floor(hr / 24);
  if (days < 30) return days + 'd ago';
  return d.toLocaleDateString();
}
function fileIcon(name) {
  if (!name) return '📁';
  const ext = name.split('.').pop().toLowerCase();
  if (['png','jpg','jpeg','gif','webp','svg','bmp','ico'].includes(ext)) return '🖼️';
  if (['mp4','webm','mov','avi','mkv'].includes(ext)) return '🎬';
  if (['mp3','wav','ogg','flac','m4a'].includes(ext)) return '🎵';
  if (ext === 'pdf') return '📄';
  if (['txt','md','json','js','html','css','xml','csv','log'].includes(ext)) return '📝';
  if (['zip','rar','7z','tar','gz'].includes(ext)) return '📦';
  if (['doc','docx','odt'].includes(ext)) return '📘';
  if (['xls','xlsx','ods'].includes(ext)) return '📊';
  if (['ppt','pptx','odp'].includes(ext)) return '📽️';
  return '📁';
}

/* ============================================================
   TOAST 2.0
   ============================================================ */

function toast(msg, type, duration) {
  type = type || 'info';
  duration = duration || 3500;
  const container = document.getElementById('toast-container');
  if (!container) return;

  const ICONS = { success: '✓', error: '✕', info: 'i', warning: '!', delete: '🗑' };
  const DEFAULT_TITLE = { success: 'Success', error: 'Error', info: 'Notice', warning: 'Warning', delete: 'Deleted' };

  let title = DEFAULT_TITLE[type] || 'Notice';
  let body = String(msg);
  const colonIdx = body.indexOf(':');
  if (colonIdx > 0 && colonIdx < 40) {
    title = body.substring(0, colonIdx).trim();
    body = body.substring(colonIdx + 1).trim();
  }

  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.innerHTML =
    '<div class="toast-icon">' + (ICONS[type] || 'i') + '</div>' +
    '<div class="toast-body">' +
      '<div class="toast-title">' + escapeHtml(title) + '</div>' +
      '<div class="toast-message">' + escapeHtml(body) + '</div>' +
    '</div>' +
    '<button class="toast-close" aria-label="Close">✕</button>' +
    '<div class="toast-progress" style="animation-duration:' + duration + 'ms"></div>';

  container.appendChild(el);

  let timeoutId = null, remaining = duration, startTime = Date.now(), paused = false, dismissed = false;
  const progressEl = el.querySelector('.toast-progress');

  function dismiss() {
    if (dismissed || !el.parentElement) return;
    dismissed = true;
    clearTimeout(timeoutId);
    el.classList.add('leaving');
    el.style.pointerEvents = 'none';
    setTimeout(function() { el.remove(); }, 360);
  }
  function scheduleDismiss() {
    startTime = Date.now();
    timeoutId = setTimeout(dismiss, remaining);
  }
  el.querySelector('.toast-close').addEventListener('click', dismiss);
  el.addEventListener('mouseenter', function() {
    if (paused || dismissed) return;
    paused = true;
    clearTimeout(timeoutId);
    remaining -= (Date.now() - startTime);
    if (remaining < 0) remaining = 0;
    if (progressEl) progressEl.style.animationPlayState = 'paused';
  });
  el.addEventListener('mouseleave', function() {
    if (!paused || dismissed) return;
    paused = false;
    if (progressEl) progressEl.style.animationPlayState = 'running';
    scheduleDismiss();
  });
  scheduleDismiss();
}

function toastSuccess(msg, d) { toast(msg, 'success', d); }
function toastError(msg, d) { toast(msg, 'error', d); }
function toastInfo(msg, d) { toast(msg, 'info', d); }
function toastWarning(msg, d) { toast(msg, 'warning', d); }
function toastDelete(msg, d) { toast(msg, 'delete', d || 4000); }

/* ============================================================
   API WRAPPER
   ============================================================ */

async function api(path, opts = {}) {
  opts.headers = opts.headers || {};
  if (token) opts.headers['Authorization'] = 'Bearer ' + token;
  if (opts.body && !(opts.body instanceof FormData)) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(API + path, opts);
  if (!res.ok) {
    const err = await res.json().catch(function() { return { error: 'Request failed' }; });
    throw new Error(err.error || 'Request failed');
  }
  return res.json();
}

/* ============================================================
   CRYPTO
   ============================================================ */

async function deriveKeyFromPassword(password) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: enc.encode('secure-share-salt-v1'), iterations: 100000, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function getMyPublicKey() {
  const stored = localStorage.getItem('my_public_key');
  if (stored) {
    try {
      return await crypto.subtle.importKey('jwk', JSON.parse(stored), { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    } catch (e) {}
  }
  if (myPrivateKey) {
    try {
      const privJwk = await crypto.subtle.exportKey('jwk', myPrivateKey);
      const pubJwk = { kty: 'RSA', n: privJwk.n, e: privJwk.e, alg: 'RSA-OAEP-256', ext: true };
      localStorage.setItem('my_public_key', JSON.stringify(pubJwk));
      return await crypto.subtle.importKey('jwk', pubJwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
    } catch (e) {}
  }
  return null;
}

/* ============================================================
   AUTH
   ============================================================ */

async function register() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  if (!username || !password) return toastError('Enter username and password');
  if (password.length < 6) return toastError('Password must be at least 6 characters');

  try {
    const keyPair = await crypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt']
    );
    const publicKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const privateKeyJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);

    const pwKey = await deriveKeyFromPassword(password);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedPriv = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, pwKey,
      new TextEncoder().encode(JSON.stringify(privateKeyJwk))
    );

    const res = await api('/register', {
      method: 'POST', body: { username, password, publicKey: JSON.stringify(publicKeyJwk) }
    });

    token = res.token;
    localStorage.setItem('token', token);
    localStorage.setItem('pk_' + username, JSON.stringify({ iv: bufToB64(iv), data: bufToB64(encryptedPriv) }));
    localStorage.setItem('my_public_key', JSON.stringify(publicKeyJwk));

    myPrivateKey = keyPair.privateKey;
    toastSuccess('Welcome, ' + username + '!');
    await loadMain();
  } catch (err) {
    toastError('Registration failed: ' + err.message);
    console.error(err);
  }
}

async function login() {
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  if (!username || !password) return toastError('Enter username and password');

  try {
    const res = await api('/login', { method: 'POST', body: { username, password } });
    token = res.token;
    localStorage.setItem('token', token);

    const stored = localStorage.getItem('pk_' + username);
    if (stored) {
      const parsed = JSON.parse(stored);
      const pwKey = await deriveKeyFromPassword(password);
      try {
        const privJwk = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBuf(parsed.iv) }, pwKey, b64ToBuf(parsed.data));
        myPrivateKey = await crypto.subtle.importKey(
          'jwk', JSON.parse(new TextDecoder().decode(privJwk)),
          { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']
        );
      } catch (e) {
        toastError('Logged in, but could not unlock private key', 5000);
      }
    } else {
      toastInfo('Logged in — import key to decrypt shared files', 5000);
    }
    await loadMain();
    toastSuccess('Welcome back, ' + username);
  } catch (err) {
    toastError('Login failed: ' + err.message);
    console.error(err);
  }
}

function logout() {
  localStorage.removeItem('token');
  token = null;
  myPrivateKey = null;
  selectedOwned.clear();
  selectedShared.clear();
  document.getElementById('auth-section').style.display = 'block';
  document.getElementById('main-section').style.display = 'none';
}

/* ============================================================
   ENCRYPT / UPLOAD
   ============================================================ */

async function encryptFile(file) {
  const fileKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const rawKey = await crypto.subtle.exportKey('raw', fileKey);
  const chunkSize = 1024 * 1024;
  const chunks = [];
  for (let offset = 0; offset < file.size; offset += chunkSize) {
    const chunk = file.slice(offset, offset + chunkSize);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, fileKey, await chunk.arrayBuffer());
    chunks.push({ iv: bufToB64(iv), data: bufToB64(enc) });
  }
  return { chunks, rawKey };
}

function onFilesSelected() {
  const input = document.getElementById('file-input');
  const list = document.getElementById('selected-files');
  const btn = document.getElementById('upload-btn');
  const files = input.files;
  list.innerHTML = '';
  if (!files || files.length === 0) {
    btn.disabled = true;
    btn.textContent = 'Encrypt & Upload';
    return;
  }
  for (let i = 0; i < files.length; i++) {
    const f = files[i];
    const li = document.createElement('li');
    li.innerHTML = '<span>' + fileIcon(f.name) + ' ' + escapeHtml(f.name) +
      ' <small style="color:var(--text-dim)">(' + formatSize(f.size) + ')</small></span>';
    list.appendChild(li);
  }
  btn.disabled = false;
  btn.textContent = 'Encrypt & Upload (' + files.length + ' file' + (files.length > 1 ? 's' : '') + ')';
}

async function uploadFile() {
  const input = document.getElementById('file-input');
  const files = input.files;
  const btn = document.getElementById('upload-btn');
  const status = document.getElementById('upload-status');
  if (!files || files.length === 0) return toastError('Choose at least one file');

  btn.disabled = true;
  const originalText = btn.textContent;
  let success = 0, failed = 0;

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    btn.textContent = 'Encrypting ' + (i + 1) + ' / ' + files.length + '...';
    status.textContent = 'Working on: ' + file.name + ' (' + formatSize(file.size) + ')';
    try {
      const result = await encryptFile(file);
      const chunks = result.chunks;
      const rawKey = result.rawKey;

      const metadata = { name: file.name, type: file.type || 'application/octet-stream', size: file.size };
      const metaIv = crypto.getRandomValues(new Uint8Array(12));
      const fileKey = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
      const encMeta = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: metaIv }, fileKey,
        new TextEncoder().encode(JSON.stringify(metadata))
      );
      const encryptedMetadata = JSON.stringify({ iv: bufToB64(metaIv), data: bufToB64(encMeta) });

      let selfWrappedKey = null;
      const myPub = await getMyPublicKey();
      if (myPub) {
        try {
          const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, myPub, rawKey);
          selfWrappedKey = bufToB64(wrapped);
        } catch (e) {}
      }

      const blob = new Blob([JSON.stringify(chunks)], { type: 'application/octet-stream' });
      const form = new FormData();
      form.append('file', blob, 'encrypted.bin');
      form.append('encryptedMetadata', encryptedMetadata);
      form.append('selfWrappedKey', selfWrappedKey || '');

      const res = await api('/upload', { method: 'POST', body: form });

      const fileKeys = JSON.parse(localStorage.getItem('fileKeys') || '{}');
      fileKeys[res.id] = bufToB64(rawKey);
      localStorage.setItem('fileKeys', JSON.stringify(fileKeys));
      success++;
    } catch (err) {
      console.error('Failed: ' + file.name, err);
      failed++;
    }
  }

  btn.disabled = false;
  btn.textContent = originalText;
  status.textContent = '';
  input.value = '';
  document.getElementById('selected-files').innerHTML = '';
  if (failed === 0) toastSuccess('Uploaded ' + success + ' file(s)');
  else toastError('Uploaded ' + success + ', failed ' + failed, 5000);
  await loadMain();
}

/* ============================================================
   DECRYPT / DOWNLOAD
   ============================================================ */

async function decryptFileToBlob(id, wrappedKeyB64) {
  const res = await fetch(API + '/download/' + id, { headers: { 'Authorization': 'Bearer ' + token } });
  if (!res.ok) throw new Error('Download failed');
  const chunks = await res.json();

  let rawKeyB64;
  if (wrappedKeyB64) {
    if (!myPrivateKey) throw new Error('Private key locked. Log in on the device where you registered.');
    const unwrapped = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, myPrivateKey, b64ToBuf(wrappedKeyB64));
    rawKeyB64 = bufToB64(unwrapped);
  } else {
    const fileKeys = JSON.parse(localStorage.getItem('fileKeys') || '{}');
    rawKeyB64 = fileKeys[id];
  }
  if (!rawKeyB64) throw new Error('No key for this file on this device.');

  const fileKey = await crypto.subtle.importKey('raw', b64ToBuf(rawKeyB64), 'AES-GCM', false, ['decrypt']);

  let filename = 'decrypted-' + id.substring(0, 8);
  let mimeType = 'application/octet-stream';
  const encryptedMetadata = fileMetadata[id];
  if (encryptedMetadata) {
    try {
      const meta = JSON.parse(encryptedMetadata);
      const decMeta = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBuf(meta.iv) }, fileKey, b64ToBuf(meta.data));
      const metaObj = JSON.parse(new TextDecoder().decode(decMeta));
      if (metaObj.name) filename = metaObj.name;
      if (metaObj.type) mimeType = metaObj.type;
    } catch (e) {}
  }

  const parts = [];
  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBuf(chunk.iv) }, fileKey, b64ToBuf(chunk.data));
    parts.push(new Uint8Array(dec));
  }
  return { blob: new Blob(parts, { type: mimeType }), filename, mimeType };
}

async function saveBlob(blob, filename) {
  if (window.showSaveFilePicker) {
    let handle;
    try {
      handle = await window.showSaveFilePicker({ suggestedName: filename });
    } catch (err) {
      if (err.name === 'AbortError') { toastInfo('Save cancelled'); return; }
      throw err;
    }
    const writable = await handle.createWritable();
    await writable.write(blob);
    await writable.close();
    toastSuccess('Saved: ' + filename);
    return;
  }
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(function() { URL.revokeObjectURL(url); }, 2000);
  toastInfo('Saving: ' + filename + ' — check Downloads');
}

async function downloadFile(id, wrappedKeyB64) {
  try {
    const r = await decryptFileToBlob(id, wrappedKeyB64);
    await saveBlob(r.blob, r.filename);
  } catch (err) {
    toastError('Download failed: ' + err.message);
  }
}

/* ============================================================
   PREVIEW
   ============================================================ */

async function previewFile(id, wrappedKeyB64) {
  const modal = document.getElementById('preview-modal');
  const title = document.getElementById('preview-title');
  const body = document.getElementById('preview-body');
  title.textContent = '🔓 Decrypting...';
  body.innerHTML = '<p>🔓 Decrypting...</p>';
  modal.style.display = 'flex';
  try {
    const r = await decryptFileToBlob(id, wrappedKeyB64);
    title.textContent = fileIcon(r.filename) + ' ' + r.filename;
    if (window._previewURL) URL.revokeObjectURL(window._previewURL);
    const url = URL.createObjectURL(r.blob);
    window._previewURL = url;
    if (r.mimeType.startsWith('image/')) body.innerHTML = '<img src="' + url + '" alt="preview">';
    else if (r.mimeType.startsWith('video/')) body.innerHTML = '<video src="' + url + '" controls autoplay></video>';
    else if (r.mimeType.startsWith('audio/')) body.innerHTML = '<audio src="' + url + '" controls autoplay></audio>';
    else if (r.mimeType === 'application/pdf') body.innerHTML = '<iframe src="' + url + '"></iframe>';
    else if (r.mimeType.startsWith('text/') || r.mimeType === 'application/json' ||
             ['js','html','css','xml','csv','md','log'].includes(r.filename.split('.').pop().toLowerCase())) {
      const text = await r.blob.text();
      body.innerHTML = '<pre>' + escapeHtml(text.length > 100000 ? text.substring(0, 100000) + '\n\n... (truncated)' : text) + '</pre>';
    } else {
      body.innerHTML = '<p>Preview not available for <code>' + escapeHtml(r.mimeType) + '</code>.</p>';
    }
  } catch (err) {
    body.innerHTML = '<p style="color:var(--danger)">❌ ' + escapeHtml(err.message) + '</p>';
  }
}

function closePreview() {
  document.getElementById('preview-modal').style.display = 'none';
  document.getElementById('preview-body').innerHTML = '';
  if (window._previewURL) { URL.revokeObjectURL(window._previewURL); window._previewURL = null; }
}

/* ============================================================
   MANAGE SHARES MODAL
   ============================================================ */

async function manageShares(fileId) {
  currentSharesFileId = fileId;
  const modal = document.getElementById('shares-modal');
  const body = document.getElementById('shares-body');
  const title = document.getElementById('shares-title');

  const file = ownedCache.find(function(f) { return f.id === fileId; });
  const fileName = file ? file.name : fileId.substring(0, 12);

  title.textContent = '🔐 ' + fileName;
  body.innerHTML = '<p style="text-align:center;padding:20px;color:var(--text-muted)">Loading…</p>';
  modal.style.display = 'flex';

  try {
    const data = await api('/files/' + fileId + '/shares');
    const shares = data.shares || [];
    const count = shares.length;

    let sharesHtml = '';
    if (count === 0) {
      sharesHtml = '<li class="empty">Not shared with anyone yet</li>';
    } else {
      sharesHtml = shares.map(function(s) {
        return '<li>' +
          '<div class="finfo">' +
            '<span class="fname">👤 ' + escapeHtml(s.recipient_username) + '</span>' +
            '<span class="fmeta">shared ' + formatTime(s.created_at) + '</span>' +
          '</div>' +
          '<div class="factions">' +
            '<button class="danger wide" onclick="revokeShare(\'' + fileId + '\', ' + s.recipient_id + ', \'' + escapeAttr(s.recipient_username) + '\')">🚫 Revoke</button>' +
          '</div>' +
        '</li>';
      }).join('');
    }

    body.innerHTML =
      '<p class="hint">File: <strong>' + escapeHtml(fileName) + '</strong></p>' +
      '<h3>Shared with (' + count + ')</h3>' +
      '<ul class="file-list">' + sharesHtml + '</ul>' +
      '<div class="add-recipient">' +
        '<input id="new-recipient-input" placeholder="Username to share with">' +
        '<button class="btn-primary" onclick="addRecipientToFile()">📤 Share</button>' +
      '</div>' +
      '<p class="hint" style="margin-top:14px">🔒 Revoking triggers a key rotation — the file is re-encrypted with a new key, and only remaining recipients keep access.</p>';
  } catch (err) {
    body.innerHTML = '<p style="color:var(--danger)">Failed to load: ' + escapeHtml(err.message) + '</p>';
  }
}

function closeSharesModal() {
  document.getElementById('shares-modal').style.display = 'none';
  document.getElementById('shares-body').innerHTML = '';
  currentSharesFileId = null;
}

async function addRecipientToFile() {
  const fileId = currentSharesFileId;
  if (!fileId) return;
  const input = document.getElementById('new-recipient-input');
  const username = input.value.trim();
  if (!username) return toastError('Enter a username');

  try {
    const users = await api('/users');
    const recipient = users.find(function(u) { return u.username === username; });
    if (!recipient || !recipient.public_key) return toastError('User not found');

    const fileKeys = JSON.parse(localStorage.getItem('fileKeys') || '{}');
    const rawKeyB64 = fileKeys[fileId];
    if (!rawKeyB64) return toastError('No file key on this device');

    const recipientPub = await crypto.subtle.importKey(
      'jwk', JSON.parse(recipient.public_key), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']
    );
    const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPub, b64ToBuf(rawKeyB64));

    await api('/share', {
      method: 'POST',
      body: { fileId: fileId, recipientId: recipient.id, wrappedKey: bufToB64(wrapped) }
    });
    toastSuccess('Shared with ' + username);
    await manageShares(fileId);
  } catch (err) {
    toastError('Share failed: ' + err.message);
  }
}

async function revokeShare(fileId, recipientId, recipientName) {
  if (!confirm('Revoke ' + recipientName + '?\n\nThe file will be decrypted and re-encrypted with a NEW key. Only remaining recipients (and you) will be able to decrypt it.\n\nThis is cryptographically real — ' + recipientName + '\'s old key becomes useless.'))

    return;

  if (navigator.vibrate) navigator.vibrate([30, 20, 30]);

  const fileKeys = JSON.parse(localStorage.getItem('fileKeys') || '{}');
  const oldRawKeyB64 = fileKeys[fileId];
  if (!oldRawKeyB64) return toastError('No file key on this device — cannot rotate');

  toastInfo('Rotating key for ' + recipientName + '...', 10000);

  try {
    const file = ownedCache.find(function(f) { return f.id === fileId; });
    const fileName = file ? file.name : 'file';

    // 1. Download current encrypted chunks
    const chunks = await api('/download/' + fileId);

    // 2. Decrypt each chunk with old key
    const oldKey = await crypto.subtle.importKey('raw', b64ToBuf(oldRawKeyB64), 'AES-GCM', false, ['decrypt']);
    const plaintexts = [];
    for (let i = 0; i < chunks.length; i++) {
      const dec = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: b64ToBuf(chunks[i].iv) }, oldKey, b64ToBuf(chunks[i].data)
      );
      plaintexts.push(dec);
    }

    // 3. Generate new key + re-encrypt chunks
    const newKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
    const newRawKey = await crypto.subtle.exportKey('raw', newKey);
    const newChunks = [];
    for (let i = 0; i < plaintexts.length; i++) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, newKey, plaintexts[i]);
      newChunks.push({ iv: bufToB64(iv), data: bufToB64(enc) });
    }

    // 4. Re-encrypt metadata
    const meta = JSON.parse(fileMetadata[fileId]);
    const decMeta = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBuf(meta.iv) }, oldKey, b64ToBuf(meta.data));
    const newMetaIv = crypto.getRandomValues(new Uint8Array(12));
    const encMeta = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: newMetaIv }, newKey, decMeta);
    const newEncryptedMetadata = JSON.stringify({ iv: bufToB64(newMetaIv), data: bufToB64(encMeta) });

    // 5. Get remaining recipients (excluding revoked one)
    const currentSharesResp = await api('/files/' + fileId + '/shares');
    const remaining = (currentSharesResp.shares || []).filter(function(s) { return s.recipient_id !== recipientId; });

    // 6. Fetch users once, build wrapped keys for remaining
    const allUsers = await api('/users');
    const newShares = [];
    for (let i = 0; i < remaining.length; i++) {
      const u = allUsers.find(function(x) { return x.id === remaining[i].recipient_id; });
      if (!u || !u.public_key) continue;
      try {
        const recipientPub = await crypto.subtle.importKey(
          'jwk', JSON.parse(u.public_key), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']
        );
        const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPub, newRawKey);
        newShares.push({ recipientId: u.id, wrappedKey: bufToB64(wrapped) });
      } catch (e) { console.warn('Skipped ' + u.username, e); }
    }

    // 7. Self-wrap new key
    const myPub = await getMyPublicKey();
    if (!myPub) throw new Error('Cannot get own public key');
    const selfWrapped = bufToB64(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, myPub, newRawKey));

    // 8. Upload new blob + metadata + self-wrap + new shares
    const newBlob = new Blob([JSON.stringify(newChunks)], { type: 'application/octet-stream' });
    const form = new FormData();
    form.append('file', newBlob, 'encrypted.bin');
    form.append('encryptedMetadata', newEncryptedMetadata);
    form.append('selfWrappedKey', selfWrapped);
    form.append('newShares', JSON.stringify(newShares));

    await api('/files/' + fileId + '/rotate', { method: 'POST', body: form });

    // 9. Update local key
    fileKeys[fileId] = bufToB64(newRawKey);
    localStorage.setItem('fileKeys', JSON.stringify(fileKeys));

    toastDelete('🔓 Revoked ' + recipientName + ' — file re-encrypted, ' + newShares.length + ' remaining');
    await loadMain();
    await manageShares(fileId);
  } catch (err) {
    toastError('Revoke failed: ' + err.message, 6000);
    console.error(err);
  }
}

/* ============================================================
   BATCH SHARE
   ============================================================ */

async function shareSelectedOwned() {
  const ids = Array.from(selectedOwned);
  if (ids.length === 0) return toastError('Select files first');
  const username = prompt('Share ' + ids.length + ' file(s) with which username?');
  if (!username) return;

  try {
    const users = await api('/users');
    const recipient = users.find(function(u) { return u.username === username; });
    if (!recipient || !recipient.public_key) return toastError('User not found');

    const recipientPub = await crypto.subtle.importKey(
      'jwk', JSON.parse(recipient.public_key), { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']
    );

    const fileKeys = JSON.parse(localStorage.getItem('fileKeys') || '{}');
    let success = 0, failed = 0;
    for (let i = 0; i < ids.length; i++) {
      try {
        const rawKeyB64 = fileKeys[ids[i]];
        if (!rawKeyB64) { failed++; continue; }
        const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, recipientPub, b64ToBuf(rawKeyB64));
        await api('/share', {
          method: 'POST',
          body: { fileId: ids[i], recipientId: recipient.id, wrappedKey: bufToB64(wrapped) }
        });
        success++;
      } catch (e) { failed++; }
    }
    if (failed === 0) toastSuccess('Shared ' + success + ' file(s) with ' + username);
    else toastError('Shared ' + success + ', failed ' + failed, 4000);
    selectedOwned.clear();
    await loadMain();
  } catch (err) {
    toastError('Share failed: ' + err.message);
  }
}

/* ============================================================
   DELETE
   ============================================================ */

async function deleteFile(id, name) {
  if (!confirm('Delete "' + name + '"?\n\nThis permanently removes it and revokes ALL shares. Recipients who already downloaded it keep their copy.\n\nThis cannot be undone.')) return;

  if (navigator.vibrate) navigator.vibrate([40, 30, 60]);
  const row = document.querySelector('#my-files li[data-file-id="' + id + '"]');
  if (row) row.classList.add('deleting');
  const anim = new Promise(function(r) { setTimeout(r, 600); });

  try {
    await api('/files/' + id, { method: 'DELETE' });
    const fileKeys = JSON.parse(localStorage.getItem('fileKeys') || '{}');
    delete fileKeys[id];
    localStorage.setItem('fileKeys', JSON.stringify(fileKeys));
    selectedOwned.delete(id);
    await anim;
    toastDelete('"' + name + '" deleted');
    await loadMain();
  } catch (err) {
    if (row) row.classList.remove('deleting');
    toastError('Delete failed: ' + err.message);
  }
}

async function deleteSelectedOwned() {
  const ids = Array.from(selectedOwned);
  if (ids.length === 0) return toastError('Select files first');
  if (!confirm('Delete ' + ids.length + ' selected file(s)?\n\nThis cannot be undone.')) return;

  if (navigator.vibrate) navigator.vibrate([60, 40, 60, 40, 80]);
  ids.forEach(function(id) {
    const row = document.querySelector('#my-files li[data-file-id="' + id + '"]');
    if (row) row.classList.add('deleting');
  });
  const anim = new Promise(function(r) { setTimeout(r, 600); });

  let success = 0, failed = 0;
  const fileKeys = JSON.parse(localStorage.getItem('fileKeys') || '{}');
  for (let i = 0; i < ids.length; i++) {
    try {
      await api('/files/' + ids[i], { method: 'DELETE' });
      delete fileKeys[ids[i]];
      success++;
    } catch (e) { failed++; }
  }
  localStorage.setItem('fileKeys', JSON.stringify(fileKeys));
  selectedOwned.clear();
  await anim;
  if (failed === 0) toastDelete(success + ' file(s) deleted');
  else toastError('Deleted ' + success + ', failed ' + failed);
  await loadMain();
}

async function removeSharedFromMyList(fileId, name) {
  if (!confirm('Remove "' + name + '" from your list?\n\nThe owner still has it and can share again.')) return;
  if (navigator.vibrate) navigator.vibrate([40, 30, 60]);
  const row = document.querySelector('#shared-files li[data-file-id="' + fileId + '"]');
  if (row) row.classList.add('deleting');
  const anim = new Promise(function(r) { setTimeout(r, 600); });
  try {
    await api('/shares/recipient/' + fileId, { method: 'DELETE' });
    selectedShared.delete(fileId);
    await anim;
    toastDelete('"' + name + '" removed');
    await loadMain();
  } catch (err) {
    if (row) row.classList.remove('deleting');
    toastError('Remove failed: ' + err.message);
  }
}

async function removeSelectedShared() {
  const ids = Array.from(selectedShared);
  if (ids.length === 0) return toastError('Select files first');
  if (!confirm('Remove ' + ids.length + ' file(s) from your list?')) return;
  if (navigator.vibrate) navigator.vibrate([60, 40, 60, 40, 80]);
  ids.forEach(function(id) {
    const row = document.querySelector('#shared-files li[data-file-id="' + id + '"]');
    if (row) row.classList.add('deleting');
  });
  const anim = new Promise(function(r) { setTimeout(r, 600); });
  let success = 0, failed = 0;
  for (let i = 0; i < ids.length; i++) {
    try {
      await api('/shares/recipient/' + ids[i], { method: 'DELETE' });
      success++;
    } catch (e) { failed++; }
  }
  selectedShared.clear();
  await anim;
  if (failed === 0) toastDelete(success + ' file(s) removed');
  else toastError('Removed ' + success + ', failed ' + failed);
  await loadMain();
}

/* ============================================================
   BATCH ZIP
   ============================================================ */

async function downloadSelectedOwned() {
  const ids = Array.from(selectedOwned);
  if (ids.length === 0) return toastError('Select files first');
  if (ids.length === 1) return await downloadFile(ids[0]);
  if (!window.JSZip) return toastError('ZIP library not loaded');
  toastInfo('Preparing ZIP of ' + ids.length + ' files...');
  const zip = new JSZip();
  let ok = 0, fail = 0;
  for (let i = 0; i < ids.length; i++) {
    try {
      const r = await decryptFileToBlob(ids[i]);
      zip.file(r.filename, r.blob);
      ok++;
    } catch (e) { fail++; }
  }
  if (ok === 0) return toastError('Nothing to download');
  const zipBlob = await zip.generateAsync({ type: 'blob' });
  try {
    await saveBlob(zipBlob, 'secure-share-' + Date.now() + '.zip');
    if (fail > 0) toastWarning('Failed: ' + fail);
  } catch (err) { toastError('Save failed: ' + err.message); }
}

async function downloadSelectedShared() {
  const ids = Array.from(selectedShared);
  if (ids.length === 0) return toastError('Select files first');
  const wrappedMap = {};
  sharedCache.forEach(function(s) { wrappedMap[s.file_id] = s.wrapped_key; });
  if (ids.length === 1) return await downloadFile(ids[0], wrappedMap[ids[0]]);
  if (!window.JSZip) return toastError('ZIP library not loaded');
  toastInfo('Preparing ZIP...');
  const zip = new JSZip();
  let ok = 0, fail = 0;
  for (let i = 0; i < ids.length; i++) {
    try {
      const r = await decryptFileToBlob(ids[i], wrappedMap[ids[i]]);
      zip.file(r.filename, r.blob);
      ok++;
    } catch (e) { fail++; }
  }
  if (ok === 0) return toastError('Nothing to download');
  const zipBlob = await zip.generateAsync({ type: 'blob' });
  try {
    await saveBlob(zipBlob, 'shared-with-me-' + Date.now() + '.zip');
    if (fail > 0) toastWarning('Failed: ' + fail);
  } catch (err) { toastError('Save failed: ' + err.message); }
}

/* ============================================================
   SELECTION
   ============================================================ */

function toggleOwned(id) {
  if (selectedOwned.has(id)) selectedOwned.delete(id);
  else selectedOwned.add(id);
  updateOwnedToolbar();
}
function toggleShared(id) {
  if (selectedShared.has(id)) selectedShared.delete(id);
  else selectedShared.add(id);
  updateSharedToolbar();
}
function toggleSelectAllOwned(cb) {
  selectedOwned.clear();
  if (cb.checked) ownedCache.forEach(function(f) { selectedOwned.add(f.id); });
  renderOwnedList();
  updateOwnedToolbar();
}
function toggleSelectAllShared(cb) {
  selectedShared.clear();
  if (cb.checked) sharedCache.forEach(function(s) { selectedShared.add(s.file_id); });
  renderSharedList();
  updateSharedToolbar();
}
function updateOwnedToolbar() {
  const count = document.getElementById('owned-count');
  const all = document.getElementById('select-all-owned');
  if (count) count.textContent = selectedOwned.size + ' selected';
  if (all) {
    all.checked = ownedCache.length > 0 && selectedOwned.size === ownedCache.length;
    all.indeterminate = selectedOwned.size > 0 && selectedOwned.size < ownedCache.length;
  }
}
function updateSharedToolbar() {
  const count = document.getElementById('shared-count');
  const all = document.getElementById('select-all-shared');
  if (count) count.textContent = selectedShared.size + ' selected';
  if (all) {
    all.checked = sharedCache.length > 0 && selectedShared.size === sharedCache.length;
    all.indeterminate = selectedShared.size > 0 && selectedShared.size < sharedCache.length;
  }
}

/* ============================================================
   RENDER
   ============================================================ */

function renderOwnedList() {
  const el = document.getElementById('my-files');
  el.innerHTML = '';
  if (ownedCache.length === 0) {
    el.innerHTML = '<li class="empty">No files yet. Upload above to get started.</li>';
    return;
  }
  for (let i = 0; i < ownedCache.length; i++) {
    const f = ownedCache[i];
    const checked = selectedOwned.has(f.id) ? 'checked' : '';
    const li = document.createElement('li');
    li.setAttribute('data-file-id', f.id);
    li.innerHTML =
      '<input type="checkbox" class="file-checkbox" ' + checked +
        ' onchange="toggleOwned(\'' + f.id + '\')">' +
      '<div class="finfo">' +
        '<span class="fname">' + fileIcon(f.name) + ' ' + escapeHtml(f.name) + '</span>' +
        '<span class="fmeta">' + formatSize(f.size) + ' · ' + formatTime(f.created_at) + '</span>' +
      '</div>' +
      '<div class="factions">' +
        '<button onclick="previewFile(\'' + f.id + '\')" title="View">👁</button>' +
        '<button onclick="downloadFile(\'' + f.id + '\')" title="Download">⬇</button>' +
        '<button onclick="manageShares(\'' + f.id + '\')" title="Manage shares">🔐</button>' +
        '<button class="danger" onclick="deleteFile(\'' + f.id + '\', \'' + escapeAttr(f.name) + '\')" title="Delete">🗑</button>' +
      '</div>';
    el.appendChild(li);
  }
}

function renderSharedList() {
  const el = document.getElementById('shared-files');
  el.innerHTML = '';
  if (sharedCache.length === 0) {
    el.innerHTML = '<li class="empty">Nothing shared with you yet.</li>';
    return;
  }
  for (let i = 0; i < sharedCache.length; i++) {
    const s = sharedCache[i];
    const checked = selectedShared.has(s.file_id) ? 'checked' : '';
    const li = document.createElement('li');
    li.setAttribute('data-file-id', s.file_id);
    li.innerHTML =
      '<input type="checkbox" class="file-checkbox" ' + checked +
        ' onchange="toggleShared(\'' + s.file_id + '\')">' +
      '<div class="finfo">' +
        '<span class="fname">' + fileIcon(s.name) + ' ' + escapeHtml(s.name) + '</span>' +
        '<span class="fmeta">from <strong style="color:var(--primary)">' + escapeHtml(s.owner) + '</strong>' +
          ' · ' + formatSize(s.size) + ' · ' + formatTime(s.created_at) + '</span>' +
      '</div>' +
      '<div class="factions">' +
        '<button onclick="previewFile(\'' + s.file_id + '\', \'' + s.wrapped_key + '\')" title="View">👁</button>' +
        '<button onclick="downloadFile(\'' + s.file_id + '\', \'' + s.wrapped_key + '\')" title="Download">⬇</button>' +
        '<button class="danger" onclick="removeSharedFromMyList(\'' + s.file_id + '\', \'' + escapeAttr(s.name) + '\')" title="Remove">🗑</button>' +
      '</div>';
    el.appendChild(li);
  }
}

/* ============================================================
   LOAD MAIN — always refresh local file keys from self_wrapped_key
   ============================================================ */

async function loadMain() {
  document.getElementById('auth-section').style.display = 'none';
  document.getElementById('main-section').style.display = 'block';

  const payload = JSON.parse(atob(token.split('.')[1]));
  document.getElementById('current-user').textContent = payload.username;
  document.getElementById('avatar').textContent = payload.username.charAt(0).toUpperCase();

  const data = await api('/files');
  const fileKeys = JSON.parse(localStorage.getItem('fileKeys') || '{}');

  ownedCache = [];
  for (let i = 0; i < data.owned.length; i++) {
    const f = data.owned[i];
    fileMetadata[f.id] = f.encrypted_metadata;

    // Always re-sync from self_wrapped_key if we have the private key.
    // This keeps the owner's local key up-to-date after rotations.
    if (f.self_wrapped_key && myPrivateKey) {
      try {
        const unwrapped = await crypto.subtle.decrypt(
          { name: 'RSA-OAEP' }, myPrivateKey, b64ToBuf(f.self_wrapped_key)
        );
        fileKeys[f.id] = bufToB64(unwrapped);
      } catch (e) { console.warn('Could not unwrap for ' + f.id, e); }
    }

    // Migration: local key exists but no self_wrapped_key → wrap and push
    if (fileKeys[f.id] && !f.self_wrapped_key && myPrivateKey) {
      try {
        const myPub = await getMyPublicKey();
        if (myPub) {
          const wrapped = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, myPub, b64ToBuf(fileKeys[f.id]));
          await api('/files/' + f.id + '/self-wrap', {
            method: 'POST', body: { selfWrappedKey: bufToB64(wrapped) }
          });
        }
      } catch (e) {}
    }

    let name = f.id.substring(0, 12) + '...';
    if (fileKeys[f.id]) {
      try {
        const fileKey = await crypto.subtle.importKey('raw', b64ToBuf(fileKeys[f.id]), 'AES-GCM', false, ['decrypt']);
        const meta = JSON.parse(f.encrypted_metadata);
        const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBuf(meta.iv) }, fileKey, b64ToBuf(meta.data));
        name = JSON.parse(new TextDecoder().decode(dec)).name;
      } catch (e) {}
    }

    ownedCache.push({ id: f.id, name, size: f.size, created_at: f.created_at });
  }

  localStorage.setItem('fileKeys', JSON.stringify(fileKeys));

  sharedCache = [];
  for (let i = 0; i < data.shared.length; i++) {
    const s = data.shared[i];
    fileMetadata[s.file_id] = s.encrypted_metadata;
    let name = s.file_id.substring(0, 12) + '...';
    if (myPrivateKey) {
      try {
        const unwrapped = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, myPrivateKey, b64ToBuf(s.wrapped_key));
        const fileKey = await crypto.subtle.importKey('raw', unwrapped, 'AES-GCM', false, ['decrypt']);
        const meta = JSON.parse(s.encrypted_metadata);
        const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBuf(meta.iv) }, fileKey, b64ToBuf(meta.data));
        name = JSON.parse(new TextDecoder().decode(dec)).name;
      } catch (e) {}
    }
    sharedCache.push({
      file_id: s.file_id, wrapped_key: s.wrapped_key,
      owner: s.owner, name, size: s.size, created_at: s.created_at
    });
  }

  renderOwnedList();
  renderSharedList();
  updateOwnedToolbar();
  updateSharedToolbar();
}

/* ============================================================
   EXPORT / IMPORT KEY
   ============================================================ */

function exportPrivateKey() {
  const username = JSON.parse(atob(token.split('.')[1])).username;
  const stored = localStorage.getItem('pk_' + username);
  if (!stored) return toastError('No key on this device to export');
  const parsed = JSON.parse(stored);
  const exportData = {
    version: 1, username,
    iv: parsed.iv, data: parsed.data,
    exported_at: new Date().toISOString()
  };
  const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = username + '-private-key.key';
  a.click();
  URL.revokeObjectURL(url);
  toastSuccess('Key exported — keep the file safe!', 5000);
}

function importPrivateKey() {
  document.getElementById('import-key-input').click();
}

async function handleImportKey(inputEl) {
  const file = inputEl.files[0];
  if (!file) return;
  inputEl.value = '';
  try {
    const imported = JSON.parse(await file.text());
    if (!imported.username || !imported.iv || !imported.data) return toastError('Invalid key file');
    const currentUser = JSON.parse(atob(token.split('.')[1])).username;
    if (imported.username !== currentUser) return toastError('This key belongs to "' + imported.username + '"', 5000);
    const password = prompt('Enter your password to unlock this key:');
    if (!password) return;
    const pwKey = await deriveKeyFromPassword(password);
    try {
      const privJwk = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBuf(imported.iv) }, pwKey, b64ToBuf(imported.data));
      localStorage.setItem('pk_' + currentUser, JSON.stringify({ iv: imported.iv, data: imported.data }));
      myPrivateKey = await crypto.subtle.importKey(
        'jwk', JSON.parse(new TextDecoder().decode(privJwk)),
        { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']
      );
      toastSuccess('Key imported successfully');
      await loadMain();
    } catch (e) {
      toastError('Could not decrypt — wrong password?');
    }
  } catch (e) {
    toastError('Could not read file');
  }
}

/* ============================================================
   DRAG & DROP + BOOT
   ============================================================ */

document.addEventListener('dragover', function(e) { e.preventDefault(); });
document.addEventListener('drop', async function(e) {
  e.preventDefault();
  if (!token) return;
  const files = e.dataTransfer.files;
  if (!files || files.length === 0) return;
  const input = document.getElementById('file-input');
  input.files = files;
  onFilesSelected();
  toastInfo(files.length + ' file(s) ready — click Encrypt & Upload');
});

if (token) loadMain().catch(function() { logout(); });