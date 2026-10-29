'use strict';

// Only the encrypted package is public. The access key is never embedded here.
const PAYLOAD_SHA256 = '39f7f21e2ca8a55dc851a65aa9e22f3c0a96ec9ec320754f7668bd9175e17fd1';
const SCOPE = new URL(self.registration.scope);
const PRIVATE_PREFIX = new URL('app/', SCOPE).pathname;
const PAYLOAD_URL = new URL('payload.bin', SCOPE);
PAYLOAD_URL.searchParams.set('v', PAYLOAD_SHA256);
const CACHE_NAME = 'ohotniki-private-cipher-v1';
const CACHE_KEY = new URL(`payload.bin?sha=${PAYLOAD_SHA256}`, SCOPE);
const AAD = new TextEncoder().encode('Ohotniki.kz Club private preview v1');
const DATABASE = 'ohotniki-private-preview';
let unlockedFiles = null;
let pendingLoad = null;

class PreviewError extends Error {
  constructor(code) { super(code); this.errorCode = code; }
}

self.addEventListener('install', (event) => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

function database() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DATABASE, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new PreviewError('storage'));
  });
}

async function storedKey(value) {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const write = value !== undefined;
      const transaction = db.transaction('keys', write ? 'readwrite' : 'readonly');
      const store = transaction.objectStore('keys');
      const request = write ? store.put(value, PAYLOAD_SHA256) : store.get(PAYLOAD_SHA256);
      let result;
      request.onsuccess = () => { result = request.result; };
      transaction.oncomplete = () => resolve(result);
      transaction.onerror = () => reject(new PreviewError('storage'));
      transaction.onabort = () => reject(new PreviewError('storage'));
    });
  } finally { db.close(); }
}

async function digest(bytes) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

async function ciphertext() {
  let cache;
  try {
    cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(CACHE_KEY);
    if (cached) {
      const bytes = await cached.arrayBuffer();
      if (await digest(bytes) === PAYLOAD_SHA256) return bytes;
      await cache.delete(CACHE_KEY);
    }
  } catch { /* Cache availability is optional; integrity verification is not. */ }
  let response;
  try { response = await fetch(PAYLOAD_URL, { cache: 'no-store', credentials: 'omit', referrerPolicy: 'no-referrer' }); }
  catch { throw new PreviewError('network'); }
  if (!response.ok) throw new PreviewError('network');
  const bytes = await response.arrayBuffer();
  if (await digest(bytes) !== PAYLOAD_SHA256) throw new PreviewError('integrity');
  if (cache) {
    try { await cache.put(CACHE_KEY, new Response(bytes, { headers: { 'Content-Type': 'application/octet-stream' } })); }
    catch { /* The verified response can be used without persistent cache. */ }
  }
  return bytes;
}

async function unpack(key) {
  if (!('DecompressionStream' in self) || !crypto.subtle) throw new PreviewError('unsupported');
  const encrypted = new Uint8Array(await ciphertext());
  if (encrypted.byteLength < 29) throw new PreviewError('integrity');
  let compressed;
  try {
    compressed = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: encrypted.subarray(0, 12), additionalData: AAD, tagLength: 128 }, key, encrypted.subarray(12));
  } catch { throw new PreviewError('invalidKey'); }
  let buffer;
  try { buffer = await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer(); }
  catch { throw new PreviewError('integrity'); }
  if (buffer.byteLength < 5 || buffer.byteLength > 160 * 1024 * 1024) throw new PreviewError('integrity');
  const manifestLength = new DataView(buffer).getUint32(0, false);
  const dataStart = 4 + manifestLength;
  if (manifestLength > 2 * 1024 * 1024 || dataStart > buffer.byteLength) throw new PreviewError('integrity');
  let manifest;
  try { manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(new Uint8Array(buffer, 4, manifestLength))); }
  catch { throw new PreviewError('integrity'); }
  if (manifest.format !== 1 || !Array.isArray(manifest.files) || !manifest.files.length || manifest.files.length > 2000) throw new PreviewError('integrity');
  const files = new Map();
  for (const file of manifest.files) {
    if (typeof file.path !== 'string' || !file.path || file.path.length > 1024 || file.path.startsWith('/') || file.path.includes('\\') || file.path.includes('\0') || file.path.split('/').some((part) => !part || part === '.' || part === '..') || files.has(file.path)) throw new PreviewError('integrity');
    if (!Number.isSafeInteger(file.offset) || !Number.isSafeInteger(file.length) || file.offset < 0 || file.length < 0 || dataStart + file.offset + file.length > buffer.byteLength) throw new PreviewError('integrity');
    if (typeof file.mime !== 'string' || !file.mime || /[\r\n\0]/.test(file.mime)) throw new PreviewError('integrity');
    files.set(file.path, { mime: file.mime, bytes: new Uint8Array(buffer, dataStart + file.offset, file.length) });
  }
  if (!files.has('index.html') || !files.has('main.dart.js')) throw new PreviewError('integrity');
  return files;
}

async function loadFiles() {
  if (unlockedFiles) return unlockedFiles;
  if (!pendingLoad) pendingLoad = (async () => {
    const key = await storedKey();
    if (!key) return null;
    unlockedFiles = await unpack(key);
    return unlockedFiles;
  })().finally(() => { pendingLoad = null; });
  return pendingLoad;
}

async function unlock(encodedKey) {
  if (typeof encodedKey !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(encodedKey)) throw new PreviewError('invalidKey');
  let bytes;
  try { bytes = Uint8Array.from(atob(encodedKey.replace(/-/g, '+').replace(/_/g, '/') + '='), (char) => char.charCodeAt(0)); }
  catch { throw new PreviewError('invalidKey'); }
  if (bytes.length !== 32) throw new PreviewError('invalidKey');
  const key = await crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM' }, false, ['decrypt']);
  const files = await unpack(key);
  await storedKey(key);
  unlockedFiles = files;
}

self.addEventListener('message', (event) => {
  const port = event.ports[0];
  if (!port) return;
  event.waitUntil((async () => {
    try {
      const source = event.source && new URL(event.source.url);
      if (!source || source.origin !== SCOPE.origin || !source.pathname.startsWith(SCOPE.pathname)) throw new PreviewError('invalidKey');
      if (event.data && event.data.type === 'unlock') {
        await unlock(event.data.key);
        port.postMessage({ ok: true });
      } else if (event.data && event.data.type === 'status') {
        port.postMessage({ unlocked: Boolean(await loadFiles()) });
      } else port.postMessage({ ok: false, errorCode: 'invalidKey' });
    } catch (error) {
      port.postMessage({ ok: false, unlocked: false, errorCode: error.errorCode || 'network' });
    } finally { port.close(); }
  })());
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== SCOPE.origin || !url.pathname.startsWith(PRIVATE_PREFIX)) return;
  event.respondWith((async () => {
    if (!['GET', 'HEAD'].includes(event.request.method)) return new Response(null, { status: 405, headers: { Allow: 'GET, HEAD' } });
    const files = await loadFiles();
    if (!files) {
      if (event.request.mode === 'navigate') return Response.redirect(SCOPE.href, 302);
      return new Response('Private preview', { status: 403, headers: { 'Cache-Control': 'no-store' } });
    }
    let path;
    try { path = decodeURIComponent(url.pathname.slice(PRIVATE_PREFIX.length)) || 'index.html'; }
    catch { return new Response(null, { status: 400 }); }
    if (path.includes('\\') || path.includes('\0') || path.split('/').some((part) => part === '.' || part === '..')) return new Response(null, { status: 403 });
    const file = files.get(path);
    if (!file) return new Response(null, { status: 404 });
    return new Response(event.request.method === 'HEAD' ? null : file.bytes, {
      headers: {
        'Content-Type': file.mime,
        'Content-Length': String(file.bytes.byteLength),
        'Cache-Control': 'private, no-store',
        'X-Content-Type-Options': 'nosniff',
        'X-Robots-Tag': 'noindex, nofollow, noarchive',
        'Referrer-Policy': 'no-referrer',
      },
    });
  })().catch(() => event.request.mode === 'navigate'
    ? Response.redirect(SCOPE.href, 302)
    : new Response('Private preview', { status: 403, headers: { 'Cache-Control': 'no-store' } })));
});
