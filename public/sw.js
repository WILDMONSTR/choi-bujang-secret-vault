const CACHE = 'byte-back-shell-v2';
const SHELL = ['/', '/manifest.webmanifest', '/device-client.js', '/app-icon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(CACHE).then((cache) => cache.addAll(SHELL)).then(() => self.skipWaiting()));
});

function removeLegacyDeviceKeyDatabase() {
  return new Promise((resolve) => {
    if (!('indexedDB' in self)) return resolve();
    let request;
    try {
      request = self.indexedDB.deleteDatabase('byte-back-device-v1');
    } catch {
      return resolve();
    }
    request.onsuccess = resolve;
    request.onerror = resolve;
    request.onblocked = resolve;
  });
}

self.addEventListener('activate', (event) => {
  event.waitUntil(
    Promise.all([
      caches.keys().then((keys) => Promise.all(
        keys.filter((key) => key.startsWith('byte-back-') && key !== CACHE)
          .map((key) => caches.delete(key))
      )),
      removeLegacyDeviceKeyDatabase()
    ]).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith('/api/')) return;
  if (!SHELL.includes(url.pathname)) return;
  event.respondWith(fetch(request).then((response) => {
    if (response.ok) {
      const copy = response.clone();
      void caches.open(CACHE).then((cache) => cache.put(request, copy));
    }
    return response;
  }).catch(async () => (await caches.match(request)) || Response.error()));
});
