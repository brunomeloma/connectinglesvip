const CACHE_NAME = 'connect-vip-v2';
const APP_SHELL = ['/', '/index.html', '/icons/icon-192.png', '/icons/icon-512.png'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((names) => Promise.all(names.filter((n) => n !== CACHE_NAME).map((n) => caches.delete(n))))
      .then(() => self.clients.claim())
  );
});

// Nunca intercepta chamadas de outra origem (Supabase, CDNs) — precisam
// sempre ir direto pra rede, nunca cacheadas, pra não servir dado velho.
self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const clone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put('/index.html', clone));
          return res;
        })
        .catch(() => caches.match('/index.html'))
    );
    return;
  }

  event.respondWith(
    caches.match(req).then((cached) => cached || fetch(req).then((res) => {
      const clone = res.clone();
      caches.open(CACHE_NAME).then((cache) => cache.put(req, clone));
      return res;
    }))
  );
});
