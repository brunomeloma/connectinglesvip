const CACHE_NAME = 'connect-vip-v3';
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
  // /supabase/* é um rewrite pro backend (proxy same-origin) — nunca cachear,
  // a resposta varia por usuário autenticado e a cache key (URL) não sabe disso.
  if (url.pathname.startsWith('/supabase/')) return;
  // Modelos de contrato (.docx): sempre da rede, pra troca anual do arquivo
  // valer na hora em todos os computadores.
  if (url.pathname.startsWith('/contratos/')) return;

  // Página e scripts (.js): rede primeiro, cache só se estiver offline. Com
  // cache primeiro, um script antigo (ex: gerador de contrato) continuava
  // rodando com a página nova e o contrato saía sem os dados do aluno.
  if (req.mode === 'navigate' || url.pathname.endsWith('.js')) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const clone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, clone));
          return res;
        })
        .catch(() => caches.match(req).then((cached) => cached || (req.mode === 'navigate' ? caches.match('/index.html') : Response.error())))
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
