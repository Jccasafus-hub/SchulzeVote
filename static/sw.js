// static/sw.js

const CACHE_NAME = 'sv-cache-v1';

// Instalação (se você já tem uma lista de assets, mantenha)
self.addEventListener('install', (event) => {
  self.skipWaiting();
});

// Ativação
self.addEventListener('activate', (event) => {
  event.waitUntil(clients.claim());
});

// MUITO IMPORTANTE: não interceptar /admin/* e NENHUMA requisição que não seja GET
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // 1) Não toca em POST/PUT/PATCH/DELETE e etc.
  if (req.method !== 'GET') return;

  // 2) Não toca em nada do admin
  if (url.pathname.startsWith('/admin/')) return;

  // 3) (Opcional) Não interceptar APIs públicas também:
  // if (url.pathname.startsWith('/public/')) return;

  // A partir daqui, APLIQUE sua estratégia de cache apenas para o app público
  // Exemplo simples: network-first para navegações públicas
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req).catch(() => caches.match('/'))
    );
    return;
  }

  // Exemplo simples para assets estáticos: cache-first
  event.respondWith(
    caches.match(req).then((hit) => {
      if (hit) return hit;
      return fetch(req).then((res) => {
        const resClone = res.clone();
        caches.open(CACHE_NAME).then((c) => c.put(req, resClone));
        return res;
      });
    })
  );
});
