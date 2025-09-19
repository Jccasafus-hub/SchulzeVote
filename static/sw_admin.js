// sw_admin.js — Service Worker do painel admin (escopo /admin/)

const CACHE_PREFIX = 'sv-admin';
const CACHE_VERSION = 'v1'; // se mudar algo crítico, incremente aqui
const CACHE_NAME = `${CACHE_PREFIX}-${CACHE_VERSION}`;

// Rotas e arquivos que vale a pena ter por perto.
// Não "forçamos" cache de páginas dinâmicas, apenas ajudamos com ícones/manifest.
const PRECACHE_URLS = [
  // Manifest e ícones
  '/static/manifest_admin.json',
  '/static/admin_icon_192.png',
  '/static/admin_icon_512.png',
  '/static/admin_icon_180.png'
  // Se quiser antecipar páginas estáticas: adicione aqui.
  // Ex.: '/admin/login'
];

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(PRECACHE_URLS))
  );
});

self.addEventListener('activate', (event) => {
  // Remove caches antigos do admin
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => k.startsWith(CACHE_PREFIX) && k !== CACHE_NAME)
          .map((oldKey) => caches.delete(oldKey))
      )
    ).then(() => self.clients.claim())
  );
});

// Estratégia:
// - Para HTML sob /admin/ → network-first (evita ficar preso em tela antiga)
// - Para tudo que estiver no PRECACHE → cache-first (rápido e offline-friendly)
// - Para o resto → network-first com fallback a cache se existir
self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Só intercepta o que estiver no mesmo host
  if (url.origin !== self.location.origin) return;

  // HTML do admin → network-first
  const isAdminHTML =
    url.pathname.startsWith('/admin') &&
    req.method === 'GET' &&
    req.headers.get('accept') &&
    req.headers.get('accept').includes('text/html');

  if (isAdminHTML) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const resClone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
          return res;
        })
        .catch(() => caches.match(req))
    );
    return;
  }

  // Arquivos precache → cache-first
  const isPrecached = PRECACHE_URLS.includes(url.pathname);
  if (isPrecached) {
    event.respondWith(
      caches.match(req).then((cached) => cached || fetch(req).then((res) => {
        const resClone = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
        return res;
      }))
    );
    return;
  }

  // Demais → network-first com fallback em cache (se já houver)
  event.respondWith(
    fetch(req)
      .then((res) => {
        const resClone = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
        return res;
      })
      .catch(() => caches.match(req))
  );
});
