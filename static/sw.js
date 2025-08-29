// static/sw.js
// v1 — aumente este número quando trocar ícones/manifest para forçar atualização de cache
const CACHE_NAME = 'schulzevote-v1';

self.addEventListener('install', (event) => {
  self.skipWaiting();
  // opcional: pré-cache bem leve (manter relativo ao escopo)
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll([
      '/',              // página inicial
      '/static/manifest.json',
      // adicione aqui seus ícones novos, por ex:
      // '/static/icons/icon-180x180.png',
      // '/static/icons/icon-192x192.png',
      // '/static/icons/icon-512x512.png',
    ]).catch(()=>{}))
  );
});

self.addEventListener('activate', (event) => {
  // limpa caches antigos
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(k => k !== CACHE_NAME ? caches.delete(k) : null))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  // Estratégia: network-first com fallback para cache
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
