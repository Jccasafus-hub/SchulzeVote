// static/sw.js
// mude 'schulzevote-v2' quando trocar ícones/manifest para forçar atualização
const CACHE_NAME = 'schulzevote-v2';

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll([
      '/',
      '/static/manifest.json',
      '/static/icon-180.png',
      '/static/icon-192.png',
      '/static/icon-512.png'
    ])).catch(() => {})
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.map(k => k !== CACHE_NAME ? caches.delete(k) : null))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
