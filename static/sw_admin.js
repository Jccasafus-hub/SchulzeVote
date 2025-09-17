// static/sw_admin.js

const CACHE_NAME = "schulzevote-admin-v1";
const URLS_TO_CACHE = [
  "/static/manifest_admin.json",
  "/static/admin_icon_180.png",
  "/static/admin_icon_192.png",
  "/static/admin_icon_512.png",
];

// Instalação: adiciona os arquivos ao cache
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(URLS_TO_CACHE);
    })
  );
  self.skipWaiting();
});

// Ativação: limpa caches antigos
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names.map((name) => {
          if (name !== CACHE_NAME) {
            return caches.delete(name);
          }
        })
      )
    )
  );
  self.clients.claim();
});

// Fetch: responde com cache ou busca na rede
self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  event.respondWith(
    caches.match(req).then((cached) => {
      return (
        cached ||
        fetch(req).then((res) => {
          // opcional: cachear recursos dinâmicos
          return caches.open(CACHE_NAME).then((cache) => {
            cache.put(req, res.clone());
            return res;
          });
        }).catch(() => {
          // fallback opcional
          return new Response(
            "<h1>Offline</h1><p>O painel administrativo não está disponível no momento.</p>",
            { headers: { "Content-Type": "text/html" } }
          );
        })
      );
    })
  );
});
