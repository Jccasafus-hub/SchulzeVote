// static/sw_admin.js

const CACHE_NAME = "schulzevote-admin-v3";
const OFFLINE_PAGE = "/static/offline_admin.html";

const URLS_TO_CACHE = [
  // PWA essentials
  "/static/manifest_admin.json",
  "/static/admin_icon_180.png",
  "/static/admin_icon_192.png",
  "/static/admin_icon_512.png",
  "/static/admin_icon_maskable_512.png",

  // Offline fallback page
  OFFLINE_PAGE,

  // Páginas principais do admin (pré-cache de shell)
  "/admin",
  "/admin/candidates",
  "/admin/election_meta",
  "/admin/audit_raw",
  "/admin/ballots_raw"
  // Observação: rotas de download ZIP não fazem sentido em cache (variáveis)
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(URLS_TO_CACHE))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((names) =>
      Promise.all(names.map((name) => (name !== CACHE_NAME ? caches.delete(name) : null)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  // Estratégia: cache-first para estáticos, network-first para páginas
  if (req.url.includes("/static/")) {
    event.respondWith(
      caches.match(req).then((cached) => {
        return (
          cached ||
          fetch(req).then((res) => {
            return caches.open(CACHE_NAME).then((cache) => {
              cache.put(req, res.clone());
              return res;
            });
          })
        );
      })
    );
    return;
  }

  // Para documentos/HTML, tentar rede primeiro; em falha, fallback offline
  event.respondWith(
    fetch(req)
      .then((res) => {
        // Cache dinâmico de páginas navegadas
        const resClone = res.clone();
        caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone));
        return res;
      })
      .catch(async () => {
        // 1) Se houver no cache, devolve
        const cached = await caches.match(req);
        if (cached) return cached;

        // 2) Fallback dedicado
        if (req.destination === "document") {
          const fallback = await caches.match(OFFLINE_PAGE);
          if (fallback) return fallback;
        }

        // 3) Último recurso: resposta simples
        return new Response("<h1>Offline</h1>", {
          headers: { "Content-Type": "text/html" }
        });
      })
  );
});
