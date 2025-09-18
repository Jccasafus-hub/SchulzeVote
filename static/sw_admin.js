// Nome do cache exclusivo do Admin
const CACHE_NAME = "admin-cache-v1";

// Lista de arquivos essenciais do Admin para cache inicial
const CORE_ASSETS = [
  "/static/manifest_admin.json",
  "/static/admin_icon_180.png",
  "/static/admin_icon_192.png",
  "/static/admin_icon_512.png",
  "/static/admin_icon_maskable_512.png",
  "/static/sw_admin.js",
  "/admin/login"
];

// Instala o SW e adiciona assets iniciais
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(CORE_ASSETS))
  );
  self.skipWaiting();
});

// Ativa o SW e limpa caches antigos
self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.map((key) => key !== CACHE_NAME && caches.delete(key)))
    )
  );
  self.clients.claim();
});

// Intercepta fetch e responde do cache se possível
self.addEventListener("fetch", (event) => {
  const req = event.request;
  event.respondWith(
    caches.match(req).then(
      (res) =>
        res ||
        fetch(req).then((response) => {
          // cache apenas GETs
          if (req.method === "GET" && response.status === 200) {
            const respClone = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, respClone));
          }
          return response;
        })
    )
  );
});

// Recebe mensagens do app (ex.: logout)
self.addEventListener("message", (event) => {
  if (event.data === "PURGE_CACHE") {
    event.waitUntil(
      caches.keys().then((keys) =>
        Promise.all(keys.map((key) => caches.delete(key)))
      )
    );
  }
});
