/* SchulzeVote Service Worker
 * Estratégias:
 * - HTML (navigate): network-first, fallback cache
 * - Assets (script/style/image/manifest/font): stale-while-revalidate
 * - Bypass de cache quando houver ?no_cache=1 ou ?secret=...
 * - Respeita querystring (ex.: ?v=APP_VERSION) -> NÃO usar ignoreSearch
 */

const CACHE_NAME = "sv-cache-v1"; // Se mudar HTML crítico, incremente esse sufixo.
const CORE_ASSETS = [
  "/",                     // index
  "/schulze_guide",        // guia do método
  "/login",
  "/register",
  "/vote",
  "/results",              // redirect -> ok se falhar, só ajuda no warmup
  "/manifest.json",
  "/manifest_admin.json",
];

// Pequena ajuda para decidir o tratamento de cada request
function isHTMLRequest(req) {
  return req.mode === "navigate" ||
         (req.headers.get("accept") || "").includes("text/html");
}
function isAssetRequest(req) {
  const dest = req.destination;
  return ["script", "style", "image", "font", "manifest"].includes(dest);
}
function shouldBypass(url) {
  // Nunca cachear coisas com ?secret=... ou ?no_cache=1
  return url.searchParams.has("secret") || url.searchParams.has("no_cache");
}

// ----------------------------------------------------------------------------
// Install: pré-cache de algumas rotas úteis (best-effort)
// ----------------------------------------------------------------------------
self.addEventListener("install", (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(CORE_ASSETS).catch(() => {
        // Se algum 404/redirect impedir o addAll, seguimos sem falhar a instalação.
        return Promise.resolve();
      });
    })
  );
});

// ----------------------------------------------------------------------------
// Activate: limpeza de caches antigos
// ----------------------------------------------------------------------------
self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(
      keys.map((k) => (k === CACHE_NAME ? null : caches.delete(k)))
    );
    await self.clients.claim();
  })());
});

// ----------------------------------------------------------------------------
// Fetch: estratégias por tipo + bypass para ?secret / ?no_cache
// ----------------------------------------------------------------------------
self.addEventListener("fetch", (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Só tratamos requests de mesma origem; terceiros seguem direto.
  if (url.origin !== self.location.origin) {
    return; // deixa o navegador tratar
  }

  if (shouldBypass(url)) {
    // Nunca cacheia páginas com segredo ou sinalizador de não-cache
    event.respondWith(fetch(req).catch(() => caches.match(req)));
    return;
  }

  // HTML (páginas) -> network-first
  if (isHTMLRequest(req)) {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const resClone = res.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone)).catch(()=>{});
          return res;
        })
        .catch(() => caches.match(req))
    );
    return;
  }

  // Assets (css/js/img/manifest/font) -> stale-while-revalidate
  if (isAssetRequest(req)) {
    event.respondWith(
      caches.match(req).then((cached) => {
        const fetchPromise = fetch(req)
          .then((res) => {
            const resClone = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone)).catch(()=>{});
            return res;
          })
          .catch(() => null);
        return cached || fetchPromise;
      })
    );
    return;
  }

  // Demais (fallback: cache-first depois network)
  event.respondWith(
    caches.match(req).then((cached) => {
      return (
        cached ||
        fetch(req)
          .then((res) => {
            const resClone = res.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, resClone)).catch(()=>{});
            return res;
          })
          .catch(() => cached || Response.error())
      );
    })
  );
});
