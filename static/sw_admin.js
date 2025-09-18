// --- Service Worker do Admin (PWA) ---
// Estratégias:
// - Pré-cache ampliado (CORE + SHELL do Admin)
// - Stale-While-Revalidate para estáticos
// - Network-First para APIs/JSON do Admin
// - PURGE_CACHE via postMessage no logout

const SW_VERSION = "admin-v3";                  // aumente a cada release
const PRECACHE_NAME = `precache-${SW_VERSION}`;
const RUNTIME_NAME  = `runtime-${SW_VERSION}`;

// Atenção: rotas /admin que requerem secret podem redirecionar p/ login.
// O pré-cache das páginas do shell garante UX rápida; dados dinâmicos ficam em runtime.
const CORE_ASSETS = [
  // Manifest & SW
  "/static/manifest_admin.json",
  "/static/sw_admin.js",

  // Ícones do Admin
  "/static/admin_icon_180.png",
  "/static/admin_icon_192.png",
  "/static/admin_icon_512.png",
  "/static/admin_icon_maskable_512.png",

  // Páginas (shell) — podem devolver login caso não haja secret
  "/admin/login",
  "/admin/",

  // Rotas utilitárias (se expostas)
  // "/admin/candidates",
  // "/admin/election_meta",

  // (Opcional) assets do app público caso você os use no admin
  // "/",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(PRECACHE_NAME).then((cache) => cache.addAll(CORE_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((k) => ![PRECACHE_NAME, RUNTIME_NAME].includes(k))
          .map((k) => caches.delete(k))
      )
    )
  );
  self.clients.claim();
});

// Helper: identifica se é requisição de API/JSON do admin
function isAdminApi(req) {
  const url = new URL(req.url);
  // Admin JSONs/CSV e auditorias
  if (url.pathname.startsWith("/admin/") && (
      url.pathname.endsWith(".json") ||
      url.pathname.endsWith("/audit_raw") ||
      url.pathname.endsWith("/ballots_raw") ||
      url.pathname.endsWith("/export_audit_bundle") ||
      url.pathname.endsWith("/backup_zip") ||
      url.pathname.endsWith("/backup_zip_eid")
    )) return true;

  // Públicos com CSV/JSON úteis ao admin
  if (url.pathname.startsWith("/public/") && (
      url.pathname.endsWith(".csv") ||
      url.pathname.endsWith("/results") ||
      url.pathname.endsWith("/audit")
    )) return true;

  return false;
}

// Helper: é um asset estático (png, json, js, css)
function isStaticAsset(req) {
  const url = new URL(req.url);
  return url.pathname.startsWith("/static/") ||
         url.pathname.match(/\.(png|jpg|jpeg|gif|webp|svg|ico|js|css|woff2?)$/i);
}

// Fetch: estratégias por tipo
self.addEventListener("fetch", (event) => {
  const req = event.request;

  // Só GET é seguro para cache
  if (req.method !== "GET") {
    event.respondWith(fetch(req));
    return;
  }

  // Network-First para APIs/JSON/ZIP/CSV do Admin
  if (isAdminApi(req)) {
    event.respondWith(networkFirst(req));
    return;
  }

  // Stale-While-Revalidate para estáticos
  if (isStaticAsset(req) || req.mode === "navigate") {
    event.respondWith(staleWhileRevalidate(req));
    return;
  }

  // Fallback padrão
  event.respondWith(staleWhileRevalidate(req));
});

// Estratégia: Network-First (boa para dados dinâmicos)
async function networkFirst(req) {
  try {
    const fresh = await fetch(req);
    if (fresh && fresh.ok) {
      const cache = await caches.open(RUNTIME_NAME);
      cache.put(req, fresh.clone());
    }
    return fresh;
  } catch (e) {
    const cached = await caches.match(req);
    if (cached) return cached;
    // Fallback simples: tenta página do login/admin shell
    return caches.match("/admin/login") || new Response("Offline", { status: 503 });
  }
}

// Estratégia: Stale-While-Revalidate (melhor UX p/ estáticos e shell)
async function staleWhileRevalidate(req) {
  const cache = await caches.open(RUNTIME_NAME);
  const cached = await cache.match(req);
  const fetchPromise = fetch(req)
    .then((res) => {
      if (res && res.ok) cache.put(req, res.clone());
      return res;
    })
    .catch(() => null);
  return cached || (await fetchPromise) || (await caches.match("/admin/login")) || new Response("Offline", { status: 503 });
}

// Mensagens do app (logout -> PURGE_CACHE)
self.addEventListener("message", (event) => {
  if (event.data === "PURGE_CACHE") {
    event.waitUntil(
      caches.keys().then((keys) => Promise.all(keys.map((k) => caches.delete(k))))
    );
  } else if (event.data === "SKIP_WAITING") {
    self.skipWaiting();
  }
});
