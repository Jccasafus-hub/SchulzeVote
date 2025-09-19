/* SchulzeVote service worker
   Estratégias:
   - HTML: network-first (com fallback para cache). NUNCA cacheia /admin/login e HTML sob /admin/*.
   - Estáticos (css/js/img/font/json/webmanifest): stale-while-revalidate.
   - Outros GET: network-first.
*/

/// ===== Utils de versão (lê ?v= do próprio URL do SW) =====
function getVersionFromSelfURL() {
  try {
    const u = new URL(self.location.href);
    return u.searchParams.get('v') || 'v0';
  } catch (e) {
    return 'v0';
  }
}
const VERSION = getVersionFromSelfURL();
const STATIC_CACHE = `sv-static-${VERSION}`;
const RUNTIME_CACHE = `sv-runtime-${VERSION}`;

/// ===== Listas auxiliares =====
const STATIC_EXT = [
  '.css', '.js', '.mjs', '.map',
  '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico',
  '.ttf', '.otf', '.woff', '.woff2',
  '.json', '.webmanifest', '.manifest', '.txt'
];

function isSameOrigin(req) {
  try { return new URL(req.url).origin === self.location.origin; }
  catch { return false; }
}

function hasStaticExt(pathname) {
  const p = pathname.toLowerCase();
  return STATIC_EXT.some(ext => p.endsWith(ext));
}

function acceptsHtml(req) {
  const h = req.headers.get('accept') || '';
  return h.includes('text/html');
}

function isHtmlRequest(req) {
  const url = new URL(req.url);
  return req.method === 'GET' && isSameOrigin(req) && acceptsHtml(req);
}

function shouldBypassAdminHtml(req) {
  if (!isHtmlRequest(req)) return false;
  const url = new URL(req.url);
  // NÃO cachear HTML do admin (especialmente /admin/login)
  return url.pathname === '/admin/login' || url.pathname.startsWith('/admin/');
}

/// ===== Instalação / ativação =====
self.addEventListener('install', (event) => {
  // Não precisamos pré-cachear nada por padrão.
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    // Limpa caches antigos
    const keys = await caches.keys();
    await Promise.all(
      keys.map(k => {
        if (!k.endsWith(VERSION) && (k.startsWith('sv-static-') || k.startsWith('sv-runtime-'))) {
          return caches.delete(k);
        }
      })
    );
    await self.clients.claim();
  })());
});

/// ===== Estratégias de fetch =====
self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Ignora métodos não-GET
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // 1) HTML do admin → network-only (sem cache)
  if (shouldBypassAdminHtml(req)) {
    event.respondWith(fetch(req).catch(() => new Response(
      '<h1>Offline</h1><p>Tente novamente quando a conexão voltar.</p>',
      { headers: { 'Content-Type': 'text/html; charset=utf-8' }, status: 503 }
    )));
    return;
  }

  // 2) Qualquer HTML (navegação) → network-first (com fallback)
  if (isHtmlRequest(req)) {
    event.respondWith(networkFirst(req, RUNTIME_CACHE, /*cacheHtml*/ true));
    return;
  }

  // 3) Estáticos do mesmo domínio → stale-while-revalidate
  if (isSameOrigin(req) && hasStaticExt(url.pathname)) {
    event.respondWith(staleWhileRevalidate(req, STATIC_CACHE));
    return;
  }

  // 4) Demais GET (APIs/JSONs do mesmo domínio etc.) → network-first
  event.respondWith(networkFirst(req, RUNTIME_CACHE, /*cacheHtml*/ false));
});

/// ===== Implementações das estratégias =====

// Network-first: tenta rede; se falhar, devolve cache (se houver).
async function networkFirst(req, cacheName, cacheHtml) {
  const cache = await caches.open(cacheName);
  try {
    const fresh = await fetch(req);
    // Opcionalmente guardamos no cache (evitando cachear admin HTML em outro caminho)
    if (fresh && fresh.ok && (cacheHtml || !acceptsHtml(req))) {
      cache.put(req, fresh.clone());
    }
    return fresh;
  } catch (err) {
    const cached = await cache.match(req);
    if (cached) return cached;
    if (acceptsHtml(req)) {
      // fallback HTML mínimo
      return new Response(
        '<h1>Offline</h1><p>Sem conexão e sem cache disponível.</p>',
        { headers: { 'Content-Type': 'text/html; charset=utf-8' }, status: 503 }
      );
    }
    throw err;
  }
}

// Stale-While-Revalidate para estáticos
async function staleWhileRevalidate(req, cacheName) {
  const cache = await caches.open(cacheName);
  const cachedPromise = cache.match(req);
  const networkPromise = fetch(req).then((res) => {
    if (res && res.ok) cache.put(req, res.clone());
    return res;
  }).catch(() => undefined);

  const cached = await cachedPromise;
  if (cached) {
    // Atualiza em segundo plano e retorna cached agora
    networkPromise; // fire-and-forget
    return cached;
  }
  // Sem cache → espera a rede
  const fresh = await networkPromise;
  if (fresh) return fresh;
  // Fallback de estático ausente
  return new Response('', { status: 504 });
}

/// ===== Mensagens (opcional: pular espera) =====
self.addEventListener('message', (event) => {
  if (event.data === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});
