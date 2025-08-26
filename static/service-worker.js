self.addEventListener('install', e=>{
  e.waitUntil(caches.open('schulze-v1').then(c=>c.addAll([
    '/', '/static/style.css', '/static/manifest.json'
  ])));
});
self.addEventListener('fetch', e=>{
  e.respondWith(caches.match(e.request).then(r=> r || fetch(e.request)));
});
