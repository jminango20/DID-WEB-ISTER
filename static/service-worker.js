/**
 * Service Worker - ISTER Wallet PWA
 *
 * Strategy: Cache-first for static assets, network-first for API calls.
 */

const CACHE_NAME = 'ister-wallet-v1';

const STATIC_ASSETS = [
    '/wallet/',
    '/wallet/recover',
    '/static/js/wallet.js',
    '/static/manifest.json',
    '/static/icons/icon-192.png',
    '/static/icons/icon-512.png',
];

// ── Install: pre-cache static assets ────────────────────────────────────────

self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS))
    );
    self.skipWaiting();
});

// ── Activate: remove old caches ──────────────────────────────────────────────

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys().then(keys =>
            Promise.all(
                keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))
            )
        )
    );
    self.clients.claim();
});

// ── Fetch: cache-first for static, network-first for API ─────────────────────

self.addEventListener('fetch', event => {
    const url = new URL(event.request.url);

    // Network-first for API and dynamic wallet pages
    if (url.pathname.startsWith('/api/') ||
        url.pathname.startsWith('/wallet/claim') ||
        url.pathname.startsWith('/wallet/view')) {
        event.respondWith(
            fetch(event.request).catch(() => caches.match(event.request))
        );
        return;
    }

    // Cache-first for everything else
    event.respondWith(
        caches.match(event.request).then(cached => {
            if (cached) return cached;
            return fetch(event.request).then(response => {
                if (response.ok) {
                    const clone = response.clone();
                    caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
                }
                return response;
            });
        })
    );
});
