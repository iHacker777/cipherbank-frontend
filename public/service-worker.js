// CipherBank Enhanced Service Worker
// Version: 2.0.0
// iOS 18 PWA Optimized

const CACHE_NAME = 'cipherbank-v2.0.0';
const RUNTIME_CACHE = 'cipherbank-runtime-v2.0.0';
const IMAGE_CACHE = 'cipherbank-images-v2.0.0';
const API_CACHE = 'cipherbank-api-v2.0.0';

// Assets to cache on install
const PRECACHE_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/offline.html',
  '/favicon.ico'
];

// API patterns
const API_PATTERNS = [
  /\/api\/auth\//,
  /\/api\/statements\//
];

// Image patterns
const IMAGE_PATTERNS = [
  /\.(?:png|jpg|jpeg|svg|gif|webp|ico)$/
];

// ==================== INSTALL EVENT ====================
self.addEventListener('install', (event) => {
  console.log('✅ Service Worker: Installing v2.0.0...');

  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('📦 Service Worker: Caching app shell');
        return cache.addAll(PRECACHE_ASSETS);
      })
      .then(() => {
        console.log('✅ Service Worker: Installation complete');
        return self.skipWaiting();
      })
      .catch((error) => {
        console.error('❌ Service Worker: Installation failed', error);
      })
  );
});

// ==================== ACTIVATE EVENT ====================
self.addEventListener('activate', (event) => {
  console.log('✅ Service Worker: Activating...');

  event.waitUntil(
    caches.keys()
      .then((cacheNames) => {
        return Promise.all(
          cacheNames
            .filter((cacheName) => {
              return cacheName !== CACHE_NAME &&
                     cacheName !== RUNTIME_CACHE &&
                     cacheName !== IMAGE_CACHE &&
                     cacheName !== API_CACHE;
            })
            .map((cacheName) => {
              console.log('🗑️ Service Worker: Deleting old cache', cacheName);
              return caches.delete(cacheName);
            })
        );
      })
      .then(() => {
        console.log('✅ Service Worker: Activation complete');
        return self.clients.claim();
      })
  );
});

// ==================== FETCH EVENT ====================
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip cross-origin requests except for our APIs
  if (url.origin !== location.origin) {
    if (url.hostname.includes('thepaytrix.com')) {
      event.respondWith(networkFirstStrategy(request, API_CACHE));
    }
    return;
  }

  // Only handle GET requests
  if (request.method !== 'GET') {
    event.respondWith(fetch(request));
    return;
  }

  // Images - Cache First Strategy
  if (IMAGE_PATTERNS.some(pattern => pattern.test(url.pathname))) {
    event.respondWith(cacheFirstStrategy(request, IMAGE_CACHE));
    return;
  }

  // App shell - Cache First Strategy
  if (PRECACHE_ASSETS.includes(url.pathname) || url.pathname === '/') {
    event.respondWith(cacheFirstStrategy(request, CACHE_NAME));
    return;
  }

  // Other requests - Network First Strategy
  event.respondWith(networkFirstStrategy(request, RUNTIME_CACHE));
});

// ==================== CACHING STRATEGIES ====================

// Cache First Strategy - Good for static assets
async function cacheFirstStrategy(request, cacheName = CACHE_NAME) {
  try {
    const cache = await caches.open(cacheName);
    const cached = await cache.match(request);

    if (cached) {
      // Return cached version and update in background
      updateCache(request, cacheName);
      return cached;
    }

    const response = await fetch(request);

    if (response && response.status === 200) {
      cache.put(request, response.clone());
    }

    return response;
  } catch (error) {
    console.error('❌ Cache First Strategy failed:', error);
    return await getOfflineFallback(request);
  }
}

// Network First Strategy - Good for dynamic content
async function networkFirstStrategy(request, cacheName = RUNTIME_CACHE) {
  try {
    const response = await fetch(request);

    if (response && response.status === 200) {
      const cache = await caches.open(cacheName);
      cache.put(request, response.clone());
    }

    return response;
  } catch (error) {
    console.log('📦 Network failed, trying cache:', request.url);

    const cache = await caches.open(cacheName);
    const cached = await cache.match(request);

    if (cached) {
      return cached;
    }

    return await getOfflineFallback(request);
  }
}

// Background cache update
async function updateCache(request, cacheName) {
  try {
    const response = await fetch(request);
    if (response && response.status === 200) {
      const cache = await caches.open(cacheName);
      cache.put(request, response.clone());
    }
  } catch (error) {
    // Silent fail for background updates
  }
}

// Get offline fallback
async function getOfflineFallback(request) {
  const cache = await caches.open(CACHE_NAME);

  // Try to return offline page for navigation requests
  if (request.mode === 'navigate') {
    const offlinePage = await cache.match('/offline.html');
    if (offlinePage) {
      return offlinePage;
    }
  }

  return new Response('Offline - Content not available', {
    status: 503,
    statusText: 'Service Unavailable',
    headers: new Headers({
      'Content-Type': 'text/plain'
    })
  });
}

// ==================== BACKGROUND SYNC ====================
self.addEventListener('sync', (event) => {
  console.log('🔄 Background Sync:', event.tag);

  if (event.tag === 'sync-statements') {
    event.waitUntil(syncStatements());
  }
});

async function syncStatements() {
  try {
    console.log('🔄 Syncing statements...');
    // Sync logic here
    console.log('✅ Statements synced');
  } catch (error) {
    console.error('❌ Sync failed:', error);
  }
}

// ==================== PUSH NOTIFICATIONS ====================
self.addEventListener('push', (event) => {
  console.log('📬 Push notification received');

  const data = event.data ? event.data.json() : {};
  const title = data.title || 'CipherBank';
  const options = {
    body: data.body || 'You have a new notification',
    icon: '/icons/icon-192x192.png',
    badge: '/icons/badge-72x72.png',
    vibrate: [200, 100, 200],
    data: data.url || '/',
    tag: data.tag || 'cipherbank-notification',
    requireInteraction: false,
    actions: [
      {
        action: 'open',
        title: 'Open',
        icon: '/icons/action-open.png'
      },
      {
        action: 'close',
        title: 'Close',
        icon: '/icons/action-close.png'
      }
    ]
  };

  event.waitUntil(
    self.registration.showNotification(title, options)
  );
});

// ==================== NOTIFICATION CLICK ====================
self.addEventListener('notificationclick', (event) => {
  console.log('🔔 Notification clicked');

  event.notification.close();

  if (event.action === 'open') {
    const urlToOpen = event.notification.data || '/';

    event.waitUntil(
      clients.matchAll({ type: 'window', includeUncontrolled: true })
        .then((clientList) => {
          for (let client of clientList) {
            if (client.url === urlToOpen && 'focus' in client) {
              return client.focus();
            }
          }

          if (clients.openWindow) {
            return clients.openWindow(urlToOpen);
          }
        })
    );
  }
});

// ==================== MESSAGE HANDLER ====================
self.addEventListener('message', (event) => {
  console.log('📨 Message received:', event.data);

  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }

  if (event.data && event.data.type === 'CLEAR_CACHE') {
    event.waitUntil(
      caches.keys().then((cacheNames) => {
        return Promise.all(
          cacheNames.map((cacheName) => {
            return caches.delete(cacheName);
          })
        );
      })
    );
  }

  if (event.data && event.data.type === 'CACHE_URLS') {
    event.waitUntil(
      caches.open(RUNTIME_CACHE).then((cache) => {
        return cache.addAll(event.data.urls);
      })
    );
  }
});

// ==================== PERIODIC BACKGROUND SYNC ====================
self.addEventListener('periodicsync', (event) => {
  if (event.tag === 'update-statements') {
    event.waitUntil(updateStatementsInBackground());
  }
});

async function updateStatementsInBackground() {
  try {
    console.log('🔄 Periodic background sync: updating statements...');
    // Update logic here
    console.log('✅ Background update complete');
  } catch (error) {
    console.error('❌ Background update failed:', error);
  }
}

console.log('🚀 CipherBank Service Worker v2.0.0 loaded');