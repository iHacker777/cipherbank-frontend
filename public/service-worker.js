// CipherBank Service Worker
// Version: 1.0.0

const CACHE_NAME = 'cipherbank-v1.0.0';
const RUNTIME_CACHE = 'cipherbank-runtime-v1.0.0';
const IMAGE_CACHE = 'cipherbank-images-v1.0.0';

// Assets to cache on install
const PRECACHE_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/static/css/main.css',
  '/static/js/main.js',
  '/favicon.ico'
];

// API endpoints to cache with network-first strategy
const API_CACHE_PATTERNS = [
  /\/api\/auth\/login/,
  /\/api\/statements/
];

// Image patterns to cache
const IMAGE_PATTERNS = [
  /\.(?:png|jpg|jpeg|svg|gif|webp|ico)$/
];

// ==================== INSTALL EVENT ====================
self.addEventListener('install', (event) => {
  console.log('✅ Service Worker: Installing...');
  
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
              // Delete old caches
              return cacheName !== CACHE_NAME && 
                     cacheName !== RUNTIME_CACHE && 
                     cacheName !== IMAGE_CACHE;
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
  
  // Skip cross-origin requests
  if (url.origin !== location.origin) {
    // Handle API requests
    if (url.hostname.includes('thepaytrix.com')) {
      event.respondWith(networkFirstStrategy(request));
    }
    return;
  }
  
  // Handle different resource types with appropriate strategies
  if (request.method !== 'GET') {
    // Don't cache POST, PUT, DELETE requests
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
  event.respondWith(networkFirstStrategy(request));
});

// ==================== CACHING STRATEGIES ====================

// Cache First Strategy - Good for static assets
async function cacheFirstStrategy(request, cacheName = CACHE_NAME) {
  try {
    const cache = await caches.open(cacheName);
    const cached = await cache.match(request);
    
    if (cached) {
      console.log('📦 Serving from cache:', request.url);
      return cached;
    }
    
    console.log('🌐 Fetching from network:', request.url);
    const response = await fetch(request);
    
    // Cache successful responses
    if (response && response.status === 200) {
      cache.put(request, response.clone());
    }
    
    return response;
  } catch (error) {
    console.error('❌ Cache First Strategy failed:', error);
    
    // Return offline page if available
    const cache = await caches.open(CACHE_NAME);
    const offlinePage = await cache.match('/offline.html');
    
    if (offlinePage) {
      return offlinePage;
    }
    
    return new Response('Offline - Content not available', {
      status: 503,
      statusText: 'Service Unavailable',
      headers: new Headers({
        'Content-Type': 'text/plain'
      })
    });
  }
}

// Network First Strategy - Good for dynamic content
async function networkFirstStrategy(request) {
  try {
    console.log('🌐 Fetching from network:', request.url);
    const response = await fetch(request);
    
    // Cache successful responses
    if (response && response.status === 200) {
      const cache = await caches.open(RUNTIME_CACHE);
      cache.put(request, response.clone());
    }
    
    return response;
  } catch (error) {
    console.log('📦 Network failed, trying cache:', request.url);
    
    // Try to serve from cache
    const cache = await caches.open(RUNTIME_CACHE);
    const cached = await cache.match(request);
    
    if (cached) {
      return cached;
    }
    
    // Try main cache
    const mainCache = await caches.open(CACHE_NAME);
    const mainCached = await mainCache.match(request);
    
    if (mainCached) {
      return mainCached;
    }
    
    console.error('❌ Network First Strategy failed:', error);
    
    return new Response('Offline - Content not available', {
      status: 503,
      statusText: 'Service Unavailable',
      headers: new Headers({
        'Content-Type': 'text/plain'
      })
    });
  }
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
    // Add your sync logic here
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
    actions: [
      {
        action: 'open',
        title: 'Open'
      },
      {
        action: 'close',
        title: 'Close'
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
          // Check if there's already a window open
          for (let client of clientList) {
            if (client.url === urlToOpen && 'focus' in client) {
              return client.focus();
            }
          }
          
          // Open new window
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
});

console.log('🚀 Service Worker loaded');