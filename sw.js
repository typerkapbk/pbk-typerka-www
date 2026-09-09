const CACHE_NAME = "pbk-typerka-pwa-v1";

const APP_SHELL = [
  "/manifest.webmanifest",
  "/icon-192.png",
  "/icon-512.png"
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys()
      .then(keys =>
        Promise.all(
          keys
            .filter(key => key !== CACHE_NAME)
            .map(key => caches.delete(key))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", event => {
  const request = event.request;
  const url = new URL(request.url);

  if (request.method !== "GET") {
    return;
  }

  /*
   * API zawsze pobieramy bezpośrednio
   * z sieci.
   *
   * Dzięki temu wyniki, typy,
   * aktualności i prywatność typów
   * nigdy nie korzystają ze starego cache.
   */
  if (
    url.origin === self.location.origin &&
    url.pathname.startsWith("/api/")
  ) {
    return;
  }

  /*
   * Główna strona:
   * najpierw najnowsza wersja z sieci.
   *
   * Cache jest używany tylko awaryjnie,
   * gdyby nie było internetu.
   */
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then(response => {
          const copy = response.clone();

          caches.open(CACHE_NAME)
            .then(cache =>
              cache.put(request, copy)
            );

          return response;
        })
        .catch(async () => {
          return (
            await caches.match(request)
          ) ||
          (
            await caches.match("/")
          ) ||
          Response.error();
        })
    );

    return;
  }

  /*
   * Pliki statyczne:
   * ikony, manifest itd.
   */
  if (
    url.origin ===
    self.location.origin
  ) {
    event.respondWith(
      caches.match(request)
        .then(cached => {
          const network =
            fetch(request)
              .then(response => {
                if (
                  response &&
                  response.ok
                ) {
                  const copy =
                    response.clone();

                  caches
                    .open(CACHE_NAME)
                    .then(cache =>
                      cache.put(
                        request,
                        copy
                      )
                    );
                }

                return response;
              })
              .catch(
                () => cached
              );

          return (
            cached ||
            network
          );
        })
    );
  }
});
