export async function onRequest() {
  return new Response(null, {
    status: 302,
    headers: {
      "Location": "/index.html?live=1",
      "Cache-Control": "no-store, no-cache, must-revalidate"
    }
  });
}
