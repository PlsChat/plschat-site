// Cloudflare Pages Function — same-origin bridge to the licence / coverage Worker.
//
//   https://plschat.net/api/<worker path>   ->   plschat-coverage-api Worker  /<worker path>
//   e.g. /api/admin/login        -> /admin/login
//        /api/licence/status/X   -> /licence/status/X
//        /api/api/repeaters      -> /api/repeaters
//
// Why: requests now arrive on plschat.net, so Cloudflare's WAF / rate-limiting rules
// on the zone protect the Worker (they never applied on *.workers.dev). The call to the
// Worker goes over a private Service Binding (env.API), so the public workers.dev
// address can be switched off entirely.
//
// Setup (done): Pages project plschat-site > Settings > Bindings > Service binding
//   Variable name: API  ->  Service: plschat-coverage-api

export async function onRequest({ request, env }) {
  if (!env.API) {
    return new Response("API binding missing", { status: 503, headers: { "Cache-Control": "no-store" } });
  }

  const url = new URL(request.url);
  const rest = url.pathname.replace(/^\/api(?=\/|$)/, "") || "/";
  const target = new URL(rest + url.search, "https://plschat-coverage-api.internal");

  // Forward method, headers and body unchanged, except browser cookies for plschat.net
  // (e.g. the Cloudflare Access session) which the Worker never needs.
  const headers = new Headers(request.headers);
  headers.delete("cookie");

  const init = {
    method: request.method,
    headers,
    redirect: "manual",
  };
  if (request.method !== "GET" && request.method !== "HEAD") {
    init.body = request.body;
  }

  const resp = await env.API.fetch(new Request(target.toString(), init));

  // Never let API responses be cached by the browser or the edge.
  const out = new Response(resp.body, resp);
  out.headers.set("Cache-Control", "no-store");
  return out;
}
