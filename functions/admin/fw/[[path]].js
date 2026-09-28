// Cloudflare Pages Function — serves COMPANY (v007) firmware to the admin page only.
//
// URL:   https://plschat.net/admin/fw/<file>      e.g. /admin/fw/manifest-v007.json
// Data:  Cloudflare KV namespace bound to this Pages project as  FIRMWARE
//        (key = file name, value = raw file bytes). Nothing lives in the git repo,
//        so the public GitHub repo never contains company firmware.
//
// Who can read it:
//   1. Cloudflare Access already guards everything under plschat.net/admin — only
//      the owner's email (one-time PIN) gets through. Access runs at the edge
//      BEFORE this function, and _middleware.js forces *.pages.dev back onto
//      plschat.net so Access can't be side-stepped.
//   2. Belt and braces: this function refuses any request that doesn't carry the
//      Access identity token. If you set the Pages env vars CF_ACCESS_TEAM
//      (e.g. "plschat" for plschat.cloudflareaccess.com) and CF_ACCESS_AUD (the
//      Application Audience tag from Zero Trust > Access > Applications), the
//      token's signature, audience and expiry are verified too.
//
// Setup (once): Workers & Pages > plschat-site > Settings > Bindings >
//   Add > KV namespace > Variable name: FIRMWARE > pick the FIRMWARE namespace.

const TYPES = { json: "application/json", bin: "application/octet-stream" };
const NAME_OK = /^[A-Za-z0-9._-]{1,120}$/;

export async function onRequest({ request, env, params }) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return deny(405, "Method not allowed");
  }

  // ---- identity check (defence in depth behind Cloudflare Access) ----
  const jwt = request.headers.get("Cf-Access-Jwt-Assertion");
  if (!jwt) return deny(403, "Forbidden");
  if (env.CF_ACCESS_TEAM && env.CF_ACCESS_AUD) {
    const ok = await verifyAccessJwt(jwt, env.CF_ACCESS_TEAM, env.CF_ACCESS_AUD).catch(() => false);
    if (!ok) return deny(403, "Forbidden");
  }

  if (!env.FIRMWARE) return deny(503, "Firmware store not bound (FIRMWARE KV)");

  const parts = Array.isArray(params.path) ? params.path : [params.path].filter(Boolean);
  const name = parts.join("/");
  if (parts.length !== 1 || !NAME_OK.test(name)) return deny(404, "Not found");

  const body = await env.FIRMWARE.get(name, { type: "arrayBuffer" });
  if (!body) return deny(404, "Not found");

  const ext = name.split(".").pop().toLowerCase();
  return new Response(request.method === "HEAD" ? null : body, {
    headers: {
      "Content-Type": TYPES[ext] || "application/octet-stream",
      "Cache-Control": "private, no-store",
      "X-Robots-Tag": "noindex",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function deny(status, msg) {
  return new Response(msg, {
    status,
    headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" },
  });
}

// ---- Cloudflare Access JWT (RS256) verification ----
function b64urlToBytes(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function verifyAccessJwt(token, team, aud) {
  const [h, p, sig] = token.split(".");
  if (!h || !p || !sig) return false;
  const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(h)));
  const payload = JSON.parse(new TextDecoder().decode(b64urlToBytes(p)));

  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp || payload.exp < now) return false;
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(aud)) return false;
  const issuer = `https://${team}.cloudflareaccess.com`;
  if (payload.iss !== issuer) return false;

  const certs = await fetch(`${issuer}/cdn-cgi/access/certs`, { cf: { cacheTtl: 3600 } }).then((r) => r.json());
  const jwk = (certs.keys || []).find((k) => k.kid === header.kid);
  if (!jwk) return false;
  const key = await crypto.subtle.importKey(
    "jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]
  );
  return crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5", key, b64urlToBytes(sig), new TextEncoder().encode(`${h}.${p}`)
  );
}
