// Cloudflare Pages Functions middleware — runs on the edge for EVERY request
// to this Pages deployment, regardless of which hostname routed to it.
//
// Purpose: the raw Pages origin (plschat-site.pages.dev) and every per-commit
// preview URL (<hash>.plschat-site.pages.dev) are public and CANNOT be gated by
// Cloudflare Access (Access on a custom domain doesn't cover *.pages.dev, and
// Redirect Rules don't run on hostnames outside your zone). That left the admin
// page reachable un-gated via the Pages URL.
//
// This closes it server-side: any request whose hostname ends in ".pages.dev"
// is 301-redirected to the Access-protected apex (plschat.net), same path and
// query. Requests on the real custom domain (plschat.net) pass straight through
// and are served normally. Because it keys on ".pages.dev" it never touches the
// apex, so there's no redirect loop and nothing else can break.
//
// Deploy: this file MUST live at  functions/_middleware.js  (one functions
// folder, filename starts with an underscore). Cloudflare Pages auto-detects
// the functions/ directory and runs it site-wide on the next build.

export async function onRequest(context) {
  const { request, next } = context;
  const url = new URL(request.url);

  if (url.hostname.endsWith(".pages.dev")) {
    url.hostname = "plschat.net";
    url.protocol = "https:";
    url.port = "";
    return Response.redirect(url.toString(), 301);
  }

  return next();
}
