// QPWON Proxy Worker — v2 (clean & updated)
// Purpose: Fetch public HTML pages server-side and return them as JSON with CORS open,
//          so a browser app can analyze content without CORS blocks.
//
// Compatible with the index.html you have. Endpoint example:
//   https://YOUR-WORKER.workers.dev/?url=https%3A%2F%2Fwww.example.com
//
// Optional security / tuning via environment vars (Wrangler > Vars):
//   - API_TOKEN        : if set, require token via ?token=... or Authorization: Bearer ...
//   - ALLOWED_ORIGINS  : CSV of allowed Origins (e.g. "http://localhost:5173,https://yourapp.com")
//   - USER_AGENT       : custom UA to use when fetching target
//   - CACHE_TTL        : seconds for Cloudflare edge cache (default 1800)
//   - BLOCK_PRIVATE    : "1" to block private/localhost hosts (default on)
//
// Endpoints:
//   GET  /?url=...     : proxy fetch -> { url, html, status, contentType, length }
//   GET  /health       : basic status ping
//   OPTIONS *          : CORS preflight
//
// Notes:
// - This proxy is for HTML/text. It will still try to read other content-types as text.
// - Be respectful: don’t crawl aggressively and honor robots/exclusions in your app layer.

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "";

    // ----- CORS helpers -----
    const allowedOrigins = parseAllowedOrigins(env?.ALLOWED_ORIGINS);
    const cors = buildCorsHeaders(origin, allowedOrigins);
    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    // ----- Health endpoint -----
    if (url.pathname === "/health") {
      return json({ ok: true, time: new Date().toISOString() }, 200, cors);
    }

    // ----- Auth (optional) -----
    const requiredToken = (env?.API_TOKEN || "").trim();
    if (requiredToken) {
      const got = extractToken(url, req.headers);
      if (!got || got !== requiredToken) {
        return json({ error: "Unauthorized" }, 401, cors);
      }
    } else {
      // If ALLOWED_ORIGINS is set, enforce it. If not set, fallback to "*".
      if (allowedOrigins && origin && !allowedOrigins.has(origin)) {
        return json({ error: "Forbidden origin" }, 403, cors);
      }
    }

    // ----- Main proxy -----
    if (req.method !== "GET") {
      return json({ error: "Method not allowed" }, 405, cors);
    }

    const target = url.searchParams.get("url");
    if (!target) {
      return json({ error: "Missing url" }, 400, cors);
    }

    let parsed;
    try {
      parsed = new URL(target);
    } catch {
      return json({ error: "Invalid url" }, 400, cors);
    }

    if (!/^https?:$/.test(parsed.protocol)) {
      return json({ error: "Only http(s) allowed" }, 400, cors);
    }

    // SSRF guard (basic) — avoid localhost/private ranges by hostname (best-effort).
    const blockPrivate = (env?.BLOCK_PRIVATE ?? "1") !== "0";
    if (blockPrivate && isPrivateHostname(parsed.hostname)) {
      return json({ error: "Target not allowed" }, 403, cors);
    }

    // Edge cache (Worker cache) — cache JSON result by target URL
    const ttl = clampInt(parseInt(env?.CACHE_TTL, 10), 60, 86400) || 1800;
    const cacheKey = new Request("https://proxy-cache/" + encodeURIComponent(parsed.href), { method: "GET" });
    const cache = caches.default;
    const cached = await cache.match(cacheKey);
    if (cached) {
      // add CORS headers on top of cached response
      return withCors(cached, cors);
    }

    const ua = (env?.USER_AGENT || "QPWON-AutoAnalyzer/2.0 (+contact: set-USER_AGENT)").trim();
    const fetchOpts = {
      redirect: "follow",
      headers: {
        "user-agent": ua,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "it-IT,it;q=0.9,en;q=0.8",
        "upgrade-insecure-requests": "1",
      },
      cf: {
        // This controls *target* fetch caching at the edge; we also cache the JSON output below.
        cacheTtl: ttl,
        cacheEverything: true,
      },
    };

    let r;
    try {
      r = await fetch(parsed.href, fetchOpts);
    } catch (e) {
      return json({ error: "Fetch failed", detail: String(e?.message || e) }, 502, cors);
    }

    let html;
    try {
      html = await r.text();
    } catch (e) {
      return json({ error: "Read failed", detail: String(e?.message || e) }, 502, cors);
    }

    const body = {
      url: parsed.href,
      status: r.status,
      contentType: r.headers.get("content-type") || "",
      length: html.length,
      html,
    };

    let resp = json(body, 200, cors);
    // Put in cache (only successful)
    ctx.waitUntil(cache.put(cacheKey, resp.clone()));
    return resp;
  }
};

/* ===================== utils ===================== */

function json(obj, status = 200, headers = {}) {
  const h = new Headers({
    "content-type": "application/json; charset=UTF-8",
    "Cache-Control": "public, max-age=0, must-revalidate",
    ...headers,
  });
  return new Response(JSON.stringify(obj), { status, headers: h });
}

function buildCorsHeaders(origin, allowedOriginsSet) {
  // If an allowlist exists, echo the incoming origin only if allowed.
  // Otherwise, allow all.
  let allowOrigin = "*";
  if (allowedOriginsSet) {
    allowOrigin = (origin && allowedOriginsSet.has(origin)) ? origin : "null";
  }
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin",
  };
}

function parseAllowedOrigins(csv) {
  if (!csv) return null;
  const set = new Set();
  for (const item of String(csv).split(",").map(s => s.trim()).filter(Boolean)) {
    set.add(item);
  }
  return set.size ? set : null;
}

function extractToken(url, headers) {
  const q = url.searchParams.get("token");
  if (q) return q;
  const auth = headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

function isPrivateHostname(host) {
  if (!host) return true;
  const h = host.toLowerCase();
  if (h === "localhost" || h === "localhost.localdomain") return true;
  if (h.endsWith(".localhost") || h.endsWith(".local")) return true;
  // IPv4 literals
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const [a,b,c,d] = h.split(".").map(n => parseInt(n,10));
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
  }
  // IPv6 loopback/link-local (very rough)
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  if (h.startsWith("fe80:")) return true;
  return false;
}

function clampInt(n, min, max) {
  if (!Number.isFinite(n)) return min;
  return Math.min(max, Math.max(min, n|0));
}

function withCors(resp, cors) {
  const h = new Headers(resp.headers);
  for (const [k,v] of Object.entries(cors)) h.set(k, v);
  return new Response(resp.body, { status: resp.status, headers: h });
}
