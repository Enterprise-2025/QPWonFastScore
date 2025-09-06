// QPWON Proxy Worker — v2.1 (clean, complete, updated)
// Purpose: Fetch public HTML pages at the edge and return them as JSON with open CORS,
//          so the front-end can analyze pages without CORS issues and without dependencies.
//
// Usage (GET):
//   https://YOUR-WORKER.workers.dev/?url=https%3A%2F%2Fwww.example.com
//
// Optional Environment Variables (Cloudflare Dashboard → Settings → Variables):
//   - API_TOKEN        : if set, require a matching token (?token=... or Authorization: Bearer ...)
//   - ALLOWED_ORIGINS  : CSV allowlist of Origins (e.g. "http://localhost:5173,https://yourapp.com").
//                        If empty and API_TOKEN is not set, Access-Control-Allow-Origin will be "*".
//                        If set, only those origins will be allowed (others get 403).
//   - USER_AGENT       : custom User-Agent string when fetching target pages
//   - CACHE_TTL        : edge cache TTL in seconds (default 1800; min 60; max 86400)
//   - BLOCK_PRIVATE    : "1" (default) to block localhost/private IP ranges; "0" to disable guard
//   - MAX_BYTES        : max HTML bytes to return (default 1_500_000). If exceeded, response is truncated.
//
// Endpoints:
//   GET  /?url=...     : proxy fetch → { url, html, status, contentType, length, truncated? }
//   GET  /health       : health probe
//   OPTIONS *          : CORS preflight
//
// Note:
// - This worker focuses on TEXT/HTML pages. Non-HTML content is still read as text (best-effort).
// - Be polite with targets: throttle/crawl responsibly in your front-end app logic.

export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "";

    // Prepare CORS (reflective if ALLOWED_ORIGINS set; otherwise permissive "*")
    const allowlist = parseAllowedOrigins(env?.ALLOWED_ORIGINS);
    const cors = buildCorsHeaders(origin, allowlist, !!env?.API_TOKEN);

    if (req.method === "OPTIONS") {
      // CORS preflight
      return new Response(null, { status: 204, headers: cors });
    }

    if (url.pathname === "/health") {
      return json({ ok: true, time: new Date().toISOString() }, 200, cors);
    }

    if (req.method !== "GET") {
      return json({ error: "Method not allowed" }, 405, cors);
    }

    // Auth (optional): if API_TOKEN is set, require it
    const requiredToken = (env?.API_TOKEN || "").trim();
    if (requiredToken) {
      const got = extractToken(url, req.headers);
      if (!got || got !== requiredToken) {
        return json({ error: "Unauthorized" }, 401, cors);
      }
    } else if (allowlist) {
      // If we have an allowlist but no token, enforce allowed origins
      if (origin && !allowlist.has(origin)) {
        return json({ error: "Forbidden origin" }, 403, cors);
      }
    }

    // Main proxy fetch
    const target = url.searchParams.get("url");
    if (!target) {
      return json({ error: "Missing url" }, 400, cors);
    }

    let parsed;
    try { parsed = new URL(target); }
    catch { return json({ error: "Invalid url" }, 400, cors); }

    if (!/^https?:$/.test(parsed.protocol)) {
      return json({ error: "Only http(s) allowed" }, 400, cors);
    }

    // SSRF guard
    const blockPrivate = (env?.BLOCK_PRIVATE ?? "1") !== "0";
    if (blockPrivate && hostLooksPrivate(parsed.hostname)) {
      return json({ error: "Target not allowed" }, 403, cors);
    }

    // Edge cache
    const ttl = clampInt(parseInt(env?.CACHE_TTL, 10), 60, 86400) || 1800;
    const cacheKey = new Request("https://qpwon-cache/" + encodeURIComponent(parsed.href), { method: "GET" });
    const cache = caches.default;
    const cached = await cache.match(cacheKey);
    if (cached) return withCors(cached, cors);

    // Outbound fetch
    const ua = (env?.USER_AGENT || "QPWON-AutoAnalyzer/2.1 (+contact: set USER_AGENT)").trim();
    const fetchOpts = {
      redirect: "follow",
      headers: {
        "user-agent": ua,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "it-IT,it;q=0.9,en;q=0.8",
        "upgrade-insecure-requests": "1",
      },
      cf: { cacheTtl: ttl, cacheEverything: true },
    };

    let r;
    try { r = await fetch(parsed.href, fetchOpts); }
    catch (e) { return json({ error: "Fetch failed", detail: String(e?.message || e) }, 502, cors); }

    // Read as text (best-effort). Enforce max size to avoid huge payloads.
    const MAX_BYTES = clampInt(parseInt(env?.MAX_BYTES, 10), 200_000, 5_000_000) || 1_500_000;
    const reader = r.body?.getReader ? r.body.getReader() : null;
    let html = "";
    let received = 0;
    let truncated = false;

    if (reader) {
      const decoder = new TextDecoder(); // default utf-8
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        received += value.byteLength;
        if (received > MAX_BYTES) {
          html += decoder.decode(value.subarray(0, Math.max(0, MAX_BYTES - (received - value.byteLength))), { stream: true });
          truncated = true;
          break;
        }
        html += decoder.decode(value, { stream: true });
      }
      html += decoder.decode();
    } else {
      try { html = await r.text(); }
      catch (e) { return json({ error: "Read failed", detail: String(e?.message || e) }, 502, cors); }
      if (html.length > MAX_BYTES) { html = html.slice(0, MAX_BYTES); truncated = true; }
    }

    const body = {
      url: parsed.href,
      status: r.status,
      contentType: r.headers.get("content-type") || "",
      length: html.length,
      truncated,
      html,
    };

    let resp = json(body, 200, cors);
    // store in edge cache
    ctx.waitUntil(cache.put(cacheKey, resp.clone()));
    return resp;
  }
};

/* ===================== utils ===================== */

/**
 * Build a JSON response with basic caching + CORS headers
 */
function json(obj, status = 200, headers = {}) {
  const h = new Headers({
    "content-type": "application/json; charset=UTF-8",
    "Cache-Control": "public, max-age=0, must-revalidate",
    ...headers,
  });
  return new Response(JSON.stringify(obj), { status, headers: h });
}

/**
 * CORS headers
 * If we have an allowlist OR API token is present, reflect the Origin if allowed; otherwise "null".
 * If neither is set, we allow "*".
 */
function buildCorsHeaders(origin, allowlistSet, tokenEnabled) {
  let allowOrigin = "*";
  if (allowlistSet || tokenEnabled) {
    allowOrigin = (origin && (!allowlistSet || allowlistSet.has(origin))) ? origin : "null";
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
  String(csv).split(",").map(s => s.trim()).filter(Boolean).forEach(v => set.add(v));
  return set.size ? set : null;
}

function extractToken(url, headers) {
  const q = url.searchParams.get("token");
  if (q) return q;
  const auth = headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

function hostLooksPrivate(host) {
  if (!host) return true;
  const h = host.toLowerCase();
  if (h === "localhost" || h === "localhost.localdomain") return true;
  if (h.endsWith(".localhost") || h.endsWith(".local")) return true;
  // IPv4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const [a,b] = h.split(".").map(n => parseInt(n,10));
    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 0) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
  }
  // IPv6 common locals
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  if (h.startsWith("fe80:")) return true;
  return false;
}

function clampInt(n, min, max) {
  const v = Number.isFinite(n) ? (n|0) : min;
  return Math.min(max, Math.max(min, v));
}

function withCors(resp, cors) {
  const h = new Headers(resp.headers);
  for (const [k,v] of Object.entries(cors)) h.set(k, v);
  return new Response(resp.body, { status: resp.status, headers: h });
}


