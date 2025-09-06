/* QPWON Proxy Worker — v2.3
   Features:
   - GET /?url=https://target[&mode=light|full]
   - /health endpoint
   - CORS with allowlist (ALLOWED_ORIGINS) or public (*)
   - Optional bearer/API token (API_TOKEN) or ?token=
   - Cache at edge (CACHE_TTL), stream read cap (MAX_BYTES), UA override (USER_AGENT)
   - Private host/SSRF guard (BLOCK_PRIVATE)
   - Returns JSON: {url,status,contentType,length,truncated,html[,htmlStripped]}
*/
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    // CORS policy
    const allowlist = parseAllowedOrigins(env?.ALLOWED_ORIGINS);
    const cors = buildCorsHeaders(origin, allowlist, !!(env?.API_TOKEN));

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (url.pathname === "/health")   return json({ ok: true, ver: "2.3", time: new Date().toISOString() }, 200, cors);
    if (request.method !== "GET")     return json({ error: "Method not allowed" }, 405, cors);

    // Auth / origin allowlist
    const requiredToken = (env?.API_TOKEN || "").trim();
    if (requiredToken) {
      const got = extractToken(url, request.headers);
      if (!got || got !== requiredToken) return json({ error: "Unauthorized" }, 401, cors);
    } else if (allowlist) {
      if (origin && !allowlist.has(origin)) return json({ error: "Forbidden origin" }, 403, cors);
    }

    // Parse target
    const target = url.searchParams.get("url");
    const mode = (url.searchParams.get("mode") || "full").toLowerCase(); // light|full
    if (!target) return json({ error: "Missing url" }, 400, cors);

    let parsed;
    try { parsed = new URL(target); }
    catch { return json({ error: "Invalid url" }, 400, cors); }
    if (!/^https?:$/.test(parsed.protocol)) return json({ error: "Only http(s) allowed" }, 400, cors);

    // SSRF guard
    const blockPrivate = (env?.BLOCK_PRIVATE ?? "1") !== "0";
    if (blockPrivate && hostLooksPrivate(parsed.hostname)) return json({ error: "Target not allowed" }, 403, cors);

    // Edge cache
    const ttl = clampInt(parseInt(env?.CACHE_TTL, 10), 60, 86400) || 1800;
    const cacheKey = new Request("https://qpwon-cache/" + encodeURIComponent(parsed.href) + "|" + mode, { method: "GET" });
    const cache = caches.default;
    const cached = await cache.match(cacheKey);
    if (cached) {
      return attachCors(cached, { ...cors, "X-QPWON": "2.3", "X-Cache": "HIT" });
    }

    // Fetch with timeout
    const timeoutMs = clampInt(parseInt(env?.TIMEOUT_MS, 10), 3000, 20000) || 12000;
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    const ua = (env?.USER_AGENT || "QPWON-AutoAnalyzer/2.3").trim();

    const fetchOpts = {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": ua,
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "accept-language": "it-IT,it;q=0.9,en;q=0.8",
        "upgrade-insecure-requests": "1",
      },
      cf: { cacheTtl: ttl, cacheEverything: true }
    };

    let r;
    try {
      r = await fetch(parsed.href, fetchOpts);
    } catch (e) {
      clearTimeout(id);
      const msg = String(e?.message || e || "");
      const timedOut = /abort|aborted|timeout/i.test(msg);
      return json({ error: timedOut ? "Fetch timeout" : "Fetch failed", detail: msg }, 502, cors);
    }
    clearTimeout(id);

    // Stream → text (cap)
    const MAX_BYTES = clampInt(parseInt(env?.MAX_BYTES, 10), 200_000, 5_000_000) || 1_500_000;
    let html = "", truncated = false;
    try {
      html = await readAsText(r, MAX_BYTES);
      truncated = html.length >= MAX_BYTES;
    } catch (e) {
      return json({ error: "Read failed", detail: String(e?.message || e) }, 502, cors);
    }

    const payload = {
      url: parsed.href,
      status: r.status,
      contentType: r.headers.get("content-type") || "",
      length: html.length,
      truncated,
      html,
    };
    if (mode === "light") payload.htmlStripped = stripHtml(html);

    // Build cacheable response WITHOUT CORS (we attach per-request CORS below)
    const baseHeaders = {
      "Cache-Control": "public, max-age=0, must-revalidate",
      "Content-Type": "application/json; charset=UTF-8",
      "X-QPWON": "2.3",
      "X-Cache": "MISS",
      "X-Truncated": String(truncated),
      "Vary": "Origin"
    };
    const cacheable = new Response(JSON.stringify(payload), { status: 200, headers: baseHeaders });
    ctx.waitUntil(cache.put(cacheKey, cacheable.clone()));

    // Return with CORS merged
    return attachCors(cacheable, cors);
  }
};

/* ----------------- utils ----------------- */
function json(obj, status = 200, headers = {}) {
  const h = new Headers({ "content-type": "application/json; charset=UTF-8", "Cache-Control": "public, max-age=0, must-revalidate", "Vary": "Origin", ...headers });
  return new Response(JSON.stringify(obj), { status, headers: h });
}
function parseAllowedOrigins(csv){
  if (!csv) return null;
  const set = new Set();
  String(csv).split(",").map(s=>s.trim()).filter(Boolean).forEach(v => set.add(v));
  return set.size ? set : null;
}
function buildCorsHeaders(origin, allowlistSet, tokenEnabled){
  let allowOrigin = "*";
  if (allowlistSet || tokenEnabled) {
    allowOrigin = (origin && (!allowlistSet || allowlistSet.has(origin))) ? origin : "null";
  }
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}
function extractToken(url, headers){
  const q = url.searchParams.get("token");
  if (q) return q;
  const auth = headers.get("Authorization") || "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}
function hostLooksPrivate(host){
  if (!host) return true;
  const h = host.toLowerCase();
  if (h === "localhost" || h === "localhost.localdomain" || h.endsWith(".localhost") || h.endsWith(".local")) return true;
  // IPv4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const [a,b] = h.split(".").map(n=>parseInt(n,10));
    if ([10,127,0].includes(a)) return true;
    if (a===169 && b===254) return true;
    if (a===192 && b===168) return true;
    if (a===172 && b>=16 && b<=31) return true;
  }
  // IPv6 simple checks
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  if (h.startsWith("fe80:")) return true;
  return false;
}
function clampInt(n, min, max){
  const v = Number.isFinite(n) ? (n|0) : min;
  return Math.min(max, Math.max(min, v));
}
async function readAsText(response, maxBytes){
  const reader = response.body?.getReader ? response.body.getReader() : null;
  if (!reader) {
    let t = await response.text();
    if (t.length > maxBytes) t = t.slice(0, maxBytes);
    return t;
  }
  const decoder = new TextDecoder();
  let html = "", received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      const allowed = Math.max(0, maxBytes - (received - value.byteLength));
      html += decoder.decode(value.subarray(0, allowed), { stream: true });
      break;
    }
    html += decoder.decode(value, { stream: true });
  }
  html += decoder.decode();
  return html;
}
function stripHtml(html){
  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi,'')
    .replace(/<style[\s\S]*?<\/style>/gi,'')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi,'')
    .replace(/<svg[\s\S]*?<\/svg>/gi,'')
    .replace(/<(div|section|footer)[^>]+(?:id|class)=["'][^"']*(cookie|gdpr|consent|banner|policy)[^"']*["'][\s\S]*?<\/\1>/gi,'');
}
function attachCors(resp, extraHeaders){
  const h = new Headers(resp.headers);
  for (const [k,v] of Object.entries(extraHeaders||{})) h.set(k,v);
  return new Response(resp.body, { status: resp.status, headers: h });
}
