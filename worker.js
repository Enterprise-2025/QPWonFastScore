/* QPWON Proxy Worker — v2.4 (IT)
   Scopo: permettere a una webapp frontend (senza dipendenze) di leggere HTML di terze parti bypassando CORS.
   Endpoints
   - GET /?url=https://target[&mode=light|full][&bypass_cache=1][&accept_lang=it-IT,it;q=0.9]
   - GET /health
   Risposta:
   { url, finalUrl, status, contentType, charset, length, truncated, html, htmlStripped? }
   Sicurezza/Caching/CORS:
   - Allowlist CORS via env ALLOWED_ORIGINS (CSV) oppure pubblico (*) se non impostato e senza API_TOKEN
   - Token opzionale via env API_TOKEN (header Authorization: Bearer X o ?token=X)
   - Cache edge controllata (CACHE_TTL in sec) + possibilità di bypass (?bypass_cache=1)
   - Guard SSRF/privati (BLOCK_PRIVATE=1 default)
   - Timeout, cap lettura bytes (MAX_BYTES), UA override (USER_AGENT), Accept-Language override (?accept_lang)
*/
export default {
  async fetch(request, env, ctx) {
    const reqUrl = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    // ---- CORS baseline
    const allowlist = parseAllowedOrigins(env?.ALLOWED_ORIGINS);
    const cors = buildCorsHeaders(origin, allowlist, !!(env?.API_TOKEN));

    // Preflight
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    // Health
    if (reqUrl.pathname === "/health") {
      return json({ ok: true, ver: "2.4", time: new Date().toISOString() }, 200, cors);
    }

    if (request.method !== "GET") {
      return json({ error: "Method not allowed" }, 405, cors);
    }

    // ---- Auth & origin policy
    const requiredToken = (env?.API_TOKEN || "").trim();
    if (requiredToken) {
      const got = extractToken(reqUrl, request.headers);
      if (!got || got !== requiredToken) return json({ error: "Unauthorized" }, 401, cors);
    } else if (allowlist) {
      if (origin && !allowlist.has(origin)) return json({ error: "Forbidden origin" }, 403, cors);
    }

    // ---- Input
    const target = reqUrl.searchParams.get("url");
    const mode = (reqUrl.searchParams.get("mode") || "full").toLowerCase(); // full|light
    const bypassCache = reqUrl.searchParams.get("bypass_cache") === "1";
    const acceptLang = reqUrl.searchParams.get("accept_lang");
    if (!target) return json({ error: "Missing url" }, 400, cors);

    let parsed;
    try { parsed = new URL(target); }
    catch { return json({ error: "Invalid url" }, 400, cors); }
    if (!/^https?:$/.test(parsed.protocol)) return json({ error: "Only http(s) allowed" }, 400, cors);

    // ---- SSRF guard
    const blockPrivate = (env?.BLOCK_PRIVATE ?? "1") !== "0";
    if (blockPrivate && hostLooksPrivate(parsed.hostname)) return json({ error: "Target not allowed" }, 403, cors);

    // ---- Edge cache (manual key to avoid tainting origin cache)
    const ttl = clampInt(parseInt(env?.CACHE_TTL, 10), 60, 86400) || 1800;
    const cacheKey = new Request("https://qpwon-cache/" + encodeURIComponent(parsed.href) + "|" + mode, { method: "GET" });
    const cache = caches.default;

    if (!bypassCache) {
      const cached = await cache.match(cacheKey);
      if (cached) return attachCors(cached, { ...cors, "X-QPWON": "2.4", "X-Cache": "HIT" });
    }

    // ---- Fetch target (with timeout)
    const timeoutMs = clampInt(parseInt(env?.TIMEOUT_MS, 10), 3000, 20000) || 12000;
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);
    const ua = (env?.USER_AGENT || "QPWON-AutoAnalyzer/2.4").trim();

    const headers = {
      "user-agent": ua,
      "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "upgrade-insecure-requests": "1",
    };
    if (acceptLang) headers["accept-language"] = acceptLang;
    else headers["accept-language"] = "it-IT,it;q=0.9,en;q=0.8";

    const fetchOpts = {
      redirect: "follow",
      signal: controller.signal,
      headers,
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

    // ---- Read stream (cap)
    const MAX_BYTES = clampInt(parseInt(env?.MAX_BYTES, 10), 200_000, 5_000_000) || 1_500_000;
    let html = "", truncated = false;
    try {
      const { text, truncated: t } = await readAsText(r, MAX_BYTES);
      html = text; truncated = t;
    } catch (e) {
      return json({ error: "Read failed", detail: String(e?.message || e) }, 502, cors);
    }

    const contentType = r.headers.get("content-type") || "";
    const charset = extractCharset(contentType) || "utf-8";
    const finalUrl = r.url || parsed.href;

    const payload = {
      url: parsed.href,
      finalUrl,
      status: r.status,
      contentType,
      charset,
      length: html.length,
      truncated,
      html,
    };
    if (mode === "light") payload.htmlStripped = stripHtml(html);

    // ---- Cacheable base response (no CORS yet)
    const baseHeaders = {
      "Cache-Control": "public, max-age=0, must-revalidate",
      "Content-Type": "application/json; charset=UTF-8",
      "X-QPWON": "2.4",
      "X-Cache": "MISS",
      "X-Truncated": String(truncated),
      "Vary": "Origin"
    };
    const cacheable = new Response(JSON.stringify(payload), { status: 200, headers: baseHeaders });

    if (!bypassCache) ctx.waitUntil(cache.put(cacheKey, cacheable.clone()));

    // ---- Send back with CORS
    return attachCors(cacheable, cors);
  }
};

/* --------------- utils --------------- */
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
  const decoder = new TextDecoder(); // utf-8
  if (!reader) {
    let t = await response.text();
    if (t.length > maxBytes) return { text: t.slice(0, maxBytes), truncated: true };
    return { text: t, truncated: false };
  }
  let html = "", received = 0, truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      const allowed = Math.max(0, maxBytes - (received - value.byteLength));
      html += decoder.decode(value.subarray(0, allowed), { stream: true });
      truncated = true;
      break;
    }
    html += decoder.decode(value, { stream: true });
  }
  html += decoder.decode();
  return { text: html, truncated };
}
function extractCharset(contentType){
  if (!contentType) return "";
  const m = contentType.match(/charset=([A-Za-z0-9_-]+)/i);
  return m ? m[1].toLowerCase() : "";
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

