/* QPWON Proxy Worker — v2.6 (IT)
   Scopo: permettere a una webapp frontend (senza dipendenze) di leggere HTML di terze parti bypassando CORS.
   Compatibile con index.html v1.7.x

   Funzioni principali:
   - GET /?url=https://target
       &mode=light|full      (default full: ritorna HTML intero; light: rimuove script/style/banner)
       &bypass_cache=1       (salta cache edge)
       &accept_lang=it-IT,it;q=0.9
       &timeout_ms=12000     (3_000–20_000)
       &max_bytes=1500000    (200_000–5_000_000)
       &ua=desktop           (UA desktop Chrome)
       &strip=1              (applica stripHtml all’HTML)
       &text=1               (aggiunge anche text plano)
       [&token=...]          (se API_TOKEN è impostato in Env)
   - GET /health             (ping)

   Output JSON:
   {
     url, finalUrl, status, contentType, charset, charsetUsed,
     length, truncated, html, htmlStripped?, text?
   }

   Env opzionali:
   - API_TOKEN: se presente, richiede Authorization: Bearer <token> o ?token=
   - ALLOWED_ORIGINS: CSV di origin ammessi per CORS; se assente e senza API_TOKEN → * (pubblico)
   - CACHE_TTL: TTL cache edge (sec). Default 1800. Clamp: 60–86400
   - TIMEOUT_MS: timeout fetch (ms). Default 12000. Clamp: 3000–20000
   - MAX_BYTES: cap lettura (byte). Default 1_500_000. Clamp: 200_000–5_000_000
   - BLOCK_PRIVATE: "1" (default) blocca host privati/localhost; "0" per disabilitare
   - USER_AGENT: UA di default (se non si usa ua=desktop)
*/

export default {
  async fetch(request, env, ctx) {
    const reqUrl = new URL(request.url);
    const origin = request.headers.get("Origin") || "";

    // CORS di base (dipende da allowlist/token)
    const allowlist = parseAllowedOrigins(env?.ALLOWED_ORIGINS);
    const cors = buildCorsHeaders(origin, allowlist, !!(env?.API_TOKEN));

    // Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }

    // /health
    if (reqUrl.pathname === "/health") {
      return json({ ok: true, ver: "2.6", time: new Date().toISOString() }, 200, cors);
    }

    if (request.method !== "GET") {
      return json({ error: "Method not allowed" }, 405, cors);
    }

    // Autorizzazione opzionale
    const requiredToken = (env?.API_TOKEN || "").trim();
    if (requiredToken) {
      const got = extractToken(reqUrl, request.headers);
      if (!got || got !== requiredToken) return json({ error: "Unauthorized" }, 401, cors);
    } else if (allowlist) {
      if (origin && !allowlist.has(origin)) return json({ error: "Forbidden origin" }, 403, cors);
    }

    // Parametri
    const target = reqUrl.searchParams.get("url");
    const mode = (reqUrl.searchParams.get("mode") || "full").toLowerCase(); // full|light
    const bypassCache = reqUrl.searchParams.get("bypass_cache") === "1";
    const acceptLang = reqUrl.searchParams.get("accept_lang");
    const strip = reqUrl.searchParams.get("strip") === "1";
    const wantText = reqUrl.searchParams.get("text") === "1";

    const qTimeout = clampInt(parseInt(reqUrl.searchParams.get("timeout_ms") || ""), 3000, 20000);
    const qMax = clampInt(parseInt(reqUrl.searchParams.get("max_bytes") || ""), 200_000, 5_000_000);
    const uaMode = (reqUrl.searchParams.get("ua") || "").toLowerCase(); // "", "desktop"

    if (!target) return json({ error: "Missing url" }, 400, cors);

    let parsed;
    try { parsed = new URL(target); }
    catch { return json({ error: "Invalid url" }, 400, cors); }

    if (!/^https?:$/i.test(parsed.protocol)) {
      return json({ error: "Only http(s) allowed" }, 400, cors);
    }

    // Protezione SSRF base
    const blockPrivate = (env?.BLOCK_PRIVATE ?? "1") !== "0";
    if (blockPrivate && hostLooksPrivate(parsed.hostname)) {
      return json({ error: "Target not allowed" }, 403, cors);
    }

    // Cache edge
    const ttl = clampInt(parseInt(env?.CACHE_TTL, 10), 60, 86400) || 1800;
    const cacheKey = new Request(
      "https://qpwon-cache/" +
      encodeURIComponent(parsed.href) +
      "|" + mode +
      "|" + (strip ? 1 : 0) +
      "|" + (wantText ? 1 : 0),
      { method: "GET" }
    );
    const cache = caches.default;

    if (!bypassCache) {
      const cached = await cache.match(cacheKey);
      if (cached) return attachCors(cached, { ...cors, "X-QPWON": "2.6", "X-Cache": "HIT" });
    }

    // Fetch con timeout
    const timeoutMs = qTimeout || (clampInt(parseInt(env?.TIMEOUT_MS, 10), 3000, 20000) || 12000);
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeoutMs);

    const uaEnv = (env?.USER_AGENT || "QPWON-AutoAnalyzer/2.6").trim();
    const uaDesktop = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36";
    const ua = (uaMode === "desktop") ? uaDesktop : uaEnv;

    const headers = {
      "user-agent": ua,
      "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "upgrade-insecure-requests": "1",
      "accept-language": acceptLang || "it-IT,it;q=0.9,en;q=0.8"
    };

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

    const contentType = r.headers.get("content-type") || "";
    const headerCharset = extractCharset(contentType);

    // Lettura stream con cap bytes + decodifica
    const MAX_BYTES = qMax || (clampInt(parseInt(env?.MAX_BYTES, 10), 200_000, 5_000_000) || 1_500_000);
    let text = "", truncated = false, usedCharset = headerCharset || "utf-8";
    try {
      const { bytes, t } = await readBytes(r, MAX_BYTES);
      truncated = t;
      usedCharset = pickCharset(bytes, headerCharset);
      text = new TextDecoder(usedCharset || "utf-8").decode(bytes);
    } catch (e) {
      return json({ error: "Read failed", detail: String(e?.message || e) }, 502, cors);
    }

    const finalUrl = r.url || parsed.href;
    let html = text;
    if (strip || mode === "light") html = stripHtml(text);

    const payload = {
      url: parsed.href,
      finalUrl,
      status: r.status,
      contentType,
      charset: headerCharset || "",
      charsetUsed: usedCharset || "utf-8",
      length: html.length,
      truncated,
      html
    };
    if (mode === "light") payload.htmlStripped = html;
    if (wantText) payload.text = stripToText(text);

    // Risposta cacheable
    const baseHeaders = {
      "Cache-Control": "public, max-age=0, must-revalidate",
      "Content-Type": "application/json; charset=UTF-8",
      "X-QPWON": "2.6",
      "X-Cache": "MISS",
      "X-Truncated": String(truncated),
      "Vary": "Origin",
      "Access-Control-Expose-Headers": "X-QPWON,X-Cache,X-Truncated"
    };
    const cacheable = new Response(JSON.stringify(payload), { status: 200, headers: baseHeaders });

    if (!bypassCache) ctx.waitUntil(cache.put(cacheKey, cacheable.clone()));

    // CORS finale
    return attachCors(cacheable, cors);
  }
};

/* ================== Utils ================== */

function json(obj, status = 200, headers = {}) {
  const h = new Headers({
    "content-type": "application/json; charset=UTF-8",
    "Cache-Control": "public, max-age=0, must-revalidate",
    "Vary": "Origin",
    "Access-Control-Expose-Headers": "X-QPWON,X-Cache,X-Truncated",
    ...headers
  });
  return new Response(JSON.stringify(obj), { status, headers: h });
}

function parseAllowedOrigins(csv) {
  if (!csv) return null;
  const set = new Set();
  String(csv).split(",").map(s => s.trim()).filter(Boolean).forEach(v => set.add(v));
  return set.size ? set : null;
}

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
    "Vary": "Origin"
  };
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

  // nomi locali
  if (h === "localhost" || h === "localhost.localdomain" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".lan")) return true;

  // IPv4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const [a,b] = h.split(".").map(n => parseInt(n,10));
    if ([10,127,0].includes(a)) return true;
    if (a===169 && b===254) return true;
    if (a===192 && b===168) return true;
    if (a===172 && b>=16 && b<=31) return true;
  }
  // IPv6 comuni
  if (h === "::1" || h === "0:0:0:0:0:0:0:1") return true;
  if (h.startsWith("fe80:")) return true; // link-local
  if (h.startsWith("fc") || h.startsWith("fd")) return true; // unique local

  return false;
}

function clampInt(n, min, max) {
  const v = Number.isFinite(n) ? (n|0) : NaN;
  if (!Number.isFinite(v)) return min;
  return Math.min(max, Math.max(min, v));
}

// Legge stream come bytes fino a maxBytes
async function readBytes(response, maxBytes) {
  const reader = response.body?.getReader ? response.body.getReader() : null;
  if (!reader) {
    const ab = await response.arrayBuffer();
    const bytes = new Uint8Array(ab.slice(0, maxBytes));
    return { bytes, t: ab.byteLength > maxBytes };
  }
  const chunks = []; let received = 0; let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      const allowed = Math.max(0, maxBytes - (received - value.byteLength));
      if (allowed > 0) chunks.push(value.subarray(0, allowed));
      truncated = true;
      break;
    }
    chunks.push(value);
  }
  const size = chunks.reduce((s,c) => s + c.byteLength, 0);
  const bytes = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) { bytes.set(c, off); off += c.byteLength; }
  return { bytes, t: truncated };
}

function extractCharset(contentType) {
  if (!contentType) return "";
  const m = contentType.match(/charset=([A-Za-z0-9._-]+)/i);
  return m ? m[1].toLowerCase() : "";
}

function sniffMetaCharset(utf8Snippet) {
  try {
    const m = utf8Snippet.match(/<meta[^>]+charset=["']?([\w-]+)["']?/i) ||
              utf8Snippet.match(/content=["'][^"']*charset=([\w-]+)[^"']*["']/i);
    return m ? (m[1]||"").toLowerCase() : "";
  } catch { return ""; }
}

function pickCharset(bytes, headerCharset) {
  // 1) header vince
  if (headerCharset) return headerCharset.toLowerCase();
  // 2) sniff su primi byte come UTF-8 (ASCII-safe)
  const dec = new TextDecoder("utf-8", { fatal: false });
  const snip = dec.decode(bytes.slice(0, Math.min(4096, bytes.length)));
  const meta = sniffMetaCharset(snip);
  if (meta) return meta;
  // 3) default
  return "utf-8";
}

function stripHtml(html) {
  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi,'')
    .replace(/<style[\s\S]*?<\/style>/gi,'')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi,'')
    .replace(/<svg[\s\S]*?<\/svg>/gi,'')
    // blocchi cookie/gdpr/banner nel markup più comuni
    .replace(/<(div|section|footer)[^>]+(?:id|class)=["'][^"']*(cookie|gdpr|consent|banner|policy)[^"']*["'][\s\S]*?<\/\1>/gi,'');
}

function stripToText(html) {
  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi,' ')
    .replace(/<style[\s\S]*?<\/style>/gi,' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi,' ')
    .replace(/<svg[\s\S]*?<\/svg>/gi,' ')
    .replace(/<[^>]+>/g,' ')
    .replace(/\s+/g,' ')
    .trim();
}

function attachCors(resp, extraHeaders) {
  const h = new Headers(resp.headers);
  for (const [k,v] of Object.entries(extraHeaders||{})) h.set(k,v);
  return new Response(resp.body, { status: resp.status, headers: h });
}