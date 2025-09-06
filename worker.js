/* QPWON Proxy Worker — v2.2 (timeout, headers, light mode) */
export default {
  async fetch(req, env, ctx) {
    const url = new URL(req.url);
    const origin = req.headers.get("Origin") || "";

    const allowlist = parseAllowedOrigins(env?.ALLOWED_ORIGINS);
    const cors = buildCorsHeaders(origin, allowlist, !!env?.API_TOKEN);

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (url.pathname === "/health") return json({ ok: true, ver: "2.2", time: new Date().toISOString() }, 200, cors);
    if (req.method !== "GET") return json({ error: "Method not allowed" }, 405, cors);

    const requiredToken = (env?.API_TOKEN || "").trim();
    if (requiredToken) {
      const got = extractToken(url, req.headers);
      if (!got || got !== requiredToken) return json({ error: "Unauthorized" }, 401, cors);
    } else if (allowlist) {
      if (origin && !allowlist.has(origin)) return json({ error: "Forbidden origin" }, 403, cors);
    }

    const target = url.searchParams.get("url");
    const mode = (url.searchParams.get("mode") || "").toLowerCase(); // light|full
    if (!target) return json({ error: "Missing url" }, 400, cors);

    let parsed;
    try { parsed = new URL(target); } catch { return json({ error: "Invalid url" }, 400, cors); }
    if (!/^https?:$/.test(parsed.protocol)) return json({ error: "Only http(s) allowed" }, 400, cors);

    const blockPrivate = (env?.BLOCK_PRIVATE ?? "1") !== "0";
    if (blockPrivate && hostLooksPrivate(parsed.hostname)) return json({ error: "Target not allowed" }, 403, cors);

    const ttl = clampInt(parseInt(env?.CACHE_TTL, 10), 60, 86400) || 1800;
    const cacheKey = new Request("https://qpwon-cache/" + encodeURIComponent(parsed.href) + "|" + mode, { method: "GET" });
    const cache = caches.default;
    const cached = await cache.match(cacheKey);
    if (cached) return withCors(cached, { ...cors, "X-QPWON": "2.2", "X-Cache": "HIT" });

    const timeoutMs = 12000;
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort("timeout"), timeoutMs);

    const ua = (env?.USER_AGENT || "QPWON-AutoAnalyzer/2.2").trim();
    const fetchOpts = {
      redirect: "follow",
      signal: controller.signal,
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
    catch (e) {
      clearTimeout(id);
      const timedOut = (String(e?.message || e).toLowerCase().includes("abort") or String(e).lower?.includes("timeout"));
      return json({ error: timedOut ? "Fetch timeout" : "Fetch failed", detail: String(e?.message || e) }, 502, cors);
    }
    clearTimeout(id);

    const MAX_BYTES = clampInt(parseInt(env?.MAX_BYTES, 10), 200_000, 5_000_000) || 1_500_000;
    let html = ""; let truncated = false;
    try {
      html = await readAsText(r, MAX_BYTES);
      truncated = html.length >= MAX_BYTES;
    } catch (e) {
      return json({ error: "Read failed", detail: String(e?.message || e) }, 502, cors);
    }

    const body = {
      url: parsed.href,
      status: r.status,
      contentType: r.headers.get("content-type") || "",
      length: html.length,
      truncated,
      html,
    };
    if (mode === "light") body.htmlStripped = stripHtml(html);

    let resp = json(body, 200, { ...cors, "X-QPWON": "2.2", "X-Cache": "MISS", "X-Truncated": String(truncated) });
    ctx.waitUntil(cache.put(cacheKey, resp.clone()));
    return resp;
  }
};

function json(obj, status = 200, headers = {}) {
  const h = new Headers({ "content-type": "application/json; charset=UTF-8", "Cache-Control": "public, max-age=0, must-revalidate", ...headers });
  return new Response(JSON.stringify(obj), { status, headers: h });
}
function buildCorsHeaders(origin, allowlistSet, tokenEnabled) {
  let allowOrigin = "*";
  if (allowlistSet || tokenEnabled) allowOrigin = (origin && (!allowlistSet || allowlistSet.has(origin))) ? origin : "null";
  return { "Access-Control-Allow-Origin": allowOrigin, "Access-Control-Allow-Methods": "GET, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With", "Access-Control-Max-Age": "86400", "Vary": "Origin" };
}
function parseAllowedOrigins(csv){ if(!csv) return null; const s=new Set(); String(csv).split(",").map(s=>s.trim()).filter(Boolean).forEach(v=>s.add(v)); return s.size?s:null; }
function extractToken(url, headers){ const q=url.searchParams.get("token"); if(q) return q; const auth=headers.get("Authorization")||""; const m=auth.match(/^Bearer\s+(.+)$/i); return m?m[1]:null; }
function hostLooksPrivate(host){ if(!host) return true; const h=host.toLowerCase(); if(h==="localhost"||h==="localhost.localdomain"||h.endsWith(".localhost")||h.endsWith(".local")) return true; if(/^\d+\.\d+\.\d+\.\d+$/.test(h)){ const [a,b]=h.split(".").map(n=>parseInt(n,10)); if(a in {10:1,127:1,0:1}) return true; if(a===169&&b===254) return true; if(a===192&&b===168) return true; if(a===172&&b>=16&&b<=31) return true; } if(h==="::1"||h==="0:0:0:0:0:0:0:1") return true; if(h.startsWith("fe80:")) return true; return false; }
function clampInt(n,min,max){ const v=Number.isFinite(n)?(n|0):min; return Math.min(max,Math.max(min,v)); }
async function readAsText(response, maxBytes){ const reader=response.body?.getReader?response.body.getReader():null; if(!reader){ let t=await response.text(); if(t.length>maxBytes) t=t.slice(0,maxBytes); return t; } const decoder=new TextDecoder(); let html="",received=0; while(true){ const {done,value}=await reader.read(); if(done) break; received+=value.byteLength; if(received>maxBytes){ html+=decoder.decode(value.subarray(0, Math.max(0, maxBytes - (received - value.byteLength))), {stream:true}); break; } html+=decoder.decode(value,{stream:true}); } html+=decoder.decode(); return html; }
function stripHtml(html){ return String(html).replace(/<script[\s\S]*?<\/script>/gi,'').replace(/<style[\s\S]*?<\/style>/gi,'').replace(/<noscript[\s\S]*?<\/noscript>/gi,'').replace(/<svg[\s\S]*?<\/svg>/gi,'').replace(/<(div|section|footer)[^>]+(?:id|class)=["'][^"']*(cookie|gdpr|consent|banner|policy)[^"']*["'][\s\S]*?<\/\1>/gi,''); }
function withCors(resp, extra){ const h=new Headers(resp.headers); for(const [k,v] of Object.entries(extra||{})) h.set(k,v); return new Response(resp.body,{status:resp.status,headers:h}); }
