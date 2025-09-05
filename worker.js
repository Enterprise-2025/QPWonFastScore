// Cloudflare Worker di riferimento (già lo hai attivo; questo è solo per archivio)
export default {
  async fetch(req) {
    const u = new URL(req.url);
    const target = u.searchParams.get("url");
    if (!target) {
      return new Response("Missing url", { status: 400, headers: { "Access-Control-Allow-Origin": "*" } });
    }
    try {
      const r = await fetch(target, {
        headers: {
          "user-agent": "QPWON-AutoAnalyzer/1.0 (+contact: you@example.com)",
          "accept": "text/html,application/xhtml+xml"
        }
      });
      const html = await r.text();
      return new Response(JSON.stringify({ url: target, html }), {
        headers: {
          "content-type": "application/json; charset=UTF-8",
          "Access-Control-Allow-Origin": "*",
          "Cache-Control": "public, max-age=1800"
        }
      });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message }), {
        status: 500,
        headers: { "content-type": "application/json; charset=UTF-8", "Access-Control-Allow-Origin": "*" }
      });
    }
  }
}
