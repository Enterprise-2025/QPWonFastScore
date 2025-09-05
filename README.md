# QPWON · Scoring Sprint (Auto‑Analyzer + Proxy‑ready)

**Obiettivo:** inserisci il link e l’analisi parte senza blocchi CORS.
**Come:** usa un proxy tuo (Cloudflare Worker incluso).

## Setup rapido
1. Crea un Worker su Cloudflare e incolla `worker.js`. Pubblica.
2. Copia l’endpoint (es. `https://TUO-WORKER.workers.dev/?url=`).
3. Apri `index.html` → **Impostazioni** → incolla l’endpoint → (opzionale) attiva **Forza uso proxy**.

## Alternative
- Bookmarklet integrato (nessun server): trascina “Analizza questa pagina”, cliccalo sul sito, incolla il testo nel tool → **Analizza testo**.

Made for Alfonso · QPWON Suite.
