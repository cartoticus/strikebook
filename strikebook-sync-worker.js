/* Strikebook sync relay — Cloudflare Worker + Workers KV
 *
 * What it does: stores ONE encrypted blob per sync ID and hands it back.
 *   GET  /            -> {"ok":true,"app":"strikebook-sync"}   (connection test)
 *   GET  /v1/<key>    -> the stored blob, or 404 if nothing saved yet
 *   PUT  /v1/<key>    -> saves the blob (JSON body), returns {"ok":true}
 *
 * <key> is a 64-character SHA-256 hash the app computes from the user's sync ID.
 * The app encrypts everything on the phone before sending (AES-GCM, key derived
 * from the sync ID), so this Worker and Cloudflare only ever hold scrambled data.
 * Nothing here can decrypt it, and nothing here knows anyone's name or ID.
 *
 * Setup (Cloudflare dashboard):
 *   1. Storage & Databases -> KV -> Create namespace (e.g. "strikebook-sync").
 *   2. Workers & Pages -> Create -> Worker -> paste this file -> Deploy.
 *   3. Worker -> Settings -> Bindings -> Add -> KV namespace.
 *      Variable name MUST be:  SYNC   -> pick the namespace from step 1.
 *   4. (Optional) Settings -> Variables -> ALLOWED_ORIGINS, comma-separated, if the
 *      app is ever served from somewhere other than the default below.
 */

const DEFAULT_ALLOWED_ORIGINS = ['https://cartoticus.github.io'];
const MAX_BYTES = 5 * 1024 * 1024;        // 5 MB per user — years of sessions fit in well under 1 MB
const KEY_RE = /^\/v1\/([0-9a-f]{64})$/;

export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || '';
    const allowed = env.ALLOWED_ORIGINS
      ? env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
      : DEFAULT_ALLOWED_ORIGINS;
    const originOk = allowed.includes('*') || allowed.includes(origin);
    const cors = {
      'Access-Control-Allow-Origin': originOk ? (allowed.includes('*') ? '*' : origin) : 'null',
      'Access-Control-Allow-Methods': 'GET, PUT, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Max-Age': '86400',
      'Vary': 'Origin'
    };
    const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
      status, headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
    });

    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (!originOk) return json({ error: 'origin not allowed' }, 403);
    if (!env.SYNC) return json({ error: 'KV binding SYNC is missing — see setup step 3' }, 500);

    const path = new URL(req.url).pathname;
    if (req.method === 'GET' && (path === '/' || path === '')) {
      return json({ ok: true, app: 'strikebook-sync' });
    }

    const m = path.match(KEY_RE);
    if (!m) return json({ error: 'not found' }, 404);
    const key = 'u:' + m[1];

    if (req.method === 'GET') {
      const val = await env.SYNC.get(key);
      if (val === null) return json({ error: 'none' }, 404);
      return new Response(val, {
        headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
      });
    }

    if (req.method === 'PUT') {
      const declared = Number(req.headers.get('Content-Length') || 0);
      if (declared > MAX_BYTES) return json({ error: 'too large' }, 413);
      const text = await req.text();
      if (text.length > MAX_BYTES) return json({ error: 'too large' }, 413);
      let body;
      try { body = JSON.parse(text); } catch (e) { return json({ error: 'bad json' }, 400); }
      // Only accept the app's encrypted envelope shape — this Worker isn't general storage.
      if (!body || body.v !== 1 || typeof body.iv !== 'string' || typeof body.ct !== 'string'
          || Object.keys(body).some(k => !['v', 'iv', 'ct', 'at', 'z'].includes(k))) {
        return json({ error: 'bad envelope' }, 400);
      }
      try {
        await env.SYNC.put(key, text);
      } catch (e) {
        // KV allows one write per second to the same key; the app just retries later.
        return json({ error: 'busy, retry' }, 429);
      }
      return json({ ok: true });
    }

    return json({ error: 'method not allowed' }, 405);
  }
};
