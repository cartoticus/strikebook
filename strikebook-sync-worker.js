/* Strikebook sync relay — Cloudflare Worker + Workers KV
 *
 * What it does: stores ONE encrypted blob per sync ID and hands it back.
 *   GET  /                 -> {"ok":true,"app":"strikebook-sync","enroll":"code"|"open"|"closed"}
 *   POST /v1/<key>/enroll  -> registers a NEW sync ID (body {"code":"<admin passcode>"})
 *   GET  /v1/<key>         -> the stored blob, 404 if nothing saved yet, 403 if the ID was never registered
 *   PUT  /v1/<key>         -> saves the blob (JSON body); registered IDs only
 *
 * <key> is a 64-character SHA-256 hash the app computes from the user's sync ID.
 * The app encrypts everything on the phone before sending (AES-GCM, key derived
 * from the sync ID), so this Worker and Cloudflare only ever hold scrambled data.
 * Nothing here can decrypt it, and nothing here knows anyone's name or ID.
 *
 * WHO CAN SET UP SYNC (enrollment):
 *   A sync ID only works after it's registered here once. Registering needs the admin
 *   passcode, which lives ONLY in this Worker as a secret — never in the app or the repo.
 *   Joining a second device with an already-registered ID needs no passcode (the ID is the key).
 *     - ADMIN_CODE secret set            -> "code":   new IDs need the passcode   (default)
 *     - OPEN_ENROLLMENT variable = true  -> "open":   anyone can set up a new ID  (gate removed)
 *     - neither                          -> "closed": no new IDs at all; existing ones keep working
 *
 * Setup (Cloudflare dashboard):
 *   1. Storage & Databases -> KV -> Create namespace (e.g. "strikebook-sync").
 *   2. Workers & Pages -> Create -> Worker -> paste this file -> Deploy.
 *   3. Worker -> Settings -> Bindings -> Add -> KV namespace.
 *      Variable name MUST be:  SYNC   -> pick the namespace from step 1.
 *   4. Worker -> Settings -> Variables and Secrets -> Add -> type "Secret",
 *      name ADMIN_CODE, value = your passcode (use 12+ characters). Deploy.
 *   5. (Optional) ALLOWED_ORIGINS, comma-separated, if the app is ever served from
 *      somewhere other than the default below.
 *   Later, to let anyone set up sync: add a plain variable OPEN_ENROLLMENT = true
 *   (you can leave ADMIN_CODE in place). Remove it to put the gate back.
 */

const DEFAULT_ALLOWED_ORIGINS = ['https://cartoticus.github.io'];
const MAX_BYTES = 5 * 1024 * 1024;        // 5 MB per user — years of sessions fit in well under 1 MB
const KEY_RE = /^\/v1\/([0-9a-f]{64})(\/enroll)?$/;

function enrollMode(env) {
  if (String(env.OPEN_ENROLLMENT || '').toLowerCase() === 'true') return 'open';
  return env.ADMIN_CODE ? 'code' : 'closed';
}
// Compare without leaking how many leading characters matched.
async function sameSecret(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(String(a))),
    crypto.subtle.digest('SHA-256', enc.encode(String(b)))
  ]);
  const x = new Uint8Array(ha), y = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}
const sleep = ms => new Promise(r => setTimeout(r, ms));

export default {
  async fetch(req, env) {
    const origin = req.headers.get('Origin') || '';
    const allowed = env.ALLOWED_ORIGINS
      ? env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
      : DEFAULT_ALLOWED_ORIGINS;
    const originOk = allowed.includes('*') || allowed.includes(origin);
    const cors = {
      'Access-Control-Allow-Origin': originOk ? (allowed.includes('*') ? '*' : origin) : 'null',
      'Access-Control-Allow-Methods': 'GET, PUT, POST, OPTIONS',
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
      return json({ ok: true, app: 'strikebook-sync', enroll: enrollMode(env) });
    }

    const m = path.match(KEY_RE);
    if (!m) return json({ error: 'not found' }, 404);
    const dataKey = 'u:' + m[1], markKey = 'e:' + m[1];
    const isEnrolled = async () => (await env.SYNC.get(markKey)) !== null || (await env.SYNC.get(dataKey)) !== null;

    // ---- register a new sync ID ----
    if (m[2]) {
      if (req.method !== 'POST') return json({ error: 'method not allowed' }, 405);
      if (await isEnrolled()) return json({ ok: true, already: true });
      const mode = enrollMode(env);
      if (mode === 'closed') return json({ error: 'enrollment closed' }, 403);
      if (mode === 'code') {
        let body = {};
        try { body = JSON.parse(await req.text()); } catch (e) {}
        if (!body || typeof body.code !== 'string' || !(await sameSecret(body.code, env.ADMIN_CODE))) {
          await sleep(1500);   // slows guessing; nothing is written on a failed attempt
          return json({ error: 'bad code' }, 401);
        }
      }
      await env.SYNC.put(markKey, new Date().toISOString());
      return json({ ok: true });
    }

    if (req.method === 'GET') {
      const val = await env.SYNC.get(dataKey);
      if (val !== null) {
        return new Response(val, {
          headers: { ...cors, 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }
        });
      }
      if ((await env.SYNC.get(markKey)) === null) return json({ error: 'not enrolled' }, 403);
      return json({ error: 'none' }, 404);
    }

    if (req.method === 'PUT') {
      if (!(await isEnrolled())) return json({ error: 'not enrolled' }, 403);
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
        await env.SYNC.put(dataKey, text);
      } catch (e) {
        // KV allows one write per second to the same key; the app just retries later.
        return json({ error: 'busy, retry' }, 429);
      }
      return json({ ok: true });
    }

    return json({ error: 'method not allowed' }, 405);
  }
};
