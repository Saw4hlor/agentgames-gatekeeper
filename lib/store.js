// Seen-set for PROOF_REUSED detection. Backed by a JSON file in a GitHub repo
// (env GH_STATE_REPO="owner/repo", GH_TOKEN) so it survives serverless cold
// starts; falls back to memory-only when unconfigured or on any error — a
// store failure must never fail a task.
const mem = new Set();
let loaded = false;
let ghCache = null; // { sha, items: Set }

const repo = process.env.GH_STATE_REPO;
const token = process.env.GH_TOKEN;
const PATH = 'seen.json';

async function ghLoad() {
  if (ghCache) return ghCache;
  try {
    const r = await fetch(`https://api.github.com/repos/${repo}/contents/${PATH}`, {
      headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json' },
    });
    if (r.status === 200) {
      const j = await r.json();
      const items = new Set(JSON.parse(Buffer.from(j.content, 'base64').toString('utf8')));
      ghCache = { sha: j.sha, items };
    } else {
      ghCache = { sha: null, items: new Set() };
    }
  } catch {
    ghCache = { sha: null, items: new Set() };
  }
  return ghCache;
}

export async function seenHas(id) {
  if (!id) return false;
  if (mem.has(id)) return true;
  if (repo && token) {
    const { items } = await ghLoad();
    if (items.has(id)) { mem.add(id); return true; }
  }
  return false;
}

export async function seenAdd(id) {
  if (!id) return;
  mem.add(id);
  if (repo && token) {
    try {
      const state = await ghLoad();
      if (state.items.has(id)) return;
      state.items.add(id);
      const body = {
        message: `seen +1 (${state.items.size})`,
        content: Buffer.from(JSON.stringify([...state.items])).toString('base64'),
      };
      if (state.sha) body.sha = state.sha;
      const r = await fetch(`https://api.github.com/repos/${repo}/contents/${PATH}`, {
        method: 'PUT',
        headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'content-type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (r.ok) {
        const j = await r.json();
        state.sha = j.content?.sha ?? state.sha;
      } else {
        ghCache = null; // force reload next time; memory still holds the id
      }
    } catch { /* memory-only fallback */ }
  }
  loaded = true;
}
