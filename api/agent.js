// Agent Games endpoint — register this full path (e.g. https://<host>/api/agent)
// as the agent endpoint. Handles the signed preflight handshake and
// Proof Gatekeeper tasks. Every response is HMAC-signed.
import { signBody, verifyBody } from '../lib/hmac.js';
import { handleGatekeeperTask } from '../lib/gatekeeper.js';

export const config = { api: { bodyParser: false } };

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';

function readRaw(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function sendSigned(res, obj, status = 200) {
  const body = JSON.stringify(obj);
  res.statusCode = status;
  res.setHeader('content-type', 'application/json');
  if (SECRET) res.setHeader('x-agent-games-signature', signBody(SECRET, body));
  res.end(body);
}

export default async function handler(req, res) {
  if (req.method === 'GET') {
    return sendSigned(res, { ok: true, protocolVersion: 'v1', agent: 'proof-gatekeeper' });
  }
  if (req.method !== 'POST') {
    return sendSigned(res, { ok: false, error: 'method not allowed' }, 405);
  }

  const raw = await readRaw(req);
  const sig = req.headers['x-agent-games-signature'];
  if (!verifyBody(SECRET, raw, sig)) {
    return sendSigned(res, { ok: false, error: 'bad signature' }, 401);
  }

  let envelope;
  try { envelope = JSON.parse(raw); } catch {
    return sendSigned(res, { ok: false, error: 'bad json' }, 400);
  }

  try {
    if (envelope.type === 'agent-games.preflight.v1') {
      return sendSigned(res, { ok: true, protocolVersion: 'v1' });
    }
    if (envelope.type === 'agent-games.proof-gatekeeper.v1') {
      const out = await handleGatekeeperTask(envelope);
      return sendSigned(res, out);
    }
    // Unknown envelope: fail closed but stay responsive.
    return sendSigned(res, { ok: false, error: 'unknown envelope type' }, 400);
  } catch (e) {
    // Fail closed: a REJECT without proof costs the same as a timeout (-2)
    // and never risks a wrong APPROVE (-6). Reason code is a best effort.
    console.error('handler error:', e);
    try {
      return sendSigned(res, { decision: 'REJECT', reason_code: 'INTERNAL_ERROR', proof_tx: envelope?.input?.proof_tx });
    } catch {
      return sendSigned(res, { ok: false, error: 'internal' }, 500);
    }
  }
}
