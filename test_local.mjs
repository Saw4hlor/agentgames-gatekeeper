// Local end-to-end test: preflight + valid task + traps + reuse + bad HMAC.
import * as snarkjs from 'snarkjs';
import { createHmac } from 'crypto';
import { readFileSync } from 'fs';

const BASE = 'http://127.0.0.1:8787/api/agent';
const SECRET = 'test-secret';
const vk = JSON.parse(readFileSync(new URL('../app/vk_gatekeeper.json', import.meta.url), 'utf8'));

const sign = (raw) => createHmac('sha256', SECRET).update(raw).digest('hex');

async function post(obj, secret = SECRET) {
  const raw = JSON.stringify(obj);
  const t = Date.now();
  const r = await fetch(BASE, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-agent-games-signature': sign(raw) && createHmac('sha256', secret).update(raw).digest('hex') },
    body: raw,
  });
  const text = await r.text();
  const sigOk = r.headers.get('x-agent-games-signature') === sign(text);
  let json = null;
  try { json = JSON.parse(text); } catch {}
  return { status: r.status, json, sigOk, ms: Date.now() - t };
}

async function proofOk(json) {
  if (!json?.proof || !json?.public_signals) return false;
  return snarkjs.groth16.verify(vk, json.public_signals, json.proof);
}

const VK = '0x' + 'ab'.repeat(32);
const ADDR = '0x' + '11'.repeat(20);
function task(overrides = {}, inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_test_1',
    mode: 'practice',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK, proof_vk: VK, minimum: '1000', public_balance: '1460',
      expiry_block: 8430000, current_block: 8420000, recipient: ADDR, condition_recipient: ADDR,
      amount: '500', max_transfer: '1000', proof_tx: '0x' + 'cd'.repeat(32),
      ...inputOverrides,
    },
    ...overrides,
  };
}

let r = await post({ type: 'agent-games.preflight.v1', agent_id: 'agt_test', issued_at: new Date().toISOString(), nonce: 'abc123' });
console.log('preflight:', r.status, JSON.stringify(r.json), 'sigOk=' + r.sigOk);

r = await post(task());
console.log('valid task:', r.status, r.json?.decision, r.json?.reason_code, 'proofVerify=' + await proofOk(r.json), 'sigOk=' + r.sigOk, r.ms + 'ms');

r = await post(task({}, { proof_tx: '0x' + 'ef'.repeat(32), proof_vk: '0x' + '99'.repeat(32) }));
console.log('vk trap:', r.status, r.json?.decision, r.json?.reason_code, 'proofVerify=' + await proofOk(r.json), r.ms + 'ms');

r = await post(task({}, { public_balance: '10', proof_tx: '0x' + 'aa'.repeat(32) }));
console.log('threshold trap:', r.status, r.json?.decision, r.json?.reason_code, 'proofVerify=' + await proofOk(r.json));

r = await post(task()); // same proof_tx as the first valid task -> reused
console.log('reused task:', r.status, r.json?.decision, r.json?.reason_code, 'hasProof=' + !!r.json?.proof);

r = await post(task(), 'wrong-secret');
console.log('bad hmac:', r.status, JSON.stringify(r.json));
process.exit(0);
