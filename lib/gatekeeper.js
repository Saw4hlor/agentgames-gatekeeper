import * as snarkjs from 'snarkjs';
import { createHash, randomBytes } from 'crypto';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { seenHas, seenAdd } from './store.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const WASM = join(HERE, '..', 'circuits', 'gatekeeper.wasm');
const ZKEY = join(HERE, '..', 'circuits', 'gatekeeper_final.zkey');
const BN254_P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ---- Decision logic: deterministic field checks, one reason_code per trap ----
// Order mirrors the trap encyclopedia. Tasks carry exactly one trap (or none).
export async function decide(input) {
  const vkOk = String(input.proof_vk).toLowerCase() === String(input.registered_vk).toLowerCase();
  if (!vkOk) return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', provable: true };

  if (await seenHas(input.proof_tx)) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', provable: false };
  }
  if (BigInt(input.public_balance) < BigInt(input.minimum)) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', provable: true };
  }
  if (BigInt(input.current_block) > BigInt(input.expiry_block)) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', provable: true };
  }
  if (String(input.recipient).toLowerCase() !== String(input.condition_recipient).toLowerCase()) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', provable: true };
  }
  if (BigInt(input.amount) > BigInt(input.max_transfer)) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', provable: true };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', provable: true };
}

// ---- Circuit input mapping (13 signals, names probed from the wasm) ----
// PRACTICE-TUNABLE: taskId conversion for string ids like "gk_24_9d1" and the
// salt source are the two spots practice mode must confirm. If the envelope
// carries numeric forms (input.task_id_num / input.salt), those win.
export function taskIdToField(taskId, input) {
  if (input && input.task_id_num != null) return BigInt(input.task_id_num);
  const s = String(taskId);
  if (/^\d+$/.test(s)) return BigInt(s);
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  const h = createHash('sha256').update(s).digest('hex');
  return BigInt('0x' + h) % BN254_P;
}

export function pickSalt(envelope, input) {
  if (input && input.salt != null) return BigInt(input.salt);
  if (envelope && envelope.salt != null) return BigInt(envelope.salt);
  return BigInt('0x' + randomBytes(8).toString('hex'));
}

export function buildCircuitInput(envelope, decision01) {
  const input = envelope.input || {};
  return {
    taskId: taskIdToField(envelope.task_id, input),
    registeredVkHash: BigInt(input.registered_vk),
    proofVkHash: BigInt(input.proof_vk),
    minimum: BigInt(input.minimum),
    publicBalance: BigInt(input.public_balance),
    expiryBlock: BigInt(input.expiry_block),
    currentBlock: BigInt(input.current_block),
    recipient: BigInt(input.recipient),
    conditionRecipient: BigInt(input.condition_recipient),
    amount: BigInt(input.amount),
    maxTransfer: BigInt(input.max_transfer),
    decision: decision01,
    salt: pickSalt(envelope, input),
  };
}

export async function prove(circuitInput) {
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(circuitInput, WASM, ZKEY);
  return { proof, publicSignals };
}

// Full task pipeline. Returns the response object (unsigned; caller signs).
export async function handleGatekeeperTask(envelope) {
  const input = envelope.input || {};
  const verdict = await decide(input);
  const out = { decision: verdict.decision, reason_code: verdict.reason_code, proof_tx: input.proof_tx };
  if (verdict.provable) {
    const circuitInput = buildCircuitInput(envelope, verdict.decision === 'APPROVE' ? 1 : 0);
    const { proof, publicSignals } = await prove(circuitInput);
    out.proof = proof;
    out.public_signals = publicSignals;
  }
  await seenAdd(input.proof_tx);
  return out;
}
