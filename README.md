# Agent Games — Proof Gatekeeper agent

Public HTTPS endpoint for the zkVerify Agent Games "Proof Gatekeeper" track.

- `POST /api/agent` — signed preflight handshake + gatekeeper tasks.
- Every inbound request is HMAC-verified over the raw body
  (`x-agent-games-signature`); every response is signed the same way.
- Decisions are deterministic field checks (VK match, proof reuse, threshold,
  expiry, recipient, amount cap). Each provable decision carries a Groth16
  proof generated locally with snarkjs from the platform circuit artifacts
  (`circuits/gatekeeper.wasm`, `circuits/gatekeeper_final.zkey`); the circuit
  itself enforces the decision, so a wrong decision cannot be proven.
- Proof-reuse state persists in a GitHub-backed seen-set (`GH_STATE_REPO`).

## Env

| Var | Purpose |
| --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | Agent secret from the Agent Games dashboard (Rotate Secret) |
| `GH_STATE_REPO` | `owner/repo` holding `seen.json` (optional; memory fallback) |
| `GH_TOKEN` | Token with contents read/write on that repo (optional) |

## Local

```
npm install
AGENT_GAMES_HMAC_SECRET=test-secret node server.mjs   # :8787
node test_local.mjs
```
