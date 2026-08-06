# Offramp

Live: https://Difdaza.github.io/Offramp/

Offramp audits subscription-cancellation flows on GenLayer, but the vulnerable text-only path has been removed. A reporter must now submit authenticated session evidence: HTTPS target URL, authenticated HTML bundle, proof id, and proof bytes. The main contract accepts the report only if the separate `WebSessionVerifier` contract has an active attestation bound to the reporter, target URL, HTML hash, proof id, and proof digest.

## What changed for the review

- `backend/web-session-verifier.py` is active in the repository and deployed. Only its owner can attest a session proof.
- `backend/subscription-trap.py` requires `proof_verifier` in the constructor and calls `verify_web_session(...)` before opening a case.
- Proof replay is blocked by `used_proofs`.
- The GenLayer consensus pass no longer stores only a loose numeric obstacle count. Validators classify canonical semantic pattern names, severity, evidence excerpts, regulatory concern, and a `pattern_signature`.
- Validator agreement requires the derived verdict to match and at least one canonical pattern overlap for non-clean cases.
- Settlement does not double-pay the reporter bond from the fee pool. For `DARK_PATTERN`, the reporter receives their own bond back plus a capped bounty from the pool. The pool is reduced only by the bounty.
- Duplicate settlement is blocked because cases move from `RULED` to `SETTLED`.

## Deployed StudioNet contracts

- Main contract: `0xBAe8B1cb793a72c80Adf33f8e90A36375aADE336`
- Verifier contract: `0x9AC26029d94b26F650ec6b63A38951860F0E6317`
- Main deployment tx: `0xe549bef895f51ff33faed0f41fa3a3ce068fa9adc2f105d6c8d6a5452f104b7c`
- Verifier deployment tx: `0x3da39732c9ce2abd3ff87db2ded4a4980a51225949dc786fda389c824959ab24`

## StudioNet smoke test

Run:

```sh
cd Offramp
set OFFRAMP_PRIVATE_KEY=...
node tests/integration/studionet-smoke.mjs
```

Covered on-chain:

- `fund_pool` success
- attacker `submit_flow` without verifier attestation fails
- authority `attest_session` success
- reporter `submit_flow` with verified proof success
- replay of same proof fails
- `analyze` stores semantic patterns
- `adjudicate` produces `DARK_PATTERN`
- `flag_or_clear` settles once
- duplicate settlement fails

Smoke result: `StudioNet smoke PASS`.

Final smoke case stored:

- `evidence_verified`: `true`
- `pattern_signature`: `FAKE_URGENCY,FORCED_PHONE_CANCEL,RETENTION_GAUNTLET,SURVEY_GATE`
- `verdict`: `DARK_PATTERN`
- `bounty_paid`: `250000000000000000`

## Local verification

```sh
genvm-lint check backend/subscription-trap.py --json
genvm-lint check backend/web-session-verifier.py --json
pytest tests/direct -v
cd frontend
npm install
npm run build
```

Current results:

- GenVM lint main contract: PASS
- GenVM lint verifier: PASS
- Direct security tests: 4/4 PASS
- Frontend production build: PASS

## Frontend

The React dashboard uses RainbowKit/wagmi and passes the connected wallet signer into `genlayer-js`. Contract writes are sent through the connected wallet provider in `frontend/src/contractService.ts`; passing only an address is no longer the write path.

The submit form now asks for:

- authenticated target URL
- authenticated HTML bundle
- proof id
- session proof bytes as hex
- review bond

The case view exposes verifier status, proof id, semantic pattern signature, catalog report, severity, regulatory concern, bounty paid, and settlement state.
