# Offramp

Cancellation-flow audit on [GenLayer](https://genlayer.com). A reporter submits a subscription's unsubscribe journey; LLM-validators count the friction obstacles and rule whether the flow is a dark pattern.

## How it works

1. A reporter **submits a flow** (the service and its unsubscribe journey) and posts a review bond.
2. **Analysis** runs on GenLayer: each validator reads the journey and counts `obstacle_count`, the number of distinct cancellation obstacles, along with a severity and a regulatory concern (for example FTC_ROSCA). Validators agree within one obstacle.
3. **Adjudication** maps the count onto a verdict: `CLEAN`, `GREY`, or `DARK_PATTERN`.
4. **Settlement** refunds the bond and pays pool-funded compensation on a confirmed dark pattern, forfeits the bond on an unfounded report, and returns it on an ambiguous one.

## Architecture

```
backend/subscription-trap.py   GenLayer Intelligent Contract (Python, runs on the GenVM)
frontend/                      React + Vite + TypeScript dashboard (genlayer-js)
```

Analysis is split from judgment, so the non-deterministic count is isolated from the deterministic verdict mapping. The measure is a discrete obstacle count against a fixed rubric, which is reproducible across validator models.

## Live deployment

- **Network**: GenLayer Studionet (chain id 61999)
- **Contract**: `0x0fDA92A6b1B0ad28576C8605A171AD88B435b346`

## Run locally

```bash
cd frontend
npm install
npm run dev
npm run build    # outputs frontend/dist
```

## Deploy the contract

Requires the [GenLayer CLI](https://docs.genlayer.com/) (`npx genlayer`). Set the address in `frontend/src/chain.ts` afterwards.

```bash
npx genlayer deploy --contract backend/subscription-trap.py
```

## Contract methods (`SubscriptionTrap`)

| Method | Type | Description |
|--------|------|-------------|
| `submit_flow` | write, payable | File a flow for review and post the bond |
| `analyze` | write | LLM consensus on `obstacle_count` and severity |
| `adjudicate` | write | Map the count onto CLEAN / GREY / DARK_PATTERN |
| `flag_or_clear` | write | Refund, compensate, or forfeit the bond |
| `get_case` | view | Read a case by id |
| `get_pool_balance` | view | Compensation pool balance |
| `get_counts` | view | `next_id \|\| ruled \|\| dark` |

## License

MIT
