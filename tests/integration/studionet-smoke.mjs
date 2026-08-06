import { createAccount, createClient } from "../../frontend/node_modules/genlayer-js/dist/index.js";
import { studionet } from "../../frontend/node_modules/genlayer-js/dist/chains/index.js";
import { CalldataAddress, ExecutionResult, TransactionStatus } from "../../frontend/node_modules/genlayer-js/dist/types/index.js";

const TRAP = process.env.OFFRAMP_CONTRACT_ADDRESS || "0xBAe8B1cb793a72c80Adf33f8e90A36375aADE336";
const VERIFIER = process.env.OFFRAMP_VERIFIER_ADDRESS || "0x9AC26029d94b26F650ec6b63A38951860F0E6317";
const pk = process.env.OFFRAMP_PRIVATE_KEY;
const GEN = 10n ** 18n;

if (!pk) throw new Error("Set OFFRAMP_PRIVATE_KEY before running this smoke test.");

const authority = createAccount(pk.startsWith("0x") ? pk : `0x${pk}`);
const reporter = createAccount();
const attacker = createAccount();
const reader = createAccount();

const authorityClient = createClient({ chain: studionet, account: authority });
const reporterClient = createClient({ chain: studionet, account: reporter });
const attackerClient = createClient({ chain: studionet, account: attacker });
const readClient = createClient({ chain: studionet, account: reader });
const txs = [];

const toAddress = (hex) => new CalldataAddress(Uint8Array.from(Buffer.from(hex.slice(2), "hex")));
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const proofBytes = Uint8Array.from(Buffer.from("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "hex"));

const targetUrl = `https://offramp-smoke.example/account/cancel/${Date.now()}`;
const proofId = `offramp-proof-${Date.now()}`;
const html = [
  "<html><body>",
  "<button style='color:#f8f8f8'>cancel subscription</button>",
  "<div>Before cancellation you must call support by phone to complete the cancellation.</div>",
  "<div>Complete a mandatory survey gate before we continue.</div>",
  "<div>Retention offer: click no thanks three times before final cancellation.</div>",
  "<div>Your plan may renew if final confirmation is not processed by support.</div>",
  "</body></html>",
].join("");

function receiptSucceeded(receipt) {
  const leader = receipt?.consensus_data?.leader_receipt;
  if (Array.isArray(leader) && leader.length > 0) {
    const nonIdle = leader.filter((entry) => !(entry.execution_result === "ERROR" && entry?.genvm_result?.error_code === "CONSENSUS_VALIDATOR_QUORUM_REACHED"));
    return nonIdle.length > 0 && nonIdle.every((entry) => entry.execution_result === "SUCCESS");
  }
  if (receipt?.execution_result) return receipt.execution_result === "SUCCESS";
  if (receipt?.txExecutionResultName === ExecutionResult.FINISHED_WITH_ERROR || receipt?.result_name === "ERROR") return false;
  return receipt?.result_name === "MAJORITY_AGREE" || receipt?.result === 6 || Boolean(receipt?.hash);
}

function isTransient(error) {
  const text = `${error?.message || ""} ${error?.details || ""}`.toLowerCase();
  return error?.code === -32006 || error?.code === -32429 || text.includes("server busy") || text.includes("execution slots") || text.includes("429") || text.includes("rate limit") || text.includes("timed out");
}

async function retry(label, fn, attempts = 40) {
  for (let i = 1; i <= attempts; i += 1) {
    try {
      return await fn();
    } catch (error) {
      if (!isTransient(error) || i === attempts) throw error;
      const wait = Math.min(2_000 * i, 15_000);
      console.warn(`${label}: StudioNet busy (${i}/${attempts}); retrying in ${wait}ms`);
      await delay(wait);
    }
  }
  throw new Error(`${label}: retry exhausted`);
}

async function read(address, functionName, args = []) {
  return retry(`${functionName} read`, () => readClient.readContract({ address, functionName, args }));
}

async function write(label, client, address, functionName, args = [], value = 0n, expectSuccess = true) {
  const hash = await retry(`${label} submit`, () => client.writeContract({ address, functionName, args, value }));
  const receipt = await retry(`${label} receipt`, () => client.waitForTransactionReceipt({
    hash,
    status: TransactionStatus.ACCEPTED,
    interval: 5_000,
    retries: 120,
    fullTransaction: false,
  }));
  const ok = receiptSucceeded(receipt);
  txs.push({ label, functionName, hash: String(hash), ok });
  if (expectSuccess && !ok) throw new Error(`${label} failed execution: ${hash}`);
  if (!expectSuccess && ok) throw new Error(`${label} unexpectedly succeeded: ${hash}`);
  console.log(`${label}: ${hash} ${ok ? "SUCCESS" : "EXPECTED_FAIL"}`);
  return hash;
}

console.log(`trap=${TRAP}`);
console.log(`verifier=${VERIFIER}`);
console.log(`authority=${authority.address}`);
console.log(`reporter=${reporter.address}`);
console.log(`attacker=${attacker.address}`);

const verifierOwner = await read(VERIFIER, "get_attestation", ["missing-digest"]);
if (verifierOwner?.exists !== false) throw new Error("verifier empty attestation view mismatch");

await write("fund_pool", authorityClient, TRAP, "fund_pool", [], 2n * GEN);
await write("attacker_submit_without_attestation_blocked", attackerClient, TRAP, "submit_flow", [targetUrl, html, `${proofId}-fake`, proofBytes], GEN, false);
await write("authority_attest_session", authorityClient, VERIFIER, "attest_session", [toAddress(reporter.address), targetUrl, html, proofId, proofBytes]);

await write("reporter_submit_verified_flow", reporterClient, TRAP, "submit_flow", [targetUrl, html, proofId, proofBytes], GEN);
const counts = String(await read(TRAP, "get_counts")).split("||");
const caseId = Number(counts[0]) - 1;
if (caseId < 0) throw new Error("case was not created");

await write("replay_same_proof_blocked", reporterClient, TRAP, "submit_flow", [targetUrl, html, proofId, proofBytes], GEN, false);
let card = await read(TRAP, "get_case_card", [caseId]);
if (card.evidence_verified !== true) throw new Error("case did not record verified evidence");
if (card.proof_id !== proofId) throw new Error("case proof id mismatch");

await write("analyze_semantic_patterns", reporterClient, TRAP, "analyze", [caseId]);
card = await read(TRAP, "get_case_card", [caseId]);
if (!String(card.pattern_signature || "").includes("FORCED_PHONE_CANCEL")) {
  throw new Error(`semantic signature missing expected pattern: ${card.pattern_signature}`);
}
if (Number(card.patterns_listed) < 4) throw new Error(`expected at least 4 patterns, got ${card.patterns_listed}`);

await write("adjudicate_verdict", reporterClient, TRAP, "adjudicate", [caseId]);
card = await read(TRAP, "get_case_card", [caseId]);
if (card.verdict !== "DARK_PATTERN") throw new Error(`expected DARK_PATTERN, got ${card.verdict}`);

const poolBefore = BigInt(await read(TRAP, "get_pool_balance"));
await write("settle_dark_pattern", reporterClient, TRAP, "flag_or_clear", [caseId]);
await write("duplicate_settlement_blocked", reporterClient, TRAP, "flag_or_clear", [caseId], 0n, false);

card = await read(TRAP, "get_case_card", [caseId]);
const poolAfter = BigInt(await read(TRAP, "get_pool_balance"));
if (Number(card.status) !== 3) throw new Error(`expected settled status, got ${card.status}`);
if (BigInt(card.bounty_paid) > GEN / 4n) throw new Error("bounty exceeded 25% bond cap");
if (poolBefore - poolAfter !== BigInt(card.bounty_paid)) throw new Error("pool accounting did not match bounty only");

console.log(JSON.stringify({
  trap: TRAP,
  verifier: VERIFIER,
  authority: authority.address,
  reporter: reporter.address,
  caseId,
  finalCard: card,
  finalPool: poolAfter.toString(),
  txs,
}, (_, value) => typeof value === "bigint" ? value.toString() : value, 2));
console.log("StudioNet smoke PASS");
