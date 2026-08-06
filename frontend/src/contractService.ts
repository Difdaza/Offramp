import { createClient, createAccount } from "genlayer-js";
import { studionet } from "genlayer-js/chains";
import { TransactionStatus } from "genlayer-js/types";
import type { WalletClient } from "viem";
import { CONTRACT_ADDRESS, GENLAYER_NETWORK } from "./chain";

type Hex = `0x${string}`;
type WalletProvider = {
  request: (args: { method: string; params?: unknown[] }) => Promise<unknown>;
};
export type ConnectedWallet = WalletClient & {
  account: NonNullable<WalletClient["account"]>;
  transport: WalletClient["transport"] & WalletProvider;
};

const ADDR = CONTRACT_ADDRESS as Hex;
const TIMEOUT_MS = 240_000;

export type Verdict = "CLEAN" | "GREY" | "DARK_PATTERN" | "";

export interface FlowCaseView {
  reporter: string;
  service: string;
  flowText: string;
  bond: string;
  status: number; // 0 FILED, 1 ANALYZED, 2 RULED, 3 SETTLED
  verdict: Verdict;
  obstacleCount: number;
  rationale: string;
  patternSignature: string;
  catalogReport: string;
  maxSeverity: number;
  regulatoryConcern: string;
  patternsListed: number;
  targetUrl: string;
  proofId: string;
  evidenceVerified: boolean;
  bountyPaid: string;
}

export interface FlowRow extends FlowCaseView {
  id: number;
}

let _read: ReturnType<typeof createClient> | null = null;
function readClient() {
  if (!_read) _read = createClient({ chain: studionet, account: createAccount() });
  return _read;
}

function requireConnectedWallet(wallet: WalletClient | undefined): ConnectedWallet {
  if (!wallet?.account?.address) {
    throw new Error("Connect a wallet before sending a transaction.");
  }
  if (typeof wallet.transport?.request !== "function") {
    throw new Error("Connected wallet does not expose an EIP-1193 request signer.");
  }
  return wallet as ConnectedWallet;
}

function writeClient(wallet: WalletClient | undefined) {
  const signer = requireConnectedWallet(wallet);
  return createClient({
    chain: studionet,
    account: signer.account.address as Hex,
    provider: {
      request: (args: { method: string; params?: unknown[] }) => signer.transport.request(args),
    },
  });
}

function pick(obj: any, key: string, idx: number): any {
  if (obj == null) return undefined;
  if (Array.isArray(obj)) return obj[idx];
  if (typeof obj === "object" && key in obj) return obj[key];
  return undefined;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/^0x/i, "");
  if (!clean || clean.length % 2 !== 0 || !/^[0-9a-f]+$/i.test(clean)) {
    throw new Error("Session proof must be valid hex bytes.");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function send(
  wallet: WalletClient | undefined,
  functionName: string,
  args: any[],
  value: bigint = 0n
): Promise<string> {
  const client = writeClient(wallet);
  await client.connect(GENLAYER_NETWORK);
  const hash = (await client.writeContract({ address: ADDR, functionName, args, value })) as Hex;

  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error("Transaction timed out")), TIMEOUT_MS);
  });
  try {
    await Promise.race([
      client.waitForTransactionReceipt({
        hash: hash as never,
        status: TransactionStatus.ACCEPTED,
        interval: 5000,
        retries: 64,
      }),
      timeout,
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
  return String(hash);
}

export async function fundPool(wallet: WalletClient | undefined, amountWei: bigint): Promise<string> {
  return send(wallet, "fund_pool", [], amountWei);
}

export async function submitFlow(
  wallet: WalletClient | undefined,
  f: { targetUrl: string; htmlBundle: string; proofId: string; sessionProofHex: string; bondWei: bigint }
): Promise<number> {
  const proofBytes = hexToBytes(f.sessionProofHex);
  await send(
    wallet,
    "submit_flow",
    [f.targetUrl.trim(), f.htmlBundle.trim(), f.proofId.trim(), proofBytes],
    f.bondWei
  );
  const c = await getCounts();
  return c.next - 1;
}

export async function analyzeFlow(wallet: WalletClient | undefined, caseId: number): Promise<void> {
  await send(wallet, "analyze", [caseId]);
}

export async function adjudicate(wallet: WalletClient | undefined, caseId: number): Promise<void> {
  await send(wallet, "adjudicate", [caseId]);
}

export async function flagOrClear(wallet: WalletClient | undefined, caseId: number): Promise<void> {
  await send(wallet, "flag_or_clear", [caseId]);
}

export async function getCase(caseId: number): Promise<FlowCaseView> {
  const r: any = await readClient().readContract({ address: ADDR, functionName: "get_case_card", args: [caseId] });
  return {
    reporter: String(pick(r, "reporter", 0) ?? ""),
    service: String(pick(r, "service", 1) ?? ""),
    flowText: String(pick(r, "flow_text", 2) ?? ""),
    bond: String(pick(r, "bond", 3) ?? "0"),
    status: Number(pick(r, "status", 4) ?? 0),
    verdict: String(pick(r, "verdict", 5) ?? "") as Verdict,
    obstacleCount: Number(pick(r, "obstacle_count", 6) ?? 0),
    rationale: String(pick(r, "rationale", 7) ?? ""),
    patternSignature: String(pick(r, "pattern_signature", 8) ?? ""),
    catalogReport: String(pick(r, "catalog_report", 9) ?? ""),
    maxSeverity: Number(pick(r, "max_severity", 10) ?? 0),
    regulatoryConcern: String(pick(r, "regulatory_concern", 11) ?? ""),
    patternsListed: Number(pick(r, "patterns_listed", 12) ?? 0),
    targetUrl: String(pick(r, "target_url", 13) ?? ""),
    proofId: String(pick(r, "proof_id", 14) ?? ""),
    evidenceVerified: Boolean(pick(r, "evidence_verified", 15) ?? false),
    bountyPaid: String(pick(r, "bounty_paid", 16) ?? "0"),
  };
}

export async function isProofUsed(proofId: string): Promise<boolean> {
  const r: any = await readClient().readContract({ address: ADDR, functionName: "is_proof_used", args: [proofId.trim()] });
  return Boolean(r);
}

export async function getCounts(): Promise<{ next: number; ruled: number; dark: number }> {
  const r: any = await readClient().readContract({ address: ADDR, functionName: "get_counts", args: [] });
  const parts = String(r).split("||").map((x) => Number(x) || 0);
  return { next: parts[0] || 0, ruled: parts[1] || 0, dark: parts[2] || 0 };
}

export async function getPoolBalance(): Promise<string> {
  const r: any = await readClient().readContract({ address: ADDR, functionName: "get_pool_balance", args: [] });
  return String(r ?? "0");
}

export async function listAll(maxRows = 50): Promise<FlowRow[]> {
  const { next } = await getCounts();
  if (next === 0) return [];
  const ids: number[] = [];
  for (let i = next - 1; i >= 0 && i >= next - maxRows; i -= 1) ids.push(i);
  const rows = await Promise.all(
    ids.map(async (id) => {
      try {
        const c = await getCase(id);
        return { id, ...c };
      } catch {
        return null;
      }
    })
  );
  return rows.filter((r): r is FlowRow => r !== null);
}
