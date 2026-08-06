import { defineChain } from "viem";

export const GENLAYER_CHAIN_ID = 61999;
export const GENLAYER_RPC_URL = "https://studio.genlayer.com/api";
export const GENLAYER_NETWORK = "studionet" as const;

// Offramp secure deployment. Updated after StudioNet deployment.
export const CONTRACT_ADDRESS = "0xBAe8B1cb793a72c80Adf33f8e90A36375aADE336" as const;
export const VERIFIER_ADDRESS = "0x9AC26029d94b26F650ec6b63A38951860F0E6317" as const;

export const genLayerStudionet = defineChain({
  id: GENLAYER_CHAIN_ID,
  name: "GenLayer Studionet",
  nativeCurrency: { name: "GEN", symbol: "GEN", decimals: 18 },
  rpcUrls: {
    default: { http: [GENLAYER_RPC_URL] },
    public: { http: [GENLAYER_RPC_URL] },
  },
  testnet: true,
});
