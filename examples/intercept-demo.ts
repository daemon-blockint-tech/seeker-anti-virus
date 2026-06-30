/**
 * Demo: screen an intercepted MWA signing request through Sync before it
 * reaches Seed Vault (PRD §5.5 Strategy A). Usage: npm run demo:intercept
 */
import {
  SyncWalletEndpoint,
  ScreeningPipeline,
  IntegratedScanner,
  type SeedVaultSigner,
} from "../src/index.js";

// Seed Vault stand-in: Sync delegates signing here and never holds keys.
const seedVault: SeedVaultSigner = {
  publicKey: () => "VaultPubKey11111111111111111111111111111111",
  signTransactions: async (txs) => txs.map((t) => Uint8Array.from([0xff, ...t])),
};

function u64le(v: bigint): number[] {
  const out: number[] = [];
  for (let i = 0; i < 8; i++) { out.push(Number(v & 0xffn)); v >>= 8n; }
  return out;
}
// A System transfer of `lamports`, wrapped as a serialized transaction.
function transfer(lamports: bigint): Uint8Array {
  const data = [2, 0, 0, 0, ...u64le(lamports)];
  const msg = [
    1, 0, 1, 3,
    ...new Array(32).fill(1), ...new Array(32).fill(2), ...new Array(32).fill(0),
    ...new Array(32).fill(9),
    1, 2, 2, 0, 1, data.length, ...data,
  ];
  return Uint8Array.from([1, ...new Array(64).fill(0), ...msg]);
}

const endpoint = new SyncWalletEndpoint(seedVault, {
  // Block critical, warn (and here auto-decline) on high.
  pipeline: new ScreeningPipeline({ scanner: new IntegratedScanner() }),
  onWarn: (r) => { console.log(`  ⚠ user prompted for ${r.severity} risk`); return false; },
});

const auth = await endpoint.authorize({ identityName: "Demo dApp" });
console.log(`Authorized as ${auth.publicKey}\n`);

for (const [label, lamports] of [["1 SOL", 1_000_000_000n], ["50 SOL", 50_000_000_000n]] as const) {
  const res = await endpoint.signTransactions([transfer(lamports)]);
  const o = res.outcomes[0]!;
  console.log(`Transfer ${label}: ${o.signed ? "SIGNED ✅" : "NOT SIGNED ⛔"} ` +
    `(severity=${o.screening.severity}, decision=${o.screening.decision})`);
}
