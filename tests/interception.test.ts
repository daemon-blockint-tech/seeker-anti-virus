import { describe, expect, it, vi } from "vitest";
import {
  bytesToBase58,
  decodeMessage,
  decodeTransaction,
  transactionToScanTarget,
  ScreeningPipeline,
  SyncWalletEndpoint,
  IntegratedScanner,
  type SeedVaultSigner,
} from "../src/index.js";

const SYSTEM_PROGRAM = "11111111111111111111111111111111";

function u64le(value: bigint): number[] {
  const out: number[] = [];
  for (let i = 0; i < 8; i++) {
    out.push(Number(value & 0xffn));
    value >>= 8n;
  }
  return out;
}

/** Build a legacy message: one System-transfer instruction of `lamports`. */
function buildTransferMessage(lamports: bigint): Uint8Array {
  const feePayer = new Array(32).fill(1);
  const dest = new Array(32).fill(2);
  const system = new Array(32).fill(0); // all-zeros == System program id
  const blockhash = new Array(32).fill(9);
  const data = [2, 0, 0, 0, ...u64le(lamports)]; // ix index 2 (transfer) + u64 lamports

  return Uint8Array.from([
    1, 0, 1, // header
    3, // account count
    ...feePayer,
    ...dest,
    ...system,
    ...blockhash,
    1, // instruction count
    2, // programIdIndex -> system
    2, // account count
    0, 1, // account indexes
    data.length,
    ...data,
  ]);
}

/** Wrap a message in a transaction (1 empty signature) for decodeTransaction. */
function asTransaction(message: Uint8Array): Uint8Array {
  return Uint8Array.from([1, ...new Array(64).fill(0), ...message]);
}

describe("wire / base58", () => {
  it("encodes 32 zero bytes as the System program id", () => {
    expect(bytesToBase58(new Uint8Array(32))).toBe(SYSTEM_PROGRAM);
  });
  it("encodes a known vector", () => {
    expect(bytesToBase58(Uint8Array.from([0, 0, 0, 1]))).toBe("1112");
  });
});

describe("txDecoder", () => {
  it("decodes a System transfer instruction", () => {
    const decoded = decodeMessage(buildTransferMessage(9_000_000_000n));
    expect(decoded.version).toBe("legacy");
    expect(decoded.accountKeys).toHaveLength(3);
    expect(decoded.instructions).toHaveLength(1);
    const ix = decoded.instructions[0]!;
    expect(ix.programId).toBe(SYSTEM_PROGRAM);
    expect(ix.programName).toBe("System Program");
  });

  it("decodeTransaction strips the signature vector", () => {
    const decoded = decodeTransaction(asTransaction(buildTransferMessage(1_000n)));
    expect(decoded.instructions[0]!.programName).toBe("System Program");
  });

  it("maps a large transfer to a crypto_transaction event", () => {
    const decoded = decodeMessage(buildTransferMessage(9_000_000_000n));
    const target = transactionToScanTarget(decoded);
    expect(target.kind).toBe("transaction");
    const ev = target.events!.find((e) => e.type === "crypto_transaction");
    expect(ev?.amountLamports).toBe(9_000_000_000);
  });
});

/** A scanner with a custom YARA rule matching the decoded transfer summary. */
function scannerFlagging(severity: "high" | "critical"): IntegratedScanner {
  return new IntegratedScanner({
    yaraRules: [
      {
        name: "Test_Tx_Flag",
        category: "drainer",
        severity,
        meta: { description: "test rule matching the decoded transfer summary" },
        strings: [{ id: "$t", value: "transfer", type: "text" }],
        condition: "any",
      },
    ],
  });
}

describe("ScreeningPipeline", () => {
  it("warns on a lone large transfer (behavioral anomaly)", async () => {
    const pipeline = new ScreeningPipeline();
    const result = await pipeline.screen(asTransaction(buildTransferMessage(9_000_000_000n)));
    expect(result.decoded.instructions).toHaveLength(1);
    expect(result.report.findings.some((f) => f.ruleId === "BEH_ANOMALOUS_TRANSFER")).toBe(true);
    expect(result.severity).toBe("high");
    expect(result.decision).toBe("warn");
  });

  it("blocks a critical-severity transaction", async () => {
    const pipeline = new ScreeningPipeline({ scanner: scannerFlagging("critical") });
    const result = await pipeline.screen(asTransaction(buildTransferMessage(9_000_000_000n)));
    expect(result.severity).toBe("critical");
    expect(result.decision).toBe("block");
  });

  it("warns on a high-severity transaction", async () => {
    const pipeline = new ScreeningPipeline({ scanner: scannerFlagging("high") });
    const result = await pipeline.screen(asTransaction(buildTransferMessage(1_000n)));
    expect(result.decision).toBe("warn");
  });

  it("allows a tiny transfer", async () => {
    const pipeline = new ScreeningPipeline();
    const result = await pipeline.screen(asTransaction(buildTransferMessage(1_000n)));
    expect(result.decision).toBe("allow");
    expect(result.severity).toBe("low");
  });
});

describe("SyncWalletEndpoint", () => {
  const makeVault = (): SeedVaultSigner => ({
    publicKey: () => "VaultPubKey11111111111111111111111111111111",
    signTransactions: vi.fn(async (txs: Uint8Array[]) =>
      txs.map((t) => Uint8Array.from([0xff, ...t])),
    ),
  });

  it("authorizes by delegating to Seed Vault (never custodies keys)", async () => {
    const endpoint = new SyncWalletEndpoint(makeVault());
    const auth = await endpoint.authorize({ identityName: "dApp" });
    expect(auth.publicKey).toBe("VaultPubKey11111111111111111111111111111111");
  });

  it("signs an approved (low-risk) transaction via Seed Vault", async () => {
    const vault = makeVault();
    const endpoint = new SyncWalletEndpoint(vault);
    const res = await endpoint.signTransactions([asTransaction(buildTransferMessage(1_000n))]);
    expect(res.allSigned).toBe(true);
    expect(res.outcomes[0]!.signed).toBeDefined();
    expect(vault.signTransactions).toHaveBeenCalledOnce();
  });

  it("blocks a critical transaction and never calls Seed Vault", async () => {
    const vault = makeVault();
    const endpoint = new SyncWalletEndpoint(vault, {
      pipeline: new ScreeningPipeline({ scanner: scannerFlagging("critical") }),
    });
    const res = await endpoint.signTransactions([asTransaction(buildTransferMessage(9_000_000_000n))]);
    expect(res.allSigned).toBe(false);
    expect(res.outcomes[0]!.signed).toBeUndefined();
    expect(res.outcomes[0]!.blockedReason).toMatch(/blocked/);
    expect(vault.signTransactions).not.toHaveBeenCalled();
  });

  it("declines a warn-level transaction unless the user confirms", async () => {
    const decline = new SyncWalletEndpoint(makeVault(), {
      pipeline: new ScreeningPipeline({ scanner: scannerFlagging("high") }),
    });
    const declined = await decline.signTransactions([
      asTransaction(buildTransferMessage(1_000n)),
    ]);
    expect(declined.outcomes[0]!.blockedReason).toBe("declined_by_user");

    const vault = makeVault();
    const confirm = new SyncWalletEndpoint(vault, {
      pipeline: new ScreeningPipeline({ scanner: scannerFlagging("high") }),
      onWarn: () => true,
    });
    const approved = await confirm.signTransactions([
      asTransaction(buildTransferMessage(1_000n)),
    ]);
    expect(approved.outcomes[0]!.signed).toBeDefined();
    expect(vault.signTransactions).toHaveBeenCalledOnce();
  });
});
