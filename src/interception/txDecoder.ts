import type { BehaviorEvent, ScanTarget } from "../types.js";
import {
  KNOWN_PROGRAMS,
  SYSTEM_TRANSFER_IX,
  TOKEN_APPROVE_IX,
  TOKEN_SET_AUTHORITY_IX,
} from "./knownPrograms.js";
import { ByteReader, bytesToBase58, readU32LE, readU64LE } from "./wire.js";

export interface DecodedInstruction {
  programId: string;
  programName?: string;
  accounts: string[];
  dataHex: string;
  dataLength: number;
}

export interface DecodedTransaction {
  version: "legacy" | number;
  feePayer: string;
  accountKeys: string[];
  instructions: DecodedInstruction[];
}

const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const TOKEN_PROGRAMS = new Set([
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
]);

function toHex(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += bytes[i]!.toString(16).padStart(2, "0");
  return s;
}

/**
 * Decode a Solana **transaction message** (legacy or v0) into a normalized
 * {@link DecodedTransaction}. Address-table lookups in v0 messages are noted
 * but not resolved (they require an RPC round-trip).
 */
export function decodeMessage(message: Uint8Array): DecodedTransaction {
  const r = new ByteReader(message);

  let version: "legacy" | number = "legacy";
  let first = r.u8();
  if ((first & 0x80) !== 0) {
    version = first & 0x7f;
    first = r.u8(); // numRequiredSignatures of the versioned message
  }
  // first === numRequiredSignatures; skip the two readonly-count header bytes.
  r.u8();
  r.u8();

  const accountCount = r.compactU16();
  const accountKeys: string[] = [];
  for (let i = 0; i < accountCount; i++) {
    accountKeys.push(bytesToBase58(r.take(32)));
  }

  r.take(32); // recent blockhash

  const ixCount = r.compactU16();
  const instructions: DecodedInstruction[] = [];
  for (let i = 0; i < ixCount; i++) {
    const programIdIndex = r.u8();
    const acctCount = r.compactU16();
    const acctIndexes: number[] = [];
    for (let j = 0; j < acctCount; j++) acctIndexes.push(r.u8());
    const dataLen = r.compactU16();
    const data = r.take(dataLen);

    const programId = accountKeys[programIdIndex] ?? `#${programIdIndex}`;
    instructions.push({
      programId,
      programName: KNOWN_PROGRAMS[programId]?.name,
      accounts: acctIndexes.map((idx) => accountKeys[idx] ?? `#${idx}`),
      dataHex: toHex(data),
      dataLength: data.length,
    });
  }

  return {
    version,
    feePayer: accountKeys[0] ?? "unknown",
    accountKeys,
    instructions,
  };
}

/**
 * Decode a full serialized transaction (signature vector + message). Falls back
 * to treating the input as a bare message if no signature vector is present.
 */
export function decodeTransaction(tx: Uint8Array): DecodedTransaction {
  const r = new ByteReader(tx);
  const sigCount = r.compactU16();
  // A signature vector is 64 bytes each; if it doesn't fit, this is a bare message.
  if (sigCount > 0 && r.remaining >= sigCount * 64) {
    r.take(sigCount * 64);
    return decodeMessage(tx.subarray(tx.length - r.remaining));
  }
  return decodeMessage(tx);
}

/**
 * Turn a decoded transaction into a {@link ScanTarget} the engine can screen:
 * a text summary (for signature/YARA matching), program-id indicators, and
 * crypto-transaction {@link BehaviorEvent}s (for the behavioral scanner).
 */
export function transactionToScanTarget(tx: DecodedTransaction, id?: string): ScanTarget {
  const events: BehaviorEvent[] = [];
  const summaryLines: string[] = [`feePayer ${tx.feePayer}`, `version ${tx.version}`];

  for (const ix of tx.instructions) {
    const label = ix.programName ?? ix.programId;
    summaryLines.push(`program ${label} data=${ix.dataHex.slice(0, 32)}`);

    // System transfer: instruction index (u32 LE) === 2, then u64 LE lamports.
    if (ix.programId === SYSTEM_PROGRAM && ix.dataLength >= 12) {
      const data = hexToBytes(ix.dataHex);
      if (readU32LE(data) === SYSTEM_TRANSFER_IX) {
        const lamports = readU64LE(data.subarray(4, 12));
        const dest = ix.accounts[1] ?? "unknown";
        summaryLines.push(`transfer ${lamports} lamports -> ${dest}`);
        events.push({
          type: "crypto_transaction",
          timestamp: Date.now(),
          amountLamports: Number(lamports),
          targetAddress: dest,
          programId: ix.programId,
        });
      }
    }

    // SPL Token delegation / authority change — classic drainer primitives.
    if (TOKEN_PROGRAMS.has(ix.programId) && ix.dataLength >= 1) {
      const op = hexToBytes(ix.dataHex)[0];
      if (op === TOKEN_APPROVE_IX) summaryLines.push("token approve (delegation)");
      if (op === TOKEN_SET_AUTHORITY_IX) summaryLines.push("token set_authority");
      events.push({
        type: "crypto_transaction",
        timestamp: Date.now(),
        programId: ix.programId,
      });
    }
  }

  return {
    id: id ?? tx.feePayer,
    kind: "transaction",
    label: `tx by ${tx.feePayer.slice(0, 8)}…`,
    text: summaryLines.join("\n"),
    events,
  };
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
