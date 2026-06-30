/**
 * Minimal, dependency-free helpers for reading the Solana transaction wire
 * format. Just enough to decode a signing request for screening — not a full
 * web3.js replacement.
 */

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Encode bytes as a base58 string (Bitcoin/Solana alphabet). */
export function bytesToBase58(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  // Leading zero bytes map to leading '1's and are excluded from the conversion.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = "1".repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]!];
  return out;
}

/** Sequential byte reader with Solana shortvec (compact-u16) support. */
export class ByteReader {
  private offset = 0;
  constructor(private readonly bytes: Uint8Array) {}

  get remaining(): number {
    return this.bytes.length - this.offset;
  }

  u8(): number {
    if (this.offset >= this.bytes.length) throw new Error("unexpected end of buffer");
    return this.bytes[this.offset++]!;
  }

  take(n: number): Uint8Array {
    if (this.offset + n > this.bytes.length) throw new Error("unexpected end of buffer");
    const slice = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return slice;
  }

  /** Decode a shortvec-encoded length (compact-u16). */
  compactU16(): number {
    let value = 0;
    let shift = 0;
    for (;;) {
      const byte = this.u8();
      value |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7;
      if (shift > 21) throw new Error("invalid compact-u16");
    }
    return value >>> 0;
  }
}

/** Read a little-endian u64 from 8 bytes as a bigint. */
export function readU64LE(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = 7; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]!);
  return value;
}

/** Read a little-endian u32 from the first 4 bytes. */
export function readU32LE(bytes: Uint8Array): number {
  return (
    (bytes[0]! | (bytes[1]! << 8) | (bytes[2]! << 16) | (bytes[3]! << 24)) >>> 0
  );
}
