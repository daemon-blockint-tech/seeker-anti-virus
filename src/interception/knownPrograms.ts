/** Well-known Solana program ids and their risk-relevant traits. */
export interface KnownProgram {
  name: string;
  /** True for programs whose instructions can move funds or change authority. */
  sensitive: boolean;
}

export const KNOWN_PROGRAMS: Record<string, KnownProgram> = {
  "11111111111111111111111111111111": { name: "System Program", sensitive: true },
  TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA: { name: "SPL Token", sensitive: true },
  TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb: { name: "SPL Token-2022", sensitive: true },
  ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL: {
    name: "Associated Token Account",
    sensitive: false,
  },
  ComputeBudget111111111111111111111111111111: {
    name: "Compute Budget",
    sensitive: false,
  },
  MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr: { name: "Memo", sensitive: false },
};

/** System Program instruction index for a lamport transfer. */
export const SYSTEM_TRANSFER_IX = 2;
/** SPL Token `Approve` instruction index (delegation — drainer primitive). */
export const TOKEN_APPROVE_IX = 4;
/** SPL Token `SetAuthority` instruction index. */
export const TOKEN_SET_AUTHORITY_IX = 6;
