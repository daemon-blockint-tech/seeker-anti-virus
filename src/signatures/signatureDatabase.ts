import type { Severity, ThreatCategory } from "../types.js";

/** A known-threat signature: matched against target text/domain/addresses. */
export interface ThreatSignature {
  id: string;
  name: string;
  category: ThreatCategory;
  severity: Severity;
  /** Regex patterns matched against target text (manifest, source, page). */
  patterns?: RegExp[];
  /** Exact-match indicators (addresses, program ids, hosts). */
  indicators?: string[];
  /** Look-alike domains for phishing detection. */
  domains?: string[];
  description: string;
}

/**
 * Curated database of known Solana-ecosystem threat patterns (PRD 5.2).
 *
 * In production this set is delivered via signed OTA updates (PRD §7,
 * "Updatability"); the bundled defaults below seed the on-device matcher.
 */
export const DEFAULT_SIGNATURES: ThreatSignature[] = [
  {
    id: "SIG_RUG_PULL_MINT_AUTH",
    name: "Rug pull — retained mint authority",
    category: "rug_pull",
    severity: "critical",
    patterns: [
      /mint[_-]?authority\s*[:=].*(?!null)/i,
      /set_authority\s*\(\s*MintTokens/i,
    ],
    description:
      "Token retains an active mint authority, allowing the owner to inflate supply and drain liquidity.",
  },
  {
    id: "SIG_HONEYPOT_SELL_BLOCK",
    name: "Honeypot — sell restriction",
    category: "honeypot",
    severity: "critical",
    patterns: [
      /require\s*\(\s*is_whitelisted/i,
      /transfer_hook.*block.*sell/i,
      /can_sell\s*=\s*false/i,
    ],
    description:
      "Contract blocks or whitelists sells, letting buyers in but trapping their funds.",
  },
  {
    id: "SIG_DRAINER_SETAUTHORITY",
    name: "Wallet drainer — token account delegation",
    category: "drainer",
    severity: "critical",
    indicators: ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"],
    patterns: [/approve\s*\(.*max.*\)/i, /set_authority.*AccountOwner/i],
    description:
      "Requests unlimited delegation/approval over token accounts — the core drainer primitive.",
  },
  {
    id: "SIG_BRIDGE_SIG_BYPASS",
    name: "Bridge exploit — signature bypass",
    category: "exploit",
    severity: "critical",
    patterns: [/verify_signature\s*=\s*false/i, /skip[_-]?verification/i],
    description: "Bridge program skips signature verification before releasing funds.",
  },
  {
    id: "SIG_FLASHLOAN_SAMEBLOCK",
    name: "Flash-loan price manipulation",
    category: "exploit",
    severity: "high",
    patterns: [/flash_?loan/i, /same[_-]?block.*repay/i],
    description: "Same-block borrow/repay pattern used to manipulate oracle prices.",
  },
  {
    id: "SIG_PHISHING_LOOKALIKE",
    name: "Phishing — look-alike domain",
    category: "phishing",
    severity: "high",
    domains: ["s0lana.xyz", "phantom-wallet.app", "magiceden-mint.com", "jupiter-swap.xyz"],
    description: "Domain impersonates a well-known Solana brand to harvest approvals or seed phrases.",
  },
  {
    id: "SIG_C2_BEACON",
    name: "C2 malware beacon",
    category: "c2",
    severity: "critical",
    patterns: [/\/gate\.php/i, /beacon.*interval/i, /cmd_?exec/i],
    description: "Command-and-control beaconing patterns associated with RAT malware.",
  },
  {
    id: "SIG_SEED_EXFIL",
    name: "Seed-phrase exfiltration",
    category: "spyware",
    severity: "critical",
    patterns: [
      /(mnemonic|seed[_-]?phrase|secret[_-]?key)\s*[:=]/i,
      /bip39/i,
    ],
    description: "Code references mnemonic/secret-key material alongside network egress.",
  },
  {
    id: "SIG_RANSOMWARE_NOTE",
    name: "Ransomware ransom note",
    category: "ransomware",
    severity: "critical",
    patterns: [
      /your\s+(files|data|device|phone)\s+(have|has)\s+been\s+(encrypted|locked)/i,
      /pay\s+(the\s+)?ransom/i,
      /send\s+(\$?\d+\s+)?(in\s+)?(bitcoin|btc|monero|xmr|usdc|sol)\b/i,
      /decrypt(ion)?\s+key/i,
      /all\s+your\s+files\s+are\s+encrypted/i,
    ],
    description: "Text contains a ransom note demanding crypto payment to restore encrypted/locked data.",
  },
];
