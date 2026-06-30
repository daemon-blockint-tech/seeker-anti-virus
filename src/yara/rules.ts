import type { Severity, ThreatCategory } from "../types.js";

/** A single string condition inside a YARA-style rule. */
export interface YaraString {
  /** Identifier, e.g. "$seed". */
  id: string;
  /** Literal text or hex/regex value. */
  value: string;
  /** How {@link value} is interpreted. */
  type: "text" | "regex" | "hex";
  /** Case-insensitive (`nocase`) for text/regex strings. */
  nocase?: boolean;
}

/**
 * A YARA-compatible rule. The {@link condition} mirrors common YARA conditions
 * we support natively: "all", "any", or "N of them".
 */
export interface YaraRule {
  name: string;
  category: ThreatCategory;
  severity: Severity;
  meta: {
    description: string;
    author?: string;
    reference?: string;
  };
  strings: YaraString[];
  /** "all" of them, "any" of them, or a minimum count. */
  condition: "all" | "any" | { atLeast: number };
}

/** The 8 Solana-specific YARA rules from the PRD (section 5.3). */
export const SOLANA_YARA_RULES: YaraRule[] = [
  {
    name: "Sync_Wallet_Stealer",
    category: "malware",
    severity: "critical",
    meta: { description: "Seed / private-key extraction and exfiltration." },
    strings: [
      { id: "$m1", value: "mnemonic", type: "text", nocase: true },
      { id: "$m2", value: "seed_phrase", type: "text", nocase: true },
      { id: "$m3", value: "secretKey", type: "text" },
      { id: "$x1", value: "(POST|fetch).{0,40}https?://", type: "regex", nocase: true },
    ],
    condition: { atLeast: 2 },
  },
  {
    name: "Sync_Rug_Pull_Contract",
    category: "exploit",
    severity: "critical",
    meta: { description: "Liquidity drain plus hidden owner logic." },
    strings: [
      { id: "$a", value: "remove_liquidity", type: "text", nocase: true },
      { id: "$b", value: "only_owner", type: "text", nocase: true },
      { id: "$c", value: "mint_authority", type: "text", nocase: true },
    ],
    condition: { atLeast: 2 },
  },
  {
    name: "Sync_Honeypot_Token",
    category: "exploit",
    severity: "critical",
    meta: { description: "Sell restrictions plus backdoors." },
    strings: [
      { id: "$s1", value: "can_sell", type: "text", nocase: true },
      { id: "$s2", value: "is_whitelisted", type: "text", nocase: true },
      { id: "$s3", value: "transfer_hook", type: "text", nocase: true },
    ],
    condition: { atLeast: 2 },
  },
  {
    name: "Sync_Flash_Loan_Attack",
    category: "exploit",
    severity: "high",
    meta: { description: "Price manipulation with same-block repay." },
    strings: [
      { id: "$f1", value: "flash_loan", type: "text", nocase: true },
      { id: "$f2", value: "borrow", type: "text", nocase: true },
      { id: "$f3", value: "repay", type: "text", nocase: true },
    ],
    condition: "all",
  },
  {
    name: "Sync_Bridge_Exploit",
    category: "exploit",
    severity: "critical",
    meta: { description: "Signature bypass and drain on a bridge program." },
    strings: [
      { id: "$b1", value: "skip_verification", type: "text", nocase: true },
      { id: "$b2", value: "verify_signature = false", type: "text", nocase: true },
      { id: "$b3", value: "release_funds", type: "text", nocase: true },
    ],
    condition: { atLeast: 2 },
  },
  {
    name: "Sync_NFT_Scam",
    category: "exploit",
    severity: "high",
    meta: { description: "Fraudulent mint plus fee extraction." },
    strings: [
      { id: "$n1", value: "hidden_fee", type: "text", nocase: true },
      { id: "$n2", value: "unlimited_mint", type: "text", nocase: true },
      { id: "$n3", value: "set_authority", type: "text", nocase: true },
    ],
    condition: { atLeast: 2 },
  },
  {
    name: "Sync_Mobile_Keylogger",
    category: "malware",
    severity: "critical",
    meta: { description: "Input capture and exfiltration." },
    strings: [
      { id: "$k1", value: "AccessibilityService", type: "text" },
      { id: "$k2", value: "onKeyEvent", type: "text" },
      { id: "$k3", value: "getClipboardData", type: "text" },
    ],
    condition: { atLeast: 2 },
  },
  {
    name: "Sync_Remote_Access_Trojan",
    category: "trojan",
    severity: "critical",
    meta: { description: "C2 socket plus command loop." },
    strings: [
      { id: "$r1", value: "Socket", type: "text" },
      { id: "$r2", value: "gate.php", type: "text", nocase: true },
      { id: "$r3", value: "exec(", type: "text" },
      { id: "$r4", value: "while.{0,20}recv", type: "regex", nocase: true },
    ],
    condition: { atLeast: 2 },
  },
];
