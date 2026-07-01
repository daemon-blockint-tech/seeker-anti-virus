/**
 * Core shared types for the Sync detection engine.
 *
 * The engine is intentionally framework-agnostic so the same TypeScript core can
 * run on a Node backend or be embedded in an on-device mobile runtime.
 */

/** Severity buckets, aligned with the PRD risk-scoring table (section 11). */
export type Severity = "low" | "medium" | "high" | "critical";

/** High-level threat taxonomy used across signatures and YARA rules. */
export type ThreatCategory =
  | "malware"
  | "spyware"
  | "trojan"
  | "exploit"
  | "phishing"
  | "rug_pull"
  | "honeypot"
  | "drainer"
  | "permission_abuse"
  | "c2"
  | "ransomware"
  | "unknown";

/** Android-style dangerous permissions Sync watches for. */
export type DangerousPermission =
  | "READ_CONTACTS"
  | "READ_SMS"
  | "RECEIVE_SMS"
  | "RECORD_AUDIO"
  | "ACCESS_FINE_LOCATION"
  | "CAMERA"
  | "READ_CLIPBOARD"
  | "SYSTEM_ALERT_WINDOW"
  | "BIND_ACCESSIBILITY_SERVICE"
  | "QUERY_ALL_PACKAGES"
  | "REQUEST_INSTALL_PACKAGES";

/** A single observed runtime event from a monitored app. */
export interface BehaviorEvent {
  type:
    | "permission_request"
    | "network"
    | "crypto_transaction"
    | "binary_load"
    | "clipboard_access"
    | "accessibility"
    | "file_access"
    | "device_admin";
  timestamp: number;
  /** Permission requested (for permission_request events). */
  permission?: DangerousPermission;
  /** Remote endpoint host for network events. */
  host?: string;
  /** Port for network events. */
  port?: number;
  /** Lamports/notional amount for crypto_transaction events. */
  amountLamports?: number;
  /** Destination address / program for crypto_transaction events. */
  targetAddress?: string;
  /** Solana program id invoked, when relevant. */
  programId?: string;
  /** Path or source for binary_load events. */
  source?: string;
  /** Whether the loaded binary/library was unsigned. */
  unsigned?: boolean;
  /** File path touched (for file_access events). */
  filePath?: string;
  /** Whether the file was written back encrypted (for file_access events). */
  encrypted?: boolean;
  /** New extension if the file was renamed (e.g. ".locked", ".enc"). */
  newExtension?: string;
  /** Device-admin action requested (for device_admin events). */
  adminAction?: "lock" | "wipe" | "reset_password";
  /** Free-form extra metadata. */
  meta?: Record<string, unknown>;
}

/** Target being scanned. */
export interface ScanTarget {
  /** Stable identifier — package name, contract address, or URL. */
  id: string;
  kind: "app" | "contract" | "token" | "url" | "transaction";
  /** Human-readable label. */
  label?: string;
  /** Raw bytes/bytecode for YARA scanning (apk, .so, program bytecode). */
  bytes?: Uint8Array;
  /** Decoded text content (manifest, source, page HTML). */
  text?: string;
  /** Observed runtime behavior, if available. */
  events?: BehaviorEvent[];
  /** Declared permissions (manifest-level). */
  permissions?: DangerousPermission[];
  /** dApp / token domain, when relevant. */
  domain?: string;
}

/** A normalized finding emitted by any detection layer. */
export interface Finding {
  /** Detection layer that produced this finding. */
  source: "behavioral" | "signature" | "yara" | "llm";
  /** Stable rule / signature id. */
  ruleId: string;
  title: string;
  description: string;
  category: ThreatCategory;
  severity: Severity;
  /** 0–1 confidence in the finding. */
  confidence: number;
  /** Evidence strings (matched strings, hosts, permissions, etc.). */
  evidence?: string[];
}

/** Mapping from severity to its numeric weight ceiling (PRD section 11). */
export const SEVERITY_SCORE: Record<Severity, number> = {
  low: 20,
  medium: 50,
  high: 70,
  critical: 95,
};

/** Map a 0–100 score to a severity bucket (PRD section 11). */
export function scoreToSeverity(score: number): Severity {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 40) return "medium";
  return "low";
}
