import type {
  BehaviorEvent,
  DangerousPermission,
  Finding,
  ScanTarget,
} from "../types.js";

/** Permissions considered high-risk on a crypto-custody device. */
const DANGEROUS_PERMISSIONS: Record<DangerousPermission, number> = {
  READ_SMS: 0.9, // 2FA / seed-recovery interception
  RECEIVE_SMS: 0.9,
  READ_CLIPBOARD: 0.95, // seed-phrase / address hijacking
  BIND_ACCESSIBILITY_SERVICE: 0.95, // overlay + input capture
  SYSTEM_ALERT_WINDOW: 0.8, // tap-jacking overlays
  RECORD_AUDIO: 0.7,
  READ_CONTACTS: 0.5,
  ACCESS_FINE_LOCATION: 0.5,
  CAMERA: 0.5,
  QUERY_ALL_PACKAGES: 0.6,
  REQUEST_INSTALL_PACKAGES: 0.7,
};

/** Known-bad / suspicious endpoint heuristics for C2 detection. */
const SUSPICIOUS_HOST_PATTERNS = [
  /\.(top|xyz|ru|tk|gq|cf)$/i,
  /\d{1,3}(\.\d{1,3}){3}/, // raw IPv4 literal C2
  /(pastebin|ngrok|trycloudflare|duckdns|no-ip)\./i,
];

/** Anomalous transfer threshold (~5 SOL) used as a heuristic trip-wire. */
const LARGE_TRANSFER_LAMPORTS = 5 * 1_000_000_000;

export interface BehavioralScannerOptions {
  /** Override the large-transfer threshold (in lamports). */
  largeTransferLamports?: number;
}

/**
 * Behavioral Scanner (PRD 5.1).
 *
 * Inspects declared permissions and a stream of runtime {@link BehaviorEvent}s
 * for permission abuse, C2 networking, anomalous transfers and binary injection.
 * Pure and synchronous so it can run inside a tight on-device monitoring loop.
 */
export class BehavioralScanner {
  private readonly largeTransfer: number;

  constructor(options: BehavioralScannerOptions = {}) {
    this.largeTransfer = options.largeTransferLamports ?? LARGE_TRANSFER_LAMPORTS;
  }

  scan(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    findings.push(...this.scanPermissions(target.permissions ?? []));
    findings.push(...this.scanEvents(target.events ?? []));
    return findings;
  }

  private scanPermissions(permissions: DangerousPermission[]): Finding[] {
    const flagged = permissions.filter((p) => p in DANGEROUS_PERMISSIONS);
    if (flagged.length === 0) return [];

    const maxWeight = Math.max(...flagged.map((p) => DANGEROUS_PERMISSIONS[p]));
    // Combining clipboard + accessibility/SMS is a classic drainer fingerprint.
    const combo =
      flagged.includes("READ_CLIPBOARD") &&
      (flagged.includes("BIND_ACCESSIBILITY_SERVICE") ||
        flagged.includes("READ_SMS"));

    return [
      {
        source: "behavioral",
        ruleId: "BEH_DANGEROUS_PERMISSIONS",
        title: "Dangerous permission set requested",
        description: combo
          ? "App requests a permission combination commonly used by wallet drainers and keyloggers (clipboard + accessibility/SMS)."
          : "App requests permissions that can be abused to capture sensitive data.",
        category: "permission_abuse",
        severity: combo ? "high" : maxWeight >= 0.9 ? "high" : "medium",
        confidence: Math.min(0.99, maxWeight + (combo ? 0.1 : 0)),
        evidence: flagged,
      },
    ];
  }

  private scanEvents(events: BehaviorEvent[]): Finding[] {
    const findings: Finding[] = [];

    const suspiciousHosts = new Set<string>();
    let unsignedLoads = 0;
    const largeTransfers: string[] = [];
    let clipboardReads = 0;

    for (const ev of events) {
      switch (ev.type) {
        case "network":
          if (ev.host && this.isSuspiciousHost(ev.host)) {
            suspiciousHosts.add(`${ev.host}${ev.port ? ":" + ev.port : ""}`);
          }
          break;
        case "binary_load":
          if (ev.unsigned) unsignedLoads++;
          break;
        case "crypto_transaction":
          if ((ev.amountLamports ?? 0) >= this.largeTransfer) {
            largeTransfers.push(
              `${(ev.amountLamports! / 1e9).toFixed(2)} SOL → ${
                ev.targetAddress ?? "unknown"
              }`,
            );
          }
          break;
        case "clipboard_access":
          clipboardReads++;
          break;
      }
    }

    if (suspiciousHosts.size > 0) {
      findings.push({
        source: "behavioral",
        ruleId: "BEH_C2_NETWORK",
        title: "Suspicious network endpoints (possible C2)",
        description:
          "App contacted endpoints matching command-and-control heuristics (raw IPs, throwaway TLDs, tunneling services).",
        category: "c2",
        severity: "high",
        confidence: 0.7,
        evidence: [...suspiciousHosts],
      });
    }

    if (unsignedLoads > 0) {
      findings.push({
        source: "behavioral",
        ruleId: "BEH_BINARY_INJECTION",
        title: "Unsigned binary / code injection",
        description:
          "App loaded unsigned native binaries at runtime — a common code-injection and RAT technique.",
        category: "malware",
        severity: "high",
        confidence: 0.75,
        evidence: [`${unsignedLoads} unsigned load(s)`],
      });
    }

    if (largeTransfers.length > 0) {
      findings.push({
        source: "behavioral",
        ruleId: "BEH_ANOMALOUS_TRANSFER",
        title: "Large / anomalous transfer detected",
        description:
          "App initiated transfers above the anomaly threshold. Verify the recipient before approving.",
        category: "drainer",
        severity: "medium",
        confidence: 0.55,
        evidence: largeTransfers,
      });
    }

    if (clipboardReads >= 3) {
      findings.push({
        source: "behavioral",
        ruleId: "BEH_CLIPBOARD_HIJACK",
        title: "Repeated clipboard access",
        description:
          "Frequent clipboard reads can indicate address-swapping or seed-phrase theft.",
        category: "spyware",
        severity: "medium",
        confidence: 0.6,
        evidence: [`${clipboardReads} clipboard reads`],
      });
    }

    return findings;
  }

  private isSuspiciousHost(host: string): boolean {
    return SUSPICIOUS_HOST_PATTERNS.some((re) => re.test(host));
  }
}
