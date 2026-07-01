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
/** Above this (~50 SOL) a transfer is treated as a near-certain anomaly. */
const VERY_LARGE_TRANSFER_LAMPORTS = 50 * 1_000_000_000;

/** Encrypting at least this many files in a session looks like ransomware. */
const RANSOMWARE_ENCRYPTION_THRESHOLD = 10;
/** Extensions commonly appended by mobile/desktop ransomware. */
const RANSOM_EXTENSIONS = new Set([
  ".locked",
  ".enc",
  ".crypt",
  ".crypto",
  ".cerber",
  ".coin",
  ".wallet",
  ".encrypted",
]);

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
    let maxTransferLamports = 0;
    let clipboardReads = 0;
    let encryptedFiles = 0;
    const ransomExtensions = new Set<string>();
    const adminActions = new Set<NonNullable<BehaviorEvent["adminAction"]>>();

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
            maxTransferLamports = Math.max(maxTransferLamports, ev.amountLamports!);
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
        case "file_access":
          if (ev.encrypted) encryptedFiles++;
          if (ev.newExtension && RANSOM_EXTENSIONS.has(ev.newExtension.toLowerCase())) {
            ransomExtensions.add(ev.newExtension.toLowerCase());
            encryptedFiles++;
          }
          break;
        case "device_admin":
          if (ev.adminAction) adminActions.add(ev.adminAction);
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
      // A transfer past the anomaly trip-wire should warn the user to confirm
      // (PRD FR-2). Confidence scales with magnitude so very large outflows land
      // firmly in the "high" band rather than reading as low-risk.
      const veryLarge = maxTransferLamports >= VERY_LARGE_TRANSFER_LAMPORTS;
      findings.push({
        source: "behavioral",
        ruleId: "BEH_ANOMALOUS_TRANSFER",
        title: "Large / anomalous transfer detected",
        description:
          "Transfer exceeds the anomaly threshold. Verify the recipient and amount before approving.",
        category: "drainer",
        severity: "high",
        confidence: veryLarge ? 0.95 : 0.87,
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

    // Ransomware: bulk file encryption / ransom-extension rewrites.
    if (encryptedFiles >= RANSOMWARE_ENCRYPTION_THRESHOLD) {
      const evidence = [`${encryptedFiles} files encrypted`];
      if (ransomExtensions.size > 0) {
        evidence.push(`extensions: ${[...ransomExtensions].join(", ")}`);
      }
      findings.push({
        source: "behavioral",
        ruleId: "BEH_RANSOMWARE_ENCRYPTION",
        title: "Mass file encryption (possible ransomware)",
        description:
          "App is rapidly encrypting or renaming many files — the hallmark of a ransomware file-locker.",
        category: "ransomware",
        // Bulk encryption alone is critical; a known ransom extension removes doubt.
        severity: "critical",
        confidence: ransomExtensions.size > 0 ? 0.95 : 0.8,
        evidence,
      });
    }

    // Ransomware / screen-locker abuse of Device Admin APIs.
    if (adminActions.size > 0) {
      const wipes = adminActions.has("wipe");
      findings.push({
        source: "behavioral",
        ruleId: "BEH_DEVICE_ADMIN_ABUSE",
        title: wipes
          ? "Device wipe requested (locker / wiper)"
          : "Device lock / password reset (screen-locker)",
        description:
          "App invoked Device Admin actions used by ransomware screen-lockers to lock the device or hold data hostage.",
        category: "ransomware",
        severity: wipes ? "critical" : "high",
        confidence: wipes ? 0.9 : 0.8,
        evidence: [...adminActions].map((a) => `device_admin:${a}`),
      });
    }

    return findings;
  }

  private isSuspiciousHost(host: string): boolean {
    return SUSPICIOUS_HOST_PATTERNS.some((re) => re.test(host));
  }
}
