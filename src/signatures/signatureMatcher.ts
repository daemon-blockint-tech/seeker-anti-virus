import type { Finding, ScanTarget } from "../types.js";
import { DEFAULT_SIGNATURES, type ThreatSignature } from "./signatureDatabase.js";

/** Normalize a domain for look-alike comparison. */
function normalizeDomain(input: string): string {
  return input
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .split("/")[0]!
    .split(":")[0]!;
}

/**
 * Signature Matcher (PRD 5.2).
 *
 * Fast lookup of a target's text / domain / indicators against the curated
 * {@link ThreatSignature} database. Designed for the <30 ms/event budget in the
 * PRD's non-functional requirements.
 */
export class SignatureMatcher {
  private signatures: ThreatSignature[];

  constructor(signatures: ThreatSignature[] = DEFAULT_SIGNATURES) {
    this.signatures = [...signatures];
  }

  /** Add or replace signatures (e.g. after a signed OTA update). */
  upsert(signatures: ThreatSignature[]): void {
    for (const sig of signatures) {
      const idx = this.signatures.findIndex((s) => s.id === sig.id);
      if (idx >= 0) this.signatures[idx] = sig;
      else this.signatures.push(sig);
    }
  }

  get size(): number {
    return this.signatures.length;
  }

  scan(target: ScanTarget): Finding[] {
    const findings: Finding[] = [];
    const text = target.text ?? "";
    const domain = target.domain ?? (target.kind === "url" ? target.id : undefined);
    const normDomain = domain ? normalizeDomain(domain) : undefined;

    for (const sig of this.signatures) {
      const evidence: string[] = [];

      if (sig.indicators?.includes(target.id)) {
        evidence.push(`indicator:${target.id}`);
      }

      if (normDomain && sig.domains) {
        for (const d of sig.domains) {
          if (normalizeDomain(d) === normDomain) evidence.push(`domain:${d}`);
        }
      }

      if (sig.patterns && text) {
        for (const re of sig.patterns) {
          const m = re.exec(text);
          if (m) evidence.push(`pattern:${m[0].slice(0, 60)}`);
        }
      }

      if (evidence.length > 0) {
        findings.push({
          source: "signature",
          ruleId: sig.id,
          title: sig.name,
          description: sig.description,
          category: sig.category,
          severity: sig.severity,
          // Exact indicator/domain hits are higher confidence than regexes.
          confidence: evidence.some((e) => e.startsWith("pattern:")) ? 0.8 : 0.95,
          evidence,
        });
      }
    }

    return findings;
  }
}
