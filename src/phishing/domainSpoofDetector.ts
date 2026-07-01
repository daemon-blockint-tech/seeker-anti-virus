import type { Finding, ScanTarget } from "../types.js";
import { analyzeDomainSpoof } from "./domainSpoof.js";

/**
 * Domain Spoof Detector (PRD FR-7 / FR-7b).
 *
 * Algorithmic look-alike detection for phishing domains and spoofed `.skr`
 * Solana Mobile naming entries impersonating known wallets — homoglyph (IDN
 * homograph), character-substitution, and typosquat variants. Complements the
 * static phishing signature list rather than duplicating it.
 */
export class DomainSpoofDetector {
  constructor(private readonly skipDomains?: Set<string>) {}

  scan(target: ScanTarget): Finding[] {
    const domain =
      target.domain ?? (target.kind === "url" ? target.id : undefined);
    if (!domain) return [];

    const result = analyzeDomainSpoof(domain, this.skipDomains);
    if (!result) return [];

    return [
      {
        source: "signature",
        ruleId: result.isSkr ? "PHISH_SKR_SPOOF" : "PHISH_DOMAIN_SPOOF",
        title: result.isSkr
          ? `Spoofed .skr handle impersonating ${result.brand}`
          : `Look-alike domain impersonating ${result.brand}`,
        description: `${result.detail}. Do not connect a wallet or enter a seed phrase.`,
        category: "phishing",
        severity: result.severity,
        confidence: result.confidence,
        evidence: [`brand:${result.brand}`, `technique:${result.technique}`, `domain:${domain}`],
      },
    ];
  }
}
