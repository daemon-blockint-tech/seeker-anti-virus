import type { Finding, ScanTarget, Severity } from "../types.js";
import type { RiskResult } from "./riskScorer.js";

export interface ThreatReport {
  target: { id: string; kind: ScanTarget["kind"]; label?: string };
  score: number;
  severity: Severity;
  verdict: "blocked" | "warn" | "caution" | "clean";
  summary: string;
  findings: Finding[];
  remediation: string[];
  generatedAt: string;
}

/** Plain-language action verb for each severity (PRD §11 / FR-12). */
const ACTION_BY_SEVERITY: Record<Severity, ThreatReport["verdict"]> = {
  critical: "blocked",
  high: "warn",
  medium: "caution",
  low: "clean",
};

/** One-tap remediation suggestions keyed by finding category (FR-13). */
const REMEDIATION_BY_CATEGORY: Record<string, string> = {
  permission_abuse: "Revoke the flagged permissions in Android settings.",
  c2: "Disconnect from the network and uninstall the app.",
  malware: "Quarantine and uninstall immediately; rotate any exposed keys.",
  spyware: "Uninstall the app and move funds to a fresh wallet.",
  trojan: "Uninstall immediately and run a full device scan.",
  drainer: "Do not sign. Revoke token approvals via your wallet.",
  rug_pull: "Do not buy. Exit any existing position if liquidity remains.",
  honeypot: "Do not buy — sells are restricted by the contract.",
  exploit: "Avoid interacting with this contract until audited.",
  phishing: "Close the site; never enter your seed phrase. Verify the official domain.",
  ransomware:
    "Do not pay the ransom. Disconnect the network, force-stop the app, and revoke its Device Admin access before uninstalling; restore files from backup.",
};

/**
 * Report Generator (PRD core module `analyzer/`, FR-10/FR-12/FR-13).
 *
 * Turns a {@link RiskResult} into a plain-language, exportable threat report
 * with deduplicated, prioritized remediation steps.
 */
export class ReportGenerator {
  generate(target: ScanTarget, result: RiskResult): ThreatReport {
    const verdict = ACTION_BY_SEVERITY[result.severity];
    const findings = [...result.findings].sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity),
    );

    return {
      target: { id: target.id, kind: target.kind, label: target.label },
      score: result.score,
      severity: result.severity,
      verdict,
      summary: this.summarize(target, result),
      findings,
      remediation: this.remediation(findings, verdict),
      generatedAt: new Date().toISOString(),
    };
  }

  private summarize(target: ScanTarget, result: RiskResult): string {
    const label = target.label ?? target.id;
    if (result.findings.length === 0) {
      return `No threats detected in ${label}. Risk score ${result.score}/100 (low).`;
    }
    const top = [...result.findings].sort(
      (a, b) => severityRank(b.severity) - severityRank(a.severity),
    )[0]!;
    const escalation = result.escalated
      ? " A critical signature/YARA match escalated the overall severity."
      : "";
    return (
      `${label} scored ${result.score}/100 (${result.severity}). ` +
      `${result.findings.length} finding(s); most severe: "${top.title}".${escalation}`
    );
  }

  private remediation(findings: Finding[], verdict: ThreatReport["verdict"]): string[] {
    const steps: string[] = [];
    if (verdict === "clean") return ["No action required. Continue monitoring."];

    const seen = new Set<string>();
    for (const f of findings) {
      const tip = REMEDIATION_BY_CATEGORY[f.category];
      if (tip && !seen.has(tip)) {
        seen.add(tip);
        steps.push(tip);
      }
    }
    if (verdict === "blocked") {
      steps.unshift("Action blocked automatically — do not proceed.");
    }
    return steps;
  }
}

function severityRank(s: Severity): number {
  return { low: 0, medium: 1, high: 2, critical: 3 }[s];
}
