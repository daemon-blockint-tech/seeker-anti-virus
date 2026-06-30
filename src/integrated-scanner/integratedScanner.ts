import { ReportGenerator, type ThreatReport } from "../analyzer/reportGenerator.js";
import { RiskScorer, type RiskResult } from "../analyzer/riskScorer.js";
import { BehavioralScanner } from "../scanner/behavioralScanner.js";
import { SignatureMatcher } from "../signatures/signatureMatcher.js";
import type { ThreatSignature } from "../signatures/signatureDatabase.js";
import type { Finding, ScanTarget } from "../types.js";
import { RuleManager } from "../yara/ruleManager.js";
import type { YaraRule } from "../yara/rules.js";

/** Optional LLM classifier hook (PRD 5.4) — opt-in, async, off by default. */
export type LlmClassifier = (
  target: ScanTarget,
  priorFindings: Finding[],
) => Promise<Finding[]>;

export interface IntegratedScannerOptions {
  signatures?: ThreatSignature[];
  yaraRules?: YaraRule[];
  /** Provide to enable opt-in LLM escalation (PRD 5.4, FR). */
  llm?: LlmClassifier;
  /** Min combined score before escalating to the LLM (default 60). */
  llmEscalationThreshold?: number;
  /** Called when the opt-in LLM step throws. Defaults to `console.warn`. */
  onLlmError?: (error: unknown, target: ScanTarget) => void;
}

export interface ScanResult extends RiskResult {
  report: ThreatReport;
}

/**
 * Integrated Scanner (PRD core module `integrated-scanner`).
 *
 * Unified pipeline: Behavioral → Signature → YARA → (opt-in) LLM, fed into the
 * Risk Scoring Engine and Report Generator. This is the primary entry point a
 * mobile/host app calls.
 */
export class IntegratedScanner {
  private readonly behavioral = new BehavioralScanner();
  private readonly signatures: SignatureMatcher;
  private readonly rules: RuleManager;
  private readonly scorer = new RiskScorer();
  private readonly reporter = new ReportGenerator();
  private readonly llm?: LlmClassifier;
  private readonly llmThreshold: number;
  private readonly onLlmError: (error: unknown, target: ScanTarget) => void;

  constructor(options: IntegratedScannerOptions = {}) {
    this.signatures = new SignatureMatcher(options.signatures);
    this.rules = new RuleManager(options.yaraRules);
    this.llm = options.llm;
    this.llmThreshold = options.llmEscalationThreshold ?? 60;
    this.onLlmError =
      options.onLlmError ??
      ((err, target) =>
        console.warn(`[sync] LLM classification failed for ${target.id}:`, err));
  }

  /** Access the rule manager for custom-rule management (FR-15). */
  get ruleManager(): RuleManager {
    return this.rules;
  }

  get signatureMatcher(): SignatureMatcher {
    return this.signatures;
  }

  /** Run the full pipeline against a target and produce a scored report. */
  async scan(target: ScanTarget): Promise<ScanResult> {
    const findings: Finding[] = [
      ...this.behavioral.scan(target),
      ...this.signatures.scan(target),
      ...this.rules.scanner().scan(target),
    ];

    // Opt-in LLM escalation for ambiguous/high-stakes cases (PRD 5.4).
    if (this.llm) {
      const interim = this.scorer.score(findings);
      if (interim.score >= this.llmThreshold) {
        try {
          findings.push(...(await this.llm(target, findings)));
        } catch (err) {
          // LLM is best-effort; never let it break local detection (PRD §7),
          // but surface the failure so operators aren't blind to it.
          this.onLlmError(err, target);
        }
      }
    }

    const result = this.scorer.score(findings);
    const report = this.reporter.generate(target, result);
    return { ...result, report };
  }

  /** Synchronous local-only scan (no LLM) for tight on-device loops. */
  scanLocal(target: ScanTarget): ScanResult {
    const findings: Finding[] = [
      ...this.behavioral.scan(target),
      ...this.signatures.scan(target),
      ...this.rules.scanner().scan(target),
    ];
    const result = this.scorer.score(findings);
    const report = this.reporter.generate(target, result);
    return { ...result, report };
  }
}
