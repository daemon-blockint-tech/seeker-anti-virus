import {
  type Finding,
  type Severity,
  SEVERITY_SCORE,
  scoreToSeverity,
} from "../types.js";

export interface RiskResult {
  /** Combined 0–100 risk score. */
  score: number;
  severity: Severity;
  /** Per-layer sub-scores for transparency. */
  breakdown: {
    behavioral: number;
    yara: number;
    signature: number;
  };
  /** True when a critical YARA match forced an escalation (PRD §11). */
  escalated: boolean;
  findings: Finding[];
}

/**
 * Risk Scoring Engine (PRD section 11).
 *
 * Combined score weights behavioral (60%) and YARA (40%). Signature hits are
 * folded into whichever layer is most relevant but also tracked separately. A
 * critical YARA match escalates the overall severity to critical regardless of
 * the behavioral score.
 */
export class RiskScorer {
  constructor(
    private readonly weights = { behavioral: 0.6, yara: 0.4 },
  ) {}

  score(findings: Finding[]): RiskResult {
    const behavioral = this.layerScore(
      findings.filter((f) => f.source === "behavioral" || f.source === "llm"),
    );
    const yara = this.layerScore(findings.filter((f) => f.source === "yara"));
    const signature = this.layerScore(
      findings.filter((f) => f.source === "signature"),
    );

    // Signatures reinforce both layers; take the stronger of (behavioral, sig)
    // and (yara, sig) so a high-confidence signature is never diluted.
    const behavioralComponent = Math.max(behavioral, signature);
    const yaraComponent = Math.max(yara, signature);

    // Normalize over the layers that actually produced findings so a strong
    // single-layer result isn't diluted by an absent layer (e.g. a behavioral
    // "high" with no YARA match should still read "high", not "medium").
    const activeWeight =
      (behavioralComponent > 0 ? this.weights.behavioral : 0) +
      (yaraComponent > 0 ? this.weights.yara : 0);

    let combined =
      activeWeight === 0
        ? 0
        : (this.weights.behavioral * behavioralComponent +
            this.weights.yara * yaraComponent) /
          activeWeight;

    const criticalYara = findings.some(
      (f) => f.source === "yara" && f.severity === "critical",
    );
    const criticalSig = findings.some(
      (f) => f.source === "signature" && f.severity === "critical" && f.confidence >= 0.9,
    );
    const escalated = criticalYara || criticalSig;
    if (escalated) combined = Math.max(combined, 85);

    const score = Math.round(Math.min(100, combined));

    return {
      score,
      severity: scoreToSeverity(score),
      breakdown: {
        behavioral: Math.round(behavioral),
        yara: Math.round(yara),
        signature: Math.round(signature),
      },
      escalated,
      findings,
    };
  }

  /**
   * Reduce a layer's findings to a 0–100 score. The strongest finding sets the
   * floor (severity ceiling × confidence); additional findings add diminishing
   * weight so many minor flags can still accumulate.
   */
  private layerScore(findings: Finding[]): number {
    if (findings.length === 0) return 0;

    const weighted = findings
      .map((f) => SEVERITY_SCORE[f.severity] * f.confidence)
      .sort((a, b) => b - a);

    let score = weighted[0]!;
    for (let i = 1; i < weighted.length; i++) {
      // Each additional finding contributes a decaying fraction.
      score += weighted[i]! * (0.3 / i);
    }
    return Math.min(100, score);
  }
}
