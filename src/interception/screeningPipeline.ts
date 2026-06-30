import { IntegratedScanner } from "../integrated-scanner/integratedScanner.js";
import type { ThreatReport } from "../analyzer/reportGenerator.js";
import type { Severity } from "../types.js";
import { decodeTransaction, transactionToScanTarget, type DecodedTransaction } from "./txDecoder.js";

export type ScreeningDecision = "allow" | "warn" | "block";

export interface ScreeningResult {
  decision: ScreeningDecision;
  severity: Severity;
  score: number;
  decoded: DecodedTransaction;
  report: ThreatReport;
}

export interface ScreeningPipelineOptions {
  scanner?: IntegratedScanner;
  /** Severity at/above which a transaction is blocked outright (default "critical"). */
  blockAt?: Severity;
  /** Severity at/above which the user must explicitly confirm (default "high"). */
  warnAt?: Severity;
}

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Transaction screening pipeline (PRD §5.5 / §10.1–10.2, FR-2).
 *
 * Decodes an intercepted signing request, runs it through the
 * {@link IntegratedScanner}, and maps the risk to an allow / warn / block
 * decision before any signature is produced.
 */
export class ScreeningPipeline {
  private readonly scanner: IntegratedScanner;
  private readonly blockAt: Severity;
  private readonly warnAt: Severity;

  constructor(options: ScreeningPipelineOptions = {}) {
    this.scanner = options.scanner ?? new IntegratedScanner();
    this.blockAt = options.blockAt ?? "critical";
    this.warnAt = options.warnAt ?? "high";
  }

  /** Screen a raw serialized transaction (signature vector + message, or message). */
  async screen(txBytes: Uint8Array, id?: string): Promise<ScreeningResult> {
    const decoded = decodeTransaction(txBytes);
    const target = transactionToScanTarget(decoded, id);
    const result = await this.scanner.scan(target);

    let decision: ScreeningDecision = "allow";
    if (RANK[result.severity] >= RANK[this.blockAt]) decision = "block";
    else if (RANK[result.severity] >= RANK[this.warnAt]) decision = "warn";

    return {
      decision,
      severity: result.severity,
      score: result.score,
      decoded,
      report: result.report,
    };
  }
}
