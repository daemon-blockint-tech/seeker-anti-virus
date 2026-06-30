import type { IntegratedScanner, ScanResult } from "../integrated-scanner/integratedScanner.js";
import type { BehaviorEvent, ScanTarget, Severity } from "../types.js";

export interface ThreatAlert {
  appId: string;
  severity: Severity;
  score: number;
  title: string;
  at: number;
  result: ScanResult;
}

export type AlertHandler = (alert: ThreatAlert) => void;

export interface MonitorOptions {
  /** Severity at or above which an alert is pushed (default "high"). */
  alertThreshold?: Severity;
  /** Re-scan every N buffered events (default 25). */
  flushEvery?: number;
}

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

/**
 * Real-Time Monitor (PRD core module `monitor/`, FR-1/FR-3).
 *
 * Maintains per-app monitoring sessions, buffers incoming behavior events, and
 * re-runs the integrated scanner, pushing alerts when a session crosses the
 * configured severity threshold.
 */
export class Monitor {
  private sessions = new Map<string, { target: ScanTarget; buffered: number }>();
  private handlers: AlertHandler[] = [];
  private readonly threshold: Severity;
  private readonly flushEvery: number;

  constructor(
    private readonly scanner: IntegratedScanner,
    options: MonitorOptions = {},
  ) {
    this.threshold = options.alertThreshold ?? "high";
    this.flushEvery = options.flushEvery ?? 25;
  }

  onAlert(handler: AlertHandler): void {
    this.handlers.push(handler);
  }

  /** Begin (or reset) a monitoring session for an app. */
  start(target: ScanTarget): void {
    this.sessions.set(target.id, {
      target: { ...target, events: [...(target.events ?? [])] },
      buffered: 0,
    });
  }

  stop(appId: string): void {
    this.sessions.delete(appId);
  }

  get activeSessions(): string[] {
    return [...this.sessions.keys()];
  }

  /**
   * Feed a runtime event into a session. Triggers a re-scan once enough events
   * have accumulated. Returns an alert if one fired, else null.
   */
  ingest(appId: string, event: BehaviorEvent): ThreatAlert | null {
    const session = this.sessions.get(appId);
    if (!session) return null;

    session.target.events!.push(event);
    session.buffered++;

    if (session.buffered < this.flushEvery) return null;
    return this.evaluate(appId);
  }

  /** Force an immediate re-scan of a session. */
  evaluate(appId: string): ThreatAlert | null {
    const session = this.sessions.get(appId);
    if (!session) return null;
    session.buffered = 0;

    const result = this.scanner.scanLocal(session.target);
    if (RANK[result.severity] < RANK[this.threshold]) return null;

    const top = result.report.findings[0];
    const alert: ThreatAlert = {
      appId,
      severity: result.severity,
      score: result.score,
      title: top?.title ?? "Threat detected",
      at: Date.now(),
      result,
    };
    for (const h of this.handlers) h(alert);
    return alert;
  }
}
