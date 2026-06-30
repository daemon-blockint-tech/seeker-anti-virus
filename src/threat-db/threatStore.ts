import type { Finding, ScanTarget } from "../types.js";
import { InMemoryBackend } from "./backend.js";
import type { ThreatRecord, ThreatStoreBackend } from "./types.js";

const VERSION_KEY = "bundle_version";

/**
 * On-device threat database (PRD §8, FR-8/FR-9).
 *
 * A local cache of threat-intelligence records over a pluggable
 * {@link ThreatStoreBackend} (in-memory or SQLite). Acts as an extra detection
 * input via {@link scan}, returning normalized {@link Finding}s for any stored
 * indicator that matches a scan target.
 */
export class ThreatStore {
  constructor(private readonly backend: ThreatStoreBackend = new InMemoryBackend()) {}

  /** Add or replace threat records. */
  add(records: ThreatRecord[]): void {
    this.backend.upsert(records);
  }

  /** Look up a single indicator, ignoring (and not returning) expired records. */
  lookup(indicator: string, now = Date.now()): ThreatRecord | undefined {
    const rec = this.backend.get(indicator);
    if (!rec) return undefined;
    if (rec.expiresAt !== undefined && rec.expiresAt <= now) return undefined;
    return rec;
  }

  /**
   * Match a scan target's indicators (id, domain, and any program ids in its
   * events) against the store, producing findings for live records.
   */
  scan(target: ScanTarget, now = Date.now()): Finding[] {
    const indicators = new Set<string>();
    indicators.add(target.id);
    if (target.domain) indicators.add(target.domain);
    for (const ev of target.events ?? []) {
      if (ev.programId) indicators.add(ev.programId);
      if (ev.targetAddress) indicators.add(ev.targetAddress);
    }

    const findings: Finding[] = [];
    for (const indicator of indicators) {
      const rec = this.lookup(indicator, now);
      if (!rec) continue;
      findings.push({
        source: "signature",
        ruleId: `THREATDB:${rec.id}`,
        title: `Known threat: ${rec.id}`,
        description: rec.description,
        category: rec.category,
        severity: rec.severity,
        confidence: 0.97, // exact indicator match from curated intel
        evidence: [`${rec.indicatorKind}:${rec.indicator}`, ...(rec.source ? [`source:${rec.source}`] : [])],
      });
    }
    return findings;
  }

  /** Remove expired records; returns how many were purged. */
  purgeExpired(now = Date.now()): number {
    return this.backend.purgeExpired(now);
  }

  /** The applied bundle version (0 if none). */
  get version(): number {
    return Number(this.backend.getMeta(VERSION_KEY) ?? "0");
  }

  set version(v: number) {
    this.backend.setMeta(VERSION_KEY, String(v));
  }

  get size(): number {
    return this.backend.list().length;
  }

  close(): void {
    this.backend.close();
  }
}
