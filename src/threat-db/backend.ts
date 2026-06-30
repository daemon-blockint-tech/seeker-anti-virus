import type { ThreatRecord, ThreatStoreBackend } from "./types.js";

/**
 * In-memory backend — the default, dependency-free store. Suitable for tests
 * and for runtimes without SQLite; data does not survive a restart.
 */
export class InMemoryBackend implements ThreatStoreBackend {
  private records = new Map<string, ThreatRecord>();
  private meta = new Map<string, string>();

  upsert(records: ThreatRecord[]): void {
    for (const r of records) this.records.set(r.indicator, r);
  }

  get(indicator: string): ThreatRecord | undefined {
    return this.records.get(indicator);
  }

  list(): ThreatRecord[] {
    return [...this.records.values()];
  }

  remove(indicator: string): boolean {
    return this.records.delete(indicator);
  }

  purgeExpired(now: number): number {
    let removed = 0;
    for (const [k, r] of this.records) {
      if (r.expiresAt !== undefined && r.expiresAt <= now) {
        this.records.delete(k);
        removed++;
      }
    }
    return removed;
  }

  getMeta(key: string): string | undefined {
    return this.meta.get(key);
  }

  setMeta(key: string, value: string): void {
    this.meta.set(key, value);
  }

  close(): void {
    this.records.clear();
    this.meta.clear();
  }
}
