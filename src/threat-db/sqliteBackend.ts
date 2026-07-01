import { DatabaseSync } from "node:sqlite";
import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";
import type { ThreatRecord, ThreatStoreBackend } from "./types.js";

export interface SqliteBackendOptions {
  /** File path, or ":memory:" (default). */
  path?: string;
  /**
   * 32-byte key enabling encryption at rest (PRD §7 Security). When set, record
   * payloads are AES-256-GCM encrypted and indicators are stored as keyed HMACs
   * so the database never holds plaintext threat data while staying queryable.
   */
  encryptionKey?: Buffer;
}

/**
 * SQLite-backed threat store using Node's built-in `node:sqlite`. Persists
 * across restarts and supports transparent encryption at rest.
 */
export class SqliteBackend implements ThreatStoreBackend {
  private db: DatabaseSync;
  private key?: Buffer;

  constructor(options: SqliteBackendOptions = {}) {
    if (options.encryptionKey && options.encryptionKey.length !== 32) {
      throw new Error("encryptionKey must be 32 bytes (AES-256)");
    }
    this.key = options.encryptionKey;
    this.db = new DatabaseSync(options.path ?? ":memory:");
    this.db.exec(
      `CREATE TABLE IF NOT EXISTS threats (
         k TEXT PRIMARY KEY,
         blob TEXT NOT NULL,
         expires_at INTEGER
       );
       CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);`,
    );
  }

  private lookupKey(indicator: string): string {
    if (!this.key) return indicator;
    return createHmac("sha256", this.key).update(indicator).digest("hex");
  }

  private encode(record: ThreatRecord): string {
    const json = JSON.stringify(record);
    if (!this.key) return json;
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const enc = Buffer.concat([cipher.update(json, "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([iv, tag, enc]).toString("base64");
  }

  private decode(blob: string): ThreatRecord {
    if (!this.key) return JSON.parse(blob);
    const buf = Buffer.from(blob, "base64");
    const iv = buf.subarray(0, 12);
    const tag = buf.subarray(12, 28);
    const enc = buf.subarray(28);
    const decipher = createDecipheriv("aes-256-gcm", this.key, iv);
    decipher.setAuthTag(tag);
    const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
    return JSON.parse(dec.toString("utf8"));
  }

  upsert(records: ThreatRecord[]): void {
    const stmt = this.db.prepare(
      "INSERT OR REPLACE INTO threats (k, blob, expires_at) VALUES (?, ?, ?)",
    );
    for (const r of records) {
      stmt.run(this.lookupKey(r.indicator), this.encode(r), r.expiresAt ?? null);
    }
  }

  get(indicator: string): ThreatRecord | undefined {
    const row = this.db
      .prepare("SELECT blob FROM threats WHERE k = ?")
      .get(this.lookupKey(indicator)) as { blob: string } | undefined;
    return row ? this.decode(row.blob) : undefined;
  }

  list(): ThreatRecord[] {
    const rows = this.db.prepare("SELECT blob FROM threats").all() as { blob: string }[];
    return rows.map((r) => this.decode(r.blob));
  }

  remove(indicator: string): boolean {
    const info = this.db
      .prepare("DELETE FROM threats WHERE k = ?")
      .run(this.lookupKey(indicator));
    return info.changes > 0;
  }

  purgeExpired(now: number): number {
    const info = this.db
      .prepare("DELETE FROM threats WHERE expires_at IS NOT NULL AND expires_at <= ?")
      .run(now);
    return Number(info.changes);
  }

  getMeta(key: string): string | undefined {
    const row = this.db.prepare("SELECT v FROM meta WHERE k = ?").get(key) as
      | { v: string }
      | undefined;
    return row?.v;
  }

  setMeta(key: string, value: string): void {
    this.db
      .prepare("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)")
      .run(key, value);
  }

  close(): void {
    this.db.close();
  }
}
