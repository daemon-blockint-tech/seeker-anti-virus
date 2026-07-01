import type { Severity, ThreatCategory } from "../types.js";
import type { ThreatSignature } from "../signatures/signatureDatabase.js";
import type { YaraRule } from "../yara/rules.js";

/** Kind of indicator a {@link ThreatRecord} matches on. */
export type IndicatorKind = "address" | "domain" | "program" | "hash";

/** A single piece of threat intelligence stored on-device. */
export interface ThreatRecord {
  /** Stable record id (e.g. "drainer-2026-001"). */
  id: string;
  /** The matched value: an address, domain, program id, or file hash. */
  indicator: string;
  indicatorKind: IndicatorKind;
  category: ThreatCategory;
  severity: Severity;
  description: string;
  /** Provenance (feed name, reporter). */
  source?: string;
  /** Epoch ms when the record was stored. */
  addedAt: number;
  /** Optional epoch ms after which the record is stale and ignored/purged. */
  expiresAt?: number;
}

/**
 * A threat-intelligence update bundle. Distributed out-of-band and applied via
 * signed OTA updates (PRD §7 "Updatability" / "signed rule updates only").
 */
export interface ThreatBundle {
  /** Monotonically increasing version — older bundles are rejected (anti-rollback). */
  version: number;
  createdAt: number;
  threats?: ThreatRecord[];
  signatures?: ThreatSignature[];
  yaraRules?: YaraRule[];
}

/** A {@link ThreatBundle} wrapped with a detached signature over its payload. */
export interface SignedBundle {
  /** Identifier of the signing key (so the verifier can select a trusted key). */
  keyId: string;
  algorithm: "ed25519";
  /** Canonical JSON of the {@link ThreatBundle} that was signed. */
  payload: string;
  /** Base64 detached signature over {@link payload}. */
  signature: string;
}

/** Backend persistence contract — synchronous to suit an on-device runtime. */
export interface ThreatStoreBackend {
  upsert(records: ThreatRecord[]): void;
  get(indicator: string): ThreatRecord | undefined;
  list(): ThreatRecord[];
  remove(indicator: string): boolean;
  /** Delete records whose `expiresAt` is at or before `now`; returns the count. */
  purgeExpired(now: number): number;
  getMeta(key: string): string | undefined;
  setMeta(key: string, value: string): void;
  close(): void;
}
