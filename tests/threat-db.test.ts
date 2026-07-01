import { describe, expect, it } from "vitest";
import { randomBytes } from "node:crypto";
import {
  ThreatStore,
  InMemoryBackend,
  SqliteBackend,
  OtaUpdater,
  BundleSigner,
  BundleVerifier,
  BundleVerificationError,
  type ThreatBundle,
  type ThreatRecord,
  type ScanTarget,
} from "../src/index.js";

const drainer: ThreatRecord = {
  id: "drainer-2026-001",
  indicator: "Drainer1111111111111111111111111111111111111",
  indicatorKind: "program",
  category: "drainer",
  severity: "critical",
  description: "Known wallet-drainer program.",
  source: "sync-feed",
  addedAt: Date.now(),
};

describe("ThreatStore", () => {
  it("matches a stored indicator against a scan target's program id", () => {
    const store = new ThreatStore();
    store.add([drainer]);
    const target: ScanTarget = {
      id: "com.app",
      kind: "app",
      events: [{ type: "crypto_transaction", timestamp: 1, programId: drainer.indicator }],
    };
    const findings = store.scan(target);
    expect(findings).toHaveLength(1);
    expect(findings[0]!.ruleId).toBe("THREATDB:drainer-2026-001");
    expect(findings[0]!.severity).toBe("critical");
  });

  it("ignores and purges expired records", () => {
    const store = new ThreatStore();
    store.add([{ ...drainer, expiresAt: 1000 }]);
    expect(store.lookup(drainer.indicator, 2000)).toBeUndefined();
    expect(store.purgeExpired(2000)).toBe(1);
    expect(store.size).toBe(0);
  });
});

describe("SqliteBackend", () => {
  it("persists and queries records", () => {
    const store = new ThreatStore(new SqliteBackend());
    store.add([drainer]);
    expect(store.lookup(drainer.indicator)?.id).toBe("drainer-2026-001");
    expect(store.size).toBe(1);
    store.close();
  });

  it("encrypts at rest while staying queryable", () => {
    const backend = new SqliteBackend({ encryptionKey: randomBytes(32) });
    backend.upsert([drainer]);
    expect(backend.get(drainer.indicator)?.description).toBe(drainer.description);
    backend.close();
  });

  it("rejects a wrong-length encryption key", () => {
    expect(() => new SqliteBackend({ encryptionKey: randomBytes(16) })).toThrow(/32 bytes/);
  });

  it("behaves identically to the in-memory backend for purge", () => {
    const sqlite = new SqliteBackend();
    sqlite.upsert([{ ...drainer, expiresAt: 500 }]);
    expect(sqlite.purgeExpired(1000)).toBe(1);
    sqlite.close();
  });
});

describe("Signed OTA updates", () => {
  const { signer, publicKeyPem } = BundleSigner.generate("sync-2026");
  const verifier = new BundleVerifier({ "sync-2026": publicKeyPem });

  const bundle: ThreatBundle = {
    version: 5,
    createdAt: Date.now(),
    threats: [drainer],
    signatures: [
      {
        id: "SIG_OTA_TEST",
        name: "ota signature",
        category: "phishing",
        severity: "high",
        domains: ["evil-ota.xyz"],
        description: "delivered via OTA",
      },
    ],
  };

  it("applies a validly signed, newer bundle", () => {
    const store = new ThreatStore();
    const updater = new OtaUpdater(verifier);
    const result = updater.apply(signer.sign(bundle), { store });
    expect(result.applied).toBe(true);
    expect(result.version).toBe(5);
    expect(result.counts.threats).toBe(1);
    expect(store.version).toBe(5);
    expect(store.lookup(drainer.indicator)).toBeDefined();
  });

  it("rejects a tampered payload", () => {
    const store = new ThreatStore();
    const updater = new OtaUpdater(verifier);
    const signed = signer.sign(bundle);
    const tampered = { ...signed, payload: signed.payload.replace("critical", "low") };
    expect(() => updater.apply(tampered, { store })).toThrow(BundleVerificationError);
  });

  it("rejects an untrusted signing key", () => {
    const other = BundleSigner.generate("attacker");
    const updater = new OtaUpdater(verifier);
    expect(() => updater.apply(other.signer.sign(bundle), { store: new ThreatStore() })).toThrow(
      /untrusted key/,
    );
  });

  it("rejects a stale (rollback) bundle version", () => {
    const store = new ThreatStore();
    const updater = new OtaUpdater(verifier);
    updater.apply(signer.sign(bundle), { store });
    const older = signer.sign({ ...bundle, version: 4 });
    expect(() => updater.apply(older, { store })).toThrow(/stale bundle/);
  });

  it("merges signatures from a bundle into a SignatureMatcher", async () => {
    const { IntegratedScanner } = await import("../src/index.js");
    const scanner = new IntegratedScanner();
    const before = scanner.signatureMatcher.size;
    new OtaUpdater(verifier).apply(signer.sign(bundle), {
      store: new ThreatStore(),
      signatureMatcher: scanner.signatureMatcher,
    });
    expect(scanner.signatureMatcher.size).toBe(before + 1);
    const result = await scanner.scan({ id: "evil-ota.xyz", kind: "url", domain: "evil-ota.xyz" });
    expect(result.findings.some((f) => f.ruleId === "SIG_OTA_TEST")).toBe(true);
  });
});
