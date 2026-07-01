/**
 * Demo: on-device threat DB + signed OTA update (PRD §8 / §7).
 * Usage: npm run demo:threatdb
 */
import { randomBytes } from "node:crypto";
import {
  ThreatStore,
  SqliteBackend,
  OtaUpdater,
  BundleSigner,
  BundleVerifier,
  IntegratedScanner,
  type ThreatBundle,
} from "../src/index.js";

// 1. The update publisher signs bundles with an Ed25519 key.
const { signer, publicKeyPem } = BundleSigner.generate("sync-2026");

// 2. The device trusts that key and uses an encrypted SQLite store.
const store = new ThreatStore(new SqliteBackend({ encryptionKey: randomBytes(32) }));
const scanner = new IntegratedScanner();
const updater = new OtaUpdater(new BundleVerifier({ "sync-2026": publicKeyPem }));

const bundle: ThreatBundle = {
  version: 1,
  createdAt: Date.now(),
  threats: [
    {
      id: "drainer-2026-001",
      indicator: "Drainer1111111111111111111111111111111111111",
      indicatorKind: "program",
      category: "drainer",
      severity: "critical",
      description: "Known wallet-drainer program.",
      source: "sync-feed",
      addedAt: Date.now(),
    },
  ],
  signatures: [
    {
      id: "SIG_OTA_PHISH",
      name: "OTA phishing domain",
      category: "phishing",
      severity: "high",
      domains: ["drainer-mint.xyz"],
      description: "Phishing domain delivered via OTA feed.",
    },
  ],
};

const result = updater.apply(signer.sign(bundle), { store, signatureMatcher: scanner.signatureMatcher });
console.log(`Applied OTA v${result.version}:`, result.counts);
console.log(`Store version: ${store.version}, records: ${store.size}`);

// 3. The new intel is now live in scans.
const hit = store.scan({
  id: "com.app",
  kind: "app",
  events: [{ type: "crypto_transaction", timestamp: Date.now(), programId: "Drainer1111111111111111111111111111111111111" }],
});
console.log("Threat-DB match:", hit.map((f) => `${f.severity} ${f.title}`));

const phish = await scanner.scan({ id: "drainer-mint.xyz", kind: "url", domain: "drainer-mint.xyz" });
console.log(`OTA signature caught phishing domain: ${phish.severity} (${phish.report.verdict})`);

// 4. A rolled-back bundle is rejected.
try {
  updater.apply(signer.sign({ ...bundle, version: 1 }), { store });
} catch (e) {
  console.log("Rollback rejected:", (e as Error).message);
}

store.close();
