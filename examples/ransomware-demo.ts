/**
 * Demo: detect a mobile ransomware app across all three layers.
 * Usage: npm run demo:ransomware
 */
import { IntegratedScanner, type BehaviorEvent, type ScanTarget } from "../src/index.js";

const encryption: BehaviorEvent[] = Array.from({ length: 18 }, (_, i) => ({
  type: "file_access",
  timestamp: i,
  filePath: `/sdcard/DCIM/photo_${i}.jpg`,
  encrypted: true,
  newExtension: ".locked",
}));

const target: ScanTarget = {
  id: "com.fake.cleaner",
  kind: "app",
  label: "Fake Cleaner (ransomware)",
  text: "AES/CBC/PKCS5Padding; DevicePolicyManager.lockNow(); All your files have been encrypted! Send 0.5 SOL for the decryption key.",
  events: [...encryption, { type: "device_admin", timestamp: 99, adminAction: "lock" }],
};

const { report } = await new IntegratedScanner().scan(target);
console.log(`${report.target.label}: ${report.score}/100 ${report.severity} → ${report.verdict}\n`);
console.log("Findings:");
for (const f of report.findings) {
  console.log(`  - [${f.severity}] ${f.title} (${f.source}/${f.category})`);
}
console.log("\nRemediation:");
for (const r of report.remediation) console.log(`  • ${r}`);
