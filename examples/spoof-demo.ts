/**
 * Demo: .skr / look-alike domain spoof detection (FR-7b).
 * Usage: npm run demo:spoof
 */
import { analyzeDomainSpoof } from "../src/index.js";

const domains = [
  "phantom.app", // legit
  "phant0m.app", // digit obfuscation
  "phаntom.com", // Cyrillic homograph
  "phant0m.skr", // spoofed .skr handle
  "solflare.skr", // exact brand .skr — verify ownership
  "solfare.xyz", // typosquat
  "magiceden-mint.io", // contains brand but not a look-alike of the label
  "example.com", // benign
];

for (const d of domains) {
  const r = analyzeDomainSpoof(d);
  if (!r) {
    console.log(`${d.padEnd(20)} → clean`);
  } else {
    console.log(
      `${d.padEnd(20)} → ${r.severity.toUpperCase()} ${r.technique} (${r.brand})${r.isSkr ? " [.skr]" : ""}`,
    );
  }
}
