/**
 * Demo: Phase 3 LLM threat classifier (PRD 5.4).
 *
 * Requires OPENROUTER_API_KEY (and optionally OPENROUTER_MODEL) in the
 * environment. The LLM is only invoked when local layers push the interim
 * score above `llmEscalationThreshold`.
 *
 * Usage: OPENROUTER_API_KEY=... npm run demo:llm
 */
import { IntegratedScanner, makeLlmClassifier, type ScanTarget } from "../src/index.js";

if (!process.env.OPENROUTER_API_KEY) {
  console.error("Set OPENROUTER_API_KEY to run the LLM demo (see .env.example).");
  process.exit(1);
}

const scanner = new IntegratedScanner({
  llm: makeLlmClassifier(),
  llmEscalationThreshold: 50,
});

const target: ScanTarget = {
  id: "AmbiguousToken1111111111111111111111111111",
  kind: "contract",
  label: "Ambiguous token contract",
  text: "pub fn transfer() { if !is_whitelisted(to) { return Err; } } mint_authority = owner;",
};

const result = await scanner.scan(target);
console.log(`Score: ${result.score}/100  Severity: ${result.severity}  Verdict: ${result.report.verdict}`);
console.log(`Escalated to LLM: ${result.score >= 50}`);
for (const f of result.findings) {
  console.log(`  - [${f.severity}] ${f.title} (${f.source})`);
}
console.log("\nRemediation:");
for (const r of result.report.remediation) console.log(`  • ${r}`);
