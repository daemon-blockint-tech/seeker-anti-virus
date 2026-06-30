/**
 * Sync — Solana Mobile Seeker Anti-Virus detection engine.
 *
 * Public entry point re-exporting the core modules described in the PRD
 * (sections 5 & 9): scanner, signatures, analyzer, monitor, yara,
 * integrated-scanner and agent-tools.
 */

export * from "./types.js";

// Behavioral scanner (PRD 5.1)
export { BehavioralScanner } from "./scanner/behavioralScanner.js";
export type { BehavioralScannerOptions } from "./scanner/behavioralScanner.js";

// Signature matching (PRD 5.2)
export { SignatureMatcher } from "./signatures/signatureMatcher.js";
export { DEFAULT_SIGNATURES } from "./signatures/signatureDatabase.js";
export type { ThreatSignature } from "./signatures/signatureDatabase.js";

// Analyzer (PRD §9)
export { RiskScorer } from "./analyzer/riskScorer.js";
export type { RiskResult } from "./analyzer/riskScorer.js";
export { ReportGenerator } from "./analyzer/reportGenerator.js";
export type { ThreatReport } from "./analyzer/reportGenerator.js";

// YARA (PRD 5.3)
export { YaraScanner } from "./yara/yaraScanner.js";
export type { YaraMatch } from "./yara/yaraScanner.js";
export { RuleManager } from "./yara/ruleManager.js";
export { SOLANA_YARA_RULES } from "./yara/rules.js";
export type { YaraRule, YaraString } from "./yara/rules.js";

// Real-time monitor (PRD §9)
export { Monitor } from "./monitor/monitor.js";
export type { ThreatAlert, AlertHandler, MonitorOptions } from "./monitor/monitor.js";

// Integrated pipeline (PRD §9)
export { IntegratedScanner } from "./integrated-scanner/integratedScanner.js";
export type {
  IntegratedScannerOptions,
  ScanResult,
  LlmClassifier,
} from "./integrated-scanner/integratedScanner.js";

// LLM agent tools (PRD §9)
export { createAgentTools } from "./agent-tools/tools.js";
export type { AgentTool } from "./agent-tools/tools.js";

// LLM threat classifier — Phase 3 (PRD 5.4)
export { makeLlmClassifier } from "./llm/classifier.js";
export type { LlmClassifierOptions } from "./llm/classifier.js";
export { createOpenRouterModel, DEFAULT_OPENROUTER_MODEL } from "./llm/openrouter.js";
export type { OpenRouterOptions } from "./llm/openrouter.js";
export { createLangchainScanTools } from "./llm/scanTools.js";

// Public scanning API + x402 micropayments — Phase 5 (PRD §6.5, FR-14/16)
export { SyncApiServer } from "./api/server.js";
export type { SyncApiServerOptions } from "./api/server.js";
export {
  PaymentGate,
  HmacPaymentVerifier,
  encodePaymentHeader,
  X402_VERSION,
  USDC_MINT,
} from "./api/x402.js";
export type {
  PaymentRequirements,
  PaymentPayload,
  PaymentVerifier,
  VerificationResult,
  PaymentGateOptions,
  GateResult,
} from "./api/x402.js";
