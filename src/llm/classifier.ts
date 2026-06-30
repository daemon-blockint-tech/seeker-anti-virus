import { HumanMessage, SystemMessage } from "@langchain/core/messages";
import type { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { tool } from "@langchain/core/tools";
import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { z } from "zod";
import { IntegratedScanner } from "../integrated-scanner/integratedScanner.js";
import type { LlmClassifier } from "../integrated-scanner/integratedScanner.js";
import type { Finding, ScanTarget, ThreatCategory } from "../types.js";
import { createOpenRouterModel } from "./openrouter.js";
import { createLangchainScanTools } from "./scanTools.js";

const CATEGORIES: [ThreatCategory, ...ThreatCategory[]] = [
  "malware",
  "spyware",
  "trojan",
  "exploit",
  "phishing",
  "rug_pull",
  "honeypot",
  "drainer",
  "permission_abuse",
  "c2",
  "unknown",
];

/** Schema the model must use to report its final classification (PRD 5.4). */
const classificationSchema = z.object({
  findings: z
    .array(
      z.object({
        ruleId: z.string().describe("Stable id, e.g. LLM_DRAINER_FLOW"),
        title: z.string(),
        description: z.string().describe("Plain-language explanation for the user"),
        category: z.enum(CATEGORIES),
        severity: z.enum(["low", "medium", "high", "critical"]),
        confidence: z.number().min(0).max(1),
        evidence: z.array(z.string()).optional(),
      }),
    )
    .describe("Zero or more threats. Empty array means the target looks safe."),
});

const DEFAULT_SYSTEM_PROMPT = `You are Sync, an on-device security analyst for the Solana Mobile Seeker.
You receive a scan target (app, contract, token, URL, or transaction) and the findings already produced by the local behavioral, signature, and YARA layers.

Your job:
- Reason about whether these signals add up to a real threat to the user's wallet and keys.
- Use the provided tools to re-scan or cross-reference when it helps.
- Focus on crypto-native risks: wallet drainers, rug pulls, honeypots, seed-phrase theft, phishing, and C2/RAT behavior.
- Avoid false positives on novel-but-legitimate contracts; calibrate confidence accordingly.

When finished, you MUST call submit_classification exactly once with your conclusions.
Add findings only for genuine, well-supported threats; return an empty array if the target looks safe.`;

export interface LlmClassifierOptions {
  /** Chat model to drive the agent. Defaults to an OpenRouter-backed model. */
  model?: BaseChatModel;
  /** Scanner whose tools the agent can call. Defaults to a fresh instance. */
  scanner?: IntegratedScanner;
  /** Override the system prompt. */
  systemPrompt?: string;
  /** Max agent iterations (recursion limit). */
  recursionLimit?: number;
}

/** Render the target + prior findings into a compact prompt for the agent. */
function renderContext(target: ScanTarget, priorFindings: Finding[]): string {
  const lines = [
    `TARGET: ${target.label ?? target.id} (kind=${target.kind}, id=${target.id})`,
  ];
  if (target.domain) lines.push(`DOMAIN: ${target.domain}`);
  if (target.permissions?.length) lines.push(`PERMISSIONS: ${target.permissions.join(", ")}`);
  if (target.text) lines.push(`CONTENT (truncated): ${target.text.slice(0, 1500)}`);
  lines.push("", "LOCAL FINDINGS:");
  if (priorFindings.length === 0) {
    lines.push("  (none — local layers found nothing)");
  } else {
    for (const f of priorFindings) {
      lines.push(`  - [${f.severity}] ${f.title} (${f.source}/${f.ruleId}, conf ${f.confidence.toFixed(2)})`);
    }
  }
  return lines.join("\n");
}

/**
 * LLM Threat Classifier (PRD 5.4).
 *
 * Returns an {@link LlmClassifier} compatible with
 * {@link IntegratedScanner}'s opt-in `llm` hook. Internally it runs a LangGraph
 * ReAct agent (model + Sync scan tools) and captures the model's structured
 * conclusions via a mandatory `submit_classification` tool call.
 */
export function makeLlmClassifier(options: LlmClassifierOptions = {}): LlmClassifier {
  const model = options.model ?? createOpenRouterModel();
  const scanner = options.scanner ?? new IntegratedScanner();
  const systemPrompt = options.systemPrompt ?? DEFAULT_SYSTEM_PROMPT;
  const recursionLimit = options.recursionLimit ?? 8;

  return async (target: ScanTarget, priorFindings: Finding[]): Promise<Finding[]> => {
    // Capture findings per-invocation so concurrent scans don't interleave.
    const captured: Finding[] = [];

    const submit = tool(
      async ({ findings }) => {
        for (const f of findings) {
          captured.push({ source: "llm", ...f });
        }
        return `Recorded ${findings.length} finding(s).`;
      },
      {
        name: "submit_classification",
        description:
          "Report your final threat classification. Call this exactly once when done.",
        schema: classificationSchema,
      },
    );

    const agent = createReactAgent({
      llm: model,
      tools: [...createLangchainScanTools(scanner), submit],
      stateModifier: new SystemMessage(systemPrompt),
    });

    await agent.invoke(
      { messages: [new HumanMessage(renderContext(target, priorFindings))] },
      { recursionLimit },
    );

    return captured;
  };
}
