import { IntegratedScanner } from "../integrated-scanner/integratedScanner.js";
import { RuleManager } from "../yara/ruleManager.js";
import type { YaraRule } from "../yara/rules.js";
import type { ScanTarget } from "../types.js";

/**
 * A provider-agnostic tool definition shaped for DeepAgentsJS / OpenRouter
 * function-calling (PRD §8, core module `agent-tools`). `parameters` follows the
 * JSON-Schema subset used by tool-calling LLMs.
 */
export interface AgentTool {
  name: string;
  description: string;
  parameters: {
    type: "object";
    properties: Record<string, unknown>;
    required?: string[];
  };
  /** Execute the tool with validated arguments. */
  handler: (args: Record<string, unknown>) => Promise<unknown> | unknown;
}

/**
 * Build the LLM agent tool-belt over a shared {@link IntegratedScanner}.
 *
 * Exposes the scanning surface (FR-14), YARA rule management (FR-15) and report
 * lookups so a DeepAgentsJS agent can drive the engine during LLM
 * classification (PRD 5.4).
 */
export function createAgentTools(scanner = new IntegratedScanner()): AgentTool[] {
  const asTarget = (args: Record<string, unknown>, kind: ScanTarget["kind"]): ScanTarget => ({
    id: String(args.id ?? args.address ?? args.url ?? args.package ?? "unknown"),
    kind,
    label: args.label ? String(args.label) : undefined,
    text: args.text ? String(args.text) : undefined,
    domain: args.domain ? String(args.domain) : undefined,
  });

  return [
    {
      name: "scan_app",
      description:
        "Scan an installed app (by package name and optional decoded manifest/text) for malware, spyware and RATs.",
      parameters: {
        type: "object",
        properties: {
          package: { type: "string", description: "Android package name" },
          text: { type: "string", description: "Decoded manifest / extracted strings" },
        },
        required: ["package"],
      },
      handler: async (args) => (await scanner.scan(asTarget(args, "app"))).report,
    },
    {
      name: "scan_contract",
      description:
        "Audit a Solana smart contract / token by address (and optional source/bytecode text) for rug pulls, honeypots and exploits.",
      parameters: {
        type: "object",
        properties: {
          address: { type: "string", description: "Program or token address" },
          text: { type: "string", description: "Program source or decoded bytecode" },
        },
        required: ["address"],
      },
      handler: async (args) => (await scanner.scan(asTarget(args, "contract"))).report,
    },
    {
      name: "scan_url",
      description: "Screen a dApp URL/domain for phishing and look-alike indicators.",
      parameters: {
        type: "object",
        properties: {
          url: { type: "string", description: "dApp URL or domain" },
          text: { type: "string", description: "Optional page HTML" },
        },
        required: ["url"],
      },
      handler: async (args) => {
        const t = asTarget(args, "url");
        t.domain = t.domain ?? t.id;
        return (await scanner.scan(t)).report;
      },
    },
    {
      name: "scan_text",
      description: "Run signature + YARA scanning over an arbitrary text/code blob (FR-14).",
      parameters: {
        type: "object",
        properties: { text: { type: "string" } },
        required: ["text"],
      },
      handler: async (args) =>
        (await scanner.scan({ id: "text-blob", kind: "app", text: String(args.text) })).report,
    },
    {
      name: "list_yara_rules",
      description: "List the active YARA rules (names, categories, severities).",
      parameters: { type: "object", properties: {} },
      handler: () =>
        scanner.ruleManager.list().map((r) => ({
          name: r.name,
          category: r.category,
          severity: r.severity,
          description: r.meta.description,
        })),
    },
    {
      name: "add_yara_rule",
      description: "Add or replace a custom YARA rule (FR-15).",
      parameters: {
        type: "object",
        properties: { rule: { type: "object", description: "A YaraRule object" } },
        required: ["rule"],
      },
      handler: (args) => {
        const rule = args.rule as YaraRule;
        RuleManager.validate(rule);
        scanner.ruleManager.add(rule);
        return { ok: true, name: rule.name };
      },
    },
    {
      name: "export_yara_rules",
      description: "Export all active rules in YARA source format for external tooling.",
      parameters: { type: "object", properties: {} },
      handler: () => scanner.ruleManager.exportAll(),
    },
  ];
}
