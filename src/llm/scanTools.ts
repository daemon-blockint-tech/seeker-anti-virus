import { tool } from "@langchain/core/tools";
import { z } from "zod";
import { IntegratedScanner } from "../integrated-scanner/integratedScanner.js";
import type { ScanTarget } from "../types.js";

/** Serialize a report compactly for the model's context window. */
function summarize(report: { score: number; severity: string; verdict: string; findings: { ruleId: string; title: string; severity: string; source: string }[] }) {
  return {
    score: report.score,
    severity: report.severity,
    verdict: report.verdict,
    findings: report.findings.map((f) => ({
      ruleId: f.ruleId,
      title: f.title,
      severity: f.severity,
      source: f.source,
    })),
  };
}

/**
 * Build LangChain tools over a shared {@link IntegratedScanner} so the LLM agent
 * can re-run local detection layers while reasoning (PRD 5.4 / §9 `agent-tools`).
 *
 * These mirror {@link createAgentTools} but use zod schemas as required by
 * `@langchain/core`'s `tool()` helper.
 */
export function createLangchainScanTools(scanner = new IntegratedScanner()) {
  const scanApp = tool(
    async ({ packageName, text }) => {
      const target: ScanTarget = { id: packageName, kind: "app", text };
      return JSON.stringify(summarize((await scanner.scanLocal(target)).report));
    },
    {
      name: "scan_app",
      description:
        "Run the local behavioral + signature + YARA layers on an installed app. Returns score, severity and findings.",
      schema: z.object({
        packageName: z.string().describe("Android package name"),
        text: z.string().optional().describe("Decoded manifest / extracted strings"),
      }),
    },
  );

  const scanContract = tool(
    async ({ address, text }) => {
      const target: ScanTarget = { id: address, kind: "contract", text };
      return JSON.stringify(summarize(scanner.scanLocal(target).report));
    },
    {
      name: "scan_contract",
      description:
        "Audit a Solana program/token by address (with optional source/bytecode) for rug pulls, honeypots and exploits.",
      schema: z.object({
        address: z.string().describe("Program or token address"),
        text: z.string().optional().describe("Program source or decoded bytecode"),
      }),
    },
  );

  const scanUrl = tool(
    async ({ url, html }) => {
      const target: ScanTarget = { id: url, kind: "url", domain: url, text: html };
      return JSON.stringify(summarize(scanner.scanLocal(target).report));
    },
    {
      name: "scan_url",
      description: "Screen a dApp URL/domain for phishing and look-alike indicators.",
      schema: z.object({
        url: z.string().describe("dApp URL or domain"),
        html: z.string().optional().describe("Optional page HTML"),
      }),
    },
  );

  const listRules = tool(
    async () =>
      JSON.stringify(
        scanner.ruleManager.list().map((r) => ({
          name: r.name,
          category: r.category,
          severity: r.severity,
        })),
      ),
    {
      name: "list_yara_rules",
      description: "List the active YARA rules (names, categories, severities).",
      schema: z.object({}),
    },
  );

  return [scanApp, scanContract, scanUrl, listRules];
}
