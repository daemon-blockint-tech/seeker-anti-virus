import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { AIMessage, type BaseMessage } from "@langchain/core/messages";
import { BaseChatModel, type BaseChatModelParams } from "@langchain/core/language_models/chat_models";
import type { ChatResult } from "@langchain/core/outputs";
import {
  makeLlmClassifier,
  createOpenRouterModel,
  DEFAULT_OPENROUTER_MODEL,
  IntegratedScanner,
  type Finding,
  type ScanTarget,
} from "../src/index.js";

/**
 * A scripted chat model: returns the queued AIMessage on each call so the
 * ReAct agent loop runs fully offline.
 */
class ScriptedChatModel extends BaseChatModel {
  private i = 0;
  constructor(private script: AIMessage[], params: BaseChatModelParams = {}) {
    super(params);
  }
  _llmType() {
    return "scripted";
  }
  override bindTools() {
    return this;
  }
  async _generate(_messages: BaseMessage[]): Promise<ChatResult> {
    const message = this.script[Math.min(this.i, this.script.length - 1)]!;
    this.i++;
    return { generations: [{ message, text: String(message.content) }] };
  }
}

describe("createOpenRouterModel", () => {
  const saved = { ...process.env };
  beforeEach(() => {
    delete process.env.OPENROUTER_API_KEY;
    delete process.env.OPENROUTER_MODEL;
  });
  afterEach(() => {
    process.env = { ...saved };
  });

  it("throws when no API key is configured", () => {
    expect(() => createOpenRouterModel()).toThrow(/API key/i);
  });

  it("builds a model with the env / default slug", () => {
    const m = createOpenRouterModel({ apiKey: "sk-test" });
    expect(m.model).toBe(DEFAULT_OPENROUTER_MODEL);
    const m2 = createOpenRouterModel({ apiKey: "sk-test", model: "openai/gpt-4o" });
    expect(m2.model).toBe("openai/gpt-4o");
  });
});

describe("makeLlmClassifier", () => {
  it("captures the model's submit_classification call as llm findings", async () => {
    const submitCall = new AIMessage({
      content: "",
      tool_calls: [
        {
          id: "c1",
          name: "submit_classification",
          args: {
            findings: [
              {
                ruleId: "LLM_DRAINER_FLOW",
                title: "Wallet drainer signing flow",
                description: "App combines clipboard access with unlimited token approval.",
                category: "drainer",
                severity: "critical",
                confidence: 0.9,
                evidence: ["unlimited approve", "clipboard read"],
              },
            ],
          },
        },
      ],
    });
    const done = new AIMessage({ content: "Classification submitted." });

    const classify = makeLlmClassifier({
      model: new ScriptedChatModel([submitCall, done]),
    });

    const target: ScanTarget = { id: "com.evil", kind: "app" };
    const prior: Finding[] = [];
    const findings = await classify(target, prior);

    expect(findings).toHaveLength(1);
    expect(findings[0]!.source).toBe("llm");
    expect(findings[0]!.ruleId).toBe("LLM_DRAINER_FLOW");
    expect(findings[0]!.severity).toBe("critical");
  });

  it("returns an empty array when the model reports no threats", async () => {
    const submitCall = new AIMessage({
      content: "",
      tool_calls: [{ id: "c1", name: "submit_classification", args: { findings: [] } }],
    });
    const classify = makeLlmClassifier({
      model: new ScriptedChatModel([submitCall, new AIMessage({ content: "done" })]),
    });
    expect(await classify({ id: "com.good", kind: "app" }, [])).toEqual([]);
  });

  it("integrates as the IntegratedScanner opt-in llm hook", async () => {
    const submitCall = new AIMessage({
      content: "",
      tool_calls: [
        {
          id: "c1",
          name: "submit_classification",
          args: {
            findings: [
              {
                ruleId: "LLM_CONFIRMED_HONEYPOT",
                title: "Confirmed honeypot",
                description: "Sell path is gated behind a whitelist.",
                category: "honeypot",
                severity: "critical",
                confidence: 0.95,
              },
            ],
          },
        },
      ],
    });
    const classifier = makeLlmClassifier({
      model: new ScriptedChatModel([submitCall, new AIMessage({ content: "done" })]),
    });
    const scanner = new IntegratedScanner({ llm: classifier, llmEscalationThreshold: 40 });

    // A signature hit pushes the interim score above the threshold, triggering the LLM.
    const result = await scanner.scan({
      id: "Tok111",
      kind: "contract",
      text: "is_whitelisted; can_sell = false; transfer_hook",
    });

    const llmFinding = result.findings.find((f) => f.ruleId === "LLM_CONFIRMED_HONEYPOT");
    expect(llmFinding).toBeDefined();
    expect(result.severity).toBe("critical");
  });
});
