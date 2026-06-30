import { describe, expect, it } from "vitest";
import { SignatureMatcher, type ScanTarget } from "../src/index.js";

describe("SignatureMatcher", () => {
  const matcher = new SignatureMatcher();

  it("matches a known phishing look-alike domain", () => {
    const target: ScanTarget = { id: "https://s0lana.xyz/connect", kind: "url" };
    const f = matcher.scan(target).find((x) => x.ruleId === "SIG_PHISHING_LOOKALIKE");
    expect(f).toBeDefined();
    expect(f!.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it("matches honeypot sell-restriction patterns in source", () => {
    const target: ScanTarget = {
      id: "Tok...",
      kind: "contract",
      text: "fn transfer() { require(is_whitelisted(addr)); let can_sell = false; }",
    };
    const ids = matcher.scan(target).map((f) => f.ruleId);
    expect(ids).toContain("SIG_HONEYPOT_SELL_BLOCK");
  });

  it("supports upserting custom signatures", () => {
    const before = matcher.size;
    matcher.upsert([
      {
        id: "SIG_CUSTOM",
        name: "custom",
        category: "malware",
        severity: "low",
        patterns: [/zzz_custom_marker/],
        description: "test",
      },
    ]);
    expect(matcher.size).toBe(before + 1);
    const f = matcher
      .scan({ id: "x", kind: "app", text: "zzz_custom_marker" })
      .find((x) => x.ruleId === "SIG_CUSTOM");
    expect(f).toBeDefined();
  });
});
