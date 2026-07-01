import { describe, expect, it } from "vitest";
import {
  analyzeDomainSpoof,
  skeletonize,
  DomainSpoofDetector,
  IntegratedScanner,
  type ScanTarget,
} from "../src/index.js";

describe("skeletonize", () => {
  it("folds digits and Cyrillic homoglyphs onto the ASCII brand", () => {
    expect(skeletonize("phant0m")).toBe("phantom");
    expect(skeletonize("s0lana")).toBe("solana");
    expect(skeletonize("pһantom")).toBe("phantom"); // Cyrillic һ folded via NFKD/skeleton
  });
});

describe("analyzeDomainSpoof", () => {
  it("flags digit-substitution look-alikes as high", () => {
    const r = analyzeDomainSpoof("phant0m.app");
    expect(r?.brand).toBe("phantom");
    expect(r?.technique).toBe("obfuscation");
    expect(r?.severity).toBe("high");
  });

  it("flags spoofed .skr handles impersonating a wallet", () => {
    const r = analyzeDomainSpoof("phant0m.skr");
    expect(r?.isSkr).toBe(true);
    expect(r?.brand).toBe("phantom");
    expect(r?.severity).toBe("high");
  });

  it("flags an exact-brand .skr handle as a medium caution", () => {
    const r = analyzeDomainSpoof("solflare.skr");
    expect(r?.technique).toBe("skr_impersonation");
    expect(r?.severity).toBe("medium");
  });

  it("flags a typosquat", () => {
    const r = analyzeDomainSpoof("solfare.xyz"); // missing an 'l'
    expect(r?.brand).toBe("solflare");
    expect(r?.technique).toBe("typosquat");
  });

  it("flags a Unicode homograph as critical", () => {
    const r = analyzeDomainSpoof("phаntom.com"); // Cyrillic 'а'
    expect(r?.technique).toBe("homograph");
    expect(r?.severity).toBe("critical");
  });

  it("does not flag a legit exact brand on a normal domain", () => {
    expect(analyzeDomainSpoof("phantom.app")).toBeNull();
  });

  it("skips domains already covered by the static phishing list", () => {
    // s0lana.xyz is in DEFAULT_SIGNATURES → skipped to avoid double-counting.
    expect(analyzeDomainSpoof("s0lana.xyz")).toBeNull();
  });

  it("ignores unrelated domains", () => {
    expect(analyzeDomainSpoof("example.com")).toBeNull();
    expect(analyzeDomainSpoof("github.com")).toBeNull();
  });
});

describe("DomainSpoofDetector + IntegratedScanner", () => {
  it("emits a phishing finding for a spoofed .skr handle", () => {
    const findings = new DomainSpoofDetector().scan({
      id: "phant0m.skr",
      kind: "url",
      domain: "phant0m.skr",
    });
    expect(findings[0]!.ruleId).toBe("PHISH_SKR_SPOOF");
  });

  it("raises a look-alike URL to high severity end-to-end", async () => {
    const scanner = new IntegratedScanner();
    const target: ScanTarget = { id: "phant0m.app", kind: "url", domain: "phant0m.app" };
    const result = await scanner.scan(target);
    expect(result.severity).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "PHISH_DOMAIN_SPOOF")).toBe(true);
  });
});
