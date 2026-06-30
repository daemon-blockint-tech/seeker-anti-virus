import { describe, expect, it } from "vitest";
import { BehavioralScanner, type ScanTarget } from "../src/index.js";

describe("BehavioralScanner", () => {
  const scanner = new BehavioralScanner();

  it("flags the clipboard + accessibility drainer combo as high severity", () => {
    const target: ScanTarget = {
      id: "com.evil.app",
      kind: "app",
      permissions: ["READ_CLIPBOARD", "BIND_ACCESSIBILITY_SERVICE"],
    };
    const findings = scanner.scan(target);
    const perm = findings.find((f) => f.ruleId === "BEH_DANGEROUS_PERMISSIONS");
    expect(perm).toBeDefined();
    expect(perm!.severity).toBe("high");
  });

  it("detects C2 endpoints and unsigned binary loads", () => {
    const target: ScanTarget = {
      id: "com.rat.app",
      kind: "app",
      events: [
        { type: "network", timestamp: 1, host: "185.23.44.1", port: 4444 },
        { type: "binary_load", timestamp: 2, source: "/data/x.so", unsigned: true },
      ],
    };
    const ids = scanner.scan(target).map((f) => f.ruleId);
    expect(ids).toContain("BEH_C2_NETWORK");
    expect(ids).toContain("BEH_BINARY_INJECTION");
  });

  it("flags large anomalous transfers", () => {
    const target: ScanTarget = {
      id: "com.app",
      kind: "app",
      events: [
        { type: "crypto_transaction", timestamp: 1, amountLamports: 9e9, targetAddress: "X" },
      ],
    };
    const f = scanner.scan(target).find((x) => x.ruleId === "BEH_ANOMALOUS_TRANSFER");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("high");
  });

  it("scales confidence up for very large transfers", () => {
    const big = scanner
      .scan({ id: "a", kind: "app", events: [{ type: "crypto_transaction", timestamp: 1, amountLamports: 60e9 }] })
      .find((x) => x.ruleId === "BEH_ANOMALOUS_TRANSFER");
    expect(big!.confidence).toBeGreaterThan(0.9);
  });

  it("returns no findings for a benign app", () => {
    expect(scanner.scan({ id: "com.good", kind: "app", permissions: [] })).toHaveLength(0);
  });
});
