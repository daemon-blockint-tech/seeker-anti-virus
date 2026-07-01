import { describe, expect, it } from "vitest";
import {
  BehavioralScanner,
  SignatureMatcher,
  YaraScanner,
  SOLANA_YARA_RULES,
  IntegratedScanner,
  type BehaviorEvent,
  type ScanTarget,
} from "../src/index.js";

/** N file_access events, each written back encrypted with a ransom extension. */
function encryptionEvents(n: number, ext = ".locked"): BehaviorEvent[] {
  return Array.from({ length: n }, (_, i) => ({
    type: "file_access" as const,
    timestamp: i,
    filePath: `/sdcard/DCIM/img_${i}.jpg`,
    encrypted: true,
    newExtension: ext,
  }));
}

describe("ransomware — behavioral", () => {
  const scanner = new BehavioralScanner();

  it("flags mass file encryption as critical", () => {
    const target: ScanTarget = { id: "com.locker", kind: "app", events: encryptionEvents(12) };
    const f = scanner.scan(target).find((x) => x.ruleId === "BEH_RANSOMWARE_ENCRYPTION");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("critical");
    expect(f!.category).toBe("ransomware");
  });

  it("does not flag a handful of encrypted files", () => {
    const f = scanner
      .scan({ id: "a", kind: "app", events: encryptionEvents(3) })
      .find((x) => x.ruleId === "BEH_RANSOMWARE_ENCRYPTION");
    expect(f).toBeUndefined();
  });

  it("flags a device wipe request as critical", () => {
    const f = scanner
      .scan({ id: "a", kind: "app", events: [{ type: "device_admin", timestamp: 1, adminAction: "wipe" }] })
      .find((x) => x.ruleId === "BEH_DEVICE_ADMIN_ABUSE");
    expect(f!.severity).toBe("critical");
  });

  it("flags a screen-lock request as high", () => {
    const f = scanner
      .scan({ id: "a", kind: "app", events: [{ type: "device_admin", timestamp: 1, adminAction: "lock" }] })
      .find((x) => x.ruleId === "BEH_DEVICE_ADMIN_ABUSE");
    expect(f!.severity).toBe("high");
  });
});

describe("ransomware — signature & YARA", () => {
  it("matches a ransom note via signature", () => {
    const f = new SignatureMatcher()
      .scan({ id: "x", kind: "app", text: "All your files have been encrypted! Pay the ransom in Bitcoin to get the decryption key." })
      .find((x) => x.ruleId === "SIG_RANSOMWARE_NOTE");
    expect(f).toBeDefined();
    expect(f!.severity).toBe("critical");
  });

  it("matches the Sync_Ransomware YARA rule", () => {
    const scanner = new YaraScanner(SOLANA_YARA_RULES);
    const text = "cipher = AES/CBC/PKCS5Padding; note: your files have been encrypted";
    const f = scanner.scan({ id: "k", kind: "app", text }).find((x) => x.ruleId === "Sync_Ransomware");
    expect(f).toBeDefined();
    expect(f!.category).toBe("ransomware");
  });
});

describe("ransomware — integrated", () => {
  it("blocks a ransomware app with remediation", async () => {
    const result = await new IntegratedScanner().scan({
      id: "com.evil.locker",
      kind: "app",
      text: "AES/CBC/PKCS5Padding; DevicePolicyManager; your files have been encrypted, send SOL for the decryption key",
      events: encryptionEvents(15),
    });
    expect(result.severity).toBe("critical");
    expect(result.report.verdict).toBe("blocked");
    expect(result.report.remediation.some((r) => /ransom/i.test(r))).toBe(true);
  });
});
