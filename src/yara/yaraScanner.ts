import type { Finding, ScanTarget } from "../types.js";
import type { YaraRule, YaraString } from "./rules.js";

/** Result of evaluating one rule against a buffer. */
export interface YaraMatch {
  rule: string;
  matchedStrings: string[];
}

/** Decode raw bytes to a latin1 string so byte patterns survive intact. */
function bytesToText(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]!);
  return out;
}

function buildMatcher(s: YaraString): (haystack: string) => boolean {
  switch (s.type) {
    case "text":
      if (s.nocase) {
        const needle = s.value.toLowerCase();
        return (h) => h.toLowerCase().includes(needle);
      }
      return (h) => h.includes(s.value);
    case "regex": {
      const re = new RegExp(s.value, s.nocase ? "i" : "");
      return (h) => re.test(h);
    }
    case "hex": {
      // "DE AD BE EF" -> raw bytes string
      const raw = s.value
        .replace(/\s+/g, "")
        .match(/.{1,2}/g)!
        .map((b) => String.fromCharCode(parseInt(b, 16)))
        .join("");
      return (h) => h.includes(raw);
    }
  }
}

/**
 * YARA Scanner (PRD 5.3).
 *
 * A self-contained, dependency-free evaluator for the subset of YARA needed by
 * Sync's bundled rules (text/regex/hex strings; all / any / "N of them"
 * conditions). Operates on raw bytes or decoded text and is YARA-export
 * compatible via {@link exportRule}.
 */
export class YaraScanner {
  constructor(private rules: YaraRule[]) {}

  get ruleNames(): string[] {
    return this.rules.map((r) => r.name);
  }

  /** Evaluate every rule against a buffer, returning raw matches. */
  matchBuffer(haystack: string): YaraMatch[] {
    const matches: YaraMatch[] = [];
    for (const rule of this.rules) {
      const hit: string[] = [];
      for (const s of rule.strings) {
        if (buildMatcher(s)(haystack)) hit.push(s.id);
      }
      if (this.conditionMet(rule, hit.length, rule.strings.length)) {
        matches.push({ rule: rule.name, matchedStrings: hit });
      }
    }
    return matches;
  }

  /** Scan a target's bytes and/or text, producing normalized findings. */
  scan(target: ScanTarget): Finding[] {
    const haystacks: string[] = [];
    if (target.bytes) haystacks.push(bytesToText(target.bytes));
    if (target.text) haystacks.push(target.text);
    if (haystacks.length === 0) return [];

    const haystack = haystacks.join("\n");
    const findings: Finding[] = [];

    for (const match of this.matchBuffer(haystack)) {
      const rule = this.rules.find((r) => r.name === match.rule)!;
      findings.push({
        source: "yara",
        ruleId: rule.name,
        title: rule.name.replace(/^Sync_/, "").replace(/_/g, " "),
        description: rule.meta.description,
        category: rule.category,
        severity: rule.severity,
        confidence: this.confidenceFor(rule, match.matchedStrings.length),
        evidence: match.matchedStrings,
      });
    }

    return findings;
  }

  private conditionMet(rule: YaraRule, hits: number, total: number): boolean {
    if (rule.condition === "all") return hits === total;
    if (rule.condition === "any") return hits > 0;
    return hits >= rule.condition.atLeast;
  }

  private confidenceFor(rule: YaraRule, hits: number): number {
    const total = rule.strings.length;
    return Math.min(0.98, 0.5 + 0.5 * (hits / Math.max(1, total)));
  }

  /** Export a rule in YARA source format for interoperability (PRD 5.3). */
  static exportRule(rule: YaraRule): string {
    const lines: string[] = [`rule ${rule.name} {`, "  meta:"];
    lines.push(`    description = ${JSON.stringify(rule.meta.description)}`);
    lines.push(`    category = ${JSON.stringify(rule.category)}`);
    lines.push(`    severity = ${JSON.stringify(rule.severity)}`);
    if (rule.meta.author) lines.push(`    author = ${JSON.stringify(rule.meta.author)}`);
    lines.push("  strings:");
    for (const s of rule.strings) {
      const mods = s.nocase ? " nocase" : "";
      if (s.type === "regex") lines.push(`    ${s.id} = /${s.value}/${s.nocase ? "i" : ""}`);
      else if (s.type === "hex") lines.push(`    ${s.id} = { ${s.value} }`);
      else lines.push(`    ${s.id} = ${JSON.stringify(s.value)}${mods}`);
    }
    lines.push("  condition:");
    if (rule.condition === "all") lines.push("    all of them");
    else if (rule.condition === "any") lines.push("    any of them");
    else lines.push(`    ${rule.condition.atLeast} of them`);
    lines.push("}");
    return lines.join("\n");
  }
}
