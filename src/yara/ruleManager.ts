import type { YaraRule } from "./rules.js";
import { SOLANA_YARA_RULES } from "./rules.js";
import { YaraScanner } from "./yaraScanner.js";

/**
 * Rule Manager (PRD core module `yara/`, FR-15).
 *
 * Owns the live YARA rule set: bundled Solana rules plus user/custom rules.
 * Supports add / remove / list / export and hands out a configured
 * {@link YaraScanner}.
 */
export class RuleManager {
  private rules = new Map<string, YaraRule>();

  constructor(initial: YaraRule[] = SOLANA_YARA_RULES) {
    for (const r of initial) this.rules.set(r.name, r);
  }

  list(): YaraRule[] {
    return [...this.rules.values()];
  }

  get(name: string): YaraRule | undefined {
    return this.rules.get(name);
  }

  /** Add or replace a (custom) rule. Throws on a structurally invalid rule. */
  add(rule: YaraRule): void {
    RuleManager.validate(rule);
    this.rules.set(rule.name, rule);
  }

  remove(name: string): boolean {
    return this.rules.delete(name);
  }

  /** Build a scanner over the current rule set. */
  scanner(): YaraScanner {
    return new YaraScanner(this.list());
  }

  /** Export all rules in YARA source format (FR-15, PRD 5.3). */
  exportAll(): string {
    return this.list()
      .map((r) => YaraScanner.exportRule(r))
      .join("\n\n");
  }

  static validate(rule: YaraRule): void {
    if (!rule.name || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(rule.name)) {
      throw new Error(`Invalid YARA rule name: ${JSON.stringify(rule.name)}`);
    }
    if (!rule.strings || rule.strings.length === 0) {
      throw new Error(`Rule ${rule.name} must declare at least one string`);
    }
    if (typeof rule.condition === "object" && rule.condition.atLeast > rule.strings.length) {
      throw new Error(
        `Rule ${rule.name}: condition 'atLeast' exceeds number of strings`,
      );
    }
    for (const s of rule.strings) {
      if (s.type === "regex") {
        try {
          new RegExp(s.value);
        } catch {
          throw new Error(`Rule ${rule.name}: invalid regex in ${s.id}`);
        }
      }
    }
  }
}
