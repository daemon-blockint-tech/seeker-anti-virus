# Sync — Solana Mobile Seeker Anti-Virus

> Make the Solana Seeker the safest place to hold and transact crypto on mobile — every app, contract, and transaction screened before it can touch the user's keys.

**Sync** is a mobile-first, AI-powered anti-virus and threat-detection engine purpose-built for the Solana Mobile **Seeker** device. This repository contains the **detection engine core** (`@daemon-blockint/sync-core`) — a portable, dependency-free TypeScript library that runs on a Node backend or embedded in an on-device runtime.

This package implements **Phase 1 (Core Engine)** and **Phase 2 (YARA Integration)** of the PRD roadmap.

## Detection pipeline

```
 App / Contract / Transaction / URL
                │
     ┌──────────▼───────────┐
     │  IntegratedScanner   │
     │  ① Behavioral        │  permissions, network/C2, crypto, binary loads
     │  ② Signature         │  known Solana threat patterns
     │  ③ YARA              │  binary/bytecode pattern matching (8 rules)
     │  ④ LLM (opt-in)      │  contextual analysis hook
     └──────────┬───────────┘
                ▼
     RiskScorer → ReportGenerator → ThreatReport (score, verdict, remediation)
```

## Install & build

```bash
npm install
npm run build      # compile to dist/
npm test           # vitest (19 tests)
npm run demo       # run examples/demo.ts
```

## Quick start

```ts
import { IntegratedScanner } from "@daemon-blockint/sync-core";

const scanner = new IntegratedScanner();

const { report } = scanner.scanLocal({
  id: "com.fake.phantom",
  kind: "app",
  permissions: ["READ_CLIPBOARD", "BIND_ACCESSIBILITY_SERVICE"],
  text: "const seed_phrase = readMnemonic(); fetch('http://1.2.3.4/gate.php')",
});

console.log(report.score, report.severity, report.verdict);
// 99 'critical' 'blocked'
console.log(report.remediation);
```

### Real-time monitoring

```ts
import { IntegratedScanner, Monitor } from "@daemon-blockint/sync-core";

const monitor = new Monitor(new IntegratedScanner(), { alertThreshold: "high" });
monitor.onAlert((a) => pushNotification(a));
monitor.start({ id: "com.some.app", kind: "app", events: [] });
monitor.ingest("com.some.app", { type: "network", timestamp: Date.now(), host: "1.2.3.4" });
```

### LLM threat classifier — Phase 3 (PRD 5.4)

A LangGraph ReAct agent (model + Sync scan tools) escalates ambiguous cases. It
runs on **OpenRouter** (any model slug via `OPENROUTER_MODEL`) and returns
structured `Finding[]` through a mandatory `submit_classification` tool call.

```ts
import { IntegratedScanner, makeLlmClassifier } from "@daemon-blockint/sync-core";

const scanner = new IntegratedScanner({
  llm: makeLlmClassifier(),    // OpenRouter-backed agent (needs OPENROUTER_API_KEY)
  llmEscalationThreshold: 60,  // only escalate above this interim score
});

await scanner.scan(target);    // LLM invoked only above the threshold; failures degrade gracefully
```

Configure via `.env` (see `.env.example`): `OPENROUTER_API_KEY`, `OPENROUTER_MODEL`,
and optional `LANGSMITH_*` for tracing. Run `npm run demo:llm` for a live example.

The `llm` hook accepts any `(target, priorFindings) => Promise<Finding[]>`, so you
can plug in a custom model or pass an injected `BaseChatModel`:

```ts
makeLlmClassifier({ model: myChatModel, llmEscalationThreshold: 50 });
```

### Custom YARA rules (FR-15)

```ts
scanner.ruleManager.add({
  name: "My_Rule",
  category: "malware",
  severity: "high",
  meta: { description: "..." },
  strings: [{ id: "$a", value: "marker", type: "text", nocase: true }],
  condition: { atLeast: 1 },
});
console.log(scanner.ruleManager.exportAll()); // YARA-source export
```

### LLM agent tools (PRD §9)

```ts
import { createAgentTools } from "@daemon-blockint/sync-core";
const tools = createAgentTools(scanner); // scan_app, scan_contract, scan_url, add_yara_rule, ...
```

## Modules

| Module | Class | Responsibility |
|--------|-------|----------------|
| `scanner/` | `BehavioralScanner` | permissions, network/C2, crypto, binary loads (PRD 5.1) |
| `signatures/` | `SignatureMatcher` | known Solana threat-pattern database (PRD 5.2) |
| `yara/` | `YaraScanner`, `RuleManager` | 8 Solana YARA rules + custom rules (PRD 5.3) |
| `analyzer/` | `RiskScorer`, `ReportGenerator` | 0–100 scoring + plain-language reports (PRD §11) |
| `monitor/` | `Monitor` | real-time sessions + alerts (FR-1/FR-3) |
| `integrated-scanner` | `IntegratedScanner` | unified pipeline (PRD §9) |
| `agent-tools` | `createAgentTools` | DeepAgentsJS tool definitions (PRD §9) |

## Risk scoring

Combined score weights **behavioral (60%)** and **YARA (40%)**, normalized over the layers that fired; a **critical YARA or high-confidence signature match escalates** the overall severity to critical (PRD §11).

| Severity | Score | Verdict |
|----------|-------|---------|
| Critical | 80–100 | blocked |
| High | 60–79 | warn |
| Medium | 40–59 | caution |
| Low | 0–39 | clean |

## Status

Phases 1 & 2 (core engine + YARA) and **Phase 3 (LLM classification)** implemented.
Mobile app and public API (Phases 4–5) are future scope.

---

*Sync — Built by Daemon Blockint Technologies. MIT licensed.*
