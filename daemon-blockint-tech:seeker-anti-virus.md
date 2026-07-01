# Product Requirements Document — Sync

> **Sync** — Solana Mobile Seeker Anti Virus for Mobile

| | |
|---|---|
| **Project Name** | Sync |
| **Repository** | `daemon-blockint-tech/seeker-anti-virus` |
| **Status** | Draft v1.1 |
| **Last Updated** | 2026-06-30 |
| **Changelog** | v1.1 — Grounded in Solana Mobile Stack docs; added interception architecture, YARA/NDK notes, dApp Store NFT metadata, MWA identity verification, .skr phishing, Neo4j cloud/local split, iOS constraint, SKR token |
| **Owner** | Daemon Blockint Technologies |
| **Target Platform** | Solana Mobile (Seeker / Saga), Android |

---

## 1. Overview

**Sync** is a mobile-first, AI-powered anti-virus and threat-detection system purpose-built for the Solana Mobile **Seeker** device and the broader Solana mobile ecosystem. Unlike traditional anti-virus products that focus only on file/OS-level malware, Sync is designed around the unique threat surface of a crypto-native phone: a hardware wallet (Seed Vault), dApp store, Mobile Wallet Adapter, on-chain transactions, and seed-phrase custody all live on the same device.

Sync combines three detection layers — **behavioral analysis**, **YARA signature matching**, and **LLM-based threat classification** — to protect users from malware, wallet drainers, malicious dApps, rug-pull tokens, and phishing, all while keeping primary analysis on-device for privacy.

### Vision

> Make the Solana Seeker the safest place to hold and transact crypto on mobile — every app, contract, and transaction screened before it can touch the user's keys.

---

## 2. Problem Statement

Crypto mobile users face a fundamentally different threat model than typical smartphone users:

- **Wallet drainers** — malicious dApps and apps that trick users into signing transactions that empty their wallets.
- **Rug pulls & honeypots** — fraudulent tokens and smart contracts engineered to steal funds at sell time.
- **Seed-phrase theft** — keyloggers, clipboard hijackers, and spyware targeting mnemonics and private keys.
- **Malicious dApps** — apps from the dApp store or web requesting unauthorized transaction signing.
- **Phishing** — fake wallet apps and look-alike domains (e.g. `s0lana.xyz`).
- **.skr domain phishing** — spoofed or look-alike `.skr` domains targeting known Solana wallet addresses, exploiting the Solana Mobile naming system.
- **Remote Access Trojans (RATs)** — malware establishing command-and-control to exfiltrate device and wallet data.

Existing mobile anti-virus solutions are **blind to on-chain threats** — they don't understand Solana programs, token mechanics, or wallet-signing flows. Sync closes this gap.

---

## 3. Goals & Non-Goals

### Goals

1. Detect and block malware, spyware, and RATs targeting the Seeker device.
2. Screen Solana smart contracts and tokens for rug pulls, honeypots, and exploits **before** a user interacts.
3. Intercept and risk-score wallet-signing requests in real time.
4. Detect phishing dApps and look-alike domains.
5. Keep primary analysis **on-device** for privacy; only escalate to cloud LLM with user consent.
6. Provide clear, actionable threat reports and remediation steps.

### Non-Goals (v1)

- Desktop / browser-extension protection (mobile-only for v1).
- iOS support — the MWA protocol is Android-only due to platform restrictions on inter-app communication; iOS is not targeted.
- Custodial fund recovery or insurance.
- Custodying keys — Sync never holds, derives, or exports seed phrases or private keys. Even under Strategy A (Sync-as-Wallet, §5.5), Sync registers as an MWA wallet endpoint purely to screen signing requests and **delegates all key custody and signing to Seed Vault**; it does not replace the Seed Vault's secure-element custody.
- Non-Solana chains (EVM bridge monitoring is partial; full multi-chain is future scope).

---

## 4. Target Users

| Persona | Description | Key Need |
|---------|-------------|----------|
| **Crypto-native power user** | Holds significant assets, interacts with many dApps daily | Pre-transaction contract screening, drainer protection |
| **DeFi newcomer** | New to Solana, vulnerable to scams | Phishing detection, plain-language warnings |
| **NFT collector** | Mints frequently, exposed to fraudulent mints | NFT scam-contract detection |
| **Developer / auditor** | Tests and audits contracts | YARA rule access, smart-contract scanning API |

---

## 5. Detection Architecture

Sync uses a layered detection pipeline. Analysis runs on-device first; cloud LLM classification is opt-in.

```
   Mobile App / Smart Contract / Transaction
                    │
         ┌──────────▼───────────┐
         │  Integrated Scanner  │
         ├──────────────────────┤
         │ ① Behavioral Scanner │ → permissions, network, crypto, binary loads
         │ ② Signature Matcher  │ → known Solana threat patterns
         │ ③ YARA Scanner       │ → binary / bytecode pattern matching
         │ ④ LLM Classifier     │ → contextual risk analysis (opt-in)
         └──────────┬───────────┘
                    │
         ┌──────────▼───────────┐
         │  Risk Scoring Engine │ → 0–100 score + severity
         └──────────┬───────────┘
                    │
       ┌────────────┼─────────────┐
       ▼            ▼             ▼
  User Alert   Local Quarantine  Threat Graph (Neo4j, cloud)
```

> **Note:** Neo4j is a cloud-side service — it cannot run on-device. The on-device threat database stores a local subset/cache of threat relationships (SQLite or similar). Cloud sync to the full Neo4j threat graph is opt-in and requires user consent.

### 5.1 Behavioral Scanner

Monitors runtime behavior of installed apps:

- **Permission monitoring** — flags dangerous requests (contacts, SMS, audio, location, camera).
- **Network analysis** — detects command-and-control (C2) connections and suspicious endpoints.
- **Crypto-transaction monitoring** — flags large/anomalous transfers and unusual program interactions.
- **Binary-injection detection** — catches code-injection and unauthorized binary loads.
- **Ransomware detection** — flags bulk file encryption / ransom-extension rewrites and abuse of Device Admin APIs (screen-lock, wipe, password reset) used by mobile ransomware and screen-lockers.
- **MWA identity verification** — leverages the dApp identity attestation from MWA's `authorize` method (`identity.uri`, `identity.name`) as a phishing-detection signal. The MWA protocol provides domain-based dApp identity verification; Sync cross-references the attested domain against known phishing patterns and reputation databases.

### 5.2 Signature Matcher

Fast lookup against a curated database of known Solana threat patterns: rug pulls, honeypots, malicious dApps, bridge drains, flash-loan attacks, phishing, permission abuse, and C2 malware.

**dApp Store reputation lookup** — dApp Store listings are represented as NFTs on Solana with on-chain metadata (name, description, icon, APK hash, publisher address). Sync cross-references this metadata for reputation scoring: listing age, publisher history, APK hash matches against known-malicious builds, and verification of publisher identity.

### 5.3 YARA Scanner

Binary/bytecode pattern-matching engine (VirusTotal YARA-compatible) with Solana-specific rules:

| Rule | Category | Severity | Detects |
|------|----------|----------|---------|
| Wallet Stealer | malware | Critical | Seed/private-key extraction |
| Rug Pull Contract | exploit | Critical | Liquidity drain + hidden owner logic |
| Honeypot Token | exploit | Critical | Sell restrictions + backdoors |
| Flash Loan Attack | exploit | High | Price manipulation + same-block repay |
| Bridge Exploit | exploit | Critical | Signature bypass + drain |
| NFT Scam | exploit | High | Fraudulent mint + fee extraction |
| Mobile Keylogger | malware | Critical | Input capture + exfiltration |
| Remote Access Trojan | trojan | Critical | C2 socket + command loop |
| Ransomware | ransomware | Critical | File encryption + ransom note + Device Admin abuse |

Supports custom rules and YARA-format export for interoperability with external tooling.

> **Implementation note:** YARA is a C library and does not run natively on Android. The YARA engine is cross-compiled for Android via the NDK and exposed to the TypeScript/Kotlin layer through JNI bindings. Rule files are loaded from encrypted local storage at scan time. This approach is proven in existing Android security projects (e.g. yara-android).

### 5.4 LLM Threat Classifier (opt-in)

Escalates ambiguous or high-stakes cases to an LLM agent for contextual analysis: cross-references on-chain history, queries the threat knowledge graph, and produces a plain-language threat report with remediation steps.

### 5.5 Transaction Interception Architecture

The Mobile Wallet Adapter (MWA) protocol is a WebSocket-based communication channel between a dApp (client) and a wallet app (wallet endpoint) on the same device. There is no built-in third-party interception point — MWA does not provide a hook for external security apps to observe or block signing requests.

Sync addresses this through one of the following integration strategies (to be finalized during Phase 4 prototyping):

| Strategy | How it works | Trade-offs |
|----------|-------------|------------|
| **A. Sync-as-Wallet** | Sync registers as an MWA-compliant wallet **endpoint** so it can see signing requests before approval, but **does not custody keys** — it delegates all key storage and signing to Seed Vault (see Non-Goals, §3). Users select Sync as their wallet, giving it full visibility into all signing requests. | Full transaction content access; requires Sync to implement the MWA wallet endpoint spec and proxy signing to Seed Vault; users must choose Sync as their wallet. |
| **B. Accessibility Service** | Sync uses Android's `AccessibilityService` to read transaction content from the wallet approval UI before the user confirms. | No MWA implementation needed; works with any wallet; limited to UI text parsing; Android permission friction. |
| **C. Wallet SDK Integration** | Sync integrates as a middleware layer within a partner wallet (e.g. Seed Vault Wallet fork or Phantom integration). | Deepest integration; requires wallet partnership; not standalone. |
| **D. Notification Listener** | Sync monitors MWA session notifications via `NotificationListenerService` to detect signing events and trigger parallel analysis. | Lightweight; limited to metadata, not full transaction content. |

**Recommended approach for v1:** Strategy A (Sync-as-Wallet) for full transaction interception, with Strategy B (Accessibility Service) as a fallback for users who prefer their existing wallet.

---

## 6. Functional Requirements

### 6.1 Real-Time Protection

- **FR-1** Continuously monitor installed apps for suspicious behavior.
- **FR-2** Intercept wallet-signing requests and display a risk score before the user signs.
- **FR-3** Push immediate alerts on critical-severity detections.
- **FR-4** Quarantine or recommend uninstall for confirmed malware.

### 6.2 On-Demand Scanning

- **FR-5** Scan any installed app (APK) for malware on demand.
- **FR-6** Audit any Solana smart contract / token address before interaction.
- **FR-7** Scan dApp URLs/domains for phishing indicators.
- **FR-7b** Detect spoofed `.skr` domains and look-alike Solana Mobile naming system entries targeting known wallets.

### 6.3 Threat Intelligence

- **FR-8** Maintain a local threat database, updated regularly.
- **FR-9** Store detected threats in a knowledge graph for cross-referencing.
- **FR-10** Generate detailed, exportable threat reports with remediation steps.

### 6.4 User Experience

- **FR-11** Provide a security dashboard (device risk score, recent scans, active threats).
- **FR-12** Plain-language explanations — no jargon-only warnings.
- **FR-13** One-tap remediation actions (uninstall, revoke permission, disconnect wallet).

### 6.5 Developer / API

- **FR-14** Expose a scanning API (app scan, contract scan, text scan).
- **FR-15** Allow custom YARA rule creation and management.
- **FR-16** Optional micropayment-gated API access for third-party integrations.

---

## 7. Non-Functional Requirements

| Category | Requirement |
|----------|-------------|
| **Performance** | Behavioral scan < 50 ms / 100 events; YARA scan < 100 ms / MB; signature match < 30 ms / event |
| **Privacy** | Primary analysis on-device; no system events leave the device without consent |
| **Battery** | Background monitoring < 3% daily battery drain (requires adaptive event-driven scanning via Android `WorkManager`, not continuous polling; YARA scans batched and scheduled) |
| **Accuracy** | False-positive rate < 2% at 80%+ confidence threshold. A false positive is defined as: (a) blocking a legitimate dApp transaction that the user intended to sign, or (b) flagging a safe installed app as malware. Benign cautionary warnings on novel-but-legit contracts are not counted as false positives. |
| **Availability** | Local detection works fully offline; cloud LLM optional |
| **Security** | Encrypt threat data at rest; signed rule updates only |
| **Updatability** | Signature/YARA rules updatable without app store release |

---

## 8. Technical Stack

| Layer | Technology |
|-------|-----------|
| **Mobile App** | Android (Kotlin) + React Native bridge / Solana Mobile Stack (SMS) |
| **Detection Engine** | TypeScript core running on React Native Hermes JS engine (on-device); Node.js for cloud-side services only |
| **Signature Matching** | YARA (VirusTotal-compatible), cross-compiled for Android NDK with JNI bindings |
| **On-device Threat DB** | SQLite (local threat cache, encrypted at rest) |
| **Knowledge Graph** | Neo4j (cloud-side threat relationships; on-device subset cached locally) |
| **On-chain Data** | Helius RPC + WebSocket + DAS API |
| **Analytics** | Dune Analytics (on-chain behavior) |
| **AI Classification** | DeepAgentsJS + OpenRouter (Claude models) |
| **Payments (API)** | PayAI x402 micropayments (USDC on Solana; SKR accepted as alternative) |
| **Device Verification** | Seeker Genesis Token (SGT) on-chain verification for Seeker-specific features |
| **Infra** | Railway (cloud services), on-device Hermes runtime (mobile) |

---

## 9. Core Modules

| Module | Responsibility |
|--------|----------------|
| `scanner/` | System behavior analysis (permissions, network, crypto, binaries) |
| `signatures/` | Known threat-pattern database |
| `analyzer/` | Risk scoring, severity, report generation |
| `monitor/` | Real-time monitoring sessions + alerts |
| `yara/` | YARA rules, rule manager, binary scanner |
| `integrated-scanner` | Unified behavioral + YARA + LLM pipeline |
| `agent-tools` | DeepAgentsJS tool definitions for LLM agent |
| `api` | Public scanning API + x402 micropayment gating (§6.5) |
| `interception/` | MWA transaction interception — wallet-endpoint / accessibility strategies (§5.5); Phase 4 |
| `threat-db/` | On-device threat database (SQLite cache, encrypted at rest; §8); Phase 4 |

---

## 10. User Flows

### 10.1 dApp Connection Screening
1. User opens a dApp and taps "Connect Wallet."
2. Sync intercepts the Mobile Wallet Adapter request via the chosen interception strategy (see §5.5).
3. dApp domain (from MWA `identity.uri`) + requested program screened (signature + YARA + reputation + dApp Store NFT metadata).
4. Risk score shown; user approves or blocks before any signing occurs.

### 10.2 Pre-Transaction Contract Audit
1. User initiates a token swap / mint.
2. Sync scans the target contract for rug-pull / honeypot patterns.
3. Critical findings block the transaction with a plain-language warning.

### 10.3 On-Demand App Scan
1. User selects an installed app to scan.
2. APK analyzed against YARA + behavioral signatures.
3. Threat report with severity and one-tap remediation.

---

## 11. Risk Scoring & Severity

| Severity | Score | Action |
|----------|-------|--------|
| **Critical** | 80–100 | Block + alert; recommend immediate uninstall / fund move |
| **High** | 60–79 | Strong warning; restrict sensitive actions |
| **Medium** | 40–59 | Caution; review permissions |
| **Low** | 0–39 | Monitor; informational |

The combined score is a weighted blend of two **layer components** — **behavioral (60%)** and **YARA (40%)** — normalized over whichever components produced findings (so a strong single-layer result isn't diluted by an absent layer):

- **Behavioral component** — behavioral-scanner findings, reinforced by signature matches and any LLM-classifier findings (the LLM contributes contextual risk into this component when escalation is active; see §5.4).
- **YARA component** — YARA-rule findings, also reinforced by signature matches.

The **signature matcher (§5.2)** is not a third weighted term: a signature hit reinforces whichever component it corroborates (behavioral and/or YARA), taking the stronger of the two. **Escalation override:** a critical YARA match — or a high-confidence critical signature match — forces overall severity to **Critical** regardless of the weighted score.

---

## 12. Success Metrics (KPIs)

| Metric | Target (6 months post-launch) |
|--------|-------------------------------|
| Threats detected / blocked | > 10,000 |
| False-positive rate | < 2% |
| Pre-transaction screens performed | > 100,000 |
| Active protected devices | > 5,000 |
| Wallet-drain incidents prevented | Measurable reduction vs. baseline |
| Avg. scan latency | < 200 ms (on-device) |

---

## 13. Roadmap

### Phase 1 — Core Engine (Planned)
- Behavioral scanner, signature database, threat analyzer, real-time monitor.

### Phase 2 — YARA Integration (Planned)
- Solana-specific YARA rules (incl. ransomware), binary/contract scanning, rule management, agent tools.

### Phase 3 — LLM Classification (Planned)
- DeepAgentsJS agent, on-chain context via Helius, Neo4j threat graph, intelligence reports.

### Phase 4 — Mobile App
- Android app, Solana Mobile Stack integration, Mobile Wallet Adapter interception (via the strategy selected in §5.5), on-device threat DB (§8), security dashboard.

### Phase 5 — API & Ecosystem
- Public scanning API, PayAI x402 monetization, custom-rule marketplace, threat-intel feed.

### Phase 6 — Advanced (Future)
- ML behavior classification, VirusTotal integration, decentralized threat-sharing network, multi-chain support.

---

## 14. Open Questions & Risks

| Item | Type | Notes |
|------|------|-------|
| On-device LLM feasibility | Risk | Cloud LLM needed for heavy analysis; latency/privacy trade-off |
| MWA interception strategy selection | Open | Choose between Sync-as-Wallet (A), Accessibility Service (B), Wallet SDK (C), or Notification Listener (D) — see §5.5; requires Phase 4 prototyping |
| Rule-update distribution | Open | Signed OTA updates vs. app-store cadence |
| False positives on novel-but-legit contracts | Risk | Tune confidence thresholds; allow user override |
| Battery impact of continuous monitoring | Risk | Profile and optimize background scanning; target 3% requires event-driven, not polling |
| YARA NDK cross-compilation | Risk | JNI bridge stability and performance on diverse Android device architectures |

---

## 15. References

- Solana Mobile Docs — https://docs.solanamobile.com
- Solana Mobile Stack Overview — https://docs.solanamobile.com/solana-mobile-stack/overview
- Seed Vault — https://docs.solanamobile.com/solana-mobile-stack/seed-vault
- Mobile Wallet Adapter — https://docs.solanamobile.com/solana-mobile-stack/mobile-wallet-adapter
- MWA Protocol Spec — https://solana-mobile.github.io/mobile-wallet-adapter/spec/spec.html
- Seeker Device — https://docs.solanamobile.com/solana-mobile-stack/seeker
- dApp Store — https://docs.solanamobile.com/solana-mobile-stack/dapp-store
- Seeker Genesis Token — https://docs.solanamobile.com/solana-mobile-stack/seeker-genesis-token
- .skr Domain — https://docs.solanamobile.com/solana-mobile-stack/skr-domain
- Detecting Seeker Users — https://docs.solanamobile.com/recipes/general/detecting-seeker-users
- YARA — https://virustotal.github.io/yara/
- Solana Security — https://docs.solana.com/security
- OWASP Mobile Security — https://owasp.org/www-project-mobile-security/

---

*Sync — Solana Mobile Seeker Anti Virus for Mobile. Built by Daemon Blockint Technologies.*
