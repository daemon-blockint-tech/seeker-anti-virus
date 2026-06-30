export { ThreatStore } from "./threatStore.js";
export { InMemoryBackend } from "./backend.js";
export { SqliteBackend } from "./sqliteBackend.js";
export type { SqliteBackendOptions } from "./sqliteBackend.js";
export {
  OtaUpdater,
  BundleSigner,
  BundleVerifier,
  BundleVerificationError,
} from "./otaUpdater.js";
export type { ApplyTargets, ApplyResult } from "./otaUpdater.js";
export type {
  ThreatRecord,
  ThreatBundle,
  SignedBundle,
  ThreatStoreBackend,
  IndicatorKind,
} from "./types.js";
