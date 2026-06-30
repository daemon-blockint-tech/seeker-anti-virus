import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as cryptoSign,
  verify as cryptoVerify,
  type KeyObject,
} from "node:crypto";
import type { SignatureMatcher } from "../signatures/signatureMatcher.js";
import type { RuleManager } from "../yara/ruleManager.js";
import type { ThreatStore } from "./threatStore.js";
import type { SignedBundle, ThreatBundle } from "./types.js";

/** Canonical serialization of a bundle (stable key order via JSON of fields). */
function canonical(bundle: ThreatBundle): string {
  return JSON.stringify(bundle);
}

/**
 * Signs threat bundles with an Ed25519 key. Intended for the update-publishing
 * side (and tests); devices only ever verify.
 */
export class BundleSigner {
  constructor(
    private readonly keyId: string,
    private readonly privateKey: KeyObject,
  ) {}

  /** Generate a fresh signer + its public key (PEM) for bootstrapping/tests. */
  static generate(keyId: string): { signer: BundleSigner; publicKeyPem: string } {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    return {
      signer: new BundleSigner(keyId, privateKey),
      publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    };
  }

  sign(bundle: ThreatBundle): SignedBundle {
    const payload = canonical(bundle);
    const signature = cryptoSign(null, Buffer.from(payload, "utf8"), this.privateKey);
    return {
      keyId: this.keyId,
      algorithm: "ed25519",
      payload,
      signature: signature.toString("base64"),
    };
  }
}

export class BundleVerificationError extends Error {}

/**
 * Verifies signed bundles against a set of trusted Ed25519 public keys
 * (PRD §7: "signed rule updates only").
 */
export class BundleVerifier {
  private keys = new Map<string, KeyObject>();

  /** @param trustedKeys map of keyId → public key (PEM string or KeyObject). */
  constructor(trustedKeys: Record<string, string | KeyObject>) {
    for (const [id, key] of Object.entries(trustedKeys)) {
      this.keys.set(id, typeof key === "string" ? createPublicKey(key) : key);
    }
  }

  /** Verify a signed bundle, returning the parsed bundle or throwing. */
  verify(signed: SignedBundle): ThreatBundle {
    if (signed.algorithm !== "ed25519") {
      throw new BundleVerificationError(`unsupported algorithm: ${signed.algorithm}`);
    }
    const key = this.keys.get(signed.keyId);
    if (!key) throw new BundleVerificationError(`untrusted key id: ${signed.keyId}`);

    let ok = false;
    try {
      ok = cryptoVerify(
        null,
        Buffer.from(signed.payload, "utf8"),
        key,
        Buffer.from(signed.signature, "base64"),
      );
    } catch {
      ok = false;
    }
    if (!ok) throw new BundleVerificationError("signature verification failed");

    return JSON.parse(signed.payload) as ThreatBundle;
  }
}

export interface ApplyTargets {
  store: ThreatStore;
  /** When provided, bundle signatures are merged in (FR-8). */
  signatureMatcher?: SignatureMatcher;
  /** When provided, bundle YARA rules are merged in (FR-15). */
  ruleManager?: RuleManager;
}

export interface ApplyResult {
  applied: boolean;
  version: number;
  counts: { threats: number; signatures: number; yaraRules: number };
}

/**
 * OTA Updater (PRD §7 "Updatability").
 *
 * Verifies a signed bundle, enforces monotonic versioning (anti-rollback), and
 * applies its threats / signatures / YARA rules into the live engine. Rejects
 * unsigned, tampered, or stale bundles.
 */
export class OtaUpdater {
  constructor(private readonly verifier: BundleVerifier) {}

  apply(signed: SignedBundle, targets: ApplyTargets): ApplyResult {
    const bundle = this.verifier.verify(signed); // throws on bad signature

    const current = targets.store.version;
    if (bundle.version <= current) {
      throw new BundleVerificationError(
        `stale bundle: version ${bundle.version} <= current ${current}`,
      );
    }

    const counts = { threats: 0, signatures: 0, yaraRules: 0 };

    if (bundle.threats?.length) {
      targets.store.add(bundle.threats);
      counts.threats = bundle.threats.length;
    }
    if (bundle.signatures?.length && targets.signatureMatcher) {
      targets.signatureMatcher.upsert(bundle.signatures);
      counts.signatures = bundle.signatures.length;
    }
    if (bundle.yaraRules?.length && targets.ruleManager) {
      for (const rule of bundle.yaraRules) targets.ruleManager.add(rule);
      counts.yaraRules = bundle.yaraRules.length;
    }

    targets.store.version = bundle.version;
    return { applied: true, version: bundle.version, counts };
  }
}

/** Re-export for callers that need to build a private key from PEM. */
export { createPrivateKey };
