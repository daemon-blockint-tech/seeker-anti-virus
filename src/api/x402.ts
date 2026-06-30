import { createHmac, timingSafeEqual } from "node:crypto";

/**
 * Minimal, dependency-free implementation of the x402 "Payment Required" flow
 * used to gate the public scanning API (PRD §8 PayAI x402, FR-16).
 *
 * Flow:
 *  1. Client requests a paid resource with no payment → server replies `402`
 *     with {@link PaymentRequirements} describing the price.
 *  2. Client retries with an `X-PAYMENT` header (base64 JSON payload).
 *  3. A {@link PaymentVerifier} validates (and, in production, settles) it.
 *
 * Verification is pluggable so production can delegate to a real PayAI x402
 * facilitator; {@link HmacPaymentVerifier} is a self-contained default for dev
 * and tests.
 */

export const X402_VERSION = 1;

/** USDC SPL mint on Solana mainnet (6 decimals). */
export const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

/** x402 payment requirements advertised on a 402 response. */
export interface PaymentRequirements {
  scheme: "exact";
  network: "solana";
  /** Price in atomic USDC units (6 decimals), as a string. */
  maxAmountRequired: string;
  /** Canonical resource identifier (path). */
  resource: string;
  description: string;
  mimeType: "application/json";
  /** Recipient wallet address. */
  payTo: string;
  /** Payment asset (USDC mint). */
  asset: string;
  maxTimeoutSeconds: number;
}

/** Decoded `X-PAYMENT` payload (the "exact" scheme on Solana). */
export interface PaymentPayload {
  x402Version: number;
  scheme: "exact";
  network: "solana";
  resource: string;
  /** Atomic USDC amount paid. */
  amount: string;
  /** Payer wallet address. */
  payer: string;
  /** Unique nonce for replay protection. */
  nonce: string;
  /** Authorization proof (signature / facilitator token). */
  signature: string;
}

export interface VerificationResult {
  valid: boolean;
  payer?: string;
  reason?: string;
}

export interface PaymentVerifier {
  verify(
    payload: PaymentPayload,
    requirement: PaymentRequirements,
  ): Promise<VerificationResult> | VerificationResult;
}

/**
 * Dev/test verifier: authorizes a payment with an HMAC over its fields and
 * enforces single-use nonces. NOT for production settlement — swap in a PayAI
 * x402 facilitator there.
 */
export class HmacPaymentVerifier implements PaymentVerifier {
  /** Insertion-ordered nonce store, capped to bound memory. */
  private usedNonces = new Set<string>();
  private readonly maxNonces: number;

  constructor(private readonly secret: string, maxNonces = 100_000) {
    this.maxNonces = maxNonces;
  }

  /** Compute the canonical signature for a payment (also used by clients). */
  sign(fields: Pick<PaymentPayload, "resource" | "amount" | "payer" | "nonce">): string {
    return createHmac("sha256", this.secret)
      .update(`${fields.resource}:${fields.amount}:${fields.payer}:${fields.nonce}`)
      .digest("hex");
  }

  verify(payload: PaymentPayload, requirement: PaymentRequirements): VerificationResult {
    // Defense-in-depth: reject mismatched protocol envelope before anything else.
    if (payload.x402Version !== X402_VERSION) {
      return { valid: false, reason: "unsupported_version" };
    }
    if (payload.scheme !== requirement.scheme) {
      return { valid: false, reason: "scheme_mismatch" };
    }
    if (payload.network !== requirement.network) {
      return { valid: false, reason: "network_mismatch" };
    }
    if (payload.resource !== requirement.resource) {
      return { valid: false, reason: "resource_mismatch" };
    }

    // Amount is attacker-controlled; BigInt() throws on non-numeric input.
    let paid: bigint;
    try {
      paid = BigInt(payload.amount ?? "0");
    } catch {
      return { valid: false, reason: "invalid_amount" };
    }
    if (paid < BigInt(requirement.maxAmountRequired)) {
      return { valid: false, reason: "insufficient_amount" };
    }

    const expected = this.sign(payload);
    const a = Buffer.from(expected);
    const b = Buffer.from(payload.signature ?? "");
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      return { valid: false, reason: "bad_signature" };
    }
    if (this.usedNonces.has(payload.nonce)) {
      return { valid: false, reason: "nonce_replayed" };
    }
    this.rememberNonce(payload.nonce);
    return { valid: true, payer: payload.payer };
  }

  /** Record a spent nonce, evicting the oldest entries past the cap. */
  private rememberNonce(nonce: string): void {
    this.usedNonces.add(nonce);
    if (this.usedNonces.size > this.maxNonces) {
      // Sets preserve insertion order — drop the oldest entry.
      const oldest = this.usedNonces.values().next().value;
      if (oldest !== undefined) this.usedNonces.delete(oldest);
    }
  }
}

export interface PaymentGateOptions {
  payTo: string;
  verifier: PaymentVerifier;
  /** Atomic USDC units (6 decimals) charged per paid request. Default 10000 = $0.01. */
  priceAtomic?: string;
  asset?: string;
  maxTimeoutSeconds?: number;
}

export type GateResult =
  | { ok: true; payer?: string }
  | { ok: false; status: 402; body: unknown };

/** Builds 402 challenges and verifies `X-PAYMENT` headers for paid routes. */
export class PaymentGate {
  private readonly payTo: string;
  private readonly verifier: PaymentVerifier;
  private readonly price: string;
  private readonly asset: string;
  private readonly timeout: number;

  constructor(options: PaymentGateOptions) {
    this.payTo = options.payTo;
    this.verifier = options.verifier;
    this.price = options.priceAtomic ?? "10000";
    this.asset = options.asset ?? USDC_MINT;
    this.timeout = options.maxTimeoutSeconds ?? 60;
  }

  requirementFor(resource: string): PaymentRequirements {
    return {
      scheme: "exact",
      network: "solana",
      maxAmountRequired: this.price,
      resource,
      description: `Sync scan of ${resource}`,
      mimeType: "application/json",
      payTo: this.payTo,
      asset: this.asset,
      maxTimeoutSeconds: this.timeout,
    };
  }

  /** Verify an incoming request's payment header against the resource price. */
  async check(resource: string, paymentHeader: string | undefined): Promise<GateResult> {
    const requirement = this.requirementFor(resource);

    if (!paymentHeader) {
      return this.challenge(requirement, "payment_required");
    }

    let payload: PaymentPayload;
    try {
      payload = JSON.parse(Buffer.from(paymentHeader, "base64").toString("utf8"));
    } catch {
      return this.challenge(requirement, "invalid_payment_header");
    }

    // A faulty/3rd-party verifier must never crash the request — fail closed.
    let result: VerificationResult;
    try {
      result = await this.verifier.verify(payload, requirement);
    } catch {
      return this.challenge(requirement, "verification_error");
    }
    if (!result.valid) {
      return this.challenge(requirement, result.reason ?? "verification_failed");
    }
    return { ok: true, payer: result.payer };
  }

  private challenge(requirement: PaymentRequirements, error: string): GateResult {
    return {
      ok: false,
      status: 402,
      body: { x402Version: X402_VERSION, error, accepts: [requirement] },
    };
  }
}

/** Encode a {@link PaymentPayload} into an `X-PAYMENT` header value. */
export function encodePaymentHeader(payload: PaymentPayload): string {
  return Buffer.from(JSON.stringify(payload)).toString("base64");
}
