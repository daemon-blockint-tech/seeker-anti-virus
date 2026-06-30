import { ScreeningPipeline, type ScreeningResult } from "./screeningPipeline.js";

/**
 * Seed Vault delegate. Sync registers as an MWA wallet endpoint but **never
 * custodies keys** (PRD §3 Non-Goals / §5.5 Strategy A): all signing is proxied
 * to the device's Seed Vault through this interface.
 */
export interface SeedVaultSigner {
  /** The wallet's public key (base58). */
  publicKey(): string | Promise<string>;
  /** Sign already-approved transactions, returning the signed bytes. */
  signTransactions(transactions: Uint8Array[]): Promise<Uint8Array[]>;
}

/** MWA `authorize` / `reauthorize` request (subset Sync cares about). */
export interface AuthorizeRequest {
  identityName?: string;
  identityUri?: string;
  cluster?: string;
}

export interface AuthorizeResult {
  publicKey: string;
  accountLabel: string;
}

/** Per-transaction outcome from a sign request. */
export interface SignedOutcome {
  index: number;
  screening: ScreeningResult;
  /** Present when the transaction was approved and signed. */
  signed?: Uint8Array;
  /** Present when the transaction was blocked or the user declined. */
  blockedReason?: string;
}

export interface SignTransactionsResult {
  outcomes: SignedOutcome[];
  /** True when every transaction was signed. */
  allSigned: boolean;
}

/**
 * Called when a transaction screens as `warn` (high severity). Return `true` to
 * proceed with signing, `false` to decline. If omitted, warns are declined.
 */
export type WarnConfirmHandler = (result: ScreeningResult) => boolean | Promise<boolean>;

export interface SyncWalletEndpointOptions {
  pipeline?: ScreeningPipeline;
  onWarn?: WarnConfirmHandler;
}

/**
 * Sync-as-Wallet MWA endpoint (PRD §5.5 Strategy A).
 *
 * Implements the wallet side of the Mobile Wallet Adapter signing flow, but
 * screens every transaction through the {@link ScreeningPipeline} first and
 * delegates the actual signing to a {@link SeedVaultSigner}. Critical findings
 * block signing outright; high findings require explicit user confirmation.
 */
export class SyncWalletEndpoint {
  private readonly pipeline: ScreeningPipeline;
  private readonly onWarn?: WarnConfirmHandler;

  constructor(
    private readonly seedVault: SeedVaultSigner,
    options: SyncWalletEndpointOptions = {},
  ) {
    this.pipeline = options.pipeline ?? new ScreeningPipeline();
    this.onWarn = options.onWarn;
  }

  /** Handle an MWA authorize/reauthorize request. */
  async authorize(_request: AuthorizeRequest = {}): Promise<AuthorizeResult> {
    const publicKey = await this.seedVault.publicKey();
    return { publicKey, accountLabel: "Seed Vault (screened by Sync)" };
  }

  /**
   * Screen then sign a batch of transactions. Each transaction is approved,
   * confirmed (warn), or blocked independently; only approved ones are sent to
   * the Seed Vault for signing.
   */
  async signTransactions(transactions: Uint8Array[]): Promise<SignTransactionsResult> {
    const outcomes: SignedOutcome[] = [];
    const toSign: { index: number; bytes: Uint8Array }[] = [];

    for (let i = 0; i < transactions.length; i++) {
      const screening = await this.pipeline.screen(transactions[i]!);

      if (screening.decision === "block") {
        outcomes.push({ index: i, screening, blockedReason: this.reason(screening) });
        continue;
      }
      if (screening.decision === "warn") {
        const proceed = this.onWarn ? await this.onWarn(screening) : false;
        if (!proceed) {
          outcomes.push({ index: i, screening, blockedReason: "declined_by_user" });
          continue;
        }
      }
      toSign.push({ index: i, bytes: transactions[i]! });
      outcomes.push({ index: i, screening });
    }

    // Delegate the approved set to Seed Vault in one call.
    if (toSign.length > 0) {
      const signed = await this.seedVault.signTransactions(toSign.map((t) => t.bytes));
      toSign.forEach((t, k) => {
        const outcome = outcomes.find((o) => o.index === t.index)!;
        outcome.signed = signed[k];
      });
    }

    outcomes.sort((a, b) => a.index - b.index);
    return { outcomes, allSigned: outcomes.every((o) => o.signed !== undefined) };
  }

  private reason(screening: ScreeningResult): string {
    const top = screening.report.findings[0];
    return top ? `blocked: ${top.title}` : `blocked: ${screening.severity} risk`;
  }
}
