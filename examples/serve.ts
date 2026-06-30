/**
 * Demo: run the Sync public scanning API with optional x402 gating.
 *
 * Free:  npm run serve
 * Paid:  X402_SECRET=dev X402_PAYTO=<wallet> npm run serve
 *
 * Then:
 *   curl localhost:8787/health
 *   curl -XPOST localhost:8787/v1/scan/url -d '{"url":"s0lana.xyz"}'
 */
import {
  SyncApiServer,
  PaymentGate,
  HmacPaymentVerifier,
} from "../src/index.js";

const port = Number(process.env.PORT ?? 8787);

const secret = process.env.X402_SECRET;
const gate = secret
  ? new PaymentGate({
      payTo: process.env.X402_PAYTO ?? "SyncTreasury11111111111111111111111111111111",
      verifier: new HmacPaymentVerifier(secret),
      priceAtomic: process.env.X402_PRICE ?? "10000", // $0.01 USDC
    })
  : undefined;

const server = new SyncApiServer({ gate });
const { port: bound } = await server.listen(port);
console.log(`Sync API listening on http://localhost:${bound}`);
console.log(gate ? "x402 micropayment gating: ENABLED" : "x402 gating: disabled (free mode)");
