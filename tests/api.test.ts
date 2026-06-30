import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import {
  SyncApiServer,
  PaymentGate,
  HmacPaymentVerifier,
  encodePaymentHeader,
  type PaymentPayload,
} from "../src/index.js";

const SECRET = "test-secret";
const PAY_TO = "SyncTreasury11111111111111111111111111111111";

/** Mint a valid X-PAYMENT header for a resource using the dev verifier. */
function payHeader(verifier: HmacPaymentVerifier, resource: string, amount = "10000"): string {
  const payer = "Payer1111111111111111111111111111111111111";
  const nonce = randomUUID();
  const signature = verifier.sign({ resource, amount, payer, nonce });
  const payload: PaymentPayload = {
    x402Version: 1,
    scheme: "exact",
    network: "solana",
    resource,
    amount,
    payer,
    nonce,
    signature,
  };
  return encodePaymentHeader(payload);
}

describe("SyncApiServer (free routes)", () => {
  const server = new SyncApiServer();
  let base = "";

  beforeAll(async () => {
    const { port } = await server.listen(0);
    base = `http://127.0.0.1:${port}`;
  });
  afterAll(() => server.close());

  it("serves health", async () => {
    const res = await fetch(`${base}/health`);
    expect(res.status).toBe(200);
    expect((await res.json()).status).toBe("ok");
  });

  it("lists YARA rules", async () => {
    const res = await fetch(`${base}/v1/rules`);
    const body = await res.json();
    expect(body.rules.length).toBeGreaterThanOrEqual(8);
  });

  it("scans a contract without payment when ungated", async () => {
    const res = await fetch(`${base}/v1/scan/contract`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ address: "Tok1", text: "is_whitelisted; can_sell = false; transfer_hook" }),
    });
    expect(res.status).toBe(200);
    const report = await res.json();
    expect(report.severity).toBeDefined();
    expect(report.findings.length).toBeGreaterThan(0);
  });

  it("400s on a missing target", async () => {
    const res = await fetch(`${base}/v1/scan/app`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: "no id" }),
    });
    expect(res.status).toBe(400);
  });

  it("404s unknown routes", async () => {
    expect((await fetch(`${base}/nope`)).status).toBe(404);
  });
});

describe("SyncApiServer with x402 gating", () => {
  const verifier = new HmacPaymentVerifier(SECRET);
  const gate = new PaymentGate({ payTo: PAY_TO, verifier, priceAtomic: "10000" });
  const server = new SyncApiServer({ gate });
  let base = "";

  beforeAll(async () => {
    const { port } = await server.listen(0);
    base = `http://127.0.0.1:${port}`;
  });
  afterAll(() => server.close());

  it("challenges unpaid scan requests with a 402 + requirements", async () => {
    const res = await fetch(`${base}/v1/scan/url`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: "s0lana.xyz" }),
    });
    expect(res.status).toBe(402);
    const body = await res.json();
    expect(body.x402Version).toBe(1);
    expect(body.accepts[0].payTo).toBe(PAY_TO);
    expect(body.accepts[0].maxAmountRequired).toBe("10000");
  });

  it("allows a request with a valid payment header", async () => {
    const res = await fetch(`${base}/v1/scan/url`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-payment": payHeader(verifier, "/v1/scan/url"),
      },
      body: JSON.stringify({ url: "s0lana.xyz" }),
    });
    expect(res.status).toBe(200);
    const report = await res.json();
    expect(report.severity).toBe("high"); // phishing look-alike
  });

  it("rejects an insufficient payment amount", async () => {
    const res = await fetch(`${base}/v1/scan/url`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-payment": payHeader(verifier, "/v1/scan/url", "1"),
      },
      body: JSON.stringify({ url: "s0lana.xyz" }),
    });
    expect(res.status).toBe(402);
  });

  it("rejects a replayed nonce", async () => {
    const header = payHeader(verifier, "/v1/scan/url");
    const opts = {
      method: "POST",
      headers: { "content-type": "application/json", "x-payment": header },
      body: JSON.stringify({ url: "s0lana.xyz" }),
    };
    expect((await fetch(`${base}/v1/scan/url`, opts)).status).toBe(200);
    expect((await fetch(`${base}/v1/scan/url`, opts)).status).toBe(402);
  });

  it("free routes remain open under gating", async () => {
    expect((await fetch(`${base}/health`)).status).toBe(200);
    expect((await fetch(`${base}/v1/rules`)).status).toBe(200);
  });

  it("returns 402 (not 500) on a malformed payment amount", async () => {
    const payer = "Payer1111111111111111111111111111111111111";
    const nonce = randomUUID();
    const resource = "/v1/scan/url";
    const amount = "not-a-number";
    const signature = verifier.sign({ resource, amount, payer, nonce });
    const header = encodePaymentHeader({
      x402Version: 1,
      scheme: "exact",
      network: "solana",
      resource,
      amount,
      payer,
      nonce,
      signature,
    });
    const res = await fetch(`${base}${resource}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-payment": header },
      body: JSON.stringify({ url: "s0lana.xyz" }),
    });
    expect(res.status).toBe(402);
    expect((await res.json()).error).toBe("invalid_amount");
  });

  it("rejects a payment with a mismatched protocol envelope", async () => {
    const payer = "Payer1111111111111111111111111111111111111";
    const nonce = randomUUID();
    const resource = "/v1/scan/url";
    const amount = "10000";
    const signature = verifier.sign({ resource, amount, payer, nonce });
    const header = encodePaymentHeader({
      x402Version: 1,
      scheme: "exact",
      network: "ethereum" as never, // wrong network
      resource,
      amount,
      payer,
      nonce,
      signature,
    });
    const res = await fetch(`${base}${resource}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-payment": header },
      body: JSON.stringify({ url: "s0lana.xyz" }),
    });
    expect(res.status).toBe(402);
    expect((await res.json()).error).toBe("network_mismatch");
  });
});

describe("SyncApiServer /v1/scan/text", () => {
  const server = new SyncApiServer();
  let base = "";
  beforeAll(async () => {
    const { port } = await server.listen(0);
    base = `http://127.0.0.1:${port}`;
  });
  afterAll(() => server.close());

  it("scans a raw text blob with no explicit id", async () => {
    const res = await fetch(`${base}/v1/scan/text`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: "is_whitelisted; can_sell = false; transfer_hook" }),
    });
    expect(res.status).toBe(200);
    expect((await res.json()).findings.length).toBeGreaterThan(0);
  });

  it("400s when text is empty", async () => {
    const res = await fetch(`${base}/v1/scan/text`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ label: "no text" }),
    });
    expect(res.status).toBe(400);
  });
});
