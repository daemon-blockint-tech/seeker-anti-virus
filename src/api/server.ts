import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { IntegratedScanner } from "../integrated-scanner/integratedScanner.js";
import type { ScanTarget } from "../types.js";
import { PaymentGate } from "./x402.js";

/**
 * Public Scanning API (PRD §6.5 / Phase 5, FR-14 & FR-16).
 *
 * A dependency-free HTTP service exposing the Sync engine:
 *   GET  /health            — liveness (free)
 *   GET  /v1/rules          — list active YARA rules (free)
 *   POST /v1/scan/app       — scan an app   (paid via x402 when a gate is set)
 *   POST /v1/scan/contract  — audit a contract/token (paid)
 *   POST /v1/scan/url       — screen a dApp URL (paid)
 *   POST /v1/scan/text      — scan a text/code blob (paid)
 *
 * When constructed with a {@link PaymentGate}, scan routes require a valid
 * `X-PAYMENT` header and otherwise return an x402 `402` challenge.
 */
export interface SyncApiServerOptions {
  scanner?: IntegratedScanner;
  /** Enable x402 micropayment gating on scan routes (FR-16). */
  gate?: PaymentGate;
  /** Max accepted request body size in bytes (default 256 KiB). */
  maxBodyBytes?: number;
}

interface ScanBody {
  id?: string;
  address?: string;
  url?: string;
  package?: string;
  text?: string;
  domain?: string;
  label?: string;
}

const SCAN_ROUTES: Record<string, ScanTarget["kind"]> = {
  "/v1/scan/app": "app",
  "/v1/scan/contract": "contract",
  "/v1/scan/url": "url",
  "/v1/scan/text": "app",
};

export class SyncApiServer {
  private readonly scanner: IntegratedScanner;
  private readonly gate?: PaymentGate;
  private readonly maxBody: number;
  private server?: Server;

  constructor(options: SyncApiServerOptions = {}) {
    this.scanner = options.scanner ?? new IntegratedScanner();
    this.gate = options.gate;
    this.maxBody = options.maxBodyBytes ?? 256 * 1024;
  }

  /** The raw request handler — exposed for testing without binding a port. */
  readonly handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      await this.route(req, res);
    } catch (err) {
      this.json(res, 500, { error: "internal_error", message: (err as Error).message });
    }
  };

  listen(port = 0): Promise<{ port: number }> {
    const server = createServer(this.handler);
    this.server = server;
    // Bound slow-loris exposure: cap how long a request may take to arrive.
    server.requestTimeout = 30_000;
    server.headersTimeout = 15_000;
    return new Promise((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      server.once("error", onError);
      server.listen(port, () => {
        server.removeListener("error", onError);
        const addr = server.address();
        resolve({ port: typeof addr === "object" && addr ? addr.port : port });
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) =>
      this.server ? this.server.close((e) => (e ? reject(e) : resolve())) : resolve(),
    );
  }

  private async route(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    const method = req.method ?? "GET";

    if (method === "GET" && path === "/health") {
      return this.json(res, 200, { status: "ok", service: "sync-api", version: 1 });
    }

    if (method === "GET" && path === "/v1/rules") {
      return this.json(res, 200, {
        rules: this.scanner.ruleManager.list().map((r) => ({
          name: r.name,
          category: r.category,
          severity: r.severity,
          description: r.meta.description,
        })),
      });
    }

    const kind = SCAN_ROUTES[path];
    if (kind && method === "POST") {
      return this.handleScan(req, res, path, kind);
    }

    this.json(res, 404, { error: "not_found", path });
  }

  private async handleScan(
    req: IncomingMessage,
    res: ServerResponse,
    path: string,
    kind: ScanTarget["kind"],
  ): Promise<void> {
    // x402 gating (FR-16): challenge unpaid requests before doing any work.
    if (this.gate) {
      const header = req.headers["x-payment"];
      const gateResult = await this.gate.check(
        path,
        Array.isArray(header) ? header[0] : header,
      );
      if (!gateResult.ok) {
        return this.json(res, gateResult.status, gateResult.body);
      }
      res.setHeader("X-Payment-Payer", gateResult.payer ?? "");
    }

    let body: ScanBody;
    try {
      body = await this.readJson(req);
    } catch (err) {
      return this.json(res, 400, { error: "invalid_body", message: (err as Error).message });
    }

    const isTextScan = path === "/v1/scan/text";
    // The text endpoint scans a raw blob, so `text` alone is a valid target.
    if (isTextScan && !body.text) {
      return this.json(res, 400, {
        error: "missing_target",
        message: "Provide a non-empty 'text' field to scan.",
      });
    }

    const id =
      body.id ?? body.address ?? body.url ?? body.package ?? (isTextScan ? "text-blob" : undefined);
    if (!id) {
      return this.json(res, 400, {
        error: "missing_target",
        message: "Provide one of: id, address, url, package.",
      });
    }

    const target: ScanTarget = {
      id,
      kind,
      label: body.label,
      text: body.text,
      domain: body.domain ?? (kind === "url" ? id : undefined),
    };

    const result = await this.scanner.scan(target);
    this.json(res, 200, result.report);
  }

  private readJson(req: IncomingMessage): Promise<ScanBody> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on("data", (c: Buffer) => {
        size += c.length;
        if (size > this.maxBody) {
          reject(new Error("request body too large"));
          req.destroy();
          return;
        }
        chunks.push(c);
      });
      req.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8").trim();
        if (!raw) return resolve({});
        try {
          resolve(JSON.parse(raw));
        } catch {
          reject(new Error("body is not valid JSON"));
        }
      });
      req.on("error", reject);
    });
  }

  private json(res: ServerResponse, status: number, body: unknown): void {
    const payload = JSON.stringify(body);
    res.writeHead(status, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(payload),
    });
    res.end(payload);
  }
}
