import crypto from "node:crypto";
import type { RequestHandler } from "express";

/**
 * Attaches a cryptographic correlation request ID (`X-Request-Id`) to every request
 * and emits structured JSON telemetry logs outside of test runs.
 */
export function createRequestContextMiddleware(): RequestHandler {
  const isTest = process.env.VITEST === "true" || process.env.NODE_ENV === "test";

  return (req, res, next) => {
    const incomingId = req.headers["x-request-id"];
    const requestId =
      typeof incomingId === "string" && incomingId.trim().length > 0
        ? incomingId.trim().slice(0, 64)
        : `req_${crypto.randomBytes(8).toString("base64url")}`;

    res.setHeader("X-Request-Id", requestId);
    const startNs = process.hrtime.bigint();

    res.on("finish", () => {
      if (isTest) return;
      const durationMs = Number(process.hrtime.bigint() - startNs) / 1_000_000;
      const logEntry = {
        level: res.statusCode >= 500 ? "error" : res.statusCode >= 400 ? "warn" : "info",
        time: new Date().toISOString(),
        requestId,
        method: req.method,
        path: req.originalUrl,
        status: res.statusCode,
        latencyMs: Number(durationMs.toFixed(2))
      };
      console.log(JSON.stringify(logEntry));
    });

    next();
  };
}

export interface SlidingWindowRateLimiterOptions {
  readonly windowMs: number;
  readonly maxRequests: number;
  readonly scopeLabel: string;
}

/**
 * Dependency-free in-memory sliding-window rate limiter with standard
 * `X-RateLimit-Limit` and `X-RateLimit-Remaining` headers.
 */
export function createRateLimiter(options: SlidingWindowRateLimiterOptions): RequestHandler {
  const buckets = new Map<string, { count: number; resetAtMs: number }>();

  return (req, res, next) => {
    const nowMs = Date.now();
    const clientKey = req.ip || req.socket.remoteAddress || "127.0.0.1";
    let entry = buckets.get(clientKey);

    if (!entry || entry.resetAtMs <= nowMs) {
      if (buckets.size > 2000) {
        buckets.clear();
      }
      entry = { count: 0, resetAtMs: nowMs + options.windowMs };
      buckets.set(clientKey, entry);
    }

    entry.count += 1;
    const remaining = Math.max(0, options.maxRequests - entry.count);
    res.setHeader("X-RateLimit-Limit", String(options.maxRequests));
    res.setHeader("X-RateLimit-Remaining", String(remaining));

    if (entry.count > options.maxRequests) {
      res.status(429).json({
        error: "too_many_requests",
        message: `Rate limit exceeded for ${options.scopeLabel} (${options.maxRequests} requests per ${Math.round(options.windowMs / 1000)}s).`
      });
      return;
    }

    next();
  };
}
