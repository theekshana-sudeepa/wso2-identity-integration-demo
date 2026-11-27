import cors from "cors";
import express, { type ErrorRequestHandler, type Express, type RequestHandler } from "express";
import helmet from "helmet";
import identityConfig from "./config/identityConfig.js";
import { createDevIdpRouter } from "./devIdp/devIdpRouter.js";
import { devIdpKeyStore } from "./devIdp/keyStore.js";
import { authenticateToken, createAuthMiddleware } from "./middleware/authMiddleware.js";
import {
  createRateLimiter,
  createRequestContextMiddleware
} from "./middleware/rateLimitAndLogger.js";
import { createApiRouter } from "./routes/apiRoutes.js";
import { createIntegrationRouter } from "./routes/integrationRoutes.js";
import {
  createMcpRouter,
  PROTECTED_RESOURCE_METADATA_URL
} from "./routes/mcpRoutes.js";
import { buildOpenApiSpec, buildScalarDocsHtml } from "./routes/openApiSpec.js";

export interface CreateAppOptions {
  readonly authMiddleware?: RequestHandler;
  readonly mcpAuthMiddleware?: RequestHandler;
}

export function createApp(options?: CreateAppOptions): Express {
  const app = express();
  const authMiddleware = options?.authMiddleware ?? authenticateToken;
  const mcpAuthMiddleware =
    options?.mcpAuthMiddleware ??
    createAuthMiddleware({
      audience: identityConfig.mcpAudience,
      resourceMetadataUrl: PROTECTED_RESOURCE_METADATA_URL
    });

  app.use(helmet());
  app.use(createRequestContextMiddleware());
  app.use(
    cors({
      origin: (origin, callback) => {
        if (!origin || identityConfig.corsOrigins.includes(origin)) {
          callback(null, true);
          return;
        }
        callback(new Error(`Origin ${origin} is not allowed by CORS policy.`));
      },
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowedHeaders: [
        "Authorization",
        "Content-Type",
        "DPoP",
        "X-Verification-Mode",
        "X-Request-Id",
        "X-WSO2-Subscription-Tier"
      ],
      exposedHeaders: [
        "WWW-Authenticate",
        "X-Request-Id",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-WSO2-Throttle-Tier",
        "X-JWT-Assertion",
        "X-Correlation-ID",
        "Retry-After"
      ]
    })
  );
  app.use(express.json({ limit: "1mb" }));

  const apiLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 300,
    scopeLabel: "/api/*"
  });
  const tokenLimiter = createRateLimiter({
    windowMs: 60_000,
    maxRequests: 120,
    scopeLabel: "/dev-idp/oauth2/token"
  });

  app.get("/health", (_req, res) => {
    res.json({
      status: "ok",
      environment: identityConfig.nodeEnv,
      devIdpEnabled: identityConfig.devIdpEnabled,
      activeKid: identityConfig.devIdpEnabled ? devIdpKeyStore.getActiveKid() : undefined,
      rotatedKid: identityConfig.devIdpEnabled ? devIdpKeyStore.getRotatedKid() : undefined,
      issuer: identityConfig.issuer,
      audience: identityConfig.audience,
      mcpAudience: identityConfig.mcpAudience,
      jwksUri: identityConfig.jwksUri,
      mcpToolsEndpoint: "/api/mcp/tools/call",
      uptimeSeconds: Math.round(process.uptime())
    });
  });

  app.get("/.well-known/oauth-protected-resource", (_req, res) => {
    res.status(200).json({
      resource: identityConfig.mcpAudience,
      authorization_servers: [identityConfig.issuer],
      jwks_uri: identityConfig.jwksUri,
      scopes_supported: ["orders:read", "refunds:execute", "users:export"],
      bearer_methods_supported: ["header"],
      dpop_signing_alg_values_supported: ["ES256"],
      resource_documentation:
        "https://github.com/theekshana-sudeepa/wso2-identity-integration-demo#readme"
    });
  });

  app.get("/api/openapi.json", (_req, res) => {
    res.status(200).json(buildOpenApiSpec());
  });

  app.get("/api/docs", (_req, res) => {
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.status(200).send(buildScalarDocsHtml());
  });

  if (identityConfig.devIdpEnabled) {
    app.use("/dev-idp/oauth2/token", tokenLimiter);
    app.use("/dev-idp", createDevIdpRouter());
  }

  app.use("/api/v1", apiLimiter, createApiRouter(authMiddleware));
  app.use("/api/mcp", apiLimiter, createMcpRouter(mcpAuthMiddleware));
  app.use("/api/integration", apiLimiter, createIntegrationRouter(authMiddleware));

  app.use((_req, res) => {
    res.status(404).json({
      error: "not_found",
      message: "Requested API endpoint does not exist."
    });
  });

  const errorHandler: ErrorRequestHandler = (err: unknown, _req, res, _next) => {
    const message = err instanceof Error ? err.message : "An unexpected server error occurred.";
    console.error("[API Error]", message);
    res.status(500).json({
      error: "internal_server_error",
      message: "An unexpected server error occurred."
    });
  };

  app.use(errorHandler);

  return app;
}

const isTestRuntime = process.env.VITEST === "true" || process.env.NODE_ENV === "test";

if (!isTestRuntime) {
  const app = createApp();
  const server = app.listen(identityConfig.port, () => {
    console.log(
      `[Choreo Labs / WSO2 Resource Server] Listening on http://localhost:${identityConfig.port} (Issuer: ${identityConfig.issuer})`
    );
  });

  const shutdown = (signal: string): void => {
    console.log(`[Choreo Labs / WSO2 Resource Server] Received ${signal}, closing gracefully...`);
    server.close(() => {
      process.exit(0);
    });
  };

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}
