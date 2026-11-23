import cors from "cors";
import express, { type ErrorRequestHandler, type Express, type RequestHandler } from "express";
import helmet from "helmet";
import identityConfig from "./config/identityConfig.js";
import { authenticateToken } from "./middleware/authMiddleware.js";
import { createApiRouter } from "./routes/apiRoutes.js";
import { createMcpRouter } from "./routes/mcpRoutes.js";

export interface CreateAppOptions {
  readonly authMiddleware?: RequestHandler;
}

export function createApp(options?: CreateAppOptions): Express {
  const app = express();
  const authMiddleware = options?.authMiddleware ?? authenticateToken;

  app.use(helmet());
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
      allowedHeaders: ["Authorization", "Content-Type"]
    })
  );
  app.use(express.json({ limit: "1mb" }));

  app.get("/health", (_req, res) => {
    res.json({
      status: "ok",
      environment: identityConfig.nodeEnv,
      issuer: identityConfig.issuer,
      jwksUri: identityConfig.jwksUri,
      mcpToolsEndpoint: "/api/mcp/tools/call",
      uptimeSeconds: Math.round(process.uptime())
    });
  });

  app.use("/api/v1", createApiRouter(authMiddleware));
  app.use("/api/mcp", createMcpRouter(authMiddleware));

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
