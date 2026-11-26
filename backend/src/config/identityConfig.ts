import dotenv from "dotenv";
import type { IdentityConfig } from "../types/auth.js";

dotenv.config();

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function parseCorsOrigins(raw: string | undefined): readonly string[] {
  const value = raw || "http://localhost:5173,http://127.0.0.1:5173";
  return value
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
}

const baseUrl = (process.env.WSO2_IS_BASE_URL || "https://localhost:9443").replace(/\/+$/, "");

const identityConfig: IdentityConfig = {
  port: parsePositiveInt(process.env.PORT, 5050),
  nodeEnv: process.env.NODE_ENV || "development",
  corsOrigins: parseCorsOrigins(process.env.CORS_ORIGIN),
  wso2BaseUrl: baseUrl,
  issuer: process.env.WSO2_ISSUER || `${baseUrl}/oauth2/token`,
  audience: process.env.WSO2_AUDIENCE || "wso2-api-demo",
  mcpAudience: process.env.MCP_AUDIENCE || "http://localhost:5050/api/mcp",
  jwksUri: process.env.WSO2_JWKS_URI || `${baseUrl}/oauth2/jwks`,
  allowSelfSignedCerts: process.env.ALLOW_SELF_SIGNED_CERTS === "true",
  jwksCacheMaxAgeMs: parsePositiveInt(process.env.JWKS_CACHE_MAX_AGE_MS, 10 * 60 * 1000),
  jwksRequestsPerMinute: parsePositiveInt(process.env.JWKS_RATE_LIMIT_RPM, 10)
};

export default identityConfig;
