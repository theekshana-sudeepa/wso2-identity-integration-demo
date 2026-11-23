import express, { type RequestHandler, type Router } from "express";
import identityConfig from "../config/identityConfig.js";
import { authenticateToken } from "../middleware/authMiddleware.js";
import { requireRoles, requireScopes } from "../middleware/rbacMiddleware.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function extractReportTitle(body: unknown): string {
  if (isRecord(body) && typeof body.title === "string") {
    const trimmed = body.title.trim();
    if (trimmed.length > 0) {
      return trimmed.slice(0, 160);
    }
  }
  return "Security Compliance Summary";
}

export function createApiRouter(authMiddleware: RequestHandler = authenticateToken): Router {
  const router = express.Router();

  router.get("/public/info", (_req, res) => {
    res.json({
      service: "wso2-identity-integration-api",
      providerFamily: "Choreo Labs (formerly WSO2) — WSO2 Identity Server 7.0 & Asgardeo",
      status: "operational",
      authProtocol: "OAuth 2.0 / OpenID Connect (OIDC) with S256 PKCE + RFC 8693 AI Agent OBO",
      tokenSigning: "Stateless RS256 via JWKS Cache",
      identityProvider: identityConfig.wso2BaseUrl,
      issuer: identityConfig.issuer,
      jwksUri: identityConfig.jwksUri,
      mcpEndpoint: "/api/mcp/tools/call",
      timestamp: new Date().toISOString()
    });
  });

  router.get("/user/profile", authMiddleware, (req, res) => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: "unauthorized", message: "Missing user context." });
      return;
    }

    res.json({
      message: "Verified identity profile retrieved from RS256 access token.",
      profile: {
        subject: user.sub,
        username: user.username,
        email: user.email,
        groups: user.groups,
        scopes: user.scopes,
        actor: user.actor
      },
      verifiedAt: new Date().toISOString()
    });
  });

  router.get("/user/roles", authMiddleware, (req, res) => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: "unauthorized", message: "Missing user context." });
      return;
    }

    res.json({
      subject: user.sub,
      roles: user.groups,
      scopes: user.scopes,
      isAdmin: user.groups.some((role) => role.toLowerCase() === "admin")
    });
  });

  router.get(
    "/admin/audit-logs",
    authMiddleware,
    requireRoles("admin", "administrator"),
    (req, res) => {
      const user = req.user;
      if (!user) {
        res.status(401).json({ error: "unauthorized", message: "Missing user context." });
        return;
      }

      res.json({
        accessedBy: user.username,
        policy: "RBAC (Role: admin)",
        entries: [
          {
            id: "evt_01",
            action: "OIDC_TOKEN_ISSUED",
            actor: user.username,
            status: "SUCCESS",
            timestamp: new Date(Date.now() - 120_000).toISOString()
          },
          {
            id: "evt_02",
            action: "JWKS_KEY_ROTATION_SYNC",
            actor: "system-jwks-cache",
            status: "VERIFIED",
            timestamp: new Date(Date.now() - 45_000).toISOString()
          },
          {
            id: "evt_03",
            action: "ADMIN_AUDIT_ACCESS",
            actor: user.username,
            status: "AUTHORIZED",
            timestamp: new Date().toISOString()
          }
        ]
      });
    }
  );

  router.post(
    "/reports",
    authMiddleware,
    requireScopes("write:reports"),
    (req, res) => {
      const user = req.user;
      if (!user) {
        res.status(401).json({ error: "unauthorized", message: "Missing user context." });
        return;
      }

      const title = extractReportTitle(req.body);

      res.status(201).json({
        id: `rep_${Date.now()}`,
        title,
        createdBy: user.username,
        status: "CREATED",
        timestamp: new Date().toISOString()
      });
    }
  );

  return router;
}

export default createApiRouter();
