import express from "express";
import identityConfig from "../config/identityConfig.js";
import { authenticateToken } from "../middleware/authMiddleware.js";
import { requireRoles, requireScopes } from "../middleware/rbacMiddleware.js";

interface CreateReportBody {
  title?: unknown;
}

const router = express.Router();

router.get("/public/info", (_req, res) => {
  res.json({
    service: "wso2-identity-integration-api",
    providerFamily: "Choreo Labs (formerly WSO2) — WSO2 Identity Server 7.0 & Asgardeo",
    status: "operational",
    authProtocol: "OAuth 2.0 / OpenID Connect (OIDC) with S256 PKCE",
    tokenSigning: "Stateless RS256 via JWKS Cache",
    identityProvider: identityConfig.wso2BaseUrl,
    issuer: identityConfig.issuer,
    jwksUri: identityConfig.jwksUri,
    timestamp: new Date().toISOString()
  });
});

router.get("/user/profile", authenticateToken, (req, res) => {
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
      scopes: user.scopes
    },
    verifiedAt: new Date().toISOString()
  });
});

router.get("/user/roles", authenticateToken, (req, res) => {
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
  authenticateToken,
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
  authenticateToken,
  requireScopes("write:reports"),
  (req, res) => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: "unauthorized", message: "Missing user context." });
      return;
    }

    const body = (req.body ?? {}) as CreateReportBody;
    const rawTitle = typeof body.title === "string" ? body.title.trim() : "";
    const title = rawTitle.length > 0 ? rawTitle.slice(0, 160) : "Security Compliance Summary";

    res.status(201).json({
      id: `rep_${Date.now()}`,
      title,
      createdBy: user.username,
      status: "CREATED",
      timestamp: new Date().toISOString()
    });
  }
);

export default router;
