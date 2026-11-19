const express = require("express");
const { authenticateToken } = require("../middleware/authMiddleware");
const { requireRoles, requireScopes } = require("../middleware/rbacMiddleware");
const identityConfig = require("../config/identityConfig");

const router = express.Router();

router.get("/public/info", (_req, res) => {
  res.json({
    service: "wso2-identity-integration-api",
    status: "operational",
    authProtocol: "OAuth 2.0 / OpenID Connect (OIDC) with PKCE",
    tokenSigning: "RS256 via JWKS",
    identityProvider: identityConfig.wso2BaseUrl,
    timestamp: new Date().toISOString()
  });
});

router.get("/user/profile", authenticateToken, (req, res) => {
  res.json({
    message: "Verified identity profile retrieved from RS256 access token.",
    profile: {
      subject: req.user.sub,
      username: req.user.username,
      email: req.user.email,
      groups: req.user.groups,
      scopes: req.user.scopes
    },
    verifiedAt: new Date().toISOString()
  });
});

router.get("/user/roles", authenticateToken, (req, res) => {
  res.json({
    subject: req.user.sub,
    roles: req.user.groups,
    scopes: req.user.scopes,
    isAdmin: req.user.groups.some((role) => role.toLowerCase() === "admin")
  });
});

router.get(
  "/admin/audit-logs",
  authenticateToken,
  requireRoles("admin", "administrator"),
  (req, res) => {
    res.json({
      accessedBy: req.user.username,
      policy: "RBAC (Role: admin)",
      entries: [
        {
          id: "evt_01",
          action: "OIDC_TOKEN_ISSUED",
          actor: req.user.username,
          status: "SUCCESS",
          timestamp: new Date(Date.now() - 120000).toISOString()
        },
        {
          id: "evt_02",
          action: "JWKS_KEY_ROTATION_SYNC",
          actor: "system-jwks-cache",
          status: "VERIFIED",
          timestamp: new Date(Date.now() - 45000).toISOString()
        },
        {
          id: "evt_03",
          action: "ADMIN_AUDIT_ACCESS",
          actor: req.user.username,
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
    const { title = "Security Compliance Summary" } = req.body || {};
    res.status(201).json({
      id: `rep_${Date.now()}`,
      title,
      createdBy: req.user.username,
      status: "CREATED",
      timestamp: new Date().toISOString()
    });
  }
);

module.exports = router;
