import type { RequestHandler } from "express";

export function requireRoles(...allowedRoles: string[]): RequestHandler {
  const normalizedAllowed = allowedRoles.map((role) => role.toLowerCase());

  return (req, res, next) => {
    if (!req.user) {
      res.status(401).json({
        error: "unauthorized",
        message: "Authentication context missing."
      });
      return;
    }

    const userGroups = req.user.groups.map((group) => group.toLowerCase());
    const hasMatch = normalizedAllowed.some((role) => userGroups.includes(role));

    if (!hasMatch) {
      res.status(403).json({
        error: "forbidden",
        message: `Access denied. Required role(s): ${allowedRoles.join(", ")}.`,
        assignedRoles: req.user.groups
      });
      return;
    }

    next();
  };
}

export function requireScopes(...requiredScopes: string[]): RequestHandler {
  return (req, res, next) => {
    if (!req.user) {
      res.status(401).json({
        error: "unauthorized",
        message: "Authentication context missing."
      });
      return;
    }

    const userScopes = req.user.scopes;
    const missingScopes = requiredScopes.filter((scope) => !userScopes.includes(scope));

    if (missingScopes.length > 0) {
      res.status(403).json({
        error: "insufficient_scope",
        message: `Missing required OAuth2 scope(s): ${missingScopes.join(", ")}.`,
        grantedScopes: userScopes
      });
      return;
    }

    next();
  };
}
