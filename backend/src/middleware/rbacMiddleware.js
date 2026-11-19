function requireRoles(...allowedRoles) {
  const normalizedAllowed = allowedRoles.map((role) => role.toLowerCase());

  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "unauthorized",
        message: "Authentication context missing."
      });
    }

    const userGroups = (req.user.groups || []).map((group) => String(group).toLowerCase());
    const hasMatch = normalizedAllowed.some((role) => userGroups.includes(role));

    if (!hasMatch) {
      return res.status(403).json({
        error: "forbidden",
        message: `Access denied. Required role(s): ${allowedRoles.join(", ")}.`,
        assignedRoles: req.user.groups
      });
    }

    return next();
  };
}

function requireScopes(...requiredScopes) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        error: "unauthorized",
        message: "Authentication context missing."
      });
    }

    const userScopes = req.user.scopes || [];
    const missingScopes = requiredScopes.filter((scope) => !userScopes.includes(scope));

    if (missingScopes.length > 0) {
      return res.status(403).json({
        error: "insufficient_scope",
        message: `Missing required OAuth2 scope(s): ${missingScopes.join(", ")}.`,
        grantedScopes: userScopes
      });
    }

    return next();
  };
}

module.exports = {
  requireRoles,
  requireScopes
};
