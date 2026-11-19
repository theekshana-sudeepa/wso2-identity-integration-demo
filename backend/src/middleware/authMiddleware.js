const https = require("https");
const jwt = require("jsonwebtoken");
const jwksRsa = require("jwks-rsa");
const identityConfig = require("../config/identityConfig");

const requestAgent = identityConfig.allowSelfSignedCerts
  ? new https.Agent({ rejectUnauthorized: false })
  : undefined;

const jwksClient = jwksRsa({
  jwksUri: identityConfig.jwksUri,
  cache: true,
  cacheMaxEntries: 5,
  cacheMaxAge: 10 * 60 * 1000,
  rateLimit: true,
  jwksRequestsPerMinute: 10,
  requestAgent
});

function getSigningKey(header, callback) {
  if (!header.kid) {
    return callback(new Error("Missing Key ID (kid) in JWT header"));
  }

  jwksClient.getSigningKey(header.kid, (err, key) => {
    if (err) {
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    return callback(null, signingKey);
  });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "unauthorized",
      message: "Missing or malformed Authorization header. Expected Bearer token."
    });
  }

  const token = authHeader.slice(7).trim();

  jwt.verify(
    token,
    getSigningKey,
    {
      algorithms: ["RS256"],
      issuer: identityConfig.issuer,
      audience: identityConfig.audience
    },
    (err, decoded) => {
      if (err) {
        return res.status(401).json({
          error: "invalid_token",
          message: err.message
        });
      }

      req.user = {
        sub: decoded.sub,
        username: decoded.username || decoded.preferred_username || decoded.sub,
        email: decoded.email || null,
        groups: Array.isArray(decoded.groups)
          ? decoded.groups
          : Array.isArray(decoded.roles)
            ? decoded.roles
            : [],
        scopes: typeof decoded.scope === "string" ? decoded.scope.split(" ").filter(Boolean) : [],
        rawClaims: decoded
      };

      return next();
    }
  );
}

module.exports = { authenticateToken };
