const dotenv = require("dotenv");

dotenv.config();

const baseUrl = (process.env.WSO2_IS_BASE_URL || "https://localhost:9443").replace(/\/+$/, "");

const identityConfig = {
  port: Number(process.env.PORT || 5050),
  nodeEnv: process.env.NODE_ENV || "development",
  corsOrigin: process.env.CORS_ORIGIN || "http://localhost:5173",
  wso2BaseUrl: baseUrl,
  issuer: process.env.WSO2_ISSUER || `${baseUrl}/oauth2/token`,
  audience: process.env.WSO2_AUDIENCE || "wso2-api-demo",
  jwksUri: process.env.WSO2_JWKS_URI || `${baseUrl}/oauth2/jwks`,
  allowSelfSignedCerts: process.env.ALLOW_SELF_SIGNED_CERTS === "true"
};

module.exports = identityConfig;
