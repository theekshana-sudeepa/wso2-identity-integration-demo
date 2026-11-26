#!/bin/sh
set -eu

WSO2_HOST="${WSO2_HOST:-https://wso2is:9443}"
ADMIN_AUTH="${WSO2_ADMIN_USER:-admin}:${WSO2_ADMIN_PASS:-admin}"

echo "[wso2-bootstrap] Registering SPA Public Client via WSO2 IS 7.0 DCR v1.1..."
curl -k -fsS -X POST "${WSO2_HOST}/api/identity/oauth2/dcr/v1.1/register" \
  -u "${ADMIN_AUTH}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "choreo_spa_public_client",
    "grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
    "redirect_uris": ["http://localhost:5173/callback"],
    "ext_public_client": true,
    "ext_pkce_mandatory": true
  }' || echo "[wso2-bootstrap] DCR client already registered."

echo "[wso2-bootstrap] Provisioning SCIM2 developer & admin groups..."
curl -k -fsS -X POST "${WSO2_HOST}/scim2/Groups" \
  -u "${ADMIN_AUTH}" \
  -H "Content-Type: application/scim+json" \
  -d '{"displayName": "admin"}' || true

echo "[wso2-bootstrap] Provisioning completed."
