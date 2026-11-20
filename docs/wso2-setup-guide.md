# Choreo Labs (formerly WSO2) — WSO2 Identity Server 7.0 & Asgardeo Setup Guide

This runbook details how to configure an OAuth 2.0 / OIDC Single-Page Application (SPA) Public Client and stateless Resource API with **Choreo Labs (formerly WSO2)** identity platforms: **WSO2 Identity Server 7.0** (local Docker) or **Asgardeo Cloud** (SaaS).

## 1. Register the SPA Public Client

1. Open the **WSO2 Identity Server 7.0 Console** (`https://localhost:9443/console`) or the **Asgardeo Console** (`https://console.asgardeo.io`).
2. Navigate to **Applications** -> **New Application** -> **Single-Page Application**.
3. Configure the application metadata:
   - **Name**: `Choreo Labs Identity Demo SPA`
   - **Authorized Redirect URLs**: `http://localhost:5173/callback`
   - **Allowed Origins (CORS)**: `http://localhost:5173`
4. Under **Protocol**:
   - **Grant Type**: `Code`
   - **Public Client**: **Enabled** (zero client secret exposed in browser bundles)
   - **PKCE**: **Mandatory** (`S256` — RFC 7636)
   - **Access Token Type**: `JWT` (asymmetric `RS256` signing)
   - **Audience**: Add `wso2-api-demo` (or match your Asgardeo API Resource identifier)

## 2. Configure Identity Claims, Groups & Scopes

1. Navigate to **User Attributes** within the registered application.
2. Enable the following OIDC scopes and claims:
   - `openid`
   - `profile` (`username`, `given_name`, `family_name`)
   - `email`
   - `groups` (Maps user groups/roles into the JWT `groups` or `roles` claim for backend RBAC middleware)
3. (Optional) Register an API Resource / custom OAuth 2.0 scope `write:reports` to test `POST /api/v1/reports`.
4. Assign at least one test user to the `admin` group to validate `GET /api/v1/admin/audit-logs`.

## 3. Configure Environment Variables

Copy the sanitized templates and substitute your generated **Client ID** and tenant URL:

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

### Local WSO2 IS 7.0 (Docker)

```env
WSO2_IS_BASE_URL=https://localhost:9443
WSO2_ISSUER=https://localhost:9443/oauth2/token
WSO2_AUDIENCE=wso2-api-demo
WSO2_JWKS_URI=https://localhost:9443/oauth2/jwks
ALLOW_SELF_SIGNED_CERTS=true
```

### Asgardeo Cloud (Choreo Labs SaaS)

```env
WSO2_IS_BASE_URL=https://api.asgardeo.io/t/<your-org-name>
WSO2_ISSUER=https://api.asgardeo.io/t/<your-org-name>/oauth2/token
WSO2_AUDIENCE=<your-asgardeo-app-client-id-or-api-resource>
WSO2_JWKS_URI=https://api.asgardeo.io/t/<your-org-name>/oauth2/jwks
ALLOW_SELF_SIGNED_CERTS=false
```

> Never commit `.env` files to version control. All `.env*` files (except `.env.example`) are blocked by `.gitignore`.
