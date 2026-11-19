# WSO2 Identity Server / Asgardeo Configuration Guide

This runbook details how to configure an OAuth 2.0 / OIDC Single Page Application (SPA) and Resource API inside **WSO2 Identity Server 7.0** or **Asgardeo Cloud**.

## 1. Register the SPA Public Client

1. Open the WSO2 Identity Server Console (`https://localhost:9443/console`) or Asgardeo Console.
2. Navigate to **Applications** -> **New Application** -> **Single-Page Application**.
3. Set the following values:
   - **Name**: `WSO2 Identity Demo SPA`
   - **Authorized Redirect URLs**: `http://localhost:5173/callback`
   - **Allowed Origins (CORS)**: `http://localhost:5173`
4. Under **Protocol**:
   - Grant Type: `Code`
   - Public Client: **Enabled** (No Client Secret exposed in browser)
   - PKCE: **Mandatory** (`S256`)
   - Access Token Type: **JWT**
   - Audience: Add `wso2-api-demo`

## 2. Configure Identity Claims & Roles

1. Navigate to **User Attributes** within the registered application.
2. Enable the following OIDC scopes and claims:
   - `openid`
   - `profile` (`username`, `given_name`, `family_name`)
   - `email`
   - `groups` (Maps user groups/roles into the JWT `groups` claim for backend RBAC enforcement)
3. Ensure at least one test user is assigned to the `admin` group to validate `/api/v1/admin/audit-logs`.

## 3. Connect Environment Variables

Copy the template files and insert your generated **Client ID** and tenant base URL:

```bash
cp backend/.env.example backend/.env
cp frontend/.env.example frontend/.env
```

> Never commit `.env` files to version control. All `.env*` files (except `.env.example`) are blocked by `.gitignore`.
