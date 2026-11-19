import { useEffect, useMemo, useState } from "react";
import {
  ShieldCheck,
  KeyRound,
  LogOut,
  Terminal,
  UserCheck,
  Lock,
  Sparkles,
  Server
} from "lucide-react";
import {
  clearSession,
  createDemoSession,
  decodeJwt,
  getOidcConfig,
  handleOidcCallback,
  initiateWso2Login,
  loadSession,
  type TokenSession
} from "./lib/pkce";
import { invokeProtectedApi, type ApiCallResult } from "./lib/apiClient";

export function App() {
  const config = useMemo(() => getOidcConfig(), []);
  const [session, setSession] = useState<TokenSession | null>(() => loadSession());
  const [authError, setAuthError] = useState<string | null>(null);
  const [apiResult, setApiResult] = useState<ApiCallResult | null>(null);
  const [loadingEndpoint, setLoadingEndpoint] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    handleOidcCallback(config)
      .then((newSession) => {
        if (active && newSession) {
          setSession(newSession);
          setAuthError(null);
        }
      })
      .catch((err: unknown) => {
        if (active) {
          setAuthError(err instanceof Error ? err.message : "Failed to complete OIDC callback.");
        }
      });

    return () => {
      active = false;
    };
  }, [config]);

  const decoded = useMemo(() => {
    return session ? decodeJwt(session.accessToken) : null;
  }, [session]);

  async function onLiveLogin() {
    setAuthError(null);
    try {
      await initiateWso2Login(config);
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Unable to initiate WSO2 login.");
    }
  }

  function onDemoLogin(role: "user" | "admin") {
    setAuthError(null);
    const demoSession = createDemoSession(role, config);
    setSession(demoSession);
  }

  function onLogout() {
    clearSession();
    setSession(null);
    setApiResult(null);
    setAuthError(null);
  }

  async function runApiTest(
    endpoint: string,
    method: "GET" | "POST",
    body?: Record<string, unknown>
  ) {
    setLoadingEndpoint(endpoint);
    const result = await invokeProtectedApi(
      config.backendApiUrl,
      endpoint,
      method,
      session?.accessToken,
      body
    );
    setApiResult(result);
    setLoadingEndpoint(null);
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-icon">
            <ShieldCheck size={22} />
          </div>
          <div>
            <h1>WSO2 Identity Integration Console</h1>
            <p>OAuth 2.0 + OIDC PKCE Public Client &amp; RS256 JWKS Resource Server</p>
          </div>
        </div>

        <div className="status-pill">
          <span className={`status-dot ${session ? "dot-active" : "dot-idle"}`} />
          {session
            ? session.mode === "live"
              ? "Authenticated (WSO2 Live)"
              : "Authenticated (Demo Simulation)"
            : "Unauthenticated"}
        </div>
      </header>

      <section className="grid-2">
        <article className="card">
          <div className="card-header">
            <div className="card-title">
              <KeyRound size={18} />
              <span>Authentication &amp; PKCE Flow</span>
            </div>
          </div>
          <p className="card-subtitle">
            Authenticate via WSO2 Identity Server / Asgardeo using Authorization Code Flow with
            S256 PKCE, or load a simulated RS256 session to inspect JWT claims.
          </p>

          <div className="meta-kv">
            <span className="meta-label">Identity Provider</span>
            <span className="meta-value">{config.baseUrl}</span>
            <span className="meta-label">Redirect URI</span>
            <span className="meta-value">{config.redirectUri}</span>
            <span className="meta-label">Resource API</span>
            <span className="meta-value">{config.backendApiUrl}</span>
          </div>

          <div className="btn-row">
            <button type="button" className="btn btn-primary" onClick={onLiveLogin}>
              <Lock size={15} />
              Sign in with WSO2 IS
            </button>
            <button type="button" className="btn" onClick={() => onDemoLogin("user")}>
              <Sparkles size={15} />
              Demo User Token
            </button>
            <button type="button" className="btn" onClick={() => onDemoLogin("admin")}>
              <UserCheck size={15} />
              Demo Admin Token
            </button>
            {session && (
              <button type="button" className="btn btn-danger" onClick={onLogout}>
                <LogOut size={15} />
                Sign Out
              </button>
            )}
          </div>

          {authError && <div className="alert">{authError}</div>}
        </article>

        <article className="card">
          <div className="card-header">
            <div className="card-title">
              <Terminal size={18} />
              <span>Decoded JWT Claims Inspector</span>
            </div>
          </div>
          <p className="card-subtitle">
            Real-time inspection of the active Bearer token header and verified identity claims.
          </p>

          <pre className="code-block">
            {decoded
              ? JSON.stringify(decoded, null, 2)
              : "// No active JWT session.\n// Sign in with WSO2 Identity Server or load a Demo Token."}
          </pre>
        </article>
      </section>

      <section className="card">
        <div className="card-header">
          <div className="card-title">
            <Server size={18} />
            <span>Protected Resource Server Test Bench</span>
          </div>
        </div>
        <p className="card-subtitle">
          Invoke Express backend endpoints to verify RS256 JWKS validation, role-based access
          control (RBAC), and OAuth 2.0 scope enforcement.
        </p>

        <div className="grid-2" style={{ marginBottom: 0 }}>
          <div className="endpoint-list">
            <div className="endpoint-row">
              <div className="endpoint-meta">
                <span className="badge badge-get">GET</span>
                <span>/api/v1/public/info</span>
              </div>
              <button
                type="button"
                className="btn"
                disabled={loadingEndpoint !== null}
                onClick={() => runApiTest("/api/v1/public/info", "GET")}
              >
                Test Public
              </button>
            </div>

            <div className="endpoint-row">
              <div className="endpoint-meta">
                <span className="badge badge-get">GET</span>
                <span>/api/v1/user/profile</span>
              </div>
              <button
                type="button"
                className="btn"
                disabled={loadingEndpoint !== null}
                onClick={() => runApiTest("/api/v1/user/profile", "GET")}
              >
                Test User Auth
              </button>
            </div>

            <div className="endpoint-row">
              <div className="endpoint-meta">
                <span className="badge badge-get">GET</span>
                <span>/api/v1/admin/audit-logs</span>
              </div>
              <button
                type="button"
                className="btn"
                disabled={loadingEndpoint !== null}
                onClick={() => runApiTest("/api/v1/admin/audit-logs", "GET")}
              >
                Test Admin RBAC
              </button>
            </div>

            <div className="endpoint-row">
              <div className="endpoint-meta">
                <span className="badge badge-post">POST</span>
                <span>/api/v1/reports</span>
              </div>
              <button
                type="button"
                className="btn"
                disabled={loadingEndpoint !== null}
                onClick={() =>
                  runApiTest("/api/v1/reports", "POST", {
                    title: "Quarterly Zero-Trust Audit"
                  })
                }
              >
                Test Write Scope
              </button>
            </div>
          </div>

          <div>
            <pre className="code-block" style={{ minHeight: "235px" }}>
              {apiResult
                ? JSON.stringify(
                    {
                      endpoint: `${apiResult.method} ${apiResult.endpoint}`,
                      httpStatus: apiResult.status,
                      latencyMs: apiResult.latencyMs,
                      body: apiResult.data
                    },
                    null,
                    2
                  )
                : "// Click any endpoint to inspect HTTP status, latency, and JSON payload."}
            </pre>
          </div>
        </div>
      </section>
    </div>
  );
}

export default App;
