import { useCallback, useEffect, useMemo, useState } from "react";
import { Moon, ShieldCheck, Sun } from "lucide-react";
import { ApiTestBench } from "./components/ApiTestBench";
import { AuthSessionCard } from "./components/AuthSessionCard";
import { JwtClaimsInspector } from "./components/JwtClaimsInspector";
import { OidcFlowVisualizer } from "./components/OidcFlowVisualizer";
import {
  checkBackendHealth,
  invokeProtectedApi,
  simulateRbacPolicyCall,
  type ApiCallResult,
  type ApiEndpointSpec,
  type BackendHealthStatus,
  type ExecutionMode
} from "./lib/apiClient";
import {
  clearSession,
  createDemoSession,
  decodeJwt,
  generateLivePkceTelemetry,
  getInitialPreset,
  getOidcConfig,
  handleOidcCallback,
  initiateWso2Login,
  loadSession,
  parseJwtClaims,
  type IdpPreset,
  type PkceTelemetry,
  type TokenSession
} from "./lib/pkce";

type ThemeMode = "dark" | "light";
const THEME_STORAGE_KEY = "wso2_console_theme";

function getInitialTheme(): ThemeMode {
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === "light" || saved === "dark") {
      return saved;
    }
  } catch {
    // Ignore storage access errors in restricted environments
  }
  return "dark";
}

export function App() {
  const [theme, setTheme] = useState<ThemeMode>(getInitialTheme);
  const [preset, setPreset] = useState<IdpPreset>(() => loadSession()?.preset ?? getInitialPreset());
  const config = useMemo(() => getOidcConfig(preset), [preset]);

  const [session, setSession] = useState<TokenSession | null>(() => loadSession());
  const [authError, setAuthError] = useState<string | null>(null);
  const [pkceTelemetry, setPkceTelemetry] = useState<PkceTelemetry | null>(null);
  const [executionMode, setExecutionMode] = useState<ExecutionMode>("live");
  const [apiResult, setApiResult] = useState<ApiCallResult | null>(null);
  const [loadingEndpoint, setLoadingEndpoint] = useState<string | null>(null);
  const [backendHealth, setBackendHealth] = useState<BackendHealthStatus>({
    reachable: false,
    statusText: "Checking API..."
  });

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // Ignore storage errors
    }
  }, [theme]);

  const regeneratePkce = useCallback(async () => {
    const fresh = await generateLivePkceTelemetry();
    setPkceTelemetry(fresh);
  }, []);

  useEffect(() => {
    let active = true;
    generateLivePkceTelemetry()
      .then((fresh) => {
        if (active) setPkceTelemetry(fresh);
      })
      .catch(() => {
        // Web Crypto fallback ignored if unavailable
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    let active = true;
    checkBackendHealth(config.backendApiUrl).then((status) => {
      if (active) {
        setBackendHealth(status);
      }
    });
    return () => {
      active = false;
    };
  }, [config.backendApiUrl]);

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

  const claims = useMemo(() => {
    return decoded ? parseJwtClaims(decoded) : null;
  }, [decoded]);

  function handleSelectPreset(nextPreset: IdpPreset) {
    setPreset(nextPreset);
    setAuthError(null);
    if (session?.mode === "demo" && session.demoRole) {
      const refreshed = createDemoSession(session.demoRole, getOidcConfig(nextPreset));
      setSession(refreshed);
    }
  }

  async function onLiveLogin() {
    setAuthError(null);
    try {
      await initiateWso2Login(config);
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Unable to initiate OIDC login.");
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

  async function handleInvokeEndpoint(spec: ApiEndpointSpec) {
    setLoadingEndpoint(spec.path);
    try {
      if (executionMode === "dry-run") {
        const simulated = simulateRbacPolicyCall(spec, config, session, claims);
        setApiResult(simulated);
      } else {
        const liveResult = await invokeProtectedApi(
          config.backendApiUrl,
          spec.path,
          spec.method,
          session?.accessToken,
          spec.defaultBody
        );
        setApiResult(liveResult);
      }
    } finally {
      setLoadingEndpoint(null);
    }
  }

  return (
    <div className="app-backdrop">
      <div className="app-shell">
        <header className="topbar">
          <div className="brand">
            <div className="brand-icon">
              <ShieldCheck size={20} />
            </div>
            <div>
              <div className="brand-title-row">
                <h1>WSO2 Identity Integration Console</h1>
                <span className="brand-tag">Choreo Labs · IS 7.0 &amp; Asgardeo</span>
              </div>
              <p>OAuth 2.0 OIDC PKCE (S256) Public Client · Stateless RS256 JWKS · RBAC Guard</p>
            </div>
          </div>

          <div className="topbar-right">
            <div className="status-pill">
              <span className={`status-dot ${session ? "dot-active" : "dot-idle"}`} />
              <span>
                {session
                  ? session.mode === "live"
                    ? "Authenticated · Live OIDC"
                    : `Demo · ${session.demoRole === "admin" ? "Admin" : "Developer"}`
                  : "Unauthenticated"}
              </span>
            </div>

            <button
              type="button"
              className="theme-toggle"
              onClick={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            >
              {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
              <span>{theme === "dark" ? "Light" : "Dark"}</span>
            </button>
          </div>
        </header>

        <main className="main-stack">
          <OidcFlowVisualizer
            config={config}
            session={session}
            claims={claims}
            pkceTelemetry={pkceTelemetry}
            lastApiResult={apiResult}
            onRegeneratePkce={regeneratePkce}
          />

          <section className="grid-2">
            <AuthSessionCard
              config={config}
              session={session}
              authError={authError}
              onSelectPreset={handleSelectPreset}
              onLiveLogin={onLiveLogin}
              onDemoLogin={onDemoLogin}
              onLogout={onLogout}
            />

            <JwtClaimsInspector decoded={decoded} claims={claims} />
          </section>

          <ApiTestBench
            executionMode={executionMode}
            backendHealth={backendHealth}
            loadingEndpoint={loadingEndpoint}
            apiResult={apiResult}
            onChangeMode={setExecutionMode}
            onInvoke={handleInvokeEndpoint}
          />
        </main>

        <footer className="app-footer">
          <span>
            Choreo Labs (formerly WSO2) CIAM Reference Architecture · React 19 + Strict TypeScript +
            Express RS256 JWKS
          </span>
          <span>RFC 7636 PKCE (S256) · OIDC Core 1.0 · MIT License</span>
        </footer>
      </div>
    </div>
  );
}

export default App;
