import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Bot, Command, Moon, ShieldCheck, Sun, UserCheck } from "lucide-react";
import { ApiTestBench } from "./components/ApiTestBench";
import { AuthSessionCard } from "./components/AuthSessionCard";
import { CodeExporterDrawer } from "./components/CodeExporterDrawer";
import { CommandPalette, type CommandPaletteAction } from "./components/CommandPalette";
import { JwtClaimsInspector } from "./components/JwtClaimsInspector";
import { OidcFlowVisualizer } from "./components/OidcFlowVisualizer";
import {
  checkBackendHealth,
  invokeProtectedApi,
  simulateMcpToolCall,
  simulateRbacPolicyCall,
  type ApiCallResult,
  type ApiEndpointSpec,
  type BackendHealthStatus,
  type ExecutionMode
} from "./lib/apiClient";
import {
  clearSession,
  createDelegatedAgentSession,
  createDemoSession,
  decodeJwt,
  generateLivePkceTelemetry,
  getInitialPreset,
  getOidcConfig,
  handleOidcCallback,
  initiateWso2Login,
  loadSession,
  parseJwtClaims,
  type DelegatedAgentSession,
  type IdpPreset,
  type PkceTelemetry,
  type TokenSession
} from "./lib/pkce";
import {
  evaluateFaultScenario,
  FAULT_PRESETS,
  generateCodeSnippets,
  type FaultState,
  type FlowMode,
  type FlowStageId,
  type McpToolName,
  type McpToolSpec
} from "./lib/securityLab";

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
  const [preset, setPreset] = useState<IdpPreset>(
    () => loadSession()?.preset ?? getInitialPreset()
  );
  const config = useMemo(() => getOidcConfig(preset), [preset]);

  const [flowMode, setFlowMode] = useState<FlowMode>("human");
  const [selectedStage, setSelectedStage] = useState<FlowStageId>("pkce");
  const [activeFault, setActiveFault] = useState<FaultState>({ id: "none" });
  const [attackLabOpen, setAttackLabOpen] = useState(false);

  const [session, setSession] = useState<TokenSession | null>(() => loadSession());
  const [authError, setAuthError] = useState<string | null>(null);
  const [pkceTelemetry, setPkceTelemetry] = useState<PkceTelemetry | null>(null);
  const [executionMode, setExecutionMode] = useState<ExecutionMode>("live");
  const userSelectedModeRef = useRef(false);

  const [apiResult, setApiResult] = useState<ApiCallResult | null>(null);
  const [lastMcpResult, setLastMcpResult] = useState<ApiCallResult | null>(null);
  const [loadingEndpoint, setLoadingEndpoint] = useState<string | null>(null);
  const [mcpLoadingTool, setMcpLoadingTool] = useState<McpToolName | null>(null);
  const [backendHealth, setBackendHealth] = useState<BackendHealthStatus>({
    reachable: false,
    statusText: "Checking API..."
  });

  const [delegatedSession, setDelegatedSession] = useState<DelegatedAgentSession | null>(null);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [exporterOpen, setExporterOpen] = useState(false);
  const [toastMessage, setToastMessage] = useState<string | null>(null);
  const toastTimerRef = useRef<number | null>(null);

  const showToast = useCallback((message: string) => {
    setToastMessage(message);
    if (toastTimerRef.current !== null) {
      window.clearTimeout(toastTimerRef.current);
    }
    toastTimerRef.current = window.setTimeout(() => {
      setToastMessage(null);
      toastTimerRef.current = null;
    }, 2400);
  }, []);

  useEffect(() => {
    return () => {
      if (toastTimerRef.current !== null) {
        window.clearTimeout(toastTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      // Ignore storage errors
    }
  }, [theme]);

  useEffect(() => {
    const onGlobalKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((prev) => !prev);
      } else if (e.key === "Escape") {
        setExporterOpen(false);
      }
    };
    window.addEventListener("keydown", onGlobalKeyDown);
    return () => window.removeEventListener("keydown", onGlobalKeyDown);
  }, []);

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
        if (!status.reachable && !userSelectedModeRef.current) {
          setExecutionMode("dry-run");
        }
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

  const delegatedDecoded = useMemo(() => {
    return delegatedSession ? decodeJwt(delegatedSession.accessToken) : null;
  }, [delegatedSession]);

  const delegatedClaims = useMemo(() => {
    return delegatedDecoded ? parseJwtClaims(delegatedDecoded) : null;
  }, [delegatedDecoded]);

  const faultEval = useMemo(
    () =>
      evaluateFaultScenario(activeFault, {
        config,
        claims,
        pkceTelemetry
      }),
    [activeFault, config, claims, pkceTelemetry]
  );

  const handleChangeMode = useCallback((nextMode: ExecutionMode) => {
    userSelectedModeRef.current = true;
    setExecutionMode(nextMode);
  }, []);

  const handleSwitchFlowMode = useCallback(
    (nextFlowMode: FlowMode) => {
      setFlowMode(nextFlowMode);
      if (nextFlowMode === "agent") {
        let activeHumanClaims = claims;
        if (!session) {
          const demo = createDemoSession("admin", config);
          setSession(demo);
          const dec = decodeJwt(demo.accessToken);
          activeHumanClaims = dec ? parseJwtClaims(dec) : null;
        }
        const obo = createDelegatedAgentSession(activeHumanClaims, config);
        setDelegatedSession(obo);
        setSelectedStage("agent_mcp");
      } else {
        setSelectedStage((current) => (current === "agent_mcp" ? "rbac" : current));
      }
    },
    [claims, config, session]
  );

  const handleRefreshDelegatedToken = useCallback(() => {
    const fresh = createDelegatedAgentSession(claims, config);
    setDelegatedSession(fresh);
    showToast("Minted fresh 60s RFC 8693 OBO delegated agent token");
  }, [claims, config, showToast]);

  const handleChangeFault = useCallback((nextFault: FaultState) => {
    setActiveFault(nextFault);
    if (nextFault.id !== "none") {
      const preview = evaluateFaultScenario(nextFault, {
        config,
        claims,
        pkceTelemetry
      });
      if (preview.failingStage) {
        setSelectedStage(preview.failingStage);
      }
    }
  }, [config, claims, pkceTelemetry]);

  const handleSelectPreset = useCallback(
    (nextPreset: IdpPreset) => {
      setPreset(nextPreset);
      setAuthError(null);
      const nextCfg = getOidcConfig(nextPreset);
      if (session?.mode === "demo" && session.demoRole) {
        const refreshed = createDemoSession(session.demoRole, nextCfg);
        setSession(refreshed);
        if (flowMode === "agent") {
          const dec = decodeJwt(refreshed.accessToken);
          setDelegatedSession(
            createDelegatedAgentSession(dec ? parseJwtClaims(dec) : null, nextCfg)
          );
        }
      } else if (flowMode === "agent") {
        setDelegatedSession(createDelegatedAgentSession(claims, nextCfg));
      }
    },
    [claims, flowMode, session]
  );

  const onLiveLogin = useCallback(async () => {
    setAuthError(null);
    try {
      await initiateWso2Login(config);
    } catch (err: unknown) {
      setAuthError(err instanceof Error ? err.message : "Unable to initiate OIDC login.");
    }
  }, [config]);

  const onDemoLogin = useCallback(
    (role: "user" | "admin") => {
      setAuthError(null);
      const demoSession = createDemoSession(role, config);
      setSession(demoSession);
      if (flowMode === "agent") {
        const dec = decodeJwt(demoSession.accessToken);
        setDelegatedSession(
          createDelegatedAgentSession(dec ? parseJwtClaims(dec) : null, config)
        );
      }
      showToast(`Loaded ${role === "admin" ? "Demo Admin" : "Demo Developer"} RS256 session`);
    },
    [config, flowMode, showToast]
  );

  const onLogout = useCallback(() => {
    clearSession();
    setSession(null);
    setDelegatedSession(null);
    setApiResult(null);
    setLastMcpResult(null);
    setAuthError(null);
    showToast("Cleared active OIDC session");
  }, [showToast]);

  const handleInvokeEndpoint = useCallback(
    async (spec: ApiEndpointSpec) => {
      setLoadingEndpoint(spec.path);
      try {
        const shouldSimulate = executionMode === "dry-run" || !backendHealth.reachable;
        if (shouldSimulate) {
          const simulated = simulateRbacPolicyCall(spec, config, session, claims, activeFault);
          setApiResult(simulated);
        } else {
          const tokenToSend = faultEval.mutatedToken ?? session?.accessToken;
          const liveResult = await invokeProtectedApi(
            config.backendApiUrl,
            spec.path,
            spec.method,
            tokenToSend,
            spec.defaultBody
          );
          setApiResult(liveResult);
        }
      } finally {
        setLoadingEndpoint(null);
      }
    },
    [activeFault, backendHealth.reachable, claims, config, executionMode, faultEval.mutatedToken, session]
  );

  const handleInvokeMcpTool = useCallback(
    async (toolSpec: McpToolSpec) => {
      const activeObo = delegatedSession ?? createDelegatedAgentSession(claims, config);
      if (!delegatedSession) {
        setDelegatedSession(activeObo);
      }
      setMcpLoadingTool(toolSpec.name);
      try {
        const shouldSimulate = executionMode === "dry-run" || !backendHealth.reachable;
        if (shouldSimulate) {
          const simulated = simulateMcpToolCall(toolSpec, activeObo, config, activeFault);
          setLastMcpResult(simulated);
          setApiResult(simulated);
        } else {
          const tokenToSend = faultEval.mutatedToken ?? activeObo.accessToken;
          const liveResult = await invokeProtectedApi(
            config.backendApiUrl,
            "/api/mcp/tools/call",
            "POST",
            tokenToSend,
            { tool: toolSpec.name, arguments: toolSpec.sampleArguments }
          );
          setLastMcpResult(liveResult);
          setApiResult(liveResult);
        }
        setSelectedStage("agent_mcp");
      } finally {
        setMcpLoadingTool(null);
      }
    },
    [
      activeFault,
      backendHealth.reachable,
      claims,
      config,
      delegatedSession,
      executionMode,
      faultEval.mutatedToken
    ]
  );

  const toggleTheme = useCallback(() => {
    setTheme((prev) => (prev === "dark" ? "light" : "dark"));
  }, []);

  const toggleAttackLab = useCallback(() => {
    setAttackLabOpen((prev) => !prev);
  }, []);

  const openCodeExporter = useCallback(() => {
    setExporterOpen(true);
  }, []);

  const closeCodeExporter = useCallback(() => {
    setExporterOpen(false);
  }, []);

  const closePalette = useCallback(() => {
    setPaletteOpen(false);
  }, []);

  const paletteActions: readonly CommandPaletteAction[] = useMemo(() => {
    const stageActions: CommandPaletteAction[] = [
      {
        id: "stage-spa",
        group: "Navigation",
        label: "Jump to Stage 01 · React Public SPA",
        hint: "Stage 01",
        keywords: "spa client public browser",
        run: () => setSelectedStage("spa")
      },
      {
        id: "stage-pkce",
        group: "Navigation",
        label: "Jump to Stage 02 · Web Crypto S256 PKCE",
        hint: "Stage 02",
        keywords: "pkce s256 verifier challenge state",
        run: () => setSelectedStage("pkce")
      },
      {
        id: "stage-idp",
        group: "Navigation",
        label: "Jump to Stage 03 · Choreo Labs / WSO2 IS",
        hint: "Stage 03",
        keywords: "wso2 asgardeo idp token authorize",
        run: () => setSelectedStage("idp")
      },
      {
        id: "stage-jwks",
        group: "Navigation",
        label: "Jump to Stage 04 · Stateless RS256 JWKS Verify",
        hint: "Stage 04",
        keywords: "jwks rs256 kid verify cache",
        run: () => setSelectedStage("jwks")
      },
      {
        id: "stage-rbac",
        group: "Navigation",
        label: "Jump to Stage 05 · RBAC Protected API",
        hint: "Stage 05",
        keywords: "rbac roles scopes api express",
        run: () => setSelectedStage("rbac")
      },
      {
        id: "stage-agent",
        group: "Navigation",
        label: "Jump to Stage 06 · AI Agent OBO & MCP Guard",
        hint: "Stage 06 · RFC 8693",
        keywords: "ai agent obo mcp 8693 delegation",
        run: () => handleSwitchFlowMode("agent")
      }
    ];

    const faultActions: CommandPaletteAction[] = FAULT_PRESETS.map((presetItem) => ({
      id: `fault-${presetItem.id}`,
      group: "Attack Lab",
      label:
        presetItem.id === "none"
          ? "Reset Attack Lab to Nominal Baseline"
          : `Inject Fault: ${presetItem.label}`,
      hint: presetItem.rfc,
      keywords: `fault attack lab ${presetItem.label} ${presetItem.rfc}`,
      run: () => {
        setAttackLabOpen(true);
        handleChangeFault(presetItem.createDefaultState());
      }
    }));

    const modeAndPersonaActions: CommandPaletteAction[] = [
      {
        id: "mode-toggle",
        group: "Mode & Personas",
        label:
          flowMode === "human"
            ? "Switch to AI Agent Delegation + MCP Guard (6-Stage)"
            : "Switch to Human CIAM Flow (5-Stage)",
        hint: flowMode === "human" ? "6-Stage" : "5-Stage",
        keywords: "mode toggle human agent mcp 8693",
        run: () => handleSwitchFlowMode(flowMode === "human" ? "agent" : "human")
      },
      {
        id: "persona-dev",
        group: "Mode & Personas",
        label: "Load Demo Developer Persona",
        hint: "Standard User",
        keywords: "demo developer persona user token",
        run: () => onDemoLogin("user")
      },
      {
        id: "persona-admin",
        group: "Mode & Personas",
        label: "Load Demo Admin Persona",
        hint: "Admin + write:reports",
        keywords: "demo admin persona privileged token",
        run: () => onDemoLogin("admin")
      },
      {
        id: "preset-wso2",
        group: "Mode & Personas",
        label: "Switch IdP to WSO2 Identity Server 7.0",
        hint: "Docker Local",
        keywords: "wso2 is7 docker local preset",
        run: () => handleSelectPreset("wso2is")
      },
      {
        id: "preset-asgardeo",
        group: "Mode & Personas",
        label: "Switch IdP to Asgardeo Cloud",
        hint: "Choreo Labs SaaS",
        keywords: "asgardeo cloud saas preset",
        run: () => handleSelectPreset("asgardeo")
      }
    ];

    const utilActions: CommandPaletteAction[] = [
      {
        id: "util-theme",
        group: "Developer Tools",
        label: `Switch to ${theme === "dark" ? "Light" : "Dark"} Theme`,
        hint: theme === "dark" ? "Light" : "Dark",
        keywords: "theme dark light appearance",
        run: toggleTheme
      },
      {
        id: "util-exporter",
        group: "Developer Tools",
        label: "Open Live Request & Code Exporter",
        hint: "curl · TS · JSON",
        keywords: "export code curl typescript json config",
        run: openCodeExporter
      },
      {
        id: "util-copy-token",
        group: "Developer Tools",
        label: "Copy Active Bearer JWT",
        hint: "Clipboard",
        keywords: "copy token jwt bearer",
        run: () => {
          const tok =
            flowMode === "agent" && delegatedSession
              ? delegatedSession.accessToken
              : session?.accessToken;
          if (!tok) {
            showToast("No active Bearer token to copy");
            return;
          }
          navigator.clipboard
            .writeText(tok)
            .then(() => showToast("Copied Bearer JWT to clipboard"))
            .catch(() => showToast("Clipboard unavailable"));
        }
      },
      {
        id: "util-copy-curl",
        group: "Developer Tools",
        label: "Copy Redacted curl Command",
        hint: "Clipboard",
        keywords: "copy curl command snippet",
        run: () => {
          const generated = generateCodeSnippets({
            config,
            flowMode,
            selectedStage,
            activeToken: session?.accessToken ?? null,
            faultEval,
            delegatedSession,
            redactToken: true
          });
          navigator.clipboard
            .writeText(generated.curl)
            .then(() => showToast("Copied curl command to clipboard"))
            .catch(() => showToast("Clipboard unavailable"));
        }
      }
    ];

    return [...stageActions, ...faultActions, ...modeAndPersonaActions, ...utilActions];
  }, [
    config,
    delegatedSession,
    faultEval,
    flowMode,
    handleChangeFault,
    handleSelectPreset,
    handleSwitchFlowMode,
    onDemoLogin,
    openCodeExporter,
    selectedStage,
    session,
    showToast,
    theme,
    toggleTheme
  ]);

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
                {!backendHealth.reachable && (
                  <span
                    className="sim-mode-badge"
                    title="Express backend unreachable — full protocol simulation runs locally in browser with zero errors"
                  >
                    Browser Simulation Mode
                  </span>
                )}
              </div>
              <p>
                OAuth 2.0 OIDC PKCE (S256) · Stateless RS256 JWKS · Attack Lab · RFC 8693 AI Agent
                MCP Guard
              </p>
            </div>
          </div>

          <div className="topbar-right">
            {/* Human CIAM (5-Stage) vs AI Agent Delegation (6-Stage) Switch */}
            <div className="segmented-tabs mode-switch-tabs" role="tablist" aria-label="Architecture Flow Mode">
              <button
                type="button"
                role="tab"
                aria-selected={flowMode === "human"}
                className={`seg-tab ${flowMode === "human" ? "seg-tab-active" : ""}`}
                onClick={() => handleSwitchFlowMode("human")}
              >
                <UserCheck size={13} />
                Human CIAM (5-Stage)
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={flowMode === "agent"}
                className={`seg-tab ${flowMode === "agent" ? "seg-tab-active seg-tab-agent" : ""}`}
                onClick={() => handleSwitchFlowMode("agent")}
              >
                <Bot size={13} />
                AI Agent + MCP (6-Stage)
              </button>
            </div>

            <button
              type="button"
              className="cmdk-trigger"
              onClick={() => setPaletteOpen(true)}
              aria-label="Open Command Palette (Cmd+K)"
              title="Open Command Palette (Cmd+K / Ctrl+K)"
            >
              <Command size={13} />
              <span>K</span>
            </button>

            <div className="status-pill">
              <span className={`status-dot ${session ? "dot-active" : "dot-idle"}`} />
              <span>
                {session
                  ? session.mode === "live"
                    ? "Live OIDC"
                    : `Demo · ${session.demoRole === "admin" ? "Admin" : "Developer"}`
                  : "Unauthenticated"}
              </span>
            </div>

            <button
              type="button"
              className="theme-toggle"
              onClick={toggleTheme}
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
            flowMode={flowMode}
            selectedStage={selectedStage}
            session={session}
            claims={claims}
            delegatedSession={delegatedSession}
            pkceTelemetry={pkceTelemetry}
            lastApiResult={apiResult}
            lastMcpResult={lastMcpResult}
            activeFault={activeFault}
            faultEval={faultEval}
            attackLabOpen={attackLabOpen}
            mcpLoadingTool={mcpLoadingTool}
            onSelectStage={setSelectedStage}
            onChangeFault={handleChangeFault}
            onToggleAttackLab={toggleAttackLab}
            onRegeneratePkce={regeneratePkce}
            onRefreshDelegatedToken={handleRefreshDelegatedToken}
            onInvokeMcpTool={handleInvokeMcpTool}
            onOpenCodeExporter={openCodeExporter}
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
              onNotifyCopy={showToast}
            />

            <JwtClaimsInspector
              flowMode={flowMode}
              decoded={decoded}
              claims={claims}
              delegatedDecoded={delegatedDecoded}
              delegatedClaims={delegatedClaims}
            />
          </section>

          <ApiTestBench
            executionMode={executionMode}
            backendHealth={backendHealth}
            loadingEndpoint={loadingEndpoint}
            apiResult={apiResult}
            faultEval={faultEval}
            onChangeMode={handleChangeMode}
            onInvoke={handleInvokeEndpoint}
          />
        </main>

        <footer className="app-footer">
          <span>
            Choreo Labs (formerly WSO2) CIAM &amp; AI Agent Identity Reference · React 19 + Strict
            TypeScript + Express RS256 JWKS
          </span>
          <span>RFC 7636 PKCE · RFC 8725 · RFC 8693 OBO · Press ⌘K for Commands</span>
        </footer>
      </div>

      <CommandPalette
        isOpen={paletteOpen}
        actions={paletteActions}
        onClose={closePalette}
      />

      <CodeExporterDrawer
        isOpen={exporterOpen}
        config={config}
        flowMode={flowMode}
        selectedStage={selectedStage}
        activeToken={session?.accessToken ?? null}
        faultEval={faultEval}
        delegatedSession={delegatedSession}
        onClose={closeCodeExporter}
        onNotifyCopy={showToast}
      />

      {toastMessage && (
        <div className="toast-banner" role="status" aria-live="polite">
          <ShieldCheck size={14} />
          <span>{toastMessage}</span>
        </div>
      )}
    </div>
  );
}

export default App;
