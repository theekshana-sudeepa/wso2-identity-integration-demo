import { createContext, useContext, type Dispatch } from "react";
import type {
  ApiCallResult,
  BackendHealthStatus,
  ExecutionMode,
  McpAuditEntry,
  PendingCibaRequest,
  VerificationMode
} from "../lib/apiClient";
import {
  getInitialPreset,
  loadSession,
  type DelegatedAgentSession,
  type IdpPreset,
  type PkceTelemetry,
  type TokenSession
} from "../lib/pkce";
import {
  assertNever,
  type FaultState,
  type FlowMode,
  type FlowStageId,
  type McpToolName
} from "../lib/securityLab";

export type ThemeMode = "dark" | "light";
export const THEME_STORAGE_KEY = "wso2_console_theme";

export function getInitialTheme(): ThemeMode {
  try {
    if (typeof localStorage !== "undefined") {
      const saved = localStorage.getItem(THEME_STORAGE_KEY);
      if (saved === "light" || saved === "dark") {
        return saved;
      }
    }
  } catch {
    // Ignore storage access errors in restricted environments
  }
  return "dark";
}

export interface ConsoleState {
  readonly theme: ThemeMode;
  readonly preset: IdpPreset;
  readonly flowMode: FlowMode;
  readonly selectedStage: FlowStageId;
  readonly activeFault: FaultState;
  readonly attackLabOpen: boolean;
  readonly session: TokenSession | null;
  readonly authError: string | null;
  readonly pkceTelemetry: PkceTelemetry | null;
  readonly executionMode: ExecutionMode;
  readonly apiResult: ApiCallResult | null;
  readonly lastMcpResult: ApiCallResult | null;
  readonly loadingEndpoint: string | null;
  readonly mcpLoadingTool: McpToolName | null;
  readonly backendHealth: BackendHealthStatus;
  readonly delegatedSession: DelegatedAgentSession | null;
  readonly mcpAuditEntries: readonly McpAuditEntry[];
  readonly pendingCibaRequest: PendingCibaRequest | null;
  readonly verificationMode: VerificationMode;
  readonly tokenRevoked: boolean;
  readonly paletteOpen: boolean;
  readonly exporterOpen: boolean;
  readonly toastMessage: string | null;
}

export type ConsoleAction =
  | { readonly type: "SET_THEME"; readonly theme: ThemeMode }
  | { readonly type: "TOGGLE_THEME" }
  | { readonly type: "SET_PRESET"; readonly preset: IdpPreset }
  | { readonly type: "SET_FLOW_MODE"; readonly flowMode: FlowMode }
  | { readonly type: "SET_SELECTED_STAGE"; readonly stage: FlowStageId }
  | { readonly type: "SET_ACTIVE_FAULT"; readonly fault: FaultState }
  | { readonly type: "SET_ATTACK_LAB_OPEN"; readonly open: boolean }
  | { readonly type: "TOGGLE_ATTACK_LAB" }
  | { readonly type: "SET_SESSION"; readonly session: TokenSession | null }
  | { readonly type: "SET_AUTH_ERROR"; readonly error: string | null }
  | { readonly type: "SET_PKCE_TELEMETRY"; readonly telemetry: PkceTelemetry | null }
  | { readonly type: "SET_EXECUTION_MODE"; readonly mode: ExecutionMode }
  | { readonly type: "SET_API_RESULT"; readonly result: ApiCallResult | null }
  | { readonly type: "SET_LAST_MCP_RESULT"; readonly result: ApiCallResult | null }
  | { readonly type: "SET_LOADING_ENDPOINT"; readonly endpoint: string | null }
  | { readonly type: "SET_MCP_LOADING_TOOL"; readonly tool: McpToolName | null }
  | { readonly type: "SET_BACKEND_HEALTH"; readonly health: BackendHealthStatus }
  | { readonly type: "SET_DELEGATED_SESSION"; readonly session: DelegatedAgentSession | null }
  | { readonly type: "SET_MCP_AUDIT_ENTRIES"; readonly entries: readonly McpAuditEntry[] }
  | { readonly type: "SET_PENDING_CIBA_REQUEST"; readonly request: PendingCibaRequest | null }
  | { readonly type: "SET_VERIFICATION_MODE"; readonly mode: VerificationMode }
  | { readonly type: "SET_TOKEN_REVOKED"; readonly revoked: boolean }
  | { readonly type: "SET_PALETTE_OPEN"; readonly open: boolean }
  | { readonly type: "TOGGLE_PALETTE" }
  | { readonly type: "SET_EXPORTER_OPEN"; readonly open: boolean }
  | { readonly type: "SET_TOAST_MESSAGE"; readonly message: string | null }
  | { readonly type: "LOGOUT_SESSION" };

export function createInitialConsoleState(): ConsoleState {
  const existingSession = loadSession();
  return {
    theme: getInitialTheme(),
    preset: existingSession?.preset ?? getInitialPreset(),
    flowMode: "human",
    selectedStage: "pkce",
    activeFault: { id: "none" },
    attackLabOpen: false,
    session: existingSession,
    authError: null,
    pkceTelemetry: null,
    executionMode: "live",
    apiResult: null,
    lastMcpResult: null,
    loadingEndpoint: null,
    mcpLoadingTool: null,
    backendHealth: {
      reachable: false,
      statusText: "Checking API..."
    },
    delegatedSession: null,
    mcpAuditEntries: [],
    pendingCibaRequest: null,
    verificationMode: "jwks",
    tokenRevoked: false,
    paletteOpen: false,
    exporterOpen: false,
    toastMessage: null
  };
}

export function consoleReducer(state: ConsoleState, action: ConsoleAction): ConsoleState {
  switch (action.type) {
    case "SET_THEME":
      return { ...state, theme: action.theme };
    case "TOGGLE_THEME":
      return { ...state, theme: state.theme === "dark" ? "light" : "dark" };
    case "SET_PRESET":
      return { ...state, preset: action.preset, authError: null };
    case "SET_FLOW_MODE":
      return {
        ...state,
        flowMode: action.flowMode,
        selectedStage:
          action.flowMode === "agent"
            ? "agent_mcp"
            : state.selectedStage === "agent_mcp"
              ? "rbac"
              : state.selectedStage
      };
    case "SET_SELECTED_STAGE":
      return { ...state, selectedStage: action.stage };
    case "SET_ACTIVE_FAULT":
      return { ...state, activeFault: action.fault };
    case "SET_ATTACK_LAB_OPEN":
      return { ...state, attackLabOpen: action.open };
    case "TOGGLE_ATTACK_LAB":
      return { ...state, attackLabOpen: !state.attackLabOpen };
    case "SET_SESSION":
      return { ...state, session: action.session };
    case "SET_AUTH_ERROR":
      return { ...state, authError: action.error };
    case "SET_PKCE_TELEMETRY":
      return { ...state, pkceTelemetry: action.telemetry };
    case "SET_EXECUTION_MODE":
      return { ...state, executionMode: action.mode };
    case "SET_API_RESULT":
      return { ...state, apiResult: action.result };
    case "SET_LAST_MCP_RESULT":
      return { ...state, lastMcpResult: action.result };
    case "SET_LOADING_ENDPOINT":
      return { ...state, loadingEndpoint: action.endpoint };
    case "SET_MCP_LOADING_TOOL":
      return { ...state, mcpLoadingTool: action.tool };
    case "SET_BACKEND_HEALTH":
      return { ...state, backendHealth: action.health };
    case "SET_DELEGATED_SESSION":
      return { ...state, delegatedSession: action.session };
    case "SET_MCP_AUDIT_ENTRIES":
      return { ...state, mcpAuditEntries: action.entries };
    case "SET_PENDING_CIBA_REQUEST":
      return { ...state, pendingCibaRequest: action.request };
    case "SET_VERIFICATION_MODE":
      return { ...state, verificationMode: action.mode };
    case "SET_TOKEN_REVOKED":
      return { ...state, tokenRevoked: action.revoked };
    case "SET_PALETTE_OPEN":
      return { ...state, paletteOpen: action.open };
    case "TOGGLE_PALETTE":
      return { ...state, paletteOpen: !state.paletteOpen };
    case "SET_EXPORTER_OPEN":
      return { ...state, exporterOpen: action.open };
    case "SET_TOAST_MESSAGE":
      return { ...state, toastMessage: action.message };
    case "LOGOUT_SESSION":
      return {
        ...state,
        session: null,
        delegatedSession: null,
        pendingCibaRequest: null,
        tokenRevoked: false,
        apiResult: null,
        lastMcpResult: null,
        authError: null
      };
    default:
      return assertNever(action);
  }
}

export interface ConsoleContextValue {
  readonly state: ConsoleState;
  readonly dispatch: Dispatch<ConsoleAction>;
}

export const ConsoleContext = createContext<ConsoleContextValue | null>(null);

export function useConsoleContext(): ConsoleContextValue {
  const ctx = useContext(ConsoleContext);
  if (!ctx) {
    throw new Error("useConsoleContext must be used inside a ConsoleContext.Provider");
  }
  return ctx;
}
