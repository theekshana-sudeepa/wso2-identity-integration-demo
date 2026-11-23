import { memo } from "react";
import { Activity, Play, Server, ShieldAlert, ShieldCheck, Zap } from "lucide-react";
import {
  API_ENDPOINTS,
  type ApiCallResult,
  type ApiEndpointSpec,
  type BackendHealthStatus,
  type ExecutionMode
} from "../lib/apiClient";
import type { FaultEvaluation } from "../lib/securityLab";
import { JsonHighlighter } from "./JsonHighlighter";

interface ApiTestBenchProps {
  readonly executionMode: ExecutionMode;
  readonly backendHealth: BackendHealthStatus;
  readonly loadingEndpoint: string | null;
  readonly apiResult: ApiCallResult | null;
  readonly faultEval: FaultEvaluation;
  readonly onChangeMode: (mode: ExecutionMode) => void;
  readonly onInvoke: (spec: ApiEndpointSpec) => Promise<void>;
}

function getStatusBadgeClass(status: number): string {
  if (status >= 200 && status < 300) return "http-2xx";
  if (status === 401) return "http-401";
  if (status === 403 || status === 400) return "http-403";
  return "http-err";
}

function getStatusText(status: number): string {
  switch (status) {
    case 200:
      return "200 OK";
    case 201:
      return "201 Created";
    case 400:
      return "400 Bad Request";
    case 401:
      return "401 Unauthorized";
    case 403:
      return "403 Forbidden";
    case 404:
      return "404 Not Found";
    case 0:
      return "Network Error";
    default:
      return `HTTP ${status}`;
  }
}

export const ApiTestBench = memo(function ApiTestBench({
  executionMode,
  backendHealth,
  loadingEndpoint,
  apiResult,
  faultEval,
  onChangeMode,
  onInvoke
}: ApiTestBenchProps) {
  return (
    <section className="card">
      <div className="bench-header">
        <div className="card-title">
          <span className="icon-box">
            <Server size={16} />
          </span>
          <div>
            <h2>Protected Resource Server Test Bench</h2>
            <p className="card-caption">
              Validate stateless RS256 JWKS verification, RBAC role guards, OAuth 2.0 scopes &amp;
              MCP tool delegation
            </p>
          </div>
        </div>

        <div className="bench-controls">
          {faultEval.active && (
            <div className="fault-active-pill" title={faultEval.summary}>
              <Zap size={12} />
              <span>Fault: {faultEval.shortLabel}</span>
            </div>
          )}

          <div
            className="health-pill"
            title={
              backendHealth.reachable
                ? backendHealth.issuer ?? "Express Resource Server online"
                : "Express backend unreachable — running seamlessly in Browser Simulation Mode"
            }
          >
            <span className={`status-dot ${backendHealth.reachable ? "dot-active" : "dot-sim"}`} />
            <span>{backendHealth.statusText}</span>
          </div>

          <div className="segmented-tabs" role="tablist" aria-label="API execution mode">
            <button
              type="button"
              role="tab"
              aria-selected={executionMode === "live"}
              className={`seg-tab ${executionMode === "live" ? "seg-tab-active" : ""}`}
              onClick={() => onChangeMode("live")}
            >
              <Activity size={13} />
              Live Express API
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={executionMode === "dry-run"}
              className={`seg-tab ${executionMode === "dry-run" ? "seg-tab-active" : ""}`}
              onClick={() => onChangeMode("dry-run")}
            >
              <ShieldCheck size={13} />
              {backendHealth.reachable ? "Policy Dry-Run" : "Browser Simulation"}
            </button>
          </div>
        </div>
      </div>

      <div className="bench-grid">
        <div className="endpoint-list">
          {API_ENDPOINTS.map((spec) => {
            const isLoading = loadingEndpoint === spec.path;
            return (
              <div key={spec.id} className="endpoint-row">
                <div className="endpoint-left">
                  <div className="endpoint-meta">
                    <span className={`badge ${spec.method === "POST" ? "badge-post" : "badge-get"}`}>
                      {spec.method}
                    </span>
                    <span className="endpoint-path">{spec.path}</span>
                    <span className={`policy-badge policy-${spec.policyKind}`}>
                      {spec.policyLabel}
                    </span>
                  </div>
                  <p className="endpoint-desc">{spec.description}</p>
                </div>

                <button
                  type="button"
                  className="btn btn-sm"
                  disabled={loadingEndpoint !== null}
                  onClick={() => onInvoke(spec)}
                >
                  <Play size={12} />
                  {isLoading ? "Calling..." : "Invoke"}
                </button>
              </div>
            );
          })}
        </div>

        <div className="response-panel">
          <div className="response-toolbar">
            <div className="response-meta-left">
              {apiResult ? (
                <>
                  <span className={`http-pill ${getStatusBadgeClass(apiResult.status)}`}>
                    {getStatusText(apiResult.status)}
                  </span>
                  <span className="response-route">
                    {apiResult.method} {apiResult.endpoint}
                  </span>
                </>
              ) : (
                <span className="response-idle">HTTP Response Telemetry</span>
              )}
            </div>

            {apiResult && (
              <div className="response-meta-right">
                <span className="latency-chip">{apiResult.latencyMs} ms</span>
                <span className="mode-chip">
                  {apiResult.mode === "live" ? "Live Express" : "Browser Simulation"}
                </span>
              </div>
            )}
          </div>

          {apiResult?.defenseTrace && (
            <div
              className={`bench-trace-banner ${
                apiResult.defenseTrace.outcome === "REJECTED"
                  ? "bench-trace-rejected"
                  : "bench-trace-allowed"
              }`}
            >
              {apiResult.defenseTrace.outcome === "REJECTED" ? (
                <ShieldAlert size={14} />
              ) : (
                <ShieldCheck size={14} />
              )}
              <div>
                <strong>{apiResult.defenseTrace.layer}</strong> ({apiResult.defenseTrace.rfc}):{" "}
                <span>{apiResult.defenseTrace.details}</span>
              </div>
            </div>
          )}

          <JsonHighlighter
            data={apiResult ? apiResult.data : null}
            maxHeight={340}
            emptyMessage={
              "// Click Invoke on any endpoint (or Execute Tool in AI Agent mode) to inspect HTTP status,\n// latency, RBAC/MCP verdicts & structured Defense Traces.\n// Static reviewers get 100% interactivity automatically via Browser Simulation Mode."
            }
            copyLabel="Copy API response JSON"
          />
        </div>
      </div>
    </section>
  );
});
