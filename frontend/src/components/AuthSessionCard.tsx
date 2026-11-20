import { useState } from "react";
import {
  Check,
  Cloud,
  Copy,
  KeyRound,
  Lock,
  LogOut,
  ServerCog,
  Sparkles,
  UserCheck
} from "lucide-react";
import {
  IDP_PRESETS,
  type IdpPreset,
  type OidcConfig,
  type TokenSession
} from "../lib/pkce";

interface AuthSessionCardProps {
  readonly config: OidcConfig;
  readonly session: TokenSession | null;
  readonly authError: string | null;
  readonly onSelectPreset: (preset: IdpPreset) => void;
  readonly onLiveLogin: () => Promise<void>;
  readonly onDemoLogin: (role: "user" | "admin") => void;
  readonly onLogout: () => void;
}

export function AuthSessionCard({
  config,
  session,
  authError,
  onSelectPreset,
  onLiveLogin,
  onDemoLogin,
  onLogout
}: AuthSessionCardProps) {
  const [copiedToken, setCopiedToken] = useState(false);
  const activePreset = IDP_PRESETS[config.preset];

  async function handleCopyToken() {
    if (!session) return;
    try {
      await navigator.clipboard.writeText(session.accessToken);
      setCopiedToken(true);
      window.setTimeout(() => setCopiedToken(false), 1600);
    } catch {
      setCopiedToken(false);
    }
  }

  return (
    <article className="card">
      <div className="card-header">
        <div className="card-title">
          <span className="icon-box">
            <KeyRound size={16} />
          </span>
          <div>
            <h2>Authentication &amp; PKCE Control Plane</h2>
            <p className="card-caption">Authorization Code Flow · S256 PKCE · Zero Client Secret</p>
          </div>
        </div>
      </div>

      {/* Choreo Labs IdP Switcher */}
      <div className="preset-switcher" role="tablist" aria-label="Identity Provider Platform">
        {(Object.keys(IDP_PRESETS) as IdpPreset[]).map((presetKey) => {
          const item = IDP_PRESETS[presetKey];
          const active = config.preset === presetKey;
          return (
            <button
              key={presetKey}
              type="button"
              role="tab"
              aria-selected={active}
              className={`preset-tab ${active ? "preset-tab-active" : ""}`}
              onClick={() => onSelectPreset(presetKey)}
            >
              {presetKey === "wso2is" ? <ServerCog size={14} /> : <Cloud size={14} />}
              <div className="preset-tab-text">
                <span>{item.shortLabel}</span>
                <small>{presetKey === "wso2is" ? "Docker Local" : "Asgardeo SaaS"}</small>
              </div>
            </button>
          );
        })}
      </div>

      <div className="meta-kv">
        <span className="meta-label">Platform</span>
        <span className="meta-value">{activePreset.label}</span>
        <span className="meta-label">OIDC Issuer</span>
        <span className="meta-value">{config.issuer}</span>
        <span className="meta-label">JWKS Endpoint</span>
        <span className="meta-value">{config.jwksUri}</span>
        <span className="meta-label">Redirect URI</span>
        <span className="meta-value">{config.redirectUri}</span>
        <span className="meta-label">Resource API</span>
        <span className="meta-value">{config.backendApiUrl}</span>
      </div>

      <div className="action-section-label">Authenticate or Explore Instantly</div>
      <div className="btn-row">
        <button type="button" className="btn btn-primary" onClick={onLiveLogin}>
          <Lock size={14} />
          Sign in with {activePreset.shortLabel}
        </button>
        <button
          type="button"
          className={`btn ${session?.demoRole === "user" ? "btn-selected" : ""}`}
          onClick={() => onDemoLogin("user")}
        >
          <Sparkles size={14} />
          Demo Developer
        </button>
        <button
          type="button"
          className={`btn ${session?.demoRole === "admin" ? "btn-selected" : ""}`}
          onClick={() => onDemoLogin("admin")}
        >
          <UserCheck size={14} />
          Demo Admin
        </button>
      </div>

      {session && (
        <div className="session-footer">
          <div className="session-meta-pill">
            <span className="status-dot dot-active" />
            <span>
              {session.mode === "live"
                ? `Live RS256 Bearer (${activePreset.shortLabel})`
                : `Simulated ${session.demoRole === "admin" ? "Admin" : "Developer"} RS256 JWT`}
            </span>
          </div>
          <div className="session-footer-actions">
            <button type="button" className="btn btn-xs" onClick={handleCopyToken}>
              {copiedToken ? <Check size={13} /> : <Copy size={13} />}
              {copiedToken ? "Copied" : "Copy JWT"}
            </button>
            <button type="button" className="btn btn-xs btn-danger" onClick={onLogout}>
              <LogOut size={13} />
              Sign Out
            </button>
          </div>
        </div>
      )}

      {authError && <div className="alert">{authError}</div>}
    </article>
  );
}
