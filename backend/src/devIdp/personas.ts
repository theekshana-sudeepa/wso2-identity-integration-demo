export type DevIdpPersonaId = "developer" | "admin" | "auditor";

export interface DevIdpPersona {
  readonly id: DevIdpPersonaId;
  readonly sub: string;
  readonly username: string;
  readonly email: string;
  readonly groups: readonly string[];
  readonly scopes: readonly string[];
  readonly mayAct: {
    readonly sub: string;
    readonly client_id: string;
  };
}

export const DEV_IDP_PERSONAS: Record<DevIdpPersonaId, DevIdpPersona> = {
  developer: {
    id: "developer",
    sub: "usr_4b21d90e_dev",
    username: "developer@acme-identity.example",
    email: "developer@acme-identity.example",
    groups: ["developer"],
    scopes: ["openid", "profile", "email", "groups", "read:profile", "orders:read"],
    mayAct: {
      sub: "agent:choreo-integrator-bot",
      client_id: "choreo-mcp-agent-v1"
    }
  },
  admin: {
    id: "admin",
    sub: "usr_9f82a10c_admin",
    username: "admin@acme-identity.example",
    email: "admin@acme-identity.example",
    groups: ["admin", "integration-lead", "developer"],
    scopes: [
      "openid",
      "profile",
      "email",
      "groups",
      "read:profile",
      "orders:read",
      "write:reports",
      "admin:write",
      "admin:audit",
      "refunds:execute",
      "users:export"
    ],
    mayAct: {
      sub: "agent:choreo-integrator-bot",
      client_id: "choreo-mcp-agent-v1"
    }
  },
  auditor: {
    id: "auditor",
    sub: "usr_7c31e44a_auditor",
    username: "auditor@acme-identity.example",
    email: "auditor@acme-identity.example",
    groups: ["auditor"],
    scopes: ["openid", "profile", "email", "groups", "read:profile", "orders:read", "admin:audit"],
    mayAct: {
      sub: "agent:choreo-integrator-bot",
      client_id: "choreo-mcp-agent-v1"
    }
  }
};

export function resolveDevIdpPersona(raw: unknown): DevIdpPersona {
  if (raw === "admin") {
    return DEV_IDP_PERSONAS.admin;
  }
  if (raw === "auditor") {
    return DEV_IDP_PERSONAS.auditor;
  }
  return DEV_IDP_PERSONAS.developer;
}
