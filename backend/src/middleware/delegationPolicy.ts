import { AGENT_ACTOR_PREFIX, MAX_DELEGATION_DEPTH } from "../config/agentPolicy.js";
import type { ActorClaim } from "../types/auth.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export interface ParsedActorChain {
  readonly chain: readonly ActorClaim[];
  readonly truncated: boolean;
}

/**
 * Iteratively walks an RFC 8693 §4.1 nested `act` claim up to `hardLimit` links
 * to prevent unbounded recursion on deeply nested or crafted payloads.
 */
export function parseActorChain(rawAct: unknown, hardLimit = 10): ParsedActorChain {
  const rawLinks: Array<{
    readonly sub: string;
    readonly client_id?: string;
    readonly delegation_protocol?: string;
  }> = [];

  let current: unknown = rawAct;
  while (
    rawLinks.length < hardLimit &&
    isRecord(current) &&
    typeof current.sub === "string" &&
    current.sub.trim().length > 0
  ) {
    rawLinks.push({
      sub: current.sub.trim(),
      client_id: typeof current.client_id === "string" ? current.client_id : undefined,
      delegation_protocol:
        typeof current.delegation_protocol === "string" ? current.delegation_protocol : undefined
    });
    current = current.act;
  }

  const truncated =
    rawLinks.length >= hardLimit &&
    isRecord(current) &&
    typeof current.sub === "string" &&
    current.sub.trim().length > 0;

  if (rawLinks.length === 0) {
    return { chain: [], truncated: false };
  }

  const chain: ActorClaim[] = new Array<ActorClaim>(rawLinks.length);
  for (let i = rawLinks.length - 1; i >= 0; i -= 1) {
    const link = rawLinks[i];
    chain[i] = {
      sub: link.sub,
      ...(link.client_id !== undefined ? { client_id: link.client_id } : {}),
      ...(link.delegation_protocol !== undefined
        ? { delegation_protocol: link.delegation_protocol }
        : {}),
      ...(i < rawLinks.length - 1 ? { act: chain[i + 1] } : {})
    };
  }

  return { chain, truncated };
}

export type ActChainVerdict =
  | { readonly ok: true }
  | {
      readonly ok: false;
      readonly reason:
        | "delegation_required"
        | "delegation_chain_too_deep"
        | "delegation_cycle_detected";
      readonly details: string;
    };

/**
 * Evaluates RFC 8693 §4.1 delegation chain invariants:
 * - Outermost actor must carry the `agent:` prefix
 * - Chain depth must not exceed `maxDepth` (or `hardLimit` truncation)
 * - No duplicate actor `sub` in the chain and no actor matching `subject`
 */
export function evaluateActChain(
  subject: string,
  chain: readonly ActorClaim[],
  truncated: boolean,
  maxDepth = MAX_DELEGATION_DEPTH
): ActChainVerdict {
  if (chain.length === 0 || !chain[0].sub.startsWith(AGENT_ACTOR_PREFIX)) {
    return {
      ok: false,
      reason: "delegation_required",
      details: "Token does not carry a valid RFC 8693 delegated AI agent actor (act.sub) claim."
    };
  }

  if (truncated || chain.length > maxDepth) {
    const depthText = truncated ? `>${chain.length}` : String(chain.length);
    return {
      ok: false,
      reason: "delegation_chain_too_deep",
      details: `Delegation chain depth (${depthText}) exceeds maximum allowed depth (${maxDepth}).`
    };
  }

  const seen = new Set<string>();
  for (const actor of chain) {
    if (actor.sub === subject || seen.has(actor.sub)) {
      return {
        ok: false,
        reason: "delegation_cycle_detected",
        details: `Delegation cycle detected involving actor "${actor.sub}".`
      };
    }
    seen.add(actor.sub);
  }

  return { ok: true };
}

export type MayActVerdict =
  | { readonly permitted: true }
  | { readonly permitted: false; readonly reason: "may_act_missing" | "actor_not_listed" };

/**
 * STS-side RFC 8693 §4.4 `may_act` authorization check.
 * Enforced by the Dev IdP token-exchange endpoint in Phase 2; exported and
 * unit-tested here as the canonical policy evaluator.
 */
export function evaluateMayAct(
  subjectTokenClaims: Record<string, unknown>,
  actorSub: string,
  opts: { readonly requireExplicitMayAct: boolean }
): MayActVerdict {
  const rawMayAct = subjectTokenClaims.may_act;
  if (rawMayAct === undefined || rawMayAct === null) {
    return opts.requireExplicitMayAct
      ? { permitted: false, reason: "may_act_missing" }
      : { permitted: true };
  }

  if (isRecord(rawMayAct)) {
    return typeof rawMayAct.sub === "string" && rawMayAct.sub.trim() === actorSub
      ? { permitted: true }
      : { permitted: false, reason: "actor_not_listed" };
  }

  if (Array.isArray(rawMayAct)) {
    const matched = rawMayAct.some(
      (entry) => isRecord(entry) && typeof entry.sub === "string" && entry.sub.trim() === actorSub
    );
    return matched ? { permitted: true } : { permitted: false, reason: "actor_not_listed" };
  }

  return { permitted: false, reason: "actor_not_listed" };
}
