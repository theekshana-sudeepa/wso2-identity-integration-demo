import { describe, expect, it } from "vitest";
import {
  evaluateActChain,
  evaluateMayAct,
  parseActorChain
} from "../middleware/delegationPolicy.js";

describe("RFC 8693 §4.1 Nested act Chain & §4.4 may_act Policy", () => {
  it("parses nested act chains iteratively and marks truncation beyond hardLimit", () => {
    let deepAct: Record<string, unknown> = { sub: "agent:leaf" };
    for (let i = 11; i >= 1; i -= 1) {
      deepAct = {
        sub: `agent:hop-${i}`,
        client_id: `client-${i}`,
        act: deepAct
      };
    }

    const parsedDefault = parseActorChain(deepAct, 10);
    expect(parsedDefault.chain).toHaveLength(10);
    expect(parsedDefault.truncated).toBe(true);
    expect(parsedDefault.chain[0].sub).toBe("agent:hop-1");
    expect(parsedDefault.chain[0].act?.sub).toBe("agent:hop-2");

    const parsedExact = parseActorChain(
      { sub: "agent:a", act: { sub: "agent:b" } },
      10
    );
    expect(parsedExact.chain).toHaveLength(2);
    expect(parsedExact.truncated).toBe(false);
  });

  it("validates depth, prefix, and cycle invariants on act chains", () => {
    expect(evaluateActChain("usr_1", [], false)).toEqual({
      ok: false,
      reason: "delegation_required",
      details: expect.any(String)
    });

    expect(
      evaluateActChain(
        "usr_1",
        [{ sub: "service:not-an-agent" }],
        false
      )
    ).toEqual({
      ok: false,
      reason: "delegation_required",
      details: expect.any(String)
    });

    expect(
      evaluateActChain(
        "usr_1",
        [{ sub: "agent:a" }, { sub: "agent:b" }],
        false
      )
    ).toEqual({ ok: true });

    expect(
      evaluateActChain(
        "usr_1",
        [{ sub: "agent:a" }, { sub: "agent:b" }, { sub: "agent:c" }],
        false
      )
    ).toEqual({
      ok: false,
      reason: "delegation_chain_too_deep",
      details: expect.any(String)
    });

    expect(
      evaluateActChain(
        "usr_1",
        [{ sub: "agent:a" }, { sub: "agent:b" }],
        true
      )
    ).toEqual({
      ok: false,
      reason: "delegation_chain_too_deep",
      details: expect.any(String)
    });

    expect(
      evaluateActChain(
        "usr_1",
        [{ sub: "agent:a" }, { sub: "agent:a" }],
        false
      )
    ).toEqual({
      ok: false,
      reason: "delegation_cycle_detected",
      details: expect.any(String)
    });

    expect(
      evaluateActChain(
        "agent:self",
        [{ sub: "agent:self" }],
        false
      )
    ).toEqual({
      ok: false,
      reason: "delegation_cycle_detected",
      details: expect.any(String)
    });
  });

  it("enforces RFC 8693 §4.4 may_act across object, array, and missing forms", () => {
    expect(
      evaluateMayAct(
        { may_act: { sub: "agent:choreo-integrator-bot" } },
        "agent:choreo-integrator-bot",
        { requireExplicitMayAct: true }
      )
    ).toEqual({ permitted: true });

    expect(
      evaluateMayAct(
        { may_act: { sub: "agent:other-bot" } },
        "agent:choreo-integrator-bot",
        { requireExplicitMayAct: false }
      )
    ).toEqual({ permitted: false, reason: "actor_not_listed" });

    expect(
      evaluateMayAct(
        {
          may_act: [
            { sub: "agent:planner-bot" },
            { sub: "agent:choreo-integrator-bot" }
          ]
        },
        "agent:choreo-integrator-bot",
        { requireExplicitMayAct: true }
      )
    ).toEqual({ permitted: true });

    expect(
      evaluateMayAct(
        { may_act: [{ sub: "agent:planner-bot" }] },
        "agent:choreo-integrator-bot",
        { requireExplicitMayAct: true }
      )
    ).toEqual({ permitted: false, reason: "actor_not_listed" });

    expect(
      evaluateMayAct({}, "agent:choreo-integrator-bot", { requireExplicitMayAct: false })
    ).toEqual({ permitted: true });

    expect(
      evaluateMayAct({}, "agent:choreo-integrator-bot", { requireExplicitMayAct: true })
    ).toEqual({ permitted: false, reason: "may_act_missing" });
  });
});
