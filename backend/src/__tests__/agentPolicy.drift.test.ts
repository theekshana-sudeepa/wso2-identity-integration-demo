import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { AGENT_TOKEN_MAX_TTL_SECONDS, MAX_DELEGATION_DEPTH } from "../config/agentPolicy.js";

function extractExportedNumber(source: string, name: string): number {
  const match = new RegExp(`export\\s+const\\s+${name}\\s*=\\s*(\\d+)\\s*;`).exec(source);
  if (!match || !match[1]) {
    throw new Error(`Unable to find exported numeric constant ${name} in frontend agentPolicy.ts`);
  }
  return Number.parseInt(match[1], 10);
}

describe("Agent Policy Constant Drift Guard", () => {
  it("keeps frontend/src/lib/agentPolicy.ts synchronized with backend/src/config/agentPolicy.ts", () => {
    const frontendPolicyPath = path.resolve(
      __dirname,
      "../../../frontend/src/lib/agentPolicy.ts"
    );
    const frontendSource = fs.readFileSync(frontendPolicyPath, "utf8");

    expect(extractExportedNumber(frontendSource, "AGENT_TOKEN_MAX_TTL_SECONDS")).toBe(
      AGENT_TOKEN_MAX_TTL_SECONDS
    );
    expect(extractExportedNumber(frontendSource, "MAX_DELEGATION_DEPTH")).toBe(
      MAX_DELEGATION_DEPTH
    );
  });
});
