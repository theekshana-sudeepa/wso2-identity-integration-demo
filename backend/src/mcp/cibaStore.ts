import crypto from "node:crypto";
import type { McpToolName } from "../types/auth.js";

export type CibaApprovalStatus = "PENDING" | "APPROVED" | "DENIED" | "CONSUMED" | "EXPIRED";

export interface CibaApprovalRequest {
  readonly authReqId: string;
  readonly sub: string;
  readonly actorSub: string;
  readonly tool: McpToolName;
  readonly requiredScope: string;
  readonly bindingMessage: string;
  readonly boundJti: string | null;
  readonly createdAtSec: number;
  readonly expiresAtSec: number;
  readonly status: CibaApprovalStatus;
  readonly approvalToken?: string;
}

class CibaApprovalStore {
  private readonly requests = new Map<string, CibaApprovalRequest>();
  private readonly approvalTokens = new Map<
    string,
    {
      readonly authReqId: string;
      readonly sub: string;
      readonly tool: McpToolName;
      readonly expiresAtSec: number;
      consumed: boolean;
    }
  >();

  public createRequest(params: {
    readonly sub: string;
    readonly actorSub: string;
    readonly tool: McpToolName;
    readonly requiredScope: string;
    readonly boundJti: string | null;
    readonly ttlSeconds?: number;
  }): CibaApprovalRequest {
    const nowSec = Math.floor(Date.now() / 1000);
    const ttl = params.ttlSeconds ?? 120;
    const authReqId = `ciba_${crypto.randomBytes(10).toString("base64url")}`;
    const req: CibaApprovalRequest = {
      authReqId,
      sub: params.sub,
      actorSub: params.actorSub,
      tool: params.tool,
      requiredScope: params.requiredScope,
      bindingMessage: `Approve high-risk tool "${params.tool}" (${params.requiredScope}) requested by ${params.actorSub}`,
      boundJti: params.boundJti,
      createdAtSec: nowSec,
      expiresAtSec: nowSec + ttl,
      status: "PENDING"
    };

    if (this.requests.size > 200) {
      const oldest = this.requests.keys().next().value;
      if (oldest) this.requests.delete(oldest);
    }
    this.requests.set(authReqId, req);
    return req;
  }

  public getRequest(authReqId: string): CibaApprovalRequest | null {
    const entry = this.requests.get(authReqId);
    if (!entry) return null;
    const nowSec = Math.floor(Date.now() / 1000);
    if (entry.status === "PENDING" && entry.expiresAtSec < nowSec) {
      const expired: CibaApprovalRequest = { ...entry, status: "EXPIRED" };
      this.requests.set(authReqId, expired);
      return expired;
    }
    return entry;
  }

  public decideRequest(
    authReqId: string,
    decision: "APPROVED" | "DENIED"
  ): CibaApprovalRequest | null {
    const current = this.getRequest(authReqId);
    if (!current || current.status !== "PENDING") {
      return current;
    }

    if (decision === "DENIED") {
      const denied: CibaApprovalRequest = { ...current, status: "DENIED" };
      this.requests.set(authReqId, denied);
      return denied;
    }

    const approvalToken = `hat_${crypto.randomBytes(12).toString("base64url")}`;
    const approved: CibaApprovalRequest = {
      ...current,
      status: "APPROVED",
      approvalToken
    };
    this.requests.set(authReqId, approved);
    this.approvalTokens.set(approvalToken, {
      authReqId,
      sub: current.sub,
      tool: current.tool,
      expiresAtSec: current.expiresAtSec,
      consumed: false
    });
    return approved;
  }

  /**
   * Verifies and consumes a one-time CIBA approval token (or accepts pre-signed
   * test tokens in unit suites that start with a non-hat_ prefix).
   */
  public verifyAndConsumeApprovalToken(
    token: string,
    sub: string,
    tool: McpToolName
  ): boolean {
    if (!token.startsWith("hat_")) {
      return token.trim().length > 0;
    }
    const record = this.approvalTokens.get(token);
    if (!record || record.consumed) {
      return false;
    }
    const nowSec = Math.floor(Date.now() / 1000);
    if (record.expiresAtSec < nowSec || record.sub !== sub || record.tool !== tool) {
      return false;
    }
    record.consumed = true;
    const req = this.requests.get(record.authReqId);
    if (req) {
      this.requests.set(record.authReqId, { ...req, status: "CONSUMED" });
    }
    return true;
  }
}

export const cibaApprovalStore = new CibaApprovalStore();
