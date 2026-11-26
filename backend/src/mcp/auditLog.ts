import crypto from "node:crypto";
import type { McpToolName } from "../types/auth.js";
import type { McpRiskTier } from "./toolRegistry.js";

export interface McpAuditEntry {
  readonly id: string;
  readonly timestamp: string;
  readonly sub: string;
  readonly actorSub: string;
  readonly tool: McpToolName;
  readonly riskTier: McpRiskTier;
  readonly decision: "ALLOWED" | "DENIED";
  readonly status: number;
  readonly reason: string;
  readonly jti: string | null;
}

class McpAuditRingBuffer {
  private readonly capacity: number;
  private readonly buffer: McpAuditEntry[] = [];
  private totalRecordedCount = 0;

  constructor(capacity = 50) {
    this.capacity = capacity;
  }

  public record(entry: Omit<McpAuditEntry, "id" | "timestamp">): McpAuditEntry {
    const fullEntry: McpAuditEntry = {
      id: `aud_${crypto.randomBytes(6).toString("base64url")}`,
      timestamp: new Date().toISOString(),
      ...entry
    };
    this.buffer.unshift(fullEntry);
    if (this.buffer.length > this.capacity) {
      this.buffer.pop();
    }
    this.totalRecordedCount += 1;
    return fullEntry;
  }

  public list(): readonly McpAuditEntry[] {
    return [...this.buffer];
  }

  public totalRecorded(): number {
    return this.totalRecordedCount;
  }

  public clear(): void {
    this.buffer.length = 0;
    this.totalRecordedCount = 0;
  }
}

export const mcpAuditLog = new McpAuditRingBuffer(50);
