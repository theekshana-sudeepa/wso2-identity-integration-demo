import crypto, { type KeyObject } from "node:crypto";
import * as jose from "jose";

export const INITIAL_ACTIVE_KID = "dev-idp-rs256-active-2026";
export const INITIAL_ROTATED_KID = "dev-idp-rs256-rotated-2026b";
export const ROGUE_UNTRUSTED_KID = "unknown-revoked-kid-9999";

export interface ManagedRsaKey {
  readonly kid: string;
  readonly privateKey: KeyObject;
  readonly publicKey: KeyObject;
  readonly publicKeyPem: string;
  readonly privateKeyPem: string;
}

function createRsaKeyPair(kid: string): ManagedRsaKey {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048
  });
  return {
    kid,
    privateKey,
    publicKey,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  };
}

class DevIdpKeyStore {
  private readonly publishedKeys = new Map<string, ManagedRsaKey>();
  private readonly rogueKey: ManagedRsaKey;
  private readonly revokedTokenHashes = new Set<string>();
  private activeKid: string;
  private rotatedKid: string;
  private rotationCounter = 1;

  constructor() {
    const active = createRsaKeyPair(INITIAL_ACTIVE_KID);
    const rotated = createRsaKeyPair(INITIAL_ROTATED_KID);
    this.rogueKey = createRsaKeyPair(ROGUE_UNTRUSTED_KID);

    this.publishedKeys.set(active.kid, active);
    this.publishedKeys.set(rotated.kid, rotated);
    this.activeKid = active.kid;
    this.rotatedKid = rotated.kid;
  }

  public getActiveKid(): string {
    return this.activeKid;
  }

  public getRotatedKid(): string {
    return this.rotatedKid;
  }

  public getActiveKey(): ManagedRsaKey {
    const key = this.publishedKeys.get(this.activeKid);
    if (!key) {
      throw new Error(`Active key ${this.activeKid} not found in DevIdpKeyStore`);
    }
    return key;
  }

  public getRotatedKey(): ManagedRsaKey {
    const key = this.publishedKeys.get(this.rotatedKid);
    if (!key) {
      throw new Error(`Rotated key ${this.rotatedKid} not found in DevIdpKeyStore`);
    }
    return key;
  }

  public getRogueKey(): ManagedRsaKey {
    return this.rogueKey;
  }

  public resolvePublicKeyPem(kid: string | undefined): string | null {
    if (!kid) return null;
    return this.publishedKeys.get(kid)?.publicKeyPem ?? null;
  }

  public revokeToken(rawToken: string, jti?: string): void {
    const hash = crypto.createHash("sha256").update(rawToken.trim(), "utf8").digest("base64url");
    this.revokedTokenHashes.add(hash);
    if (jti && jti.trim().length > 0) {
      this.revokedTokenHashes.add(`jti:${jti.trim()}`);
    }
  }

  public isTokenRevoked(rawToken: string, jti?: string): boolean {
    const hash = crypto.createHash("sha256").update(rawToken.trim(), "utf8").digest("base64url");
    if (this.revokedTokenHashes.has(hash)) {
      return true;
    }
    if (jti && this.revokedTokenHashes.has(`jti:${jti.trim()}`)) {
      return true;
    }
    return false;
  }

  public clearRevocations(): void {
    this.revokedTokenHashes.clear();
  }

  public rotateKeys(): {
    readonly previousActiveKid: string;
    readonly activeKid: string;
    readonly rotatedKid: string;
  } {
    const previousActiveKid = this.activeKid;
    this.rotationCounter += 1;
    const nextRotatedKid = `dev-idp-rs256-rotated-2026-v${this.rotationCounter}`;
    const nextKey = createRsaKeyPair(nextRotatedKid);
    this.publishedKeys.set(nextKey.kid, nextKey);

    this.activeKid = this.rotatedKid;
    this.rotatedKid = nextKey.kid;

    return {
      previousActiveKid,
      activeKid: this.activeKid,
      rotatedKid: this.rotatedKid
    };
  }

  public async getJwks(): Promise<{ readonly keys: jose.JWK[] }> {
    const keys: jose.JWK[] = [];
    for (const entry of this.publishedKeys.values()) {
      const jwk = await jose.exportJWK(entry.publicKey);
      keys.push({
        ...jwk,
        kty: "RSA",
        use: "sig",
        alg: "RS256",
        kid: entry.kid
      });
    }
    return { keys };
  }

  public async signRs256Jwt(
    payload: jose.JWTPayload,
    options?: {
      readonly kid?: string;
      readonly typ?: string;
      readonly useKey?: "active" | "rotated" | "rogue";
    }
  ): Promise<string> {
    const keyChoice = options?.useKey ?? "active";
    const signingKey =
      keyChoice === "rotated"
        ? this.getRotatedKey()
        : keyChoice === "rogue"
          ? this.rogueKey
          : this.getActiveKey();
    const kid = options?.kid ?? signingKey.kid;
    const typ = options?.typ ?? "JWT";

    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: "RS256", typ, kid })
      .sign(signingKey.privateKey);
  }

  public async verifyToken(
    token: string,
    expectedIssuer?: string
  ): Promise<jose.JWTVerifyResult> {
    return jose.jwtVerify(
      token,
      (protectedHeader) => {
        const kid = protectedHeader.kid;
        const entry = kid ? this.publishedKeys.get(kid) : undefined;
        if (!entry) {
          throw new Error(`Unknown signing key kid "${kid ?? "missing"}"`);
        }
        return entry.publicKey;
      },
      {
        algorithms: ["RS256"],
        ...(expectedIssuer ? { issuer: expectedIssuer } : {})
      }
    );
  }
}

export const devIdpKeyStore = new DevIdpKeyStore();
