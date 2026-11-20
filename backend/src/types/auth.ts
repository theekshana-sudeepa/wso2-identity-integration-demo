import type { JwtPayload } from "jsonwebtoken";

export interface IdentityConfig {
  readonly port: number;
  readonly nodeEnv: string;
  readonly corsOrigins: readonly string[];
  readonly wso2BaseUrl: string;
  readonly issuer: string;
  readonly audience: string;
  readonly jwksUri: string;
  readonly allowSelfSignedCerts: boolean;
  readonly jwksCacheMaxAgeMs: number;
  readonly jwksRequestsPerMinute: number;
}

export interface VerifiedJwtClaims extends JwtPayload {
  sub?: string;
  username?: string;
  preferred_username?: string;
  email?: string;
  groups?: string[] | string;
  roles?: string[] | string;
  scope?: string;
}

export interface AuthenticatedUser {
  readonly sub: string;
  readonly username: string;
  readonly email: string | null;
  readonly groups: readonly string[];
  readonly scopes: readonly string[];
  readonly rawClaims: VerifiedJwtClaims;
}

declare module "express-serve-static-core" {
  interface Request {
    user?: AuthenticatedUser;
  }
}
