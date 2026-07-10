export interface CapabilityClaims {
  iss: string;
  aud: string;
  sub: string;
  iat: number;
  nbf: number;
  exp: number;
  jti: string;
  ver: number;
  scope: string[];
}

export interface AppleSendRequest {
  token: string;
  environment: "production" | "sandbox";
  topic: string;
  mode: "private_alert" | "background_wake";
  server_device_id: string;
  delivery_id: string;
  badge?: number;
  collapse_id?: string;
}

export interface DeploymentSendInput {
  generation: number;
  idempotencyKey: string;
  payloadHash: string;
  requestId: string;
  request: AppleSendRequest;
}

export interface RelayResult {
  status: number;
  body: string;
  headers?: Record<string, string>;
}

export interface RotationMetadata {
  generation: number;
  issuedAt: number;
  expiresAt: number;
  jti: string;
}

export type APNsResult =
  | { kind: "accepted"; apnsId: string }
  | { kind: "terminal"; apnsId: string; reason: string }
  | { kind: "configuration"; apnsId: string; reason: string }
  | {
      kind: "retryable";
      apnsId: string;
      reason: string;
      status: number;
      retryAfterSeconds?: number;
    }
  | { kind: "internal"; reason: string }
  | { kind: "unknown"; reason: string };
