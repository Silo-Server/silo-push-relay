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

export interface FcmSendRequest {
  token: string;
  mode: "private_alert" | "background_wake";
  server_device_id: string;
  delivery_id: string;
  collapse_id?: string;
}

export type PushProvider = "apple" | "fcm";

interface DeploymentSendBase {
  generation: number;
  idempotencyKey: string;
  payloadHash: string;
  requestId: string;
}

export type DeploymentSendInput =
  | (DeploymentSendBase & { provider: "apple"; request: AppleSendRequest })
  | (DeploymentSendBase & { provider: "fcm"; request: FcmSendRequest });

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

export type ProviderSendResult =
  | { kind: "accepted"; messageId: string }
  | { kind: "terminal"; messageId: string; reason: string }
  | { kind: "configuration"; messageId: string; reason: string }
  | {
      kind: "retryable";
      messageId: string;
      reason: string;
      status: number;
      retryAfterSeconds?: number;
    }
  | { kind: "internal"; reason: string }
  | { kind: "unknown"; reason: string };
