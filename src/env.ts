import type { DeploymentObject } from "./deployment-object";
import type { ProviderTokenObject } from "./provider-token-object";

export interface Env {
  DEPLOYMENTS: DurableObjectNamespace<DeploymentObject>;
  PROVIDER_TOKENS: DurableObjectNamespace<ProviderTokenObject>;
  INGRESS_RATE_LIMITER: RateLimit;
  REGISTRATION_IP_RATE_LIMITER: RateLimit;
  REGISTRATION_LOCATION_RATE_LIMITER: RateLimit;
  DEPLOYMENT_RATE_LIMITER: RateLimit;
  DEVICE_RATE_LIMITER: RateLimit;

  CAPABILITY_SIGNING_PRIVATE_KEY_PEM: string;
  CAPABILITY_VERIFY_KEYS_JSON: string;
  CAPABILITY_ISSUER: string;
  CAPABILITY_AUDIENCE: string;
  CAPABILITY_SIGNING_KEY_ID: string;
  CAPABILITY_TTL_SECONDS: string;
  CAPABILITY_RENEW_GRACE_SECONDS: string;

  APNS_TEAM_ID: string;
  APNS_KEY_ID: string;
  APNS_PRIVATE_KEY_PEM: string;
  APNS_TOPICS: string;
  APNS_PRODUCTION_URL: string;
  APNS_SANDBOX_URL: string;
  APNS_EXPIRATION_SECONDS: string;
  APNS_TIMEOUT_MS: string;

  FCM_PROJECT_ID: string;
  FCM_CLIENT_EMAIL: string;
  FCM_PRIVATE_KEY_PEM: string;
  FCM_SEND_URL: string;
  FCM_TOKEN_URL: string;
  FCM_TTL_SECONDS: string;
  FCM_TIMEOUT_MS: string;

  IDEMPOTENCY_DISPATCH_TIMEOUT_SECONDS: string;
  IDEMPOTENCY_RETENTION_SECONDS: string;

  ADMIN_TOKEN: string;
}

export function numberSetting(value: string, name: string, minimum = 0): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < minimum) {
    throw new Error(`${name} must be a number >= ${minimum}`);
  }
  return parsed;
}

export function allowedTopics(env: Env): Set<string> {
  return new Set(
    env.APNS_TOPICS.split(",")
      .map((topic) => topic.trim())
      .filter(Boolean),
  );
}
