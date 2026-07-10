import { allowedTopics, numberSetting, type Env } from "./env";

export function configurationError(env: Env): string | undefined {
  const required: Array<[string, string]> = [
    ["CAPABILITY_SIGNING_PRIVATE_KEY_PEM", env.CAPABILITY_SIGNING_PRIVATE_KEY_PEM],
    ["CAPABILITY_VERIFY_KEYS_JSON", env.CAPABILITY_VERIFY_KEYS_JSON],
    ["CAPABILITY_ISSUER", env.CAPABILITY_ISSUER],
    ["CAPABILITY_AUDIENCE", env.CAPABILITY_AUDIENCE],
    ["CAPABILITY_SIGNING_KEY_ID", env.CAPABILITY_SIGNING_KEY_ID],
    ["APNS_TEAM_ID", env.APNS_TEAM_ID],
    ["APNS_KEY_ID", env.APNS_KEY_ID],
    ["APNS_PRIVATE_KEY_PEM", env.APNS_PRIVATE_KEY_PEM],
    ["ADMIN_TOKEN", env.ADMIN_TOKEN],
  ];
  for (const [name, value] of required) {
    if (!value?.trim()) return `${name} is required`;
  }
  if (allowedTopics(env).size === 0) return "APNS_TOPICS must include at least one topic";
  try {
    const keys = JSON.parse(env.CAPABILITY_VERIFY_KEYS_JSON) as Record<string, unknown>;
    if (typeof keys[env.CAPABILITY_SIGNING_KEY_ID] !== "string") {
      return "CAPABILITY_VERIFY_KEYS_JSON does not contain the signing key id";
    }
    numberSetting(env.CAPABILITY_TTL_SECONDS, "CAPABILITY_TTL_SECONDS", 60);
    numberSetting(env.CAPABILITY_RENEW_GRACE_SECONDS, "CAPABILITY_RENEW_GRACE_SECONDS", 0);
    numberSetting(env.APNS_EXPIRATION_SECONDS, "APNS_EXPIRATION_SECONDS", 1);
    numberSetting(env.APNS_TIMEOUT_MS, "APNS_TIMEOUT_MS", 1);
    numberSetting(env.DAILY_PUSH_LIMIT, "DAILY_PUSH_LIMIT", 1);
    numberSetting(env.ACCOUNT_RATE_PER_SECOND, "ACCOUNT_RATE_PER_SECOND", 0.000_001);
    numberSetting(env.ACCOUNT_RATE_BURST, "ACCOUNT_RATE_BURST", 1);
    numberSetting(env.TOKEN_RATE_PER_SECOND, "TOKEN_RATE_PER_SECOND", 0.000_001);
    numberSetting(env.TOKEN_RATE_BURST, "TOKEN_RATE_BURST", 1);
    numberSetting(
      env.IDEMPOTENCY_DISPATCH_TIMEOUT_SECONDS,
      "IDEMPOTENCY_DISPATCH_TIMEOUT_SECONDS",
      1,
    );
    numberSetting(env.IDEMPOTENCY_RETENTION_SECONDS, "IDEMPOTENCY_RETENTION_SECONDS", 60);
  } catch (error) {
    return error instanceof Error ? error.message : "configuration is invalid";
  }
  return undefined;
}
