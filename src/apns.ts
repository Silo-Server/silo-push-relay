import type { Env } from "./env";
import { numberSetting } from "./env";
import type { ProviderToken } from "./provider-token-object";
import type { APNsResult, AppleSendRequest } from "./types";

const TERMINAL_DEVICE_REASONS = new Set([
  "BadDeviceToken",
  "DeviceTokenNotForTopic",
  "Unregistered",
]);
// Apple currently documents BadEnvironmentKeyIdInToken. APNs has also returned
// the older BadEnvironmentKeyInToken spelling in production, so recognize both.
const CONFIGURATION_REASONS = new Set([
  "BadEnvironmentKeyIdInToken",
  "BadEnvironmentKeyInToken",
]);
const PROVIDER_TOKEN_REASONS = new Set([
  "ExpiredProviderToken",
  "InvalidProviderToken",
  "MissingProviderToken",
  "TooManyProviderTokenUpdates",
]);

interface RawAPNsResult {
  status: number;
  apnsId: string;
  reason: string;
  retryAfterSeconds?: number;
}

export async function sendToAPNs(
  env: Env,
  request: AppleSendRequest,
  providerToken: ProviderToken,
): Promise<{ result: APNsResult; expiredProviderToken?: string }> {
  let raw: RawAPNsResult;
  try {
    raw = await performAPNsRequest(env, request, providerToken.token);
  } catch {
    return { result: { kind: "unknown", reason: "network_error" } };
  }

  if (raw.status >= 200 && raw.status < 300) {
    return { result: { kind: "accepted", apnsId: raw.apnsId } };
  }
  if (raw.reason === "ExpiredProviderToken") {
    return {
      result: {
        kind: "retryable",
        apnsId: raw.apnsId,
        reason: raw.reason,
        status: 503,
      },
      expiredProviderToken: providerToken.token,
    };
  }
  if (TERMINAL_DEVICE_REASONS.has(raw.reason)) {
    return { result: { kind: "terminal", apnsId: raw.apnsId, reason: raw.reason } };
  }
  if (CONFIGURATION_REASONS.has(raw.reason)) {
    return { result: { kind: "configuration", apnsId: raw.apnsId, reason: raw.reason } };
  }
  if (raw.status === 429) {
    return {
      result: {
        kind: "retryable",
        apnsId: raw.apnsId,
        reason: raw.reason || "TooManyRequests",
        status: 429,
        retryAfterSeconds: raw.retryAfterSeconds,
      },
    };
  }
  return {
    result: {
      kind: "retryable",
      apnsId: raw.apnsId,
      reason: raw.reason || (PROVIDER_TOKEN_REASONS.has(raw.reason) ? raw.reason : "upstream_error"),
      status: 503,
      retryAfterSeconds: raw.retryAfterSeconds,
    },
  };
}

async function performAPNsRequest(
  env: Env,
  request: AppleSendRequest,
  providerToken: string,
): Promise<RawAPNsResult> {
  const origin =
    request.environment === "production" ? env.APNS_PRODUCTION_URL : env.APNS_SANDBOX_URL;
  const expiration = Math.floor(Date.now() / 1000) + numberSetting(env.APNS_EXPIRATION_SECONDS, "APNS_EXPIRATION_SECONDS", 1);
  const timeout = numberSetting(env.APNS_TIMEOUT_MS, "APNS_TIMEOUT_MS", 1);
  const { body, pushType, priority } = buildPayload(request);
  const headers = new Headers({
    authorization: `bearer ${providerToken}`,
    "content-type": "application/json",
    "apns-topic": request.topic,
    "apns-push-type": pushType,
    "apns-priority": priority,
    "apns-expiration": String(expiration),
  });
  if (request.collapse_id?.trim()) headers.set("apns-collapse-id", request.collapse_id.trim());

  const response = await fetch(`${origin.replace(/\/$/u, "")}/3/device/${request.token}`, {
    method: "POST",
    headers,
    body,
    signal: AbortSignal.timeout(timeout),
  });
  const text = (await response.text()).slice(0, 16 << 10);
  let reason = "";
  if (text) {
    try {
      const parsed = JSON.parse(text) as { reason?: unknown };
      if (typeof parsed.reason === "string") reason = parsed.reason;
    } catch {
      // APNs sometimes returns an empty/non-JSON proxy response. Status still controls retryability.
    }
  }
  return {
    status: response.status,
    apnsId: response.headers.get("apns-id") ?? "",
    reason,
    retryAfterSeconds: parseRetryAfter(response.headers.get("retry-after")),
  };
}

function buildPayload(request: AppleSendRequest): {
  body: string;
  pushType: string;
  priority: string;
} {
  const aps: Record<string, unknown> = { "content-available": 1 };
  if (request.badge !== undefined) aps.badge = request.badge;
  const payload: Record<string, unknown> = {
    aps,
    silo_delivery_id: request.delivery_id,
  };
  if (request.mode === "background_wake") {
    return { body: JSON.stringify(payload), pushType: "background", priority: "5" };
  }
  aps.alert = { title: "Silo", body: "New notification available" };
  aps["mutable-content"] = 1;
  aps.sound = "default";
  return { body: JSON.stringify(payload), pushType: "alert", priority: "10" };
}

function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds > 0) return Math.ceil(seconds);
  const timestamp = Date.parse(value);
  if (Number.isFinite(timestamp) && timestamp > Date.now()) {
    return Math.ceil((timestamp - Date.now()) / 1000);
  }
  return undefined;
}
