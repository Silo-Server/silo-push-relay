import type { Env } from "./env";
import { numberSetting } from "./env";
import type { ProviderToken } from "./provider-token-object";
import type { AppleSendRequest, ProviderSendResult } from "./types";

// Apple currently documents BadEnvironmentKeyIdInToken. APNs has also returned
// the older BadEnvironmentKeyInToken spelling in production, so recognize both.
const CONFIGURATION_REASONS = new Set([
  "BadCertificate",
  "BadCertificateEnvironment",
  "BadEnvironmentKeyIdInToken",
  "BadEnvironmentKeyInToken",
  "InvalidProviderToken",
  "MissingProviderToken",
  "Forbidden",
  "TopicDisallowed",
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
): Promise<{ result: ProviderSendResult; expiredProviderToken?: string }> {
  let prepared: PreparedAPNsRequest;
  try {
    prepared = prepareAPNsRequest(env, request, providerToken.token);
  } catch {
    return { result: { kind: "internal", reason: "request_construction_failed" } };
  }

  let response: Response;
  try {
    response = await fetch(prepared.url, prepared.init);
  } catch {
    return { result: { kind: "unknown", reason: "network_error" } };
  }

  const raw = await readAPNsResponse(response);

  if (raw.status >= 200 && raw.status < 300) {
    return { result: { kind: "accepted", messageId: raw.apnsId } };
  }
  if (raw.reason === "ExpiredProviderToken") {
    return {
      result: {
        kind: "retryable",
        messageId: raw.apnsId,
        reason: raw.reason,
        status: 503,
      },
      expiredProviderToken: providerToken.token,
    };
  }
  if (CONFIGURATION_REASONS.has(raw.reason) || raw.status === 403) {
    return {
      result: {
        kind: "configuration",
        messageId: raw.apnsId,
        reason: raw.reason || "provider_auth_rejected",
      },
    };
  }
  if (raw.status === 429) {
    return {
      result: {
        kind: "retryable",
        messageId: raw.apnsId,
        reason: raw.reason || "TooManyRequests",
        status: 429,
        retryAfterSeconds: raw.retryAfterSeconds,
      },
    };
  }
  if (raw.status >= 400 && raw.status < 500) {
    return {
      result: {
        kind: "terminal",
        messageId: raw.apnsId,
        reason: raw.reason || `http_${raw.status}`,
      },
    };
  }
  return {
    result: {
      kind: "retryable",
      messageId: raw.apnsId,
      reason: raw.reason || "upstream_error",
      status: 503,
      retryAfterSeconds: raw.retryAfterSeconds,
    },
  };
}

interface PreparedAPNsRequest {
  url: string;
  init: RequestInit;
}

function prepareAPNsRequest(
  env: Env,
  request: AppleSendRequest,
  providerToken: string,
): PreparedAPNsRequest {
  const origin =
    request.environment === "production" ? env.APNS_PRODUCTION_URL : env.APNS_SANDBOX_URL;
  const expiration =
    Math.floor(Date.now() / 1000) +
    numberSetting(env.APNS_EXPIRATION_SECONDS, "APNS_EXPIRATION_SECONDS", 1);
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
  if (request.collapse_id) headers.set("apns-collapse-id", request.collapse_id);

  const url = new URL(`/3/device/${request.token}`, `${origin.replace(/\/$/u, "")}/`).toString();
  return {
    url,
    init: {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(timeout),
    },
  };
}

async function readAPNsResponse(response: Response): Promise<RawAPNsResult> {
  let text = "";
  try {
    text = (await response.text()).slice(0, 16 << 10);
  } catch {
    // Response headers already prove whether APNs accepted or rejected the request.
  }
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

export function parseRetryAfter(value: string | null): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value);
  if (Number.isFinite(seconds) && seconds > 0) return Math.ceil(seconds);
  const timestamp = Date.parse(value);
  if (Number.isFinite(timestamp) && timestamp > Date.now()) {
    return Math.ceil((timestamp - Date.now()) / 1000);
  }
  return undefined;
}
