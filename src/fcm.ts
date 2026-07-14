import { parseRetryAfter } from "./apns";
import type { Env } from "./env";
import { numberSetting } from "./env";
import type { ProviderToken } from "./provider-token-object";
import type { FcmSendRequest, ProviderSendResult } from "./types";

// google.firebase.fcm.v1.FcmError codes that no retry can fix for this token.
const TERMINAL_ERROR_CODES = new Set(["UNREGISTERED", "INVALID_ARGUMENT"]);
// Codes that indicate the relay's Firebase project or service account is
// misconfigured rather than anything about the individual device.
const CONFIGURATION_ERROR_CODES = new Set([
  "SENDER_ID_MISMATCH",
  "PERMISSION_DENIED",
  "THIRD_PARTY_AUTH_ERROR",
]);

interface RawFCMResult {
  status: number;
  messageId: string;
  errorCode: string;
  retryAfterSeconds?: number;
}

export async function sendToFCM(
  env: Env,
  request: FcmSendRequest,
  providerToken: ProviderToken,
): Promise<{ result: ProviderSendResult; expiredProviderToken?: string }> {
  let prepared: PreparedFCMRequest;
  try {
    prepared = prepareFCMRequest(env, request, providerToken.token);
  } catch {
    return { result: { kind: "internal", reason: "request_construction_failed" } };
  }

  let response: Response;
  try {
    response = await fetch(prepared.url, prepared.init);
  } catch {
    return { result: { kind: "unknown", reason: "network_error" } };
  }

  const raw = await readFCMResponse(response);

  if (raw.status >= 200 && raw.status < 300) {
    return { result: { kind: "accepted", messageId: raw.messageId } };
  }
  if (raw.status === 401 || raw.errorCode === "UNAUTHENTICATED") {
    return {
      result: {
        kind: "retryable",
        messageId: "",
        reason: raw.errorCode || "UNAUTHENTICATED",
        status: 503,
      },
      expiredProviderToken: providerToken.token,
    };
  }
  if (CONFIGURATION_ERROR_CODES.has(raw.errorCode) || raw.status === 403) {
    return {
      result: {
        kind: "configuration",
        messageId: "",
        reason: raw.errorCode || "provider_auth_rejected",
      },
    };
  }
  if (raw.status === 429) {
    return {
      result: {
        kind: "retryable",
        messageId: "",
        reason: raw.errorCode || "QUOTA_EXCEEDED",
        status: 429,
        retryAfterSeconds: raw.retryAfterSeconds,
      },
    };
  }
  if (TERMINAL_ERROR_CODES.has(raw.errorCode) || (raw.status >= 400 && raw.status < 500)) {
    return {
      result: {
        kind: "terminal",
        messageId: "",
        reason: raw.errorCode || `http_${raw.status}`,
      },
    };
  }
  return {
    result: {
      kind: "retryable",
      messageId: "",
      reason: raw.errorCode || "upstream_error",
      status: 503,
      retryAfterSeconds: raw.retryAfterSeconds,
    },
  };
}

interface PreparedFCMRequest {
  url: string;
  init: RequestInit;
}

function prepareFCMRequest(
  env: Env,
  request: FcmSendRequest,
  accessToken: string,
): PreparedFCMRequest {
  const origin = env.FCM_SEND_URL.replace(/\/$/u, "");
  const url = `${origin}/v1/projects/${env.FCM_PROJECT_ID}/messages:send`;
  const ttl = numberSetting(env.FCM_TTL_SECONDS, "FCM_TTL_SECONDS", 1);
  const timeout = numberSetting(env.FCM_TIMEOUT_MS, "FCM_TIMEOUT_MS", 1);
  // Fixed content-private payload: a data-only message so Android never shows a
  // relay-authored notification. The app fetches real content by delivery ID.
  const message: Record<string, unknown> = {
    token: request.token,
    data: {
      silo_delivery_id: request.delivery_id,
      silo_mode: request.mode,
    },
    android: {
      priority: request.mode === "background_wake" ? "NORMAL" : "HIGH",
      ttl: `${ttl}s`,
      ...(request.collapse_id ? { collapse_key: request.collapse_id } : {}),
    },
  };
  return {
    url,
    init: {
      method: "POST",
      headers: {
        authorization: `Bearer ${accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ message }),
      signal: AbortSignal.timeout(timeout),
    },
  };
}

async function readFCMResponse(response: Response): Promise<RawFCMResult> {
  let text = "";
  try {
    text = (await response.text()).slice(0, 16 << 10);
  } catch {
    // The status code alone still classifies retryability below.
  }
  let messageId = "";
  let errorCode = "";
  if (text) {
    try {
      const parsed = JSON.parse(text) as {
        name?: unknown;
        error?: { status?: unknown; details?: unknown };
      };
      if (typeof parsed.name === "string") {
        messageId = parsed.name.split("/").at(-1) ?? "";
      }
      if (typeof parsed.error?.status === "string") errorCode = parsed.error.status;
      // The FcmError detail carries the precise code (e.g. UNREGISTERED) that
      // the generic google.rpc status (e.g. NOT_FOUND) obscures.
      for (const detail of Array.isArray(parsed.error?.details) ? parsed.error.details : []) {
        const candidate = (detail as { errorCode?: unknown }).errorCode;
        if (typeof candidate === "string") errorCode = candidate;
      }
    } catch {
      // Non-JSON proxy responses happen; the status code still controls retryability.
    }
  }
  return {
    status: response.status,
    messageId,
    errorCode,
    retryAfterSeconds: parseRetryAfter(response.headers.get("retry-after")),
  };
}
