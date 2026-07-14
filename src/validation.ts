import { errorResponse } from "./http";
import type { AppleSendRequest, FcmSendRequest } from "./types";

const APNS_TOKEN = /^[0-9a-fA-F]{64,200}$/u;
const FCM_TOKEN = /^[A-Za-z0-9_:-]{64,512}$/u;
const PRINTABLE_ASCII = /^[\u0020-\u007e]+$/u;
const APPLE_FIELDS = new Set([
  "token",
  "environment",
  "topic",
  "mode",
  "server_device_id",
  "delivery_id",
  "badge",
  "collapse_id",
]);
const FCM_FIELDS = new Set([
  "token",
  "mode",
  "server_device_id",
  "delivery_id",
  "collapse_id",
]);

export { APPLE_FIELDS, FCM_FIELDS };

function requiredString(
  object: Record<string, unknown>,
  field: string,
  requestId: string,
): string | Response {
  const value = object[field];
  if (typeof value !== "string" || value.length === 0) {
    return errorResponse(400, "invalid_field", `${field} is required`, requestId);
  }
  return value;
}

export function validateAppleRequest(
  object: Record<string, unknown>,
  requestId: string,
): AppleSendRequest | Response {
  const token = requiredString(object, "token", requestId);
  if (token instanceof Response) return token;
  if (!APNS_TOKEN.test(token)) {
    return errorResponse(400, "invalid_token", "token is not a plausible APNs device token", requestId);
  }

  const environment = requiredString(object, "environment", requestId);
  if (environment instanceof Response) return environment;
  if (environment !== "production" && environment !== "sandbox") {
    return errorResponse(400, "invalid_environment", "environment must be production or sandbox", requestId);
  }

  const mode = requiredString(object, "mode", requestId);
  if (mode instanceof Response) return mode;
  if (mode !== "private_alert" && mode !== "background_wake") {
    return errorResponse(400, "invalid_mode", "mode must be private_alert or background_wake", requestId);
  }

  const topic = requiredString(object, "topic", requestId);
  if (topic instanceof Response) return topic;
  const serverDeviceId = requiredString(object, "server_device_id", requestId);
  if (serverDeviceId instanceof Response) return serverDeviceId;
  const deliveryId = requiredString(object, "delivery_id", requestId);
  if (deliveryId instanceof Response) return deliveryId;
  if (serverDeviceId.length > 128 || deliveryId.length > 128) {
    return errorResponse(400, "invalid_field", "opaque IDs must be 1-128 characters", requestId);
  }

  const badge = object.badge;
  if (badge !== undefined && (!Number.isInteger(badge) || (badge as number) < 0 || (badge as number) > 9999)) {
    return errorResponse(400, "invalid_field", "badge must be between 0 and 9999", requestId);
  }
  const normalizedCollapseId = normalizeCollapseId(object.collapse_id, requestId);
  if (normalizedCollapseId instanceof Response) return normalizedCollapseId;

  return {
    token,
    environment,
    topic,
    mode,
    server_device_id: serverDeviceId,
    delivery_id: deliveryId,
    ...(badge === undefined ? {} : { badge: badge as number }),
    ...(normalizedCollapseId === undefined ? {} : { collapse_id: normalizedCollapseId }),
  };
}

export function validateFcmRequest(
  object: Record<string, unknown>,
  requestId: string,
): FcmSendRequest | Response {
  const token = requiredString(object, "token", requestId);
  if (token instanceof Response) return token;
  if (!FCM_TOKEN.test(token)) {
    return errorResponse(
      400,
      "invalid_token",
      "token is not a plausible FCM registration token",
      requestId,
    );
  }

  const mode = requiredString(object, "mode", requestId);
  if (mode instanceof Response) return mode;
  if (mode !== "private_alert" && mode !== "background_wake") {
    return errorResponse(400, "invalid_mode", "mode must be private_alert or background_wake", requestId);
  }

  const serverDeviceId = requiredString(object, "server_device_id", requestId);
  if (serverDeviceId instanceof Response) return serverDeviceId;
  const deliveryId = requiredString(object, "delivery_id", requestId);
  if (deliveryId instanceof Response) return deliveryId;
  if (serverDeviceId.length > 128 || deliveryId.length > 128) {
    return errorResponse(400, "invalid_field", "opaque IDs must be 1-128 characters", requestId);
  }

  const normalizedCollapseId = normalizeCollapseId(object.collapse_id, requestId);
  if (normalizedCollapseId instanceof Response) return normalizedCollapseId;

  return {
    token,
    mode,
    server_device_id: serverDeviceId,
    delivery_id: deliveryId,
    ...(normalizedCollapseId === undefined ? {} : { collapse_id: normalizedCollapseId }),
  };
}

function normalizeCollapseId(
  collapseId: unknown,
  requestId: string,
): string | undefined | Response {
  if (collapseId === undefined) return undefined;
  if (typeof collapseId !== "string") {
    return errorResponse(
      400,
      "invalid_collapse_id",
      "collapse_id must be 1-64 bytes of printable ASCII",
      requestId,
    );
  }
  const normalized = collapseId.trim();
  if (!normalized || encoderLength(normalized) > 64 || !PRINTABLE_ASCII.test(normalized)) {
    return errorResponse(
      400,
      "invalid_collapse_id",
      "collapse_id must be 1-64 bytes of printable ASCII",
      requestId,
    );
  }
  return normalized;
}

function encoderLength(value: string): number {
  return new TextEncoder().encode(value).byteLength;
}
