import { allowedTopics, numberSetting, type Env } from "./env";
import { configurationError } from "./config";
import {
  canonicalAppleHash,
  capabilityDisplayPrefix,
  CapabilityError,
  constantTimeSecretEqual,
  newCapabilityClaims,
  sha256,
  signCapability,
  verifyCapability,
} from "./crypto";
import {
  bearerToken,
  errorResponse,
  jsonResponse,
  responseFromResult,
  strictJSON,
} from "./http";
import type { CapabilityClaims } from "./types";
import { APPLE_FIELDS, validateAppleRequest } from "./validation";

export { DeploymentObject } from "./deployment-object";
export { ProviderTokenObject } from "./provider-token-object";

const EMPTY_FIELDS = new Set<string>();
const ADMIN_REVOKE_FIELDS = new Set(["deployment_id"]);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const requestId = crypto.randomUUID();
    try {
      const url = new URL(request.url);
      if (request.method === "GET" && url.pathname === "/healthz") {
        return jsonResponse(200, { status: "ok" });
      }
      if (request.method === "GET" && url.pathname === "/readyz") {
        const problem = configurationError(env);
        return problem
          ? jsonResponse(503, { status: "not_ready", reason: problem })
          : jsonResponse(200, { status: "ready" });
      }
      if (request.method === "POST" && url.pathname === "/v1/deployments/register") {
        return handleRegister(request, env, requestId);
      }
      if (request.method === "POST" && url.pathname === "/v1/deployments/renew") {
        return handleRenew(request, env, requestId);
      }
      if (request.method === "POST" && url.pathname === "/v1/deployments/rotate") {
        return handleRotate(request, env, requestId);
      }
      if (request.method === "POST" && url.pathname === "/v1/deployments/revoke") {
        return handleSelfRevoke(request, env, requestId);
      }
      if (request.method === "POST" && url.pathname === "/v1/admin/deployments/revoke") {
        return handleAdminRevoke(request, env, requestId);
      }
      if (request.method === "POST" && url.pathname === "/v1/apple/send") {
        return handleAppleSend(request, env, requestId);
      }
      if (request.method === "POST" && url.pathname === "/v1/fcm/send") {
        const authorized = await requestCapability(request, env, requestId, "apns:send");
        if (authorized instanceof Response) return authorized;
        return errorResponse(
          501,
          "not_implemented",
          "FCM upstream delivery is not implemented",
          requestId,
        );
      }
      return errorResponse(404, "not_found", "not found", requestId);
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "request.failed",
          request_id: requestId,
          error: error instanceof Error ? error.name : "unknown_error",
        }),
      );
      return errorResponse(500, "internal_error", "internal server error", requestId);
    }
  },
} satisfies ExportedHandler<Env>;

async function handleRegister(request: Request, env: Env, requestId: string): Promise<Response> {
  const body = await strictJSON(request, EMPTY_FIELDS, requestId);
  if (body instanceof Response) return body;
  const deploymentId = crypto.randomUUID();
  const claims = newCapabilityClaims(env, deploymentId, 1);
  return credentialResponse(env, claims, await signCapability(env, claims), requestId);
}

async function handleRenew(request: Request, env: Env, requestId: string): Promise<Response> {
  const body = await strictJSON(request, EMPTY_FIELDS, requestId);
  if (body instanceof Response) return body;
  const grace = numberSetting(
    env.CAPABILITY_RENEW_GRACE_SECONDS,
    "CAPABILITY_RENEW_GRACE_SECONDS",
    0,
  );
  const claims = await requestCapability(request, env, requestId, "deployment:renew", {
    allowExpiredSeconds: grace,
  });
  if (claims instanceof Response) return claims;
  const renewed = newCapabilityClaims(env, claims.sub, claims.ver);
  return credentialResponse(env, renewed, await signCapability(env, renewed), requestId);
}

async function handleRotate(request: Request, env: Env, requestId: string): Promise<Response> {
  const body = await strictJSON(request, EMPTY_FIELDS, requestId);
  if (body instanceof Response) return body;
  const idempotencyKey = request.headers.get("idempotency-key")?.trim() ?? "";
  if (!idempotencyKey || idempotencyKey.length > 255) {
    return errorResponse(
      400,
      "missing_idempotency_key",
      "Idempotency-Key header is required for credential rotation",
      requestId,
    );
  }
  const claims = await verifyRequestToken(request, env, requestId, "deployment:rotate");
  if (claims instanceof Response) return claims;
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + numberSetting(env.CAPABILITY_TTL_SECONDS, "CAPABILITY_TTL_SECONDS", 60);
  const rotation = await env.DEPLOYMENTS.getByName(claims.sub).prepareRotation(
    claims.ver,
    idempotencyKey,
    issuedAt,
    expiresAt,
  );
  if (!rotation.ok || !rotation.metadata) {
    const code = rotation.reason === "invalid_idempotency_key" ? "invalid_field" : "unauthorized";
    const status = code === "invalid_field" ? 400 : 401;
    return errorResponse(status, code, code === "unauthorized" ? "unauthorized" : "invalid Idempotency-Key", requestId);
  }
  const rotated = newCapabilityClaims(env, claims.sub, rotation.metadata.generation, issuedAt, {
    iat: rotation.metadata.issuedAt,
    exp: rotation.metadata.expiresAt,
    jti: rotation.metadata.jti,
  });
  return credentialResponse(env, rotated, await signCapability(env, rotated), requestId);
}

async function handleSelfRevoke(request: Request, env: Env, requestId: string): Promise<Response> {
  const body = await strictJSON(request, EMPTY_FIELDS, requestId);
  if (body instanceof Response) return body;
  const claims = await requestCapability(request, env, requestId, "deployment:rotate");
  if (claims instanceof Response) return claims;
  const result = await env.DEPLOYMENTS.getByName(claims.sub).disable(claims.ver);
  if (!result.allowed) return errorResponse(401, "unauthorized", "unauthorized", requestId);
  return jsonResponse(200, { request_id: requestId, deployment_id: claims.sub, status: "revoked" });
}

async function handleAdminRevoke(request: Request, env: Env, requestId: string): Promise<Response> {
  const supplied = bearerToken(request) ?? "";
  if (!env.ADMIN_TOKEN || !(await constantTimeSecretEqual(supplied, env.ADMIN_TOKEN))) {
    return errorResponse(401, "unauthorized", "unauthorized", requestId);
  }
  const body = await strictJSON(request, ADMIN_REVOKE_FIELDS, requestId);
  if (body instanceof Response) return body;
  const deploymentId = body.deployment_id;
  if (typeof deploymentId !== "string" || deploymentId.length < 1 || deploymentId.length > 128) {
    return errorResponse(400, "invalid_field", "deployment_id must be 1-128 characters", requestId);
  }
  await env.DEPLOYMENTS.getByName(deploymentId).disable();
  return jsonResponse(200, { request_id: requestId, deployment_id: deploymentId, status: "revoked" });
}

async function handleAppleSend(request: Request, env: Env, requestId: string): Promise<Response> {
  // DeploymentObject.send performs the durable generation/revocation check in
  // the same call that owns idempotency. Avoid a separate authorization RPC on
  // the hot path: one push should require only one deployment-object request.
  const claims = await verifyRequestToken(request, env, requestId, "apns:send");
  if (claims instanceof Response) return claims;

  const idempotencyKey = request.headers.get("idempotency-key")?.trim() ?? "";
  if (!idempotencyKey) {
    return errorResponse(
      400,
      "missing_idempotency_key",
      "Idempotency-Key header is required",
      requestId,
    );
  }
  if (idempotencyKey.length > 255) {
    return errorResponse(400, "invalid_field", "Idempotency-Key is too long", requestId);
  }

  const body = await strictJSON(request, APPLE_FIELDS, requestId);
  if (body instanceof Response) return body;
  const appleRequest = validateAppleRequest(body, requestId);
  if (appleRequest instanceof Response) return appleRequest;
  if (!allowedTopics(env).has(appleRequest.topic)) {
    return errorResponse(
      403,
      "topic_not_allowed",
      "topic is not allowlisted for this relay",
      requestId,
    );
  }

  const [payloadHash, tokenHash] = await Promise.all([
    canonicalAppleHash(appleRequest),
    sha256(appleRequest.token),
  ]);
  const result = await env.DEPLOYMENTS.getByName(claims.sub).send({
    generation: claims.ver,
    idempotencyKey,
    payloadHash,
    tokenHash,
    requestId,
    request: appleRequest,
  });
  return responseFromResult(result);
}

async function requestCapability(
  request: Request,
  env: Env,
  requestId: string,
  requiredScope: string,
  options: { allowExpiredSeconds?: number } = {},
): Promise<CapabilityClaims | Response> {
  const claims = await verifyRequestToken(request, env, requestId, requiredScope, options);
  if (claims instanceof Response) return claims;
  const authorization = await env.DEPLOYMENTS.getByName(claims.sub).authorizeGeneration(claims.ver);
  if (!authorization.allowed) return errorResponse(401, "unauthorized", "unauthorized", requestId);
  return claims;
}

async function verifyRequestToken(
  request: Request,
  env: Env,
  requestId: string,
  requiredScope: string,
  options: { allowExpiredSeconds?: number } = {},
): Promise<CapabilityClaims | Response> {
  const token = bearerToken(request);
  if (!token) return errorResponse(401, "unauthorized", "unauthorized", requestId);
  try {
    return await verifyCapability(env, token, { ...options, requiredScope });
  } catch (error) {
    if (error instanceof CapabilityError && error.code === "token_expired") {
      return errorResponse(401, "token_expired", "relay capability has expired", requestId);
    }
    return errorResponse(401, "unauthorized", "unauthorized", requestId);
  }
}

async function credentialResponse(
  env: Env,
  claims: CapabilityClaims,
  token: string,
  requestId: string,
): Promise<Response> {
  return jsonResponse(200, {
    request_id: requestId,
    deployment_id: claims.sub,
    api_key: token,
    key_prefix: capabilityDisplayPrefix(env, claims),
    apns_topics: [...allowedTopics(env)],
    expires_at: new Date(claims.exp * 1000).toISOString(),
  });
}
