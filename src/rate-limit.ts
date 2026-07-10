import { errorResponse } from "./http";

export type RateLimitKind =
  | "ingress"
  | "registration_ip"
  | "registration_location"
  | "deployment"
  | "device";

interface RateLimitCheck {
  limiter: RateLimit;
  key: string;
  kind: RateLimitKind;
  requestId: string;
  code: string;
  message: string;
  retryAfterSeconds: number;
  deploymentId?: string;
}

export function clientRateLimitKey(request: Request): string {
  return request.headers.get("cf-connecting-ip")?.trim() || "unknown";
}

export async function enforceRateLimit(check: RateLimitCheck): Promise<Response | undefined> {
  try {
    const { success } = await check.limiter.limit({ key: check.key });
    if (success) return undefined;
  } catch (error) {
    console.error(
      JSON.stringify({
        event: "rate_limit.check_failed",
        kind: check.kind,
        request_id: check.requestId,
        error: error instanceof Error ? error.name : "unknown_error",
      }),
    );
    return undefined;
  }

  console.warn(
    JSON.stringify({
      event: "rate_limit.denied",
      kind: check.kind,
      request_id: check.requestId,
      ...(check.deploymentId ? { deployment_id: check.deploymentId } : {}),
    }),
  );
  return errorResponse(429, check.code, check.message, check.requestId, {
    "retry-after": String(check.retryAfterSeconds),
  });
}
