import type { RelayResult } from "./types";

export const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
} as const;

export function jsonResponse(status: number, value: unknown, headers?: HeadersInit): Response {
  const responseHeaders = new Headers(headers);
  responseHeaders.set("content-type", JSON_HEADERS["content-type"]);
  return new Response(JSON.stringify(value), { status, headers: responseHeaders });
}

export function errorBody(code: string, message: string, requestId: string): string {
  return JSON.stringify({ error: { code, message, request_id: requestId } });
}

export function errorResponse(
  status: number,
  code: string,
  message: string,
  requestId: string,
  headers?: HeadersInit,
): Response {
  return new Response(errorBody(code, message, requestId), {
    status,
    headers: { ...JSON_HEADERS, ...Object.fromEntries(new Headers(headers)) },
  });
}

export function errorResult(
  status: number,
  code: string,
  message: string,
  requestId: string,
  headers?: Record<string, string>,
): RelayResult {
  return { status, body: errorBody(code, message, requestId), headers };
}

export function responseFromResult(result: RelayResult): Response {
  return new Response(result.body, {
    status: result.status,
    headers: { ...JSON_HEADERS, ...result.headers },
  });
}

export async function strictJSON(
  request: Request,
  allowedFields: ReadonlySet<string>,
  requestId: string,
  maxBytes = 16 << 10,
): Promise<Record<string, unknown> | Response> {
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.byteLength > maxBytes) {
    return errorResponse(413, "request_too_large", "request body is too large", requestId);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return errorResponse(400, "bad_request", "invalid JSON body", requestId);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return errorResponse(400, "bad_request", "request body must be a JSON object", requestId);
  }
  const object = parsed as Record<string, unknown>;
  for (const field of Object.keys(object)) {
    if (!allowedFields.has(field)) {
      return errorResponse(400, "unexpected_field", `unexpected field: ${field}`, requestId);
    }
  }
  return object;
}

export function bearerToken(request: Request): string | undefined {
  const header = request.headers.get("authorization") ?? "";
  const match = /^Bearer ([^\s]+)$/i.exec(header);
  return match?.[1];
}
