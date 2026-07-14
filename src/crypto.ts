import { numberSetting, type Env } from "./env";
import type { AppleSendRequest, CapabilityClaims, FcmSendRequest } from "./types";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const CAPABILITY_TYPE = "silo-relay-cap+jwt";
const CAPABILITY_SCOPE = [
  "apns:send",
  "fcm:send",
  "deployment:renew",
  "deployment:rotate",
  "deployment:revoke",
];
let signingKeyCache:
  | { pem: string; key: Promise<CryptoKey> }
  | undefined;
const verificationKeyCache = new Map<string, { pem: string; key: Promise<CryptoKey> }>();

export class CapabilityError extends Error {
  constructor(
    readonly code: "unauthorized" | "token_expired",
    message: string,
  ) {
    super(message);
  }
}

export function base64url(data: ArrayBuffer | Uint8Array | string): string {
  const bytes =
    typeof data === "string"
      ? encoder.encode(data)
      : data instanceof Uint8Array
        ? data
        : new Uint8Array(data);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodeBase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/u.test(value)) throw new Error("invalid base64url");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function pemBytes(pem: string, label: string): Uint8Array {
  const normalized = pem.trim();
  const begin = `-----BEGIN ${label}-----`;
  const end = `-----END ${label}-----`;
  if (!normalized.startsWith(begin) || !normalized.endsWith(end)) {
    throw new Error(`expected PEM ${label}`);
  }
  const body = normalized.slice(begin.length, -end.length).replace(/\s+/gu, "");
  return Uint8Array.from(atob(body), (character) => character.charCodeAt(0));
}

async function capabilityPrivateKey(env: Env): Promise<CryptoKey> {
  if (signingKeyCache?.pem === env.CAPABILITY_SIGNING_PRIVATE_KEY_PEM) {
    return signingKeyCache.key;
  }
  const key = crypto.subtle.importKey(
    "pkcs8",
    arrayBuffer(pemBytes(env.CAPABILITY_SIGNING_PRIVATE_KEY_PEM, "PRIVATE KEY")),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  signingKeyCache = { pem: env.CAPABILITY_SIGNING_PRIVATE_KEY_PEM, key };
  return key;
}

async function capabilityPublicKey(env: Env, keyId: string): Promise<CryptoKey> {
  let keys: Record<string, unknown>;
  try {
    keys = JSON.parse(env.CAPABILITY_VERIFY_KEYS_JSON) as Record<string, unknown>;
  } catch {
    throw new CapabilityError("unauthorized", "invalid verification key configuration");
  }
  const pem = keys[keyId];
  if (typeof pem !== "string") throw new CapabilityError("unauthorized", "unknown key id");
  const cached = verificationKeyCache.get(keyId);
  if (cached?.pem === pem) return cached.key;
  const key = crypto.subtle.importKey(
    "spki",
    arrayBuffer(pemBytes(pem, "PUBLIC KEY")),
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  verificationKeyCache.set(keyId, { pem, key });
  return key;
}

export function newCapabilityClaims(
  env: Env,
  deploymentId: string,
  generation: number,
  nowSeconds = Math.floor(Date.now() / 1000),
  overrides?: Pick<CapabilityClaims, "iat" | "exp" | "jti">,
): CapabilityClaims {
  const issuedAt = overrides?.iat ?? nowSeconds;
  const ttl = numberSetting(env.CAPABILITY_TTL_SECONDS, "CAPABILITY_TTL_SECONDS", 60);
  return {
    iss: env.CAPABILITY_ISSUER,
    aud: env.CAPABILITY_AUDIENCE,
    sub: deploymentId,
    iat: issuedAt,
    nbf: issuedAt - 5,
    exp: overrides?.exp ?? issuedAt + ttl,
    jti: overrides?.jti ?? crypto.randomUUID(),
    ver: generation,
    scope: [...CAPABILITY_SCOPE],
  };
}

export async function signCapability(env: Env, claims: CapabilityClaims): Promise<string> {
  const header = {
    alg: "EdDSA",
    typ: CAPABILITY_TYPE,
    kid: env.CAPABILITY_SIGNING_KEY_ID,
  };
  const unsigned = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const signature = await crypto.subtle.sign(
    { name: "Ed25519" },
    await capabilityPrivateKey(env),
    encoder.encode(unsigned),
  );
  return `${unsigned}.${base64url(signature)}`;
}

export async function verifyCapability(
  env: Env,
  token: string,
  options: { allowExpiredSeconds?: number; requiredScope?: string } = {},
): Promise<CapabilityClaims> {
  const segments = token.split(".");
  if (segments.length !== 3) throw new CapabilityError("unauthorized", "malformed token");
  const [encodedHeader, encodedClaims, encodedSignature] = segments;
  if (!encodedHeader || !encodedClaims || !encodedSignature) {
    throw new CapabilityError("unauthorized", "malformed token");
  }

  let header: Record<string, unknown>;
  let claims: CapabilityClaims;
  try {
    header = JSON.parse(decoder.decode(decodeBase64url(encodedHeader))) as Record<string, unknown>;
    claims = JSON.parse(decoder.decode(decodeBase64url(encodedClaims))) as CapabilityClaims;
  } catch {
    throw new CapabilityError("unauthorized", "malformed token");
  }
  if (header.alg !== "EdDSA" || header.typ !== CAPABILITY_TYPE || typeof header.kid !== "string") {
    throw new CapabilityError("unauthorized", "invalid token header");
  }

  const valid = await crypto.subtle.verify(
    { name: "Ed25519" },
    await capabilityPublicKey(env, header.kid),
    arrayBuffer(decodeBase64url(encodedSignature)),
    encoder.encode(`${encodedHeader}.${encodedClaims}`),
  );
  if (!valid) throw new CapabilityError("unauthorized", "invalid signature");

  const now = Math.floor(Date.now() / 1000);
  if (
    claims.iss !== env.CAPABILITY_ISSUER ||
    claims.aud !== env.CAPABILITY_AUDIENCE ||
    typeof claims.sub !== "string" ||
    claims.sub.length < 1 ||
    claims.sub.length > 128 ||
    !Number.isInteger(claims.iat) ||
    !Number.isInteger(claims.nbf) ||
    !Number.isInteger(claims.exp) ||
    !Number.isInteger(claims.ver) ||
    claims.ver < 1 ||
    typeof claims.jti !== "string" ||
    !Array.isArray(claims.scope)
  ) {
    throw new CapabilityError("unauthorized", "invalid token claims");
  }
  if (claims.nbf > now + 30 || claims.iat > now + 30) {
    throw new CapabilityError("unauthorized", "token is not active");
  }
  const expiredBy = now - claims.exp;
  if (expiredBy > (options.allowExpiredSeconds ?? 0)) {
    throw new CapabilityError("token_expired", "capability has expired");
  }
  if (options.requiredScope && !claims.scope.includes(options.requiredScope)) {
    throw new CapabilityError("unauthorized", "scope is not allowed");
  }
  return claims;
}

export async function sha256(value: string): Promise<string> {
  return base64url(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

export async function canonicalAppleHash(request: AppleSendRequest): Promise<string> {
  const tokenHash = await sha256(request.token);
  const values = [
    "apple",
    request.environment,
    request.topic,
    request.mode,
    request.server_device_id,
    request.delivery_id,
    request.badge === undefined ? "" : String(request.badge),
    request.collapse_id ?? "",
    tokenHash,
  ];
  return sha256(values.map((value) => `${value.length}:${value}`).join(""));
}

export async function canonicalFcmHash(request: FcmSendRequest): Promise<string> {
  const tokenHash = await sha256(request.token);
  const values = [
    "fcm",
    request.mode,
    request.server_device_id,
    request.delivery_id,
    request.collapse_id ?? "",
    tokenHash,
  ];
  return sha256(values.map((value) => `${value.length}:${value}`).join(""));
}

export async function constantTimeSecretEqual(left: string, right: string): Promise<boolean> {
  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right)),
  ]);
  const a = new Uint8Array(leftHash);
  const b = new Uint8Array(rightHash);
  let difference = a.length ^ b.length;
  for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
    difference |= (a[index % a.length] ?? 0) ^ (b[index % b.length] ?? 0);
  }
  return difference === 0;
}

export function capabilityDisplayPrefix(env: Env, claims: CapabilityClaims): string {
  return `cap_${env.CAPABILITY_SIGNING_KEY_ID}_${claims.jti.slice(0, 8)}`;
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
