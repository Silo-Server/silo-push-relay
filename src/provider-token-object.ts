import { DurableObject } from "cloudflare:workers";

import { base64url } from "./crypto";
import type { Env } from "./env";
import { numberSetting } from "./env";

const REFRESH_AFTER_SECONDS = 50 * 60;
const GOOGLE_OAUTH_SCOPE = "https://www.googleapis.com/auth/firebase.messaging";
const GOOGLE_JWT_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const encoder = new TextEncoder();

export interface ProviderToken {
  token: string;
  issuedAt: number;
}

interface StoredProviderToken {
  [key: string]: SqlStorageValue;
  token: string;
  issued_at: number;
}

// One instance per upstream provider: "apns" signs APNs provider JWTs locally,
// "fcm" exchanges a signed service-account assertion for a Google OAuth access
// token. Both cache under the same singleton row and refresh window.
export class ProviderTokenObject extends DurableObject<Env> {
  private cached?: ProviderToken;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS provider_token (
        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
        token TEXT NOT NULL,
        issued_at INTEGER NOT NULL
      )
    `);
  }

  async getToken(): Promise<ProviderToken> {
    const now = Math.floor(Date.now() / 1000);
    if (this.cached && now - this.cached.issuedAt < REFRESH_AFTER_SECONDS) {
      return this.cached;
    }

    const stored = this.ctx.storage.sql
      .exec<StoredProviderToken>("SELECT token, issued_at FROM provider_token WHERE singleton = 1")
      .toArray()[0];
    if (stored && now - stored.issued_at < REFRESH_AFTER_SECONDS) {
      this.cached = { token: stored.token, issuedAt: stored.issued_at };
      return this.cached;
    }

    const token =
      this.ctx.id.name === "fcm"
        ? await mintFcmAccessToken(this.env, now)
        : await signAPNsProviderToken(this.env, now);
    this.ctx.storage.sql.exec(
      `INSERT INTO provider_token (singleton, token, issued_at)
       VALUES (1, ?, ?)
       ON CONFLICT(singleton) DO UPDATE SET token = excluded.token, issued_at = excluded.issued_at`,
      token,
      now,
    );
    this.cached = { token, issuedAt: now };
    return this.cached;
  }

  invalidate(expectedToken: string): boolean {
    const stored = this.ctx.storage.sql
      .exec<StoredProviderToken>("SELECT token, issued_at FROM provider_token WHERE singleton = 1")
      .toArray()[0];
    if (!stored || stored.token !== expectedToken) return false;
    this.ctx.storage.sql.exec("DELETE FROM provider_token WHERE singleton = 1");
    if (this.cached?.token === expectedToken) this.cached = undefined;
    return true;
  }
}

async function signAPNsProviderToken(env: Env, issuedAt: number): Promise<string> {
  const header = base64url(JSON.stringify({ alg: "ES256", kid: env.APNS_KEY_ID }));
  const claims = base64url(JSON.stringify({ iss: env.APNS_TEAM_ID, iat: issuedAt }));
  const unsigned = `${header}.${claims}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    await crypto.subtle.importKey(
      "pkcs8",
      arrayBuffer(pemBytes(env.APNS_PRIVATE_KEY_PEM, "APNS_PRIVATE_KEY_PEM")),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    ),
    encoder.encode(unsigned),
  );
  return `${unsigned}.${base64url(signature)}`;
}

async function mintFcmAccessToken(env: Env, issuedAt: number): Promise<string> {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64url(
    JSON.stringify({
      iss: env.FCM_CLIENT_EMAIL,
      scope: GOOGLE_OAUTH_SCOPE,
      aud: env.FCM_TOKEN_URL,
      iat: issuedAt,
      exp: issuedAt + 3600,
    }),
  );
  const unsigned = `${header}.${claims}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    await crypto.subtle.importKey(
      "pkcs8",
      arrayBuffer(pemBytes(env.FCM_PRIVATE_KEY_PEM, "FCM_PRIVATE_KEY_PEM")),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    ),
    encoder.encode(unsigned),
  );
  const assertion = `${unsigned}.${base64url(signature)}`;

  const response = await fetch(env.FCM_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: GOOGLE_JWT_GRANT, assertion }).toString(),
    signal: AbortSignal.timeout(numberSetting(env.FCM_TIMEOUT_MS, "FCM_TIMEOUT_MS", 1)),
  });
  if (!response.ok) {
    throw new Error(`google_token_exchange_failed_${response.status}`);
  }
  const parsed = (await response.json()) as { access_token?: unknown };
  if (typeof parsed.access_token !== "string" || parsed.access_token.length === 0) {
    throw new Error("google_token_exchange_malformed");
  }
  return parsed.access_token;
}

function pemBytes(pem: string, name: string): Uint8Array {
  const begin = "-----BEGIN PRIVATE KEY-----";
  const end = "-----END PRIVATE KEY-----";
  const normalized = pem.trim();
  if (!normalized.startsWith(begin) || !normalized.endsWith(end)) {
    throw new Error(`${name} must be a PKCS#8 PRIVATE KEY`);
  }
  const body = normalized.slice(begin.length, -end.length).replace(/\s+/gu, "");
  return Uint8Array.from(atob(body), (character) => character.charCodeAt(0));
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
