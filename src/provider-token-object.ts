import { DurableObject } from "cloudflare:workers";

import { base64url } from "./crypto";
import type { Env } from "./env";

const REFRESH_AFTER_SECONDS = 50 * 60;
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

    const token = await signProviderToken(this.env, now);
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

async function signProviderToken(env: Env, issuedAt: number): Promise<string> {
  const header = base64url(JSON.stringify({ alg: "ES256", kid: env.APNS_KEY_ID }));
  const claims = base64url(JSON.stringify({ iss: env.APNS_TEAM_ID, iat: issuedAt }));
  const unsigned = `${header}.${claims}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    await crypto.subtle.importKey(
      "pkcs8",
      arrayBuffer(pemBytes(env.APNS_PRIVATE_KEY_PEM)),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    ),
    encoder.encode(unsigned),
  );
  return `${unsigned}.${base64url(signature)}`;
}

function pemBytes(pem: string): Uint8Array {
  const begin = "-----BEGIN PRIVATE KEY-----";
  const end = "-----END PRIVATE KEY-----";
  const normalized = pem.trim();
  if (!normalized.startsWith(begin) || !normalized.endsWith(end)) {
    throw new Error("APNS_PRIVATE_KEY_PEM must be a PKCS#8 PRIVATE KEY");
  }
  const body = normalized.slice(begin.length, -end.length).replace(/\s+/gu, "");
  return Uint8Array.from(atob(body), (character) => character.charCodeAt(0));
}

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}
