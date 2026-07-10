import { DurableObject } from "cloudflare:workers";

import { sendToAPNs } from "./apns";
import type { Env } from "./env";
import { numberSetting } from "./env";
import { errorBody, errorResult } from "./http";
import type {
  APNsResult,
  DeploymentSendInput,
  RelayResult,
  RotationMetadata,
} from "./types";

interface IdempotencyRow {
  [key: string]: SqlStorageValue;
  payload_hash: string;
  state: "dispatching" | "done" | "retryable" | "unknown";
  nonce: string | null;
  response_status: number | null;
  response_body: string | null;
  response_headers: string | null;
  updated_at: number;
}

interface MetaRow {
  [key: string]: SqlStorageValue;
  value: string;
}

interface RotationRow {
  [key: string]: SqlStorageValue;
  previous_generation: number;
  generation: number;
  issued_at: number;
  expires_at: number;
  jti: string;
}

interface Bucket {
  tokens: number;
  updatedAt: number;
}

const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const CLEANUP_BATCH_SIZE = 250;
const CLEANUP_MAX_BATCHES = 40;

type BeginResult =
  | { kind: "proceed"; nonce: string }
  | { kind: "response"; response: RelayResult };

export interface AuthorizationResult {
  allowed: boolean;
  reason?: "disabled" | "revoked";
}

export interface RotationResult {
  ok: boolean;
  metadata?: RotationMetadata;
  reason?: "disabled" | "revoked" | "invalid_idempotency_key" | "rate_limited";
  retryAfterSeconds?: number;
}

export class DeploymentObject extends DurableObject<Env> {
  private accountBucket?: Bucket;
  private readonly tokenBuckets = new Map<string, Bucket>();
  private providerToken?: { token: string; issuedAt: number };
  private cleanupAlarmScheduled = false;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS daily_quota (
        day TEXT PRIMARY KEY,
        count INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS idempotency (
        key TEXT PRIMARY KEY,
        payload_hash TEXT NOT NULL,
        state TEXT NOT NULL CHECK (state IN ('dispatching', 'done', 'retryable', 'unknown')),
        nonce TEXT,
        response_status INTEGER,
        response_body TEXT,
        response_headers TEXT,
        created_at INTEGER NOT NULL,
        updated_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idempotency_updated_at_idx ON idempotency(updated_at);
      CREATE TABLE IF NOT EXISTS rotations (
        idempotency_key TEXT PRIMARY KEY,
        previous_generation INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        jti TEXT NOT NULL,
        created_at INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS rotations_created_at_idx ON rotations(created_at);
      INSERT OR IGNORE INTO metadata (key, value) VALUES ('status', 'active');
      INSERT OR IGNORE INTO metadata (key, value) VALUES ('generation', '1');
    `);
    void this.ctx.blockConcurrencyWhile(async () => {
      this.cleanupAlarmScheduled = (await this.ctx.storage.getAlarm()) !== null;
      if (!this.cleanupAlarmScheduled && this.hasCleanupState()) {
        await this.setCleanupAlarm();
      }
    });
  }

  authorizeGeneration(generation: number): AuthorizationResult {
    const status = this.metadata("status");
    if (status !== "active") return { allowed: false, reason: "disabled" };
    if (generation !== Number(this.metadata("generation"))) {
      return { allowed: false, reason: "revoked" };
    }
    return { allowed: true };
  }

  prepareRotation(
    generation: number,
    idempotencyKey: string,
    issuedAt: number,
    expiresAt: number,
  ): RotationResult {
    if (!idempotencyKey || idempotencyKey.length > 255) {
      return { ok: false, reason: "invalid_idempotency_key" };
    }
    const accountLimit = this.consumeAccountBucket();
    if (!accountLimit.allowed) {
      return {
        ok: false,
        reason: "rate_limited",
        retryAfterSeconds: accountLimit.retryAfterSeconds,
      };
    }
    const result = this.ctx.storage.transactionSync<RotationResult>(() => {
      const existing = this.ctx.storage.sql
        .exec<RotationRow>(
          `SELECT previous_generation, generation, issued_at, expires_at, jti
           FROM rotations WHERE idempotency_key = ?`,
          idempotencyKey,
        )
        .toArray()[0];
      if (existing) {
        if (existing.previous_generation !== generation) return { ok: false, reason: "revoked" };
        return {
          ok: true,
          metadata: {
            generation: existing.generation,
            issuedAt: existing.issued_at,
            expiresAt: existing.expires_at,
            jti: existing.jti,
          },
        };
      }

      const authorized = this.authorizeGeneration(generation);
      if (!authorized.allowed) return { ok: false, reason: authorized.reason };
      const metadata: RotationMetadata = {
        generation: generation + 1,
        issuedAt,
        expiresAt,
        jti: crypto.randomUUID(),
      };
      this.ctx.storage.sql.exec(
        `INSERT INTO rotations
         (idempotency_key, previous_generation, generation, issued_at, expires_at, jti, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        idempotencyKey,
        generation,
        metadata.generation,
        metadata.issuedAt,
        metadata.expiresAt,
        metadata.jti,
        issuedAt,
      );
      this.ctx.storage.sql.exec(
        "UPDATE metadata SET value = ? WHERE key = 'generation'",
        String(metadata.generation),
      );
      return { ok: true, metadata };
    });
    if (result.ok) this.scheduleCleanupAlarm();
    return result;
  }

  disable(generation?: number): AuthorizationResult {
    return this.ctx.storage.transactionSync(() => {
      if (generation !== undefined && generation !== Number(this.metadata("generation"))) {
        return { allowed: false, reason: "revoked" };
      }
      if (this.metadata("status") === "disabled") return { allowed: true };
      this.ctx.storage.sql.exec("UPDATE metadata SET value = 'disabled' WHERE key = 'status'");
      return { allowed: true };
    });
  }

  async send(input: DeploymentSendInput): Promise<RelayResult> {
    const accountLimit = this.consumeAccountBucket();
    if (!accountLimit.allowed) {
      return errorResult(429, "rate_limited", "deployment request rate exceeded", input.requestId, {
        "retry-after": String(accountLimit.retryAfterSeconds),
      });
    }

    const begin = this.begin(input);
    if (begin.kind === "response") return begin.response;
    this.scheduleCleanupAlarm();

    let providerToken;
    try {
      providerToken = await this.getProviderToken();
    } catch {
      this.markRetryable(input.idempotencyKey, begin.nonce);
      return errorResult(503, "upstream_unavailable", "APNs authentication is unavailable", input.requestId);
    }

    let delivery = await sendToAPNs(this.env, input.request, providerToken);
    if (delivery.expiredProviderToken) {
      try {
        const tokenStub = this.env.PROVIDER_TOKENS.getByName("apns");
        await tokenStub.invalidate(delivery.expiredProviderToken);
        this.providerToken = undefined;
        providerToken = await this.getProviderToken();
        delivery = await sendToAPNs(this.env, input.request, providerToken);
      } catch {
        this.markRetryable(input.idempotencyKey, begin.nonce);
        return errorResult(503, "upstream_unavailable", "APNs authentication is unavailable", input.requestId);
      }
    }
    return this.complete(input, begin.nonce, delivery.result);
  }

  private begin(input: DeploymentSendInput): BeginResult {
    const now = Math.floor(Date.now() / 1000);
    return this.ctx.storage.transactionSync(() => {
      const authorized = this.authorizeGeneration(input.generation);
      if (!authorized.allowed) {
        return {
          kind: "response",
          response: errorResult(401, "unauthorized", "unauthorized", input.requestId),
        };
      }

      const existing = this.ctx.storage.sql
        .exec<IdempotencyRow>(
          `SELECT payload_hash, state, nonce, response_status, response_body, response_headers, updated_at
           FROM idempotency WHERE key = ?`,
          input.idempotencyKey,
        )
        .toArray()[0];
      if (existing) {
        if (existing.payload_hash !== input.payloadHash) {
          return {
            kind: "response",
            response: errorResult(
              422,
              "idempotency_key_reuse",
              "Idempotency-Key reused with a different payload",
              input.requestId,
            ),
          };
        }
        if (existing.state === "done" && existing.response_status && existing.response_body) {
          return {
            kind: "response",
            response: {
              status: existing.response_status,
              body: existing.response_body,
              headers: parseStoredHeaders(existing.response_headers),
            },
          };
        }
        if (existing.state === "unknown") {
          return {
            kind: "response",
            response:
              existing.response_status && existing.response_body
                ? {
                    status: existing.response_status,
                    body: existing.response_body,
                    headers: parseStoredHeaders(existing.response_headers),
                  }
                : errorResult(
                    409,
                    "delivery_unknown",
                    "delivery may have reached APNs; it will not be sent again",
                    input.requestId,
                  ),
          };
        }
        if (existing.state === "dispatching") {
          const staleAfter = numberSetting(
            this.env.IDEMPOTENCY_DISPATCH_TIMEOUT_SECONDS,
            "IDEMPOTENCY_DISPATCH_TIMEOUT_SECONDS",
            1,
          );
          if (now - existing.updated_at < staleAfter) {
            return {
              kind: "response",
              response: errorResult(
                425,
                "idempotency_in_progress",
                "a request with this Idempotency-Key is still in progress",
                input.requestId,
                { "retry-after": String(Math.max(1, staleAfter - (now - existing.updated_at))) },
              ),
            };
          }
          const body = errorBody(
            "delivery_unknown",
            "delivery may have reached APNs; it will not be sent again",
            input.requestId,
          );
          this.ctx.storage.sql.exec(
            `UPDATE idempotency
             SET state = 'unknown', nonce = NULL, response_status = 409, response_body = ?,
                 response_headers = '{}', updated_at = ?
             WHERE key = ?`,
            body,
            now,
            input.idempotencyKey,
          );
          return { kind: "response", response: { status: 409, body } };
        }

        const nonce = crypto.randomUUID();
        this.ctx.storage.sql.exec(
          `UPDATE idempotency
           SET state = 'dispatching', nonce = ?, response_status = NULL, response_body = NULL,
               response_headers = NULL, updated_at = ?
           WHERE key = ?`,
          nonce,
          now,
          input.idempotencyKey,
        );
        return { kind: "proceed", nonce };
      }

      const tokenLimit = this.consumeTokenBucket(input.tokenHash);
      if (!tokenLimit.allowed) {
        return {
          kind: "response",
          response: errorResult(429, "rate_limited", "device rate limit exceeded", input.requestId, {
            "retry-after": String(tokenLimit.retryAfterSeconds),
          }),
        };
      }

      const day = new Date(now * 1000).toISOString().slice(0, 10);
      const quota = this.ctx.storage.sql
        .exec<{ count: number }>("SELECT count FROM daily_quota WHERE day = ?", day)
        .toArray()[0]?.count ?? 0;
      const dailyLimit = numberSetting(this.env.DAILY_PUSH_LIMIT, "DAILY_PUSH_LIMIT", 1);
      if (quota >= dailyLimit) {
        return {
          kind: "response",
          response: errorResult(429, "rate_limited", "deployment daily quota exceeded", input.requestId, {
            "retry-after": String(secondsUntilMidnight(now)),
          }),
        };
      }

      const nonce = crypto.randomUUID();
      this.ctx.storage.sql.exec(
        `INSERT INTO daily_quota (day, count) VALUES (?, 1)
         ON CONFLICT(day) DO UPDATE SET count = count + 1`,
        day,
      );
      this.ctx.storage.sql.exec(
        `INSERT INTO idempotency
         (key, payload_hash, state, nonce, created_at, updated_at)
         VALUES (?, ?, 'dispatching', ?, ?, ?)`,
        input.idempotencyKey,
        input.payloadHash,
        nonce,
        now,
        now,
      );
      return { kind: "proceed", nonce };
    });
  }

  private complete(input: DeploymentSendInput, nonce: string, result: APNsResult): RelayResult {
    const now = Math.floor(Date.now() / 1000);
    if (result.kind === "unknown") {
      const response = errorResult(
        409,
        "delivery_unknown",
        "delivery may have reached APNs; it will not be sent again",
        input.requestId,
      );
      this.storeFinal(input.idempotencyKey, nonce, "unknown", response, now);
      return response;
    }
    if (result.kind === "retryable") {
      this.markRetryable(input.idempotencyKey, nonce, now);
      const status = result.status === 429 ? 429 : 503;
      const response = errorResult(
        status,
        status === 429 ? "upstream_rate_limited" : "upstream_unavailable",
        status === 429 ? "APNs upstream rate limited the request" : "APNs upstream unavailable",
        input.requestId,
        result.retryAfterSeconds ? { "retry-after": String(result.retryAfterSeconds) } : undefined,
        result.apnsId ? { apns_id: result.apnsId } : undefined,
      );
      return response;
    }
    if (result.kind === "internal") {
      this.markRetryable(input.idempotencyKey, nonce, now);
      return errorResult(
        500,
        "internal_error",
        "internal server error",
        input.requestId,
      );
    }
    if (result.kind === "terminal") {
      const response = errorResult(
        422,
        "apns_rejected",
        `APNs rejected the notification: ${result.reason}`,
        input.requestId,
        undefined,
        result.apnsId ? { apns_id: result.apnsId } : undefined,
      );
      this.storeFinal(input.idempotencyKey, nonce, "done", response, now);
      return response;
    }
    if (result.kind === "configuration") {
      const response = errorResult(
        502,
        "upstream_auth_error",
        `APNs authentication rejected: ${result.reason}`,
        input.requestId,
        { "retry-after": "60" },
        result.apnsId ? { apns_id: result.apnsId } : undefined,
      );
      this.markRetryable(input.idempotencyKey, nonce, now);
      return response;
    }

    const response: RelayResult = {
      status: 200,
      body: JSON.stringify({ request_id: input.requestId, apns_id: result.apnsId, status: "accepted" }),
    };
    this.storeFinal(input.idempotencyKey, nonce, "done", response, now);
    return response;
  }

  private storeFinal(
    key: string,
    nonce: string,
    state: "done" | "unknown",
    response: RelayResult,
    now: number,
  ): void {
    this.ctx.storage.sql.exec(
      `UPDATE idempotency
       SET state = ?, nonce = NULL, response_status = ?, response_body = ?, response_headers = ?,
           updated_at = ?
       WHERE key = ? AND state = 'dispatching' AND nonce = ?`,
      state,
      response.status,
      response.body,
      JSON.stringify(response.headers ?? {}),
      now,
      key,
      nonce,
    );
  }

  private markRetryable(key: string, nonce: string, now = Math.floor(Date.now() / 1000)): void {
    this.ctx.storage.sql.exec(
      `UPDATE idempotency
       SET state = 'retryable', nonce = NULL, response_status = NULL, response_body = NULL,
           response_headers = NULL, updated_at = ?
       WHERE key = ? AND state = 'dispatching' AND nonce = ?`,
      now,
      key,
      nonce,
    );
  }

  private async getProviderToken(): Promise<{ token: string; issuedAt: number }> {
    const now = Math.floor(Date.now() / 1000);
    if (this.providerToken && now - this.providerToken.issuedAt < 50 * 60) {
      return this.providerToken;
    }
    this.providerToken = await this.env.PROVIDER_TOKENS.getByName("apns").getToken();
    return this.providerToken;
  }

  private metadata(key: string): string {
    return this.ctx.storage.sql
      .exec<MetaRow>("SELECT value FROM metadata WHERE key = ?", key)
      .one().value;
  }

  private consumeTokenBucket(tokenHash: string): { allowed: boolean; retryAfterSeconds: number } {
    const result = this.consumeBucket(
      this.tokenBuckets.get(tokenHash),
      numberSetting(this.env.TOKEN_RATE_PER_SECOND, "TOKEN_RATE_PER_SECOND", 0.000_001),
      numberSetting(this.env.TOKEN_RATE_BURST, "TOKEN_RATE_BURST", 1),
    );
    this.tokenBuckets.set(tokenHash, result.bucket);
    if (this.tokenBuckets.size > 10_000) {
      const cutoff = Date.now() - 10 * 60 * 1000;
      for (const [key, bucket] of this.tokenBuckets) {
        if (bucket.updatedAt < cutoff) this.tokenBuckets.delete(key);
      }
    }
    return { allowed: result.allowed, retryAfterSeconds: result.retryAfterSeconds };
  }

  private consumeAccountBucket(): { allowed: boolean; retryAfterSeconds: number } {
    const result = this.consumeBucket(
      this.accountBucket,
      numberSetting(this.env.ACCOUNT_RATE_PER_SECOND, "ACCOUNT_RATE_PER_SECOND", 0.000_001),
      numberSetting(this.env.ACCOUNT_RATE_BURST, "ACCOUNT_RATE_BURST", 1),
    );
    this.accountBucket = result.bucket;
    return { allowed: result.allowed, retryAfterSeconds: result.retryAfterSeconds };
  }

  private consumeBucket(
    current: Bucket | undefined,
    rate: number,
    capacity: number,
  ): { allowed: boolean; retryAfterSeconds: number; bucket: Bucket } {
    const now = Date.now();
    const bucket = current ?? { tokens: capacity, updatedAt: now };
    const elapsed = Math.max(0, now - bucket.updatedAt) / 1000;
    bucket.tokens = Math.min(capacity, bucket.tokens + elapsed * rate);
    bucket.updatedAt = now;
    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      return { allowed: true, retryAfterSeconds: 0, bucket };
    }
    return {
      allowed: false,
      retryAfterSeconds: Math.max(1, Math.ceil((1 - bucket.tokens) / rate)),
      bucket,
    };
  }

  async alarm(): Promise<void> {
    this.cleanupAlarmScheduled = false;
    try {
      this.cleanup(Math.floor(Date.now() / 1000));
    } finally {
      if (this.hasCleanupState()) await this.setCleanupAlarm();
    }
  }

  private scheduleCleanupAlarm(): void {
    if (this.cleanupAlarmScheduled) return;
    this.cleanupAlarmScheduled = true;
    this.ctx.waitUntil(
      this.ctx.storage.setAlarm(Date.now() + CLEANUP_INTERVAL_MS).catch((error: unknown) => {
        this.cleanupAlarmScheduled = false;
        console.error(
          JSON.stringify({
            event: "cleanup.alarm_schedule_failed",
            error: error instanceof Error ? error.name : "unknown_error",
          }),
        );
      }),
    );
  }

  private async setCleanupAlarm(): Promise<void> {
    await this.ctx.storage.setAlarm(Date.now() + CLEANUP_INTERVAL_MS);
    this.cleanupAlarmScheduled = true;
  }

  private hasCleanupState(): boolean {
    return (
      this.ctx.storage.sql
        .exec<{ present: number }>(
          `SELECT (
             EXISTS(SELECT 1 FROM idempotency) OR
             EXISTS(SELECT 1 FROM rotations) OR
             EXISTS(SELECT 1 FROM daily_quota)
           ) AS present`,
        )
        .one().present === 1
    );
  }

  private cleanup(now: number): void {
    const retention = numberSetting(
      this.env.IDEMPOTENCY_RETENTION_SECONDS,
      "IDEMPOTENCY_RETENTION_SECONDS",
      60,
    );
    const staleAfter = numberSetting(
      this.env.IDEMPOTENCY_DISPATCH_TIMEOUT_SECONDS,
      "IDEMPOTENCY_DISPATCH_TIMEOUT_SECONDS",
      1,
    );
    this.ctx.storage.sql.exec(
      `UPDATE idempotency
       SET state = 'unknown', nonce = NULL, response_status = NULL, response_body = NULL,
           response_headers = NULL, updated_at = ?
       WHERE state = 'dispatching' AND updated_at < ?`,
      now,
      now - staleAfter,
    );
    this.deleteInBatches(
      `DELETE FROM idempotency
       WHERE key IN (
         SELECT key FROM idempotency
         WHERE state != 'dispatching' AND updated_at < ?
         LIMIT ${CLEANUP_BATCH_SIZE}
       )`,
      now - retention,
    );
    this.ctx.storage.sql.exec("DELETE FROM daily_quota WHERE day < ?", daysAgo(now, 2));
    this.deleteInBatches(
      `DELETE FROM rotations
       WHERE idempotency_key IN (
         SELECT idempotency_key FROM rotations
         WHERE created_at < ?
         LIMIT ${CLEANUP_BATCH_SIZE}
       )`,
      now - retention,
    );
  }

  private deleteInBatches(statement: string, cutoff: number): void {
    for (let batch = 0; batch < CLEANUP_MAX_BATCHES; batch += 1) {
      const result = this.ctx.storage.sql.exec(statement, cutoff);
      if (result.rowsWritten < CLEANUP_BATCH_SIZE) return;
    }
  }
}

function parseStoredHeaders(value: string | null): Record<string, string> | undefined {
  if (!value) return undefined;
  try {
    return JSON.parse(value) as Record<string, string>;
  } catch {
    return undefined;
  }
}

function secondsUntilMidnight(nowSeconds: number): number {
  const now = new Date(nowSeconds * 1000);
  const next = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - now.getTime()) / 1000));
}

function daysAgo(nowSeconds: number, days: number): string {
  return new Date((nowSeconds - days * 24 * 60 * 60) * 1000).toISOString().slice(0, 10);
}
