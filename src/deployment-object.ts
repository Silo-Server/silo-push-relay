import { DurableObject } from "cloudflare:workers";

import { sendToAPNs } from "./apns";
import type { Env } from "./env";
import { numberSetting } from "./env";
import { sendToFCM } from "./fcm";
import { errorBody, errorResult } from "./http";
import type { ProviderToken } from "./provider-token-object";
import type {
  DeploymentSendInput,
  ProviderSendResult,
  PushProvider,
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

interface TableInfoRow {
  [key: string]: SqlStorageValue;
  name: string;
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
  created_at: number;
}

const CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
const CLEANUP_BATCH_SIZE = 250;
const CLEANUP_MAX_BATCHES = 40;
const PROVIDER_TOKEN_REFRESH_SECONDS = 50 * 60;

const sharedProviderTokens = new Map<string, ProviderToken>();
const sharedProviderTokenPromises = new Map<string, Promise<ProviderToken>>();

interface UpstreamLabels {
  name: string;
  tokenName: string;
  idField: string;
  rejectedCode: string;
}

function upstreamLabels(provider: PushProvider): UpstreamLabels {
  return provider === "fcm"
    ? { name: "FCM", tokenName: "fcm", idField: "fcm_message_id", rejectedCode: "fcm_rejected" }
    : { name: "APNs", tokenName: "apns", idField: "apns_id", rejectedCode: "apns_rejected" };
}

type BeginResult =
  | { kind: "proceed"; nonce: string; cleanupAt: number }
  | { kind: "response"; response: RelayResult };

type StoredRotationResult = RotationResult & { cleanupAt?: number };

export interface AuthorizationResult {
  allowed: boolean;
  reason?: "disabled" | "revoked";
}

export interface RotationResult {
  ok: boolean;
  metadata?: RotationMetadata;
  reason?: "disabled" | "revoked" | "invalid_idempotency_key";
}

export class DeploymentObject extends DurableObject<Env> {
  private cleanupAlarmAt?: number;

  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`
      DROP TABLE IF EXISTS daily_quota;
      CREATE TABLE IF NOT EXISTS metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
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
        updated_at INTEGER NOT NULL,
        cleanup_at INTEGER NOT NULL
      );
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
    const hasCleanupAt = this.ctx.storage.sql
      .exec<TableInfoRow>("PRAGMA table_info(idempotency)")
      .toArray()
      .some((column) => column.name === "cleanup_at");
    if (!hasCleanupAt) {
      this.ctx.storage.transactionSync(() => {
        this.ctx.storage.sql.exec("ALTER TABLE idempotency ADD COLUMN cleanup_at INTEGER");
        this.ctx.storage.sql.exec(
          "UPDATE idempotency SET cleanup_at = updated_at + ? WHERE cleanup_at IS NULL",
          this.retentionSeconds(),
        );
      });
    }
    this.ctx.storage.sql.exec(`
      CREATE INDEX IF NOT EXISTS idempotency_cleanup_at_idx ON idempotency(cleanup_at);
      DROP INDEX IF EXISTS idempotency_updated_at_idx;
    `);
    void this.ctx.blockConcurrencyWhile(async () => this.restoreCleanupAlarm());
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
    const stored = this.ctx.storage.transactionSync<StoredRotationResult>(() => {
      const existing = this.ctx.storage.sql
        .exec<RotationRow>(
          `SELECT previous_generation, generation, issued_at, expires_at, jti, created_at
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
          cleanupAt: existing.created_at + this.retentionSeconds(),
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
      return { ok: true, metadata, cleanupAt: issuedAt + this.retentionSeconds() };
    });
    if (stored.cleanupAt !== undefined) this.scheduleCleanupAt(stored.cleanupAt);
    const { cleanupAt: _cleanupAt, ...result } = stored;
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
    const begin = this.begin(input);
    if (begin.kind === "response") return begin.response;
    this.scheduleCleanupAt(begin.cleanupAt);

    const upstream = upstreamLabels(input.provider);
    let providerToken;
    try {
      providerToken = await this.getProviderToken(upstream.tokenName);
    } catch {
      this.markRetryable(input.idempotencyKey, begin.nonce);
      return errorResult(
        503,
        "upstream_unavailable",
        `${upstream.name} authentication is unavailable`,
        input.requestId,
      );
    }

    let delivery = await this.dispatch(input, providerToken);
    if (delivery.expiredProviderToken) {
      try {
        const tokenStub = this.env.PROVIDER_TOKENS.getByName(upstream.tokenName);
        await tokenStub.invalidate(delivery.expiredProviderToken);
        if (sharedProviderTokens.get(upstream.tokenName)?.token === delivery.expiredProviderToken) {
          sharedProviderTokens.delete(upstream.tokenName);
        }
        providerToken = await this.getProviderToken(upstream.tokenName);
        delivery = await this.dispatch(input, providerToken);
      } catch {
        this.markRetryable(input.idempotencyKey, begin.nonce);
        return errorResult(
          503,
          "upstream_unavailable",
          `${upstream.name} authentication is unavailable`,
          input.requestId,
        );
      }
    }
    return this.complete(input, begin.nonce, delivery.result);
  }

  private dispatch(
    input: DeploymentSendInput,
    providerToken: ProviderToken,
  ): Promise<{ result: ProviderSendResult; expiredProviderToken?: string }> {
    return input.provider === "fcm"
      ? sendToFCM(this.env, input.request, providerToken)
      : sendToAPNs(this.env, input.request, providerToken);
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
                    `delivery may have reached ${upstreamLabels(input.provider).name}; it will not be sent again`,
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
            `delivery may have reached ${upstreamLabels(input.provider).name}; it will not be sent again`,
            input.requestId,
          );
          this.ctx.storage.sql.exec(
            `UPDATE idempotency
             SET state = 'unknown', nonce = NULL, response_status = 409, response_body = ?,
                 response_headers = '{}', updated_at = ?, cleanup_at = ?
             WHERE key = ?`,
            body,
            now,
            now + this.retentionSeconds(),
            input.idempotencyKey,
          );
          return { kind: "response", response: { status: 409, body } };
        }

        const nonce = crypto.randomUUID();
        this.ctx.storage.sql.exec(
          `UPDATE idempotency
           SET state = 'dispatching', nonce = ?, response_status = NULL, response_body = NULL,
               response_headers = NULL, updated_at = ?, cleanup_at = ?
           WHERE key = ?`,
          nonce,
          now,
          now + this.retentionSeconds(),
          input.idempotencyKey,
        );
        return { kind: "proceed", nonce, cleanupAt: now + this.retentionSeconds() };
      }

      const nonce = crypto.randomUUID();
      this.ctx.storage.sql.exec(
        `INSERT INTO idempotency
         (key, payload_hash, state, nonce, created_at, updated_at, cleanup_at)
         VALUES (?, ?, 'dispatching', ?, ?, ?, ?)`,
        input.idempotencyKey,
        input.payloadHash,
        nonce,
        now,
        now,
        now + this.retentionSeconds(),
      );
      return { kind: "proceed", nonce, cleanupAt: now + this.retentionSeconds() };
    });
  }

  private complete(
    input: DeploymentSendInput,
    nonce: string,
    result: ProviderSendResult,
  ): RelayResult {
    const upstream = upstreamLabels(input.provider);
    const now = Math.floor(Date.now() / 1000);
    if (result.kind === "unknown") {
      const response = errorResult(
        409,
        "delivery_unknown",
        `delivery may have reached ${upstream.name}; it will not be sent again`,
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
        status === 429
          ? `${upstream.name} upstream rate limited the request`
          : `${upstream.name} upstream unavailable`,
        input.requestId,
        result.retryAfterSeconds ? { "retry-after": String(result.retryAfterSeconds) } : undefined,
        result.messageId ? { [upstream.idField]: result.messageId } : undefined,
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
        upstream.rejectedCode,
        `${upstream.name} rejected the notification: ${result.reason}`,
        input.requestId,
        undefined,
        result.messageId ? { [upstream.idField]: result.messageId } : undefined,
      );
      this.storeFinal(input.idempotencyKey, nonce, "done", response, now);
      return response;
    }
    if (result.kind === "configuration") {
      const response = errorResult(
        502,
        "upstream_auth_error",
        `${upstream.name} authentication rejected: ${result.reason}`,
        input.requestId,
        { "retry-after": "60" },
        result.messageId ? { [upstream.idField]: result.messageId } : undefined,
      );
      this.markRetryable(input.idempotencyKey, nonce, now);
      return response;
    }

    const response: RelayResult = {
      status: 200,
      body: JSON.stringify({
        request_id: input.requestId,
        [upstream.idField]: result.messageId,
        status: "accepted",
      }),
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
           response_headers = NULL, updated_at = ?, cleanup_at = ?
       WHERE key = ? AND state = 'dispatching' AND nonce = ?`,
      now,
      now + this.retentionSeconds(),
      key,
      nonce,
    );
  }

  private async getProviderToken(tokenName: string): Promise<ProviderToken> {
    const now = Math.floor(Date.now() / 1000);
    const shared = sharedProviderTokens.get(tokenName);
    if (shared && now - shared.issuedAt < PROVIDER_TOKEN_REFRESH_SECONDS) {
      return shared;
    }
    const pending = sharedProviderTokenPromises.get(tokenName);
    if (pending) return pending;

    const promise = this.env.PROVIDER_TOKENS.getByName(tokenName).getToken().then((token) => {
      sharedProviderTokens.set(tokenName, token);
      return token;
    });
    sharedProviderTokenPromises.set(tokenName, promise);
    try {
      return await promise;
    } finally {
      if (sharedProviderTokenPromises.get(tokenName) === promise) {
        sharedProviderTokenPromises.delete(tokenName);
      }
    }
  }

  private metadata(key: string): string {
    return this.ctx.storage.sql
      .exec<MetaRow>("SELECT value FROM metadata WHERE key = ?", key)
      .one().value;
  }

  async alarm(): Promise<void> {
    this.cleanupAlarmAt = undefined;
    const now = Math.floor(Date.now() / 1000);
    this.cleanup(now);
    const nextCleanupAt = this.nextCleanupAt();
    if (nextCleanupAt !== undefined) await this.setCleanupAlarmAt(nextCleanupAt);
  }

  private async restoreCleanupAlarm(): Promise<void> {
    const existing = await this.ctx.storage.getAlarm();
    if (existing !== null) {
      this.cleanupAlarmAt = existing;
      return;
    }
    const nextCleanupAt = this.nextCleanupAt();
    if (nextCleanupAt !== undefined) await this.setCleanupAlarmAt(nextCleanupAt);
  }

  private scheduleCleanupAt(expiresAt: number): void {
    const target = this.cleanupAlarmTarget(expiresAt);
    if (this.cleanupAlarmAt !== undefined && this.cleanupAlarmAt <= target) return;
    this.ctx.waitUntil(
      this.setCleanupAlarmAt(expiresAt).catch((error: unknown) => {
        console.error(
          JSON.stringify({
            event: "cleanup.alarm_schedule_failed",
            error: error instanceof Error ? error.name : "unknown_error",
          }),
        );
      }),
    );
  }

  private async setCleanupAlarmAt(expiresAt: number): Promise<void> {
    const target = this.cleanupAlarmTarget(expiresAt);
    if (this.cleanupAlarmAt !== undefined && this.cleanupAlarmAt <= target) return;
    this.cleanupAlarmAt = target;
    try {
      await this.ctx.storage.setAlarm(target);
    } catch (error) {
      if (this.cleanupAlarmAt === target) this.cleanupAlarmAt = undefined;
      throw error;
    }
  }

  private cleanupAlarmTarget(expiresAt: number): number {
    const expiresAtMs = expiresAt * 1000;
    if (expiresAtMs <= Date.now()) return Date.now() + 1000;
    return Math.ceil(expiresAtMs / CLEANUP_INTERVAL_MS) * CLEANUP_INTERVAL_MS;
  }

  private nextCleanupAt(): number | undefined {
    const retention = this.retentionSeconds();
    const idempotencyCleanupAt = this.ctx.storage.sql
      .exec<{ value: number | null }>("SELECT MIN(cleanup_at) AS value FROM idempotency")
      .one().value;
    const rotationCreatedAt = this.ctx.storage.sql
      .exec<{ value: number | null }>("SELECT MIN(created_at) AS value FROM rotations")
      .one().value;
    const candidates = [
      idempotencyCleanupAt,
      rotationCreatedAt === null ? null : rotationCreatedAt + retention,
    ].filter((value): value is number => value !== null);
    return candidates.length > 0 ? Math.min(...candidates) : undefined;
  }

  private retentionSeconds(): number {
    return numberSetting(
      this.env.IDEMPOTENCY_RETENTION_SECONDS,
      "IDEMPOTENCY_RETENTION_SECONDS",
      60,
    );
  }

  private cleanup(now: number): void {
    const retention = this.retentionSeconds();
    this.deleteInBatches(
      `DELETE FROM idempotency
       WHERE key IN (
         SELECT key FROM idempotency
         WHERE cleanup_at < ?
         LIMIT ${CLEANUP_BATCH_SIZE}
       )`,
      now,
    );
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
