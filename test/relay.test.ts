import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";

import { sendToAPNs } from "../src/apns";
import { canonicalAppleHash, newCapabilityClaims, signCapability } from "../src/crypto";
import type { AppleSendRequest, FcmSendRequest } from "../src/types";

const ACCEPT_TOKEN = "a".repeat(64);
const TERMINAL_TOKEN = "b".repeat(64);
const RETRY_TOKEN = "c".repeat(64);
const CONFIGURATION_TOKEN = "d".repeat(64);
const EXPIRED_PROVIDER_TOKEN = "e".repeat(64);

const FCM_ACCEPT_TOKEN = "A".repeat(140);
const FCM_TERMINAL_TOKEN = "B".repeat(140);
const FCM_RETRY_TOKEN = "C".repeat(140);
const FCM_CONFIGURATION_TOKEN = "D".repeat(140);
const FCM_EXPIRED_AUTH_TOKEN = "E".repeat(140);

interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    request_id: string;
    apns_id?: string;
    fcm_message_id?: string;
  };
}

interface Registration {
  request_id: string;
  deployment_id: string;
  api_key: string;
  key_prefix: string;
  apns_topics: string[];
  expires_at: string;
}

function appleRequest(token = ACCEPT_TOKEN, deliveryId = crypto.randomUUID()): AppleSendRequest {
  return {
    token,
    environment: "sandbox",
    topic: "org.siloserver.silo",
    mode: "private_alert",
    server_device_id: crypto.randomUUID(),
    delivery_id: deliveryId,
    collapse_id: deliveryId,
  };
}

async function register(
  body: Record<string, unknown> = {},
  clientKey = crypto.randomUUID(),
): Promise<Registration> {
  const response = await SELF.fetch("https://relay.test/v1/deployments/register", {
    method: "POST",
    headers: { "cf-connecting-ip": clientKey, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  expect(response.status).toBe(200);
  return response.json<Registration>();
}

async function send(
  capability: string,
  idempotencyKey: string,
  body: AppleSendRequest,
): Promise<Response> {
  return SELF.fetch("https://relay.test/v1/apple/send", {
    method: "POST",
    headers: {
      authorization: `Bearer ${capability}`,
      "content-type": "application/json",
      "idempotency-key": idempotencyKey,
    },
    body: JSON.stringify(body),
  });
}

function fcmRequest(token = FCM_ACCEPT_TOKEN, deliveryId = crypto.randomUUID()): FcmSendRequest {
  return {
    token,
    mode: "private_alert",
    server_device_id: crypto.randomUUID(),
    delivery_id: deliveryId,
    collapse_id: deliveryId,
  };
}

async function sendFcm(
  capability: string,
  idempotencyKey: string,
  body: unknown,
): Promise<Response> {
  return SELF.fetch("https://relay.test/v1/fcm/send", {
    method: "POST",
    headers: {
      authorization: `Bearer ${capability}`,
      "content-type": "application/json",
      "idempotency-key": idempotencyKey,
    },
    body: JSON.stringify(body),
  });
}

describe("relay worker", () => {
  it("reports health and readiness", async () => {
    expect((await SELF.fetch("https://relay.test/healthz")).status).toBe(200);
    expect((await SELF.fetch("https://relay.test/readyz")).status).toBe(200);
  });

  it("registers without durable account state and rejects caller-selected deployment IDs", async () => {
    const registration = await register();
    expect(registration.deployment_id).toMatch(/^[0-9a-f-]{36}$/u);
    expect(registration.api_key.split(".")).toHaveLength(3);
    expect(registration.key_prefix).toMatch(/^cap_v1_/u);
    expect(registration.apns_topics).toEqual(["org.siloserver.silo"]);
    expect(Date.parse(registration.expires_at)).toBeGreaterThan(Date.now());

    const response = await SELF.fetch("https://relay.test/v1/deployments/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ deployment_id: registration.deployment_id }),
    });
    expect(response.status).toBe(400);
    expect((await response.json<{ error: { code: string } }>()).error.code).toBe("unexpected_field");
  });

  it("delivers once and replays the stored response", async () => {
    const registration = await register();
    const body = appleRequest();
    const key = crypto.randomUUID();
    const first = await send(registration.api_key, key, body);
    const firstText = await first.text();
    expect(first.status).toBe(200);

    const replay = await send(registration.api_key, key, body);
    expect(replay.status).toBe(200);
    expect(await replay.text()).toBe(firstText);
  });

  it("requires idempotency and rejects fields outside the privacy contract", async () => {
    const registration = await register();
    const body = appleRequest();
    const missingKey = await SELF.fetch("https://relay.test/v1/apple/send", {
      method: "POST",
      headers: {
        authorization: `Bearer ${registration.api_key}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
    });
    expect(missingKey.status).toBe(400);
    expect((await missingKey.json<{ error: { code: string } }>()).error.code).toBe(
      "missing_idempotency_key",
    );

    const unexpected = await SELF.fetch("https://relay.test/v1/apple/send", {
      method: "POST",
      headers: {
        authorization: `Bearer ${registration.api_key}`,
        "content-type": "application/json",
        "idempotency-key": crypto.randomUUID(),
      },
      body: JSON.stringify({ ...body, title: "private content" }),
    });
    expect(unexpected.status).toBe(400);
    expect((await unexpected.json<{ error: { code: string } }>()).error.code).toBe(
      "unexpected_field",
    );
  });

  it("bounds request bodies before JSON parsing", async () => {
    const oversized = await SELF.fetch("https://relay.test/v1/deployments/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ padding: "x".repeat(17 << 10) }),
    });
    expect(oversized.status).toBe(413);
    expect((await oversized.json<ErrorEnvelope>()).error.code).toBe("request_too_large");

    const declaredOversized = await SELF.fetch("https://relay.test/v1/deployments/register", {
      method: "POST",
      headers: {
        "content-length": String((16 << 10) + 1),
        "content-type": "application/json",
      },
      body: "{}",
    });
    expect(declaredOversized.status).toBe(413);
  });

  it("validates and normalizes collapse IDs and badge boundaries", async () => {
    const registration = await register();
    const invalidBodies = [
      { ...appleRequest(), collapse_id: "a\nb" },
      { ...appleRequest(), collapse_id: "café-Ω" },
      { ...appleRequest(), collapse_id: "a".repeat(65) },
      { ...appleRequest(), badge: -1 },
      { ...appleRequest(), badge: 10_000 },
    ];
    for (const body of invalidBodies) {
      const response = await send(registration.api_key, crypto.randomUUID(), body);
      expect(response.status).toBe(400);
    }

    const normalizedKey = crypto.randomUUID();
    const padded = { ...appleRequest(), collapse_id: " normalized " };
    expect((await send(registration.api_key, normalizedKey, padded)).status).toBe(200);
    expect(
      (await send(registration.api_key, normalizedKey, { ...padded, collapse_id: "normalized" }))
        .status,
    ).toBe(200);

    const boundaryRegistration = await register();
    const lowerBoundary = {
      ...appleRequest("6".repeat(64)),
      badge: 0,
      collapse_id: "a".repeat(64),
    };
    expect(
      (await send(boundaryRegistration.api_key, crypto.randomUUID(), lowerBoundary)).status,
    ).toBe(200);
    const upperBoundary = {
      ...appleRequest("7".repeat(64)),
      badge: 9999,
      collapse_id: "b".repeat(64),
    };
    expect(
      (await send(boundaryRegistration.api_key, crypto.randomUUID(), upperBoundary)).status,
    ).toBe(200);
  });

  it("rejects topics outside the relay allowlist", async () => {
    const registration = await register();
    const response = await send(registration.api_key, crypto.randomUUID(), {
      ...appleRequest(),
      topic: "org.example.not-allowed",
    });
    expect(response.status).toBe(403);
    expect((await response.json<ErrorEnvelope>()).error.code).toBe("topic_not_allowed");
  });

  it("builds the fixed content-private background payload", async () => {
    const registration = await register();
    const body = { ...appleRequest(), mode: "background_wake" as const };
    expect((await send(registration.api_key, crypto.randomUUID(), body)).status).toBe(200);
  });

  it("rejects reuse of an idempotency key with a different payload", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    expect((await send(registration.api_key, key, appleRequest())).status).toBe(200);
    const mismatch = await send(registration.api_key, key, appleRequest());
    expect(mismatch.status).toBe(422);
    expect((await mismatch.json<{ error: { code: string } }>()).error.code).toBe(
      "idempotency_key_reuse",
    );
  });

  it("uses a stable indexed cleanup deadline and replays successful responses exactly", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = appleRequest();
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    await runInDurableObject(stub, (_instance, state) => {
      const columns = state.storage.sql
        .exec<{ name: string }>("PRAGMA table_info(idempotency)")
        .toArray()
        .map((column) => column.name);
      expect(columns).toContain("cleanup_at");

      const indexes = state.storage.sql
        .exec<{ name: string }>("PRAGMA index_list(idempotency)")
        .toArray()
        .map((index) => index.name);
      expect(indexes).toContain("idempotency_cleanup_at_idx");
      expect(indexes).not.toContain("idempotency_updated_at_idx");

      state.storage.sql.exec(`
        CREATE TABLE cleanup_at_updates (previous INTEGER NOT NULL, next INTEGER NOT NULL);
        CREATE TRIGGER track_cleanup_at_updates
        AFTER UPDATE OF cleanup_at ON idempotency
        BEGIN
          INSERT INTO cleanup_at_updates (previous, next) VALUES (OLD.cleanup_at, NEW.cleanup_at);
        END;
      `);
    });

    const first = await send(registration.api_key, key, body);
    const firstText = await first.text();
    expect(first.status).toBe(200);
    await runInDurableObject(stub, (_instance, state) => {
      const row = state.storage.sql
        .exec<{ created_at: number; cleanup_at: number; state: string }>(
          "SELECT created_at, cleanup_at, state FROM idempotency WHERE key = ?",
          key,
        )
        .one();
      expect(row.state).toBe("done");
      expect(row.cleanup_at).toBe(row.created_at + 86_400);
      expect(
        state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM cleanup_at_updates")
          .one().count,
      ).toBe(0);
    });

    const replay = await send(registration.api_key, key, body);
    expect(replay.status).toBe(first.status);
    expect(await replay.text()).toBe(firstText);
  });

  it("allows the same key to retry a definitive APNs 5xx", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = appleRequest(RETRY_TOKEN);
    const first = await send(registration.api_key, key, body);
    expect(first.status).toBe(503);
    expect((await first.json<ErrorEnvelope>()).error.apns_id).toBe("retryable-apns-id");
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec("UPDATE idempotency SET cleanup_at = 1 WHERE key = ?", key);
    });
    const second = await send(registration.api_key, key, body);
    expect(second.status).toBe(200);
    await runInDurableObject(stub, (_instance, state) => {
      expect(
        state.storage.sql
          .exec<{ cleanup_at: number }>("SELECT cleanup_at FROM idempotency WHERE key = ?", key)
          .one().cleanup_at,
      ).toBeGreaterThan(Math.floor(Date.now() / 1000) + 86_300);
    });
  });

  it("stores terminal APNs device rejection responses", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = appleRequest(TERMINAL_TOKEN);
    const first = await send(registration.api_key, key, body);
    const firstText = await first.text();
    expect(first.status).toBe(422);
    expect((JSON.parse(firstText) as ErrorEnvelope).error.apns_id).toBe("terminal-apns-id");
    const replay = await send(registration.api_key, key, body);
    expect(replay.status).toBe(422);
    expect(await replay.text()).toBe(firstText);
  });

  it("allows configuration failures to recover with the same idempotency key", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = appleRequest(CONFIGURATION_TOKEN);
    const first = await send(registration.api_key, key, body);
    const firstText = await first.text();
    const parsed = JSON.parse(firstText) as ErrorEnvelope;

    expect(first.status).toBe(502);
    expect(parsed.error.code).toBe("upstream_auth_error");
    expect(parsed.error.message).toContain("BadEnvironmentKeyIdInToken");
    expect(parsed.error.apns_id).toBe("configuration-apns-id");
    expect(first.headers.get("retry-after")).toBe("60");

    const retry = await send(registration.api_key, key, body);
    expect(retry.status).toBe(200);
    expect(await retry.text()).not.toBe(firstText);
  });

  it("recognizes the legacy APNs environment key mismatch spelling", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ reason: "BadEnvironmentKeyInToken" }), {
        status: 403,
        headers: { "apns-id": "legacy-configuration-apns-id" },
      }),
    );
    try {
      const delivery = await sendToAPNs(env, appleRequest(), {
        token: "test-provider-token",
        issuedAt: Math.floor(Date.now() / 1000),
      });
      expect(delivery.result).toEqual({
        kind: "configuration",
        messageId: "legacy-configuration-apns-id",
        reason: "BadEnvironmentKeyInToken",
      });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("classifies provider authentication and deterministic APNs failures explicitly", async () => {
    for (const reason of ["InvalidProviderToken", "MissingProviderToken", "TopicDisallowed"]) {
      const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
        new Response(JSON.stringify({ reason }), {
          status: 403,
          headers: { "apns-id": `${reason}-apns-id` },
        }),
      );
      try {
        const delivery = await sendToAPNs(env, appleRequest(), {
          token: "test-provider-token",
          issuedAt: Math.floor(Date.now() / 1000),
        });
        expect(delivery.result).toEqual({
          kind: "configuration",
          messageId: `${reason}-apns-id`,
          reason,
        });
      } finally {
        fetchSpy.mockRestore();
      }
    }

    const emptyForbiddenSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response("", { status: 403 }));
    try {
      const delivery = await sendToAPNs(env, appleRequest(), {
        token: "test-provider-token",
        issuedAt: Math.floor(Date.now() / 1000),
      });
      expect(delivery.result).toEqual({
        kind: "configuration",
        messageId: "",
        reason: "provider_auth_rejected",
      });
    } finally {
      emptyForbiddenSpy.mockRestore();
    }

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify({ reason: "BadPriority" }), {
        status: 400,
        headers: { "apns-id": "bad-priority-apns-id" },
      }),
    );
    try {
      const delivery = await sendToAPNs(env, appleRequest(), {
        token: "test-provider-token",
        issuedAt: Math.floor(Date.now() / 1000),
      });
      expect(delivery.result).toEqual({
        kind: "terminal",
        messageId: "bad-priority-apns-id",
        reason: "BadPriority",
      });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("distinguishes local construction failures from ambiguous network failures", async () => {
    const localFailure = await sendToAPNs(
      { ...env, APNS_TIMEOUT_MS: "not-a-number" },
      appleRequest(),
      { token: "test-provider-token", issuedAt: Math.floor(Date.now() / 1000) },
    );
    expect(localFailure.result).toEqual({
      kind: "internal",
      reason: "request_construction_failed",
    });

    const responseBody = new ReadableStream({
      pull(controller) {
        controller.error(new Error("response body failed"));
      },
    });
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(new Response(responseBody, { status: 503 }));
    try {
      const delivery = await sendToAPNs(env, appleRequest(), {
        token: "test-provider-token",
        issuedAt: Math.floor(Date.now() / 1000),
      });
      expect(delivery.result).toEqual({
        kind: "retryable",
        messageId: "",
        reason: "upstream_error",
        status: 503,
        retryAfterSeconds: undefined,
      });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("classifies an ambiguous APNs network failure as unknown", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockRejectedValueOnce(new Error("network failure"));
    try {
      const delivery = await sendToAPNs(env, appleRequest(), {
        token: "test-provider-token",
        issuedAt: Math.floor(Date.now() / 1000),
      });
      expect(delivery.result).toEqual({ kind: "unknown", reason: "network_error" });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("refreshes an expired provider token and resends once", async () => {
    const registration = await register();
    const response = await send(
      registration.api_key,
      crypto.randomUUID(),
      appleRequest(EXPIRED_PROVIDER_TOKEN),
    );
    expect(response.status).toBe(200);
    expect(await response.json<{ status: string; apns_id: string }>()).toEqual({
      status: "accepted",
      apns_id: `accepted-${EXPIRED_PROVIDER_TOKEN.slice(0, 8)}-2`,
      request_id: expect.any(String),
    });
  });

  it("converts abandoned dispatches to unknown instead of resending", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = appleRequest();
    const payloadHash = await canonicalAppleHash(body);
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    await runInDurableObject(stub, (_instance, state) => {
      const stale = Math.floor(Date.now() / 1000) - 61;
      state.storage.sql.exec(
        `INSERT INTO idempotency
         (key, payload_hash, state, nonce, created_at, updated_at, cleanup_at)
         VALUES (?, ?, 'dispatching', ?, ?, ?, ?)`,
        key,
        payloadHash,
        crypto.randomUUID(),
        stale,
        stale,
        stale + 86_400,
      );
    });

    const response = await send(registration.api_key, key, body);
    expect(response.status).toBe(409);
    expect((await response.json<{ error: { code: string } }>()).error.code).toBe("delivery_unknown");
    await runInDurableObject(stub, (_instance, state) => {
      expect(
        state.storage.sql
          .exec<{ cleanup_at: number }>("SELECT cleanup_at FROM idempotency WHERE key = ?", key)
          .one().cleanup_at,
      ).toBeGreaterThan(Math.floor(Date.now() / 1000) + 86_300);
    });
  });

  it("returns 425 while an idempotent dispatch is still in progress", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = appleRequest();
    const payloadHash = await canonicalAppleHash(body);
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    await runInDurableObject(stub, (_instance, state) => {
      const now = Math.floor(Date.now() / 1000);
      state.storage.sql.exec(
        `INSERT INTO idempotency
         (key, payload_hash, state, nonce, created_at, updated_at, cleanup_at)
         VALUES (?, ?, 'dispatching', ?, ?, ?, ?)`,
        key,
        payloadHash,
        crypto.randomUUID(),
        now,
        now,
        now + 86_400,
      );
    });

    const response = await send(registration.api_key, key, body);
    expect(response.status).toBe(425);
    expect(response.headers.get("retry-after")).not.toBeNull();
    expect((await response.json<ErrorEnvelope>()).error.code).toBe("idempotency_in_progress");
  });

  it("renews a recently expired signed capability", async () => {
    const registration = await register();
    const now = Math.floor(Date.now() / 1000);
    const expiredClaims = newCapabilityClaims(env, registration.deployment_id, 1, now - 100, {
      iat: now - 100,
      exp: now - 1,
      jti: crypto.randomUUID(),
    });
    const expired = await signCapability(env, expiredClaims);
    const rejected = await send(expired, crypto.randomUUID(), appleRequest());
    expect(rejected.status).toBe(401);
    expect((await rejected.json<{ error: { code: string } }>()).error.code).toBe("token_expired");

    const renewed = await SELF.fetch("https://relay.test/v1/deployments/renew", {
      method: "POST",
      headers: { authorization: `Bearer ${expired}`, "content-type": "application/json" },
      body: "{}",
    });
    expect(renewed.status).toBe(200);
    const value = await renewed.json<Registration>();
    expect(value.deployment_id).toBe(registration.deployment_id);
    expect(value.api_key).not.toBe(expired);
  });

  it("rejects renewal after the configured grace window", async () => {
    const registration = await register();
    const now = Math.floor(Date.now() / 1000);
    const expiredAt = now - 604_801;
    const expiredClaims = newCapabilityClaims(env, registration.deployment_id, 1, expiredAt - 100, {
      iat: expiredAt - 100,
      exp: expiredAt,
      jti: crypto.randomUUID(),
    });
    const expired = await signCapability(env, expiredClaims);
    const response = await SELF.fetch("https://relay.test/v1/deployments/renew", {
      method: "POST",
      headers: { authorization: `Bearer ${expired}`, "content-type": "application/json" },
      body: "{}",
    });
    expect(response.status).toBe(401);
    expect((await response.json<ErrorEnvelope>()).error.code).toBe("token_expired");
  });

  it("enforces Cloudflare registration, deployment, and device limits", async () => {
    const registrationClient = "198.51.100.10";
    for (let registration = 0; registration < 10; registration += 1) {
      expect((await register({}, registrationClient)).deployment_id).not.toBe("");
    }
    const registrationLimited = await SELF.fetch(
      "https://relay.test/v1/deployments/register",
      {
        method: "POST",
        headers: {
          "cf-connecting-ip": registrationClient,
          "content-type": "application/json",
        },
        body: "{}",
      },
    );
    expect(registrationLimited.status).toBe(429);
    expect(registrationLimited.headers.get("retry-after")).toBe("60");
    expect((await registrationLimited.json<ErrorEnvelope>()).error.code).toBe(
      "registration_rate_limited",
    );

    const deploymentRegistration = await register();
    for (let request = 0; request < 1_000; request += 1) {
      expect(
        (await env.DEPLOYMENT_RATE_LIMITER.limit({ key: deploymentRegistration.deployment_id }))
          .success,
      ).toBe(true);
    }
    const deploymentLimited = await send(
      deploymentRegistration.api_key,
      crypto.randomUUID(),
      appleRequest("1".repeat(64)),
    );
    expect(deploymentLimited.status).toBe(429);
    expect(deploymentLimited.headers.get("retry-after")).toBe("10");
    expect((await deploymentLimited.json<ErrorEnvelope>()).error.code).toBe(
      "deployment_rate_limited",
    );

    const deviceRegistration = await register();
    const deviceToken = "2".repeat(64);
    for (let delivery = 0; delivery < 30; delivery += 1) {
      expect(
        (
          await send(
            deviceRegistration.api_key,
            crypto.randomUUID(),
            appleRequest(deviceToken),
          )
        ).status,
      ).toBe(200);
    }
    const deviceLimited = await send(
      deviceRegistration.api_key,
      crypto.randomUUID(),
      appleRequest(deviceToken),
    );
    expect(deviceLimited.status).toBe(429);
    expect(deviceLimited.headers.get("retry-after")).toBe("60");
    expect((await deviceLimited.json<ErrorEnvelope>()).error.code).toBe(
      "device_rate_limited",
    );
  });

  it("rotates credentials idempotently without storing the bearer", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const rotate = () =>
      SELF.fetch("https://relay.test/v1/deployments/rotate", {
        method: "POST",
        headers: {
          authorization: `Bearer ${registration.api_key}`,
          "content-type": "application/json",
          "idempotency-key": key,
        },
        body: "{}",
      });
    const first = await rotate();
    expect(first.status).toBe(200);
    const firstValue = await first.json<Registration>();
    const replay = await rotate();
    expect(replay.status).toBe(200);
    const replayValue = await replay.json<Registration>();
    expect(replayValue.api_key).toBe(firstValue.api_key);

    expect((await send(registration.api_key, crypto.randomUUID(), appleRequest())).status).toBe(401);
    expect((await send(firstValue.api_key, crypto.randomUUID(), appleRequest())).status).toBe(200);
  });

  it("schedules cleanup only after transient state is created", async () => {
    const registration = await register();
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    expect(
      await runInDurableObject(stub, async (_instance, state) => state.storage.getAlarm()),
    ).toBeNull();

    expect(
      (await send(registration.api_key, crypto.randomUUID(), appleRequest("8".repeat(64)))).status,
    ).toBe(200);
    const alarm = await runInDurableObject(stub, async (_instance, state) =>
      state.storage.getAlarm(),
    );
    expect(alarm).not.toBeNull();
    expect(alarm as number).toBeGreaterThan(Date.now() + 23 * 60 * 60 * 1000);
    expect(alarm as number).toBeLessThan(Date.now() + 26 * 60 * 60 * 1000);
  });

  it("drains expired transient state in bounded alarm batches", async () => {
    const registration = await register();
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    await runInDurableObject(stub, async (instance, state) => {
      const now = Math.floor(Date.now() / 1000);
      const expired = now - 86_401;
      state.storage.sql.exec(
        `WITH RECURSIVE sequence(value) AS (
           VALUES(1) UNION ALL SELECT value + 1 FROM sequence WHERE value < 600
         )
         INSERT INTO idempotency
         (key, payload_hash, state, nonce, response_status, response_body, response_headers,
          created_at, updated_at, cleanup_at)
         SELECT 'expired-' || value, 'hash', 'done', NULL, 200, '{}', '{}', ?, ?, ?
         FROM sequence`,
        expired,
        expired,
        expired,
      );
      state.storage.sql.exec(
        `WITH RECURSIVE sequence(value) AS (
           VALUES(1) UNION ALL SELECT value + 1 FROM sequence WHERE value < 300
         )
         INSERT INTO rotations
         (idempotency_key, previous_generation, generation, issued_at, expires_at, jti, created_at)
         SELECT 'rotation-' || value, 1, 2, ?, ?, 'jti-' || value, ?
         FROM sequence`,
        expired,
        expired + 3600,
        expired,
      );
      state.storage.sql.exec(
        `INSERT INTO idempotency
         (key, payload_hash, state, nonce, created_at, updated_at, cleanup_at)
         VALUES ('expired-dispatch', 'hash', 'dispatching', 'nonce', ?, ?, ?)`,
        expired,
        expired,
        expired,
      );
      state.storage.sql.exec(
        `INSERT INTO idempotency
         (key, payload_hash, state, nonce, created_at, updated_at, cleanup_at)
         VALUES ('recent-dispatch', 'hash', 'dispatching', 'nonce', ?, ?, ?)`,
        now - 61,
        now - 61,
        now + 86_339,
      );

      await state.storage.deleteAlarm();
      await instance.alarm();

      expect(
        state.storage.sql
          .exec<{ count: number }>("SELECT COUNT(*) AS count FROM idempotency WHERE key LIKE 'expired-%'")
          .one().count,
      ).toBe(0);
      expect(
        state.storage.sql.exec<{ count: number }>("SELECT COUNT(*) AS count FROM rotations").one()
          .count,
      ).toBe(0);
      expect(
        state.storage.sql
          .exec<{ state: string }>("SELECT state FROM idempotency WHERE key = 'recent-dispatch'")
          .one().state,
      ).toBe("dispatching");
      expect(await state.storage.getAlarm()).not.toBeNull();
    });
  });

  it("stops scheduling alarms after transient state drains", async () => {
    const registration = await register();
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    await runInDurableObject(stub, async (instance, state) => {
      const expired = Math.floor(Date.now() / 1000) - 86_401;
      state.storage.sql.exec(
        `INSERT INTO idempotency
         (key, payload_hash, state, nonce, response_status, response_body, response_headers,
          created_at, updated_at, cleanup_at)
         VALUES ('last-expired', 'hash', 'done', NULL, 200, '{}', '{}', ?, ?, ?)`,
        expired,
        expired,
        expired,
      );

      await state.storage.deleteAlarm();
      await instance.alarm();

      expect(
        state.storage.sql
          .exec<{ count: number }>("SELECT COUNT(*) AS count FROM idempotency")
          .one().count,
      ).toBe(0);
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });

  it("keeps quota state out of new deployment objects", async () => {
    const registration = await register();
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    await runInDurableObject(stub, (_instance, state) => {
      const rows = state.storage.sql
        .exec<{ name: string }>(
          "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'daily_quota'",
        )
        .toArray();
      expect(rows).toHaveLength(0);
    });
  });

  it("revokes a deployment immediately and idempotently", async () => {
    const registration = await register();
    const revoke = (capability: string) =>
      SELF.fetch("https://relay.test/v1/deployments/revoke", {
        method: "POST",
        headers: { authorization: `Bearer ${capability}`, "content-type": "application/json" },
        body: "{}",
      });
    expect((await revoke(registration.api_key)).status).toBe(200);
    expect((await revoke(registration.api_key)).status).toBe(200);
    expect((await send(registration.api_key, crypto.randomUUID(), appleRequest())).status).toBe(401);
  });

  it("keeps self-revoke compatible with capabilities issued before the revoke scope", async () => {
    const registration = await register();
    const claims = newCapabilityClaims(env, registration.deployment_id, 1);
    claims.scope = claims.scope.filter((scope) => scope !== "deployment:revoke");
    const legacyCapability = await signCapability(env, claims);
    const response = await SELF.fetch("https://relay.test/v1/deployments/revoke", {
      method: "POST",
      headers: {
        authorization: `Bearer ${legacyCapability}`,
        "content-type": "application/json",
      },
      body: "{}",
    });
    expect(response.status).toBe(200);
  });

  it("supports an independently authenticated administrative revocation", async () => {
    const registration = await register();
    const rejected = await SELF.fetch("https://relay.test/v1/admin/deployments/revoke", {
      method: "POST",
      headers: {
        authorization: "Bearer incorrect-admin-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({ deployment_id: registration.deployment_id }),
    });
    expect(rejected.status).toBe(401);

    const logSpy = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const revoked = await SELF.fetch("https://relay.test/v1/admin/deployments/revoke", {
      method: "POST",
      headers: {
        authorization: "Bearer test-admin-token-that-is-not-a-production-secret",
        "content-type": "application/json",
      },
      body: JSON.stringify({ deployment_id: registration.deployment_id }),
    });
    expect(revoked.status).toBe(200);
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining("deployment.admin_revoked"));
    expect(logSpy).toHaveBeenCalledWith(expect.stringContaining(registration.deployment_id));
    logSpy.mockRestore();
    expect((await send(registration.api_key, crypto.randomUUID(), appleRequest())).status).toBe(401);
  });

  it("delivers FCM messages once and replays the stored response", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = fcmRequest();
    const first = await sendFcm(registration.api_key, key, { ...body });
    const firstText = await first.text();
    expect(first.status).toBe(200);
    const parsed = JSON.parse(firstText) as { status: string; fcm_message_id: string };
    expect(parsed.status).toBe("accepted");
    expect(parsed.fcm_message_id).toMatch(/^accepted-A{8}-\d+$/u);

    const replay = await sendFcm(registration.api_key, key, { ...body });
    expect(replay.status).toBe(200);
    expect(await replay.text()).toBe(firstText);
  });

  it("rejects FCM requests outside the privacy contract", async () => {
    const registration = await register();
    const withTopic = await sendFcm(registration.api_key, crypto.randomUUID(), {
      ...fcmRequest(),
      topic: "org.siloserver.silo",
    });
    expect(withTopic.status).toBe(400);
    expect((await withTopic.json<ErrorEnvelope>()).error.code).toBe("unexpected_field");

    const badToken = await sendFcm(registration.api_key, crypto.randomUUID(), {
      ...fcmRequest(),
      token: "too-short",
    });
    expect(badToken.status).toBe(400);
    expect((await badToken.json<ErrorEnvelope>()).error.code).toBe("invalid_token");
  });

  it("stores terminal FCM unregistered-device responses", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = fcmRequest(FCM_TERMINAL_TOKEN);
    const first = await sendFcm(registration.api_key, key, { ...body });
    const firstText = await first.text();
    expect(first.status).toBe(422);
    const parsed = JSON.parse(firstText) as ErrorEnvelope;
    expect(parsed.error.code).toBe("fcm_rejected");
    expect(parsed.error.message).toContain("UNREGISTERED");
    const replay = await sendFcm(registration.api_key, key, { ...body });
    expect(replay.status).toBe(422);
    expect(await replay.text()).toBe(firstText);
  });

  it("allows the same key to retry a definitive FCM 5xx", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = fcmRequest(FCM_RETRY_TOKEN);
    const first = await sendFcm(registration.api_key, key, { ...body });
    expect(first.status).toBe(503);
    expect((await first.json<ErrorEnvelope>()).error.code).toBe("upstream_unavailable");
    const second = await sendFcm(registration.api_key, key, { ...body });
    expect(second.status).toBe(200);
  });

  it("classifies FCM sender mismatches as configuration failures", async () => {
    const registration = await register();
    const response = await sendFcm(registration.api_key, crypto.randomUUID(), {
      ...fcmRequest(FCM_CONFIGURATION_TOKEN),
    });
    expect(response.status).toBe(502);
    const parsed = await response.json<ErrorEnvelope>();
    expect(parsed.error.code).toBe("upstream_auth_error");
    expect(parsed.error.message).toContain("SENDER_ID_MISMATCH");
    expect(response.headers.get("retry-after")).toBe("60");
  });

  it("refreshes a rejected Google access token and resends once", async () => {
    const registration = await register();
    const response = await sendFcm(registration.api_key, crypto.randomUUID(), {
      ...fcmRequest(FCM_EXPIRED_AUTH_TOKEN),
    });
    expect(response.status).toBe(200);
    expect(await response.json<{ status: string; fcm_message_id: string }>()).toEqual({
      status: "accepted",
      fcm_message_id: `accepted-${FCM_EXPIRED_AUTH_TOKEN.slice(0, 8)}-2`,
      request_id: expect.any(String),
    });
  });

  it("keeps FCM sends compatible with capabilities issued before the fcm:send scope", async () => {
    const registration = await register();
    const claims = newCapabilityClaims(env, registration.deployment_id, 1);
    claims.scope = claims.scope.filter((scope) => scope !== "fcm:send");
    const legacyCapability = await signCapability(env, claims);
    const response = await sendFcm(legacyCapability, crypto.randomUUID(), fcmRequest());
    expect(response.status).toBe(200);
  });

  it("shares device rate limits across a hashed FCM token", async () => {
    const registration = await register();
    const deviceToken = `${"F".repeat(139)}1`;
    for (let delivery = 0; delivery < 30; delivery += 1) {
      expect(
        (await sendFcm(registration.api_key, crypto.randomUUID(), fcmRequest(deviceToken))).status,
      ).toBe(200);
    }
    const limited = await sendFcm(registration.api_key, crypto.randomUUID(), fcmRequest(deviceToken));
    expect(limited.status).toBe(429);
    expect((await limited.json<ErrorEnvelope>()).error.code).toBe("device_rate_limited");
  });
});
