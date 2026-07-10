import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";

import { sendToAPNs } from "../src/apns";
import { canonicalAppleHash, newCapabilityClaims, signCapability } from "../src/crypto";
import type { AppleSendRequest } from "../src/types";

const ACCEPT_TOKEN = "a".repeat(64);
const TERMINAL_TOKEN = "b".repeat(64);
const RETRY_TOKEN = "c".repeat(64);
const CONFIGURATION_TOKEN = "d".repeat(64);
const EXPIRED_PROVIDER_TOKEN = "e".repeat(64);

interface ErrorEnvelope {
  error: {
    code: string;
    message: string;
    request_id: string;
    apns_id?: string;
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

async function register(body: Record<string, unknown> = {}): Promise<Registration> {
  const response = await SELF.fetch("https://relay.test/v1/deployments/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
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

  it("allows the same key to retry a definitive APNs 5xx", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = appleRequest(RETRY_TOKEN);
    const first = await send(registration.api_key, key, body);
    expect(first.status).toBe(503);
    expect((await first.json<ErrorEnvelope>()).error.apns_id).toBe("retryable-apns-id");
    const second = await send(registration.api_key, key, body);
    expect(second.status).toBe(200);
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
        apnsId: "legacy-configuration-apns-id",
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
          apnsId: `${reason}-apns-id`,
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
        apnsId: "",
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
        apnsId: "bad-priority-apns-id",
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
        apnsId: "",
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
    expect((await response.json<{ status: string }>()).status).toBe("accepted");
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
         (key, payload_hash, state, nonce, created_at, updated_at)
         VALUES (?, ?, 'dispatching', ?, ?, ?)`,
        key,
        payloadHash,
        crypto.randomUUID(),
        stale,
        stale,
      );
    });

    const response = await send(registration.api_key, key, body);
    expect(response.status).toBe(409);
    expect((await response.json<{ error: { code: string } }>()).error.code).toBe("delivery_unknown");
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
         (key, payload_hash, state, nonce, created_at, updated_at)
         VALUES (?, ?, 'dispatching', ?, ?, ?)`,
        key,
        payloadHash,
        crypto.randomUUID(),
        now,
        now,
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

  it("enforces account, device, and daily push limits", async () => {
    const accountRegistration = await register();
    const accountKey = crypto.randomUUID();
    const accountBody = appleRequest("1".repeat(64));
    expect((await send(accountRegistration.api_key, accountKey, accountBody)).status).toBe(200);
    for (let replay = 0; replay < 3; replay += 1) {
      expect((await send(accountRegistration.api_key, accountKey, accountBody)).status).toBe(200);
    }
    const accountLimited = await send(accountRegistration.api_key, accountKey, accountBody);
    expect(accountLimited.status).toBe(429);
    expect((await accountLimited.json<ErrorEnvelope>()).error.code).toBe("rate_limited");

    const deviceRegistration = await register();
    const deviceToken = "2".repeat(64);
    expect(
      (
        await send(
          deviceRegistration.api_key,
          crypto.randomUUID(),
          appleRequest(deviceToken),
        )
      ).status,
    ).toBe(200);
    const deviceLimited = await send(
      deviceRegistration.api_key,
      crypto.randomUUID(),
      appleRequest(deviceToken),
    );
    expect(deviceLimited.status).toBe(429);
    expect((await deviceLimited.json<ErrorEnvelope>()).error.message).toContain("device");

    const quotaRegistration = await register();
    expect(
      (
        await send(
          quotaRegistration.api_key,
          crypto.randomUUID(),
          appleRequest("3".repeat(64)),
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await send(
          quotaRegistration.api_key,
          crypto.randomUUID(),
          appleRequest("4".repeat(64)),
        )
      ).status,
    ).toBe(200);
    const quotaLimited = await send(
      quotaRegistration.api_key,
      crypto.randomUUID(),
      appleRequest("5".repeat(64)),
    );
    expect(quotaLimited.status).toBe(429);
    expect((await quotaLimited.json<ErrorEnvelope>()).error.message).toContain("daily quota");
  });

  it("meters credential rotation with the deployment account bucket", async () => {
    const registration = await register();
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    await runInDurableObject(stub, (instance) => {
      const issuedAt = Math.floor(Date.now() / 1000);
      let generation = 1;
      for (let rotation = 0; rotation < 4; rotation += 1) {
        const result = instance.prepareRotation(
          generation,
          crypto.randomUUID(),
          issuedAt,
          issuedAt + 3600,
        );
        expect(result.ok).toBe(true);
        generation += 1;
      }
      const limited = instance.prepareRotation(
        generation,
        crypto.randomUUID(),
        issuedAt,
        issuedAt + 3600,
      );
      expect(limited).toMatchObject({ ok: false, reason: "rate_limited" });
      expect(limited.retryAfterSeconds).toBeGreaterThan(0);
    });
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
          created_at, updated_at)
         SELECT 'expired-' || value, 'hash', 'done', NULL, 200, '{}', '{}', ?, ?
         FROM sequence`,
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
         (key, payload_hash, state, nonce, created_at, updated_at)
         VALUES ('expired-dispatch', 'hash', 'dispatching', 'nonce', ?, ?)`,
        expired,
        expired,
      );
      state.storage.sql.exec(
        `INSERT INTO idempotency
         (key, payload_hash, state, nonce, created_at, updated_at)
         VALUES ('recent-dispatch', 'hash', 'dispatching', 'nonce', ?, ?)`,
        now - 61,
        now - 61,
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
          created_at, updated_at)
         VALUES ('last-expired', 'hash', 'done', NULL, 200, '{}', '{}', ?, ?)`,
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

  it("cleans historical quota rows on the next new delivery", async () => {
    const registration = await register();
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    await runInDurableObject(stub, (_instance, state) => {
      state.storage.sql.exec(
        "INSERT INTO daily_quota (day, count) VALUES ('2000-01-01', 1)",
      );
    });

    expect(
      (await send(registration.api_key, crypto.randomUUID(), appleRequest("9".repeat(64)))).status,
    ).toBe(200);
    await runInDurableObject(stub, (_instance, state) => {
      const rows = state.storage.sql
        .exec<{ day: string; count: number }>("SELECT day, count FROM daily_quota")
        .toArray();
      expect(rows).toHaveLength(1);
      expect(rows[0]?.day).toBe(new Date().toISOString().slice(0, 10));
      expect(rows[0]?.count).toBe(1);
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
});
