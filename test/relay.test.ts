import { env, runInDurableObject, SELF } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";

import { sendToAPNs } from "../src/apns";
import { canonicalAppleHash, newCapabilityClaims, signCapability } from "../src/crypto";
import type { AppleSendRequest } from "../src/types";

const ACCEPT_TOKEN = "a".repeat(64);
const TERMINAL_TOKEN = "b".repeat(64);
const RETRY_TOKEN = "c".repeat(64);
const CONFIGURATION_TOKEN = "d".repeat(64);

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
    const replay = await send(registration.api_key, key, body);
    expect(replay.status).toBe(422);
    expect(await replay.text()).toBe(firstText);
  });

  it("surfaces APNs environment key mismatches as non-retryable configuration errors", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = appleRequest(CONFIGURATION_TOKEN);
    const first = await send(registration.api_key, key, body);
    const firstText = await first.text();
    const parsed = JSON.parse(firstText) as { error: { code: string; message: string } };

    expect(first.status).toBe(502);
    expect(parsed.error.code).toBe("upstream_auth_error");
    expect(parsed.error.message).toContain("BadEnvironmentKeyIdInToken");

    const replay = await send(registration.api_key, key, body);
    expect(replay.status).toBe(502);
    expect(await replay.text()).toBe(firstText);
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

  it("converts abandoned dispatches to unknown instead of resending", async () => {
    const registration = await register();
    const key = crypto.randomUUID();
    const body = appleRequest();
    const payloadHash = await canonicalAppleHash(body);
    const stub = env.DEPLOYMENTS.getByName(registration.deployment_id);
    await runInDurableObject(stub, (_instance, state) => {
      const stale = Math.floor(Date.now() / 1000) - 31;
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

  it("revokes a deployment immediately", async () => {
    const registration = await register();
    const revoked = await SELF.fetch("https://relay.test/v1/deployments/revoke", {
      method: "POST",
      headers: { authorization: `Bearer ${registration.api_key}`, "content-type": "application/json" },
      body: "{}",
    });
    expect(revoked.status).toBe(200);
    expect((await send(registration.api_key, crypto.randomUUID(), appleRequest())).status).toBe(401);
  });

  it("supports an independently authenticated administrative revocation", async () => {
    const registration = await register();
    const revoked = await SELF.fetch("https://relay.test/v1/admin/deployments/revoke", {
      method: "POST",
      headers: {
        authorization: "Bearer test-admin-token-that-is-not-a-production-secret",
        "content-type": "application/json",
      },
      body: JSON.stringify({ deployment_id: registration.deployment_id }),
    });
    expect(revoked.status).toBe(200);
    expect((await send(registration.api_key, crypto.randomUUID(), appleRequest())).status).toBe(401);
  });
});
