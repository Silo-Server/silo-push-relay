import { generateKeyPairSync } from "node:crypto";

import { cloudflareTest } from "@cloudflare/vitest-pool-workers";
import { defineConfig } from "vitest/config";

const capabilityKeys = generateKeyPairSync("ed25519");
const capabilityPrivateKey = capabilityKeys.privateKey
  .export({ format: "pem", type: "pkcs8" })
  .toString();
const capabilityPublicKey = capabilityKeys.publicKey
  .export({ format: "pem", type: "spki" })
  .toString();
const apnsKeys = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const apnsPrivateKey = apnsKeys.privateKey.export({ format: "pem", type: "pkcs8" }).toString();
const fcmKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const fcmPrivateKey = fcmKeys.privateKey.export({ format: "pem", type: "pkcs8" }).toString();

const attempts = new Map();

function fcmError(status, googleStatus, errorCode) {
  return new Response(
    JSON.stringify({
      error: {
        code: status,
        message: `test ${errorCode ?? googleStatus}`,
        status: googleStatus,
        details: errorCode
          ? [
              {
                "@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError",
                errorCode,
              },
            ]
          : [],
      },
    }),
    { status, headers: { "content-type": "application/json" } },
  );
}

async function handleFcmRequest(request, url) {
  if (url.host === "oauth2.googleapis.com" && url.pathname === "/token") {
    const form = new URLSearchParams(await request.text());
    if (
      form.get("grant_type") !== "urn:ietf:params:oauth:grant-type:jwt-bearer" ||
      !form.get("assertion")?.includes(".")
    ) {
      return fcmError(400, "INVALID_ARGUMENT");
    }
    const count = (attempts.get("google-oauth") ?? 0) + 1;
    attempts.set("google-oauth", count);
    return new Response(
      JSON.stringify({
        access_token: `test-google-access-token-${count}`,
        expires_in: 3599,
        token_type: "Bearer",
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  }

  if (!/^bearer test-google-access-token-\d+$/iu.test(request.headers.get("authorization") ?? "")) {
    return fcmError(401, "UNAUTHENTICATED");
  }
  if (!url.pathname.endsWith("/projects/siloandroid-a60b9/messages:send")) {
    return fcmError(404, "NOT_FOUND");
  }
  const body = await request.json();
  const message = body?.message;
  const token = message?.token ?? "";
  const count = (attempts.get(token) ?? 0) + 1;
  attempts.set(token, count);

  const dataKeys = Object.keys(message?.data ?? {}).sort();
  if (
    !token ||
    message.notification !== undefined ||
    dataKeys.join(",") !== "silo_delivery_id,silo_mode" ||
    !["HIGH", "NORMAL"].includes(message?.android?.priority) ||
    Object.keys(body).some((field) => field !== "message")
  ) {
    return fcmError(400, "INVALID_ARGUMENT", "INVALID_ARGUMENT");
  }
  if (token === "B".repeat(140)) {
    return fcmError(404, "NOT_FOUND", "UNREGISTERED");
  }
  if (token === "C".repeat(140) && count === 1) {
    return fcmError(503, "UNAVAILABLE", "UNAVAILABLE");
  }
  if (token === "D".repeat(140)) {
    return fcmError(403, "PERMISSION_DENIED", "SENDER_ID_MISMATCH");
  }
  if (token === "E".repeat(140) && count === 1) {
    return fcmError(401, "UNAUTHENTICATED");
  }
  return new Response(
    JSON.stringify({
      name: `projects/siloandroid-a60b9/messages/accepted-${token.slice(0, 8)}-${count}`,
    }),
    { status: 200, headers: { "content-type": "application/json" } },
  );
}

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          CAPABILITY_SIGNING_PRIVATE_KEY_PEM: capabilityPrivateKey,
          CAPABILITY_VERIFY_KEYS_JSON: JSON.stringify({ v1: capabilityPublicKey }),
          APNS_TEAM_ID: "TESTTEAM01",
          APNS_KEY_ID: "TESTKEY001",
          APNS_PRIVATE_KEY_PEM: apnsPrivateKey,
          FCM_CLIENT_EMAIL: "relay-test@siloandroid-a60b9.iam.gserviceaccount.com",
          FCM_PRIVATE_KEY_PEM: fcmPrivateKey,
          ADMIN_TOKEN: "test-admin-token-that-is-not-a-production-secret",
        },
        outboundService: async (request) => {
          const url = new URL(request.url);
          if (["oauth2.googleapis.com", "fcm.googleapis.com"].includes(url.host)) {
            return handleFcmRequest(request, url);
          }
          const token = url.pathname.split("/").at(-1) ?? "";
          const count = (attempts.get(token) ?? 0) + 1;
          attempts.set(token, count);

          if (!request.headers.get("authorization")?.startsWith("bearer ")) {
            return new Response(JSON.stringify({ reason: "MissingProviderToken" }), { status: 403 });
          }
          if (
            request.headers.get("apns-topic") !== "org.siloserver.silo" ||
            !["alert", "background"].includes(request.headers.get("apns-push-type") ?? "")
          ) {
            return new Response(JSON.stringify({ reason: "BadTopic" }), { status: 400 });
          }
          const payload = await request.json();
          if (
            !payload ||
            typeof payload !== "object" ||
            !payload.aps ||
            !payload.silo_delivery_id ||
            Object.keys(payload).some((field) => !["aps", "silo_delivery_id"].includes(field))
          ) {
            return new Response(JSON.stringify({ reason: "BadPayload" }), { status: 400 });
          }
          if (token === "b".repeat(64)) {
            return new Response(JSON.stringify({ reason: "Unregistered" }), {
              status: 410,
              headers: { "apns-id": "terminal-apns-id" },
            });
          }
          if (token === "c".repeat(64) && count === 1) {
            return new Response(JSON.stringify({ reason: "InternalServerError" }), {
              status: 503,
              headers: { "apns-id": "retryable-apns-id", "retry-after": "1" },
            });
          }
          if (token === "d".repeat(64) && count === 1) {
            return new Response(JSON.stringify({ reason: "BadEnvironmentKeyIdInToken" }), {
              status: 403,
              headers: { "apns-id": "configuration-apns-id" },
            });
          }
          if (token === "e".repeat(64) && count === 1) {
            return new Response(JSON.stringify({ reason: "ExpiredProviderToken" }), {
              status: 403,
              headers: { "apns-id": "expired-provider-token-apns-id" },
            });
          }
          return new Response("", {
            status: 200,
            headers: { "apns-id": `accepted-${token.slice(0, 8)}-${count}` },
          });
        },
      },
    }),
  ],
  test: {
    sequence: { concurrent: false },
  },
});
