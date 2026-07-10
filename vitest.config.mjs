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

const attempts = new Map();

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
          ADMIN_TOKEN: "test-admin-token-that-is-not-a-production-secret",
        },
        outboundService: async (request) => {
          const url = new URL(request.url);
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
