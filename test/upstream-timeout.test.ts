import { env } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";

import { sendToAPNs } from "../src/apns";
import { sendToFCM } from "../src/fcm";

function send(provider: "apns" | "fcm") {
  const testEnv = { ...env, APNS_TIMEOUT_MS: "20", FCM_TIMEOUT_MS: "20" };
  const request = {
    token: "a".repeat(140),
    mode: "background_wake" as const,
    server_device_id: "test-device",
    delivery_id: "test-delivery",
  };
  const credential = { token: "test-provider-token", issuedAt: Math.floor(Date.now() / 1000) };
  return provider === "apns"
    ? sendToAPNs(testEnv, { ...request, environment: "sandbox", topic: "org.siloserver.silo" }, credential)
    : sendToFCM(testEnv, request, credential);
}

describe.each(["apns", "fcm"] as const)("%s request timeout", (provider) => {
  it("releases the timeout after an early response", async () => {
    let signal: AbortSignal | null | undefined;
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      signal = init?.signal;
      return Response.json({ name: "projects/test/messages/accepted" });
    });
    try {
      expect((await send(provider)).result.kind).toBe("accepted");
      expect(signal).toBeDefined();
      await new Promise((resolve) => setTimeout(resolve, 40));
      expect(signal?.aborted).toBe(false);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("keeps a timed out dispatch delivery-unknown", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation((_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(init.signal?.reason), { once: true });
      }),
    );
    try {
      expect((await send(provider)).result).toEqual({ kind: "unknown", reason: "network_error" });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("releases the timeout after an early transport failure", async () => {
    let signal: AbortSignal | null | undefined;
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      signal = init?.signal;
      throw new Error("connection reset");
    });
    try {
      expect((await send(provider)).result.kind).toBe("unknown");
      expect(signal).toBeDefined();
      await new Promise((resolve) => setTimeout(resolve, 40));
      expect(signal?.aborted).toBe(false);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("keeps the deadline through body consumption and honors the received status", async () => {
    let signal: AbortSignal | null | undefined;
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      signal = init?.signal;
      return new Response(new ReadableStream({
        start(controller) {
          signal?.addEventListener("abort", () => controller.error(signal?.reason), { once: true });
        },
      }), { status: 200 });
    });
    try {
      expect((await send(provider)).result.kind).toBe("accepted");
      expect(signal?.aborted).toBe(true);
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
