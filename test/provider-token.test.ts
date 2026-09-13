import { env, runInDurableObject } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";

import { ProviderTokenObject } from "../src/provider-token-object";

describe("provider token refresh", () => {
  it("shares one Google exchange across concurrent requests and persists the result", async () => {
    const stub = env.PROVIDER_TOKENS.getByName("fcm");
    await stub.invalidate((await stub.getToken()).token);
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return Response.json({ access_token: "shared-google-token" });
    });
    try {
      await runInDurableObject(stub, async (instance, state) => {
        const tokens = await Promise.all(Array.from({ length: 20 }, () => instance.getToken()));
        expect(fetchSpy).toHaveBeenCalledTimes(1);
        expect(tokens.every((token) => token.token === "shared-google-token")).toBe(true);
        expect(state.storage.sql.exec("SELECT token FROM provider_token").one().token)
          .toBe("shared-google-token");
        expect(await instance.getToken()).toEqual(tokens[0]);
        const restored = new ProviderTokenObject(state, env);
        expect(await restored.getToken()).toEqual(tokens[0]);
        expect(fetchSpy).toHaveBeenCalledTimes(1);
      });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("shares APNs signing across concurrent requests", async () => {
    const stub = env.PROVIDER_TOKENS.getByName(crypto.randomUUID());
    const signSpy = vi.spyOn(crypto.subtle, "sign");
    try {
      await runInDurableObject(stub, async (instance) => {
        const tokens = await Promise.all(Array.from({ length: 20 }, () => instance.getToken()));
        expect(signSpy).toHaveBeenCalledTimes(1);
        expect(tokens.every((token) => token.token === tokens[0]?.token)).toBe(true);
      });
    } finally {
      signSpy.mockRestore();
    }
  });

  it("releases the Google exchange timeout after consuming the response", async () => {
    const stub = env.PROVIDER_TOKENS.getByName("fcm");
    await stub.invalidate((await stub.getToken()).token);
    let signal: AbortSignal | null | undefined;
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async (_url, init) => {
      signal = init?.signal;
      return Response.json({ access_token: "google-token-with-cleared-timeout" });
    });
    try {
      await runInDurableObject(stub, async (_instance, state) => {
        const instance = new ProviderTokenObject(state, { ...env, FCM_TIMEOUT_MS: "20" });
        expect((await instance.getToken()).token).toBe("google-token-with-cleared-timeout");
        expect(signal).toBeDefined();
        await new Promise((resolve) => setTimeout(resolve, 40));
        expect(signal?.aborted).toBe(false);
      });
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("allows a fresh attempt after a shared refresh fails", async () => {
    const stub = env.PROVIDER_TOKENS.getByName("fcm");
    await stub.invalidate((await stub.getToken()).token);
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      return new Response("", { status: 503 });
    });
    try {
      await runInDurableObject(stub, async (instance, state) => {
        const results = await Promise.allSettled(Array.from({ length: 20 }, () => instance.getToken()));
        expect(results.every((result) => result.status === "rejected")).toBe(true);
        expect(fetchSpy).toHaveBeenCalledTimes(1);
        expect(state.storage.sql.exec("SELECT token FROM provider_token").toArray()).toEqual([]);
        fetchSpy.mockResolvedValue(Response.json({ access_token: "recovered-google-token" }));
        expect((await instance.getToken()).token).toBe("recovered-google-token");
        expect(fetchSpy).toHaveBeenCalledTimes(2);
      });
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
