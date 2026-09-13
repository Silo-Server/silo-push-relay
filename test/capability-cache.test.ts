import { env } from "cloudflare:test";
import { describe, expect, it, vi } from "vitest";

import { newCapabilityClaims, signCapability, verifyCapability } from "../src/crypto";

describe("capability verification configuration", () => {
  it("parses unchanged key configuration once for repeated verification", async () => {
    const testEnv = { ...env, CAPABILITY_VERIFY_KEYS_JSON: `${env.CAPABILITY_VERIFY_KEYS_JSON} ` };
    const claims = newCapabilityClaims(env, crypto.randomUUID(), 1);
    const token = await signCapability(env, claims);
    const parseSpy = vi.spyOn(JSON, "parse");
    try {
      for (let index = 0; index < 5; index++) {
        expect(await verifyCapability(testEnv, token)).toEqual(claims);
      }
      expect(parseSpy.mock.calls.filter(([value]) => value === testEnv.CAPABILITY_VERIFY_KEYS_JSON))
        .toHaveLength(1);
    } finally {
      parseSpy.mockRestore();
    }
  });

  it("honors removed and replaced keys immediately after configuration changes", async () => {
    const token = await signCapability(env, newCapabilityClaims(env, crypto.randomUUID(), 1));
    await verifyCapability(env, token);
    await expect(verifyCapability({ ...env, CAPABILITY_VERIFY_KEYS_JSON: "{}" }, token))
      .rejects.toThrow("unknown key id");
    await verifyCapability(env, token);
    await expect(verifyCapability({
      ...env,
      CAPABILITY_VERIFY_KEYS_JSON: JSON.stringify({ [env.CAPABILITY_SIGNING_KEY_ID]: "invalid PEM" }),
    }, token)).rejects.toThrow();
    await expect(verifyCapability(env, token)).resolves.toHaveProperty("ver", 1);
  });

  it.each(["null", "[]", "invalid JSON"])("rejects malformed configuration %s after warming the cache", async (config) => {
    const token = await signCapability(env, newCapabilityClaims(env, crypto.randomUUID(), 1));
    await verifyCapability(env, token);
    await expect(verifyCapability({ ...env, CAPABILITY_VERIFY_KEYS_JSON: config }, token))
      .rejects.toThrow("invalid verification key configuration");
  });
});
