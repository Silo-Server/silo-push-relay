# CLAUDE.md

This repository is the production Cloudflare Worker push relay for Silo. The
legacy Go/PostgreSQL/Redis implementation lives on `legacy/go-relay`.

## Commands

```sh
pnpm install
pnpm run check
pnpm test
pnpm exec wrangler deploy --dry-run
pnpm run deploy
```

## Architecture

- `src/index.ts` and `src/config.ts` own the public HTTP surface and capability
  authentication.
- Cloudflare Rate Limiting bindings own ingress, registration, deployment, and
  per-device abuse throttling; there is no daily usage quota.
- `DeploymentObject` owns per-deployment rotation, revocation, and fail-closed
  idempotency in Durable Object SQLite.
- `ProviderTokenObject` signs and caches APNs provider JWTs.
- `src/apns.ts` builds fixed content-private payloads and maps APNs responses.
- Production is deployed at `push.siloserver.org`; `workers.dev` and preview
  URLs are disabled in `wrangler.jsonc`.

## Privacy and reliability invariants

- Never accept, store, or log notification content, user identity, server URLs,
  raw bearer capabilities, or plaintext device tokens.
- Reject unknown request fields; this is the anti-smuggling boundary.
- Hash device tokens before storage, logging, idempotency, or rate-limit use.
- Treat ambiguous transport failures as delivery-unknown, never as safe to
  resend.
- Keep APNs keys and Cloudflare credentials out of Git. Runtime secrets live in
  Cloudflare; CI receives only a narrowly scoped deployment token and account
  ID through the GitHub `production` environment.
