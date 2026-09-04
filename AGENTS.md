# Repository Guidelines

## Project Structure & Module Organization

This is the production Cloudflare Worker behind `push.siloserver.org`. Code lives in `src/`: `index.ts` defines routes, `deployment-object.ts` owns per-deployment rotation, revocation, and idempotency, and `provider-token-object.ts` signs APNs provider tokens and mints Google OAuth access tokens for FCM. Supporting logic is split across `apns.ts`, `fcm.ts`, `crypto.ts`, and `validation.ts`. Worker configuration and Durable Object migrations are in `wrangler.jsonc`. Integration tests and fixtures live in `test/` and `vitest.config.mjs`. The retired Go service remains on `legacy/go-relay`.

## Architecture

- `src/index.ts` and `src/config.ts` own the public HTTP surface and capability
  authentication.
- Cloudflare Rate Limiting bindings own ingress, registration, deployment, and
  per-device abuse throttling; there is no daily usage quota.
- `DeploymentObject` owns per-deployment rotation, revocation, and fail-closed
  idempotency in Durable Object SQLite.
- `ProviderTokenObject` caches upstream credentials per provider instance:
  `"apns"` signs provider JWTs and `"fcm"` exchanges a service-account assertion
  for a Google OAuth access token.
- `src/apns.ts` and `src/fcm.ts` build fixed content-private payloads and map
  upstream responses into one shared result shape.
- Production runs at `push.siloserver.org`; `workers.dev` and preview URLs are
  disabled in `wrangler.jsonc`.

## Build, Test, and Development Commands

- `pnpm install --frozen-lockfile` installs pinned dependencies.
- `pnpm run check` type-checks both `src/` and `test/` without emitting files.
- `pnpm test` runs the Vitest Worker suite once; `pnpm run test:watch` reruns tests during development.
- `pnpm dev` starts a local Wrangler session using values from `.dev.vars`.
- `pnpm exec wrangler deploy --dry-run` verifies the production bundle without publishing it.

Run `pnpm run check`, `pnpm test`, and the Wrangler dry run before opening a pull request. Use `pnpm run deploy` only when explicitly authorized to publish production.

## Coding Style & Naming Conventions

Use strict TypeScript and ES modules. Match the existing style: two-space indentation, double quotes, semicolons, trailing commas in multiline constructs, `camelCase` functions and variables, `PascalCase` classes and interfaces, and `UPPER_SNAKE_CASE` constants. File names use lowercase kebab case, such as `provider-token-object.ts`. No formatter or linter is configured, so match adjacent code and rely on `tsc` plus review.

## Testing Guidelines

Tests use Vitest with `@cloudflare/vitest-pool-workers`; name files `*.test.ts` under `test/`. Add regression coverage for changes to routes, validation, APNs response mapping, rate limits, idempotency, or Durable Object alarms. Tests run sequentially because fixtures share Worker and Durable Object state. There is no numeric coverage threshold, but new behavior and failure modes should be exercised.

## Writing

Before submitting human-facing prose, make a final readability pass. Lead with
the outcome, use concrete plain language and active voice, and cut filler, stock
framing, repetition, and promotional claims. Preserve the original meaning,
evidence, citations, uncertainty, and terminology. Never rewrite exact quotes,
commands, logs, identifiers, API names, or contractual language. Match the
audience and use formatting only when it improves readability.

## Pull requests

- Never create a pull request unless the developer explicitly asks you to do so.
- Use a Conventional Commit title in plain language. Keep one concern per pull
  request; if the description needs “also,” split it.
- Start the body with the problem, then explain the solution. Include privacy or
  delivery risks, configuration impact, commands run, and representative
  request/response examples. Link the relevant issue when one exists.
- End with the required AI disclosure, including the exact model and
  harness/tooling that did the work.
- Upload review evidence to GitHub. Never commit pull-request-only screenshots,
  recordings, or assets such as `.github/pr-assets/`.
- When babysitting a pull request, poll checks and comments newer than the last
  push. Verify every bot finding against the source, fix real findings, and
  dismiss false positives with a written reason. Stay quiet when nothing is new
  and stop when the latest commit is green.

## Security & Configuration Tips

- Never accept, store, or log notification content, user identities, server
  URLs, raw bearer capabilities, or plaintext device tokens.
- Reject unknown request fields; this is the anti-smuggling boundary.
- Hash device tokens before storage, logging, idempotency, or rate-limit use.
- Treat ambiguous transport failures as delivery-unknown, never as safe to
  resend.
- Never commit `.dev.vars`, `.env*`, PEM or `.p8` keys, APNs keys, Cloudflare
  credentials, or provider secrets. Runtime secrets live in Cloudflare; CI gets
  only the narrowly scoped deployment token and account ID through the
  branch-selected GitHub `development` or `production` environment.
