# Repository Guidelines

## Project Structure & Module Organization

This is the production Cloudflare Worker behind `push.siloserver.org`. Code lives in `src/`: `index.ts` defines routes, `deployment-object.ts` owns per-deployment state and quotas, and `provider-token-object.ts` signs APNs provider tokens. Supporting logic is split across `apns.ts`, `crypto.ts`, and `validation.ts`. Worker configuration and Durable Object migrations are in `wrangler.jsonc`. Integration tests and fixtures live in `test/` and `vitest.config.mjs`. The retired Go service remains on `legacy/go-relay`.

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

Tests use Vitest with `@cloudflare/vitest-pool-workers`; name files `*.test.ts` under `test/`. Add regression coverage for changes to routes, validation, APNs response mapping, quotas, idempotency, or Durable Object alarms. Tests run sequentially because fixtures share Worker and Durable Object state. There is no numeric coverage threshold, but new behavior and failure modes should be exercised.

## Commit & Pull Request Guidelines

Recent commits use short, imperative subjects such as `Optimize Durable Object cleanup scheduling`; scoped prefixes such as `fix:` are also accepted. Keep each commit focused. Pull requests should explain the behavior change, privacy or delivery risks, configuration impact, and commands run. Link relevant issues when available. For this API-only project, include request/response examples instead of screenshots.

## Security & Configuration Tips

Never commit `.dev.vars`, `.env*`, PEM or `.p8` keys, device tokens, raw capabilities, notification content, user identities, or server URLs. Reject unknown request fields, hash device tokens before persistence or logging, and treat ambiguous APNs transport failures as delivery-unknown rather than safe to retry.
