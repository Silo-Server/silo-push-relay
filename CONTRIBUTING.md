# Contributing to Silo Push Relay

The [Silo contribution guide](https://github.com/Silo-Server/.github/blob/main/CONTRIBUTING.md)
covers project-wide coordination, focused changes, evidence, AI disclosure, and
pull request expectations. Those requirements apply here; this guide adds the
relay-specific workflow.

## Before you start

Open an [issue](https://github.com/Silo-Server/silo-push-relay/issues) before
changing the public protocol, retained state, privacy guarantees, quotas,
deployment topology, or product behavior. Documentation and narrow fixes can go
straight to a pull request.

Read [README.md](README.md) for the relay's privacy model and [AGENTS.md](AGENTS.md)
for route ownership, security invariants, and coding conventions. Changes must
preserve the content-free payload contract and must not add sensitive values to
storage or logs.

## Development setup

Use Node.js 22 and pnpm 10. Local Wrangler development reads secrets from
`.dev.vars`; never commit that file, device tokens, provider keys, capabilities,
notification content, user identities, or server URLs.

```sh
pnpm install --frozen-lockfile
pnpm dev
```

## Validate your change

Before opening a pull request, run the complete CI gate:

```sh
pnpm install --frozen-lockfile
pnpm run check
pnpm test
pnpm exec wrangler deploy --dry-run
```

Add focused Vitest coverage for changes to routes, validation, provider response
mapping, quotas, idempotency, or Durable Object alarms. A pull request that
changes the API should include representative request and response examples.

## Open the pull request

Use a Conventional Commit title. Explain the behavior change, privacy or
delivery risks, configuration impact, and actual commands run. Read the
[AI-assisted contribution policy](https://github.com/Silo-Server/silo-server/blob/main/docs/ai-contributions.md)
and include its disclosure block.

## Instructions for coding agents

Coding agents must read [AGENTS.md](AGENTS.md) before changing the repository
(`CLAUDE.md` contains additional project context). The organization-wide
contribution guide and AI-assisted contribution policy apply to agent and human
authors equally.
