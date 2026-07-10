# Cloudflare Worker relay

This repository contains the production PostgreSQL/Redis-free relay running at
[`push.siloserver.org`](https://push.siloserver.org/healthz). The retired Go,
PostgreSQL, and Redis implementation is preserved on the
[`legacy/go-relay`](https://github.com/Silo-Server/silo-push-relay/tree/legacy/go-relay)
branch.

## Runtime shape

- The edge Worker strictly validates requests and verifies Ed25519 capability
  JWTs without an account lookup.
- One SQLite-backed `DeploymentObject` per deployment owns credential
  generation/revocation, durable daily quota, and the idempotency state
  machine.
- A singleton `ProviderTokenObject` is the only component that signs APNs
  provider JWTs. Deployment objects cache its result in memory.
- No device token, notification content, raw capability, user identity, or
  server URL is persisted. Idempotency rows contain only a canonical request
  hash and the redacted relay response.

## Development

```sh
pnpm install
pnpm run check
pnpm test
pnpm dev
```

Copy secrets into `worker/.dev.vars` for local development. Never commit that
file. The required names are declared in `wrangler.jsonc`.

Generate capability keys:

```sh
openssl genpkey -algorithm Ed25519 -out capability-private.pem
openssl pkey -in capability-private.pem -pubout -out capability-public.pem
```

Set `CAPABILITY_SIGNING_PRIVATE_KEY_PEM` to the private PEM. Set
`CAPABILITY_VERIFY_KEYS_JSON` to a JSON object whose key matches
`CAPABILITY_SIGNING_KEY_ID`, for example `{"v1":"<public PEM>"}`. Retain old
public keys in that JSON during signing-key rotations until all capabilities
they signed have expired.

`APNS_PRIVATE_KEY_PEM` accepts the existing Apple `.p8` PKCS#8 PEM contents.

Production secrets are uploaded with `wrangler secret put <NAME>`. Configure a
Cloudflare WAF rate-limit rule for `POST /v1/deployments/register` before
directing public traffic at the Worker.

## Deployment

Pull requests and pushes to `main` run type checks, the Worker test suite, and
a Wrangler dry-run bundle. After those checks pass on `main`, GitHub Actions
deploys the exact commit to Cloudflare and verifies
`https://push.siloserver.org/healthz`.

The `production` GitHub environment must contain:

- `CLOUDFLARE_API_TOKEN` — a narrowly scoped Cloudflare Workers deployment
  token for the Silo account and `siloserver.org` zone.
- `CLOUDFLARE_ACCOUNT_ID` — the target Cloudflare account ID.

Runtime secrets such as the APNs `.p8` remain in Cloudflare and are not copied
into GitHub. Wrangler preserves existing encrypted Worker secrets during code
deployments.

## Migration safety

- New registrations always create a fresh deployment ID. Caller-selected IDs
  are rejected so an unauthenticated request cannot rotate another server.
- `renew`, `rotate`, and `revoke` require a signed capability. Rotation also
  requires an `Idempotency-Key` and can replay its metadata without storing the
  bearer token.
- Silo Server must use one stable idempotency key across all retries. A stale
  `dispatching` row becomes `delivery_unknown` and is never automatically sent
  again.
- Test provider changes on Cloudflare itself; local `workerd` APNs behavior is
  not a substitute for the live HTTP/2 path.
