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
  generation/revocation and the idempotency state machine.
- Cloudflare Rate Limiting bindings provide the abuse backstops; the relay does
  not impose usage quotas or persist rate-limit counters itself.
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

Copy secrets into `.dev.vars` at the repository root for local development.
Never commit that file. The required names are declared in `wrangler.jsonc`.
Keep long-lived source credentials such as the Apple `.p8` outside the checkout;
copy their contents into `.dev.vars` or upload them directly with Wrangler.

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

Production secrets are uploaded with `wrangler secret put <NAME>`.

Cloudflare Rate Limiting bindings enforce deliberately generous abuse ceilings:

- all API writes: 2,000 requests per 10 seconds per source IP;
- deployment registration: 10 per minute per source IP and 100 per minute per
  Cloudflare location;
- authenticated deployment traffic: 1,000 requests per 10 seconds per opaque
  deployment ID; and
- Apple delivery traffic: 30 requests per minute per deployment and hashed
  device token.

These counters are permissive and local to a Cloudflare location, so they are
abuse backstops rather than accounting quotas. Device-token limits remain scoped
to a deployment: a global token key would correlate a device across independent
self-hosted servers and let one hostile server starve another server's
notifications. Rate-limit denials and check failures emit structured events for
Worker observability. Binding failures degrade open so a control-plane problem
does not stop push delivery.

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
  again during the 24-hour idempotency retention window. After that window the
  row may be deleted and a very late retry can dispatch again, so 24 hours is
  the maximum safe automatic retry horizon.
- Durable Object alarms are scheduled only while idempotency or rotation state
  exists. Expirations are coalesced into hourly buckets, cleanup drains bounded
  batches, and an object stops scheduling alarms once its transient state is
  gone. The obsolete `daily_quota` table is removed when an existing deployment
  object next starts under this Worker version.
- Administrative revocations emit a structured audit event containing only the
  request ID and opaque deployment ID.
- Test provider changes on Cloudflare itself; local `workerd` APNs behavior is
  not a substitute for the live HTTP/2 path.
