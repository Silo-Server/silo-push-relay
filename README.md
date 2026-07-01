# silo-push-relay

A privacy-respecting push-notification relay for the **Silo** apps. It lets
self-hosted Silo servers deliver push notifications to Silo's mobile apps
**without** the app publisher's Apple/Google push credentials ever leaving
Silo's control, and **without** the relay ever seeing who the notification is
for or what it says.

> **Platform support:** Apple push (APNs) for the iOS app is live today.
> Android (FCM) support is planned — the API surface and allowlisting exist,
> but FCM sends currently fail closed with `501 not_implemented`.

## Why this exists

Apple and Google only accept push notifications that are signed with the
**app's** push credentials — the APNs `.p8` key and the Firebase
service-account key that belong to the Silo apps. A self-hosted Silo server has
no way to hold those credentials: they're the app publisher's secrets, and
handing them out would let any server impersonate the app.

The relay is the bridge. It is the single component that holds Silo's official
Apple and Google push credentials and is authorized to sign for the Silo apps.
Opted-in self-hosted Silo servers send it a narrow, content-free request; the
relay signs and forwards it to APNs/FCM on their behalf.

## Privacy model

The relay is designed so that it **cannot** learn the things a naive push proxy
would see:

- **No notification content.** The request carries no title, body, sender,
  message text, or any app payload. The relay builds a fixed, generic
  "content-private" alert or a silent background-wake payload itself.
- **No identities.** No user IDs, profile names, account names, or server URLs
  are sent. The only identifiers are opaque, caller-chosen values
  (`server_device_id`, `delivery_id`).
- **Strict request shapes.** Both send endpoints decode with
  `DisallowUnknownFields` and reject any unexpected field with `400
  unexpected_field`. There is no channel to smuggle extra data through.
- **Device tokens are never stored or logged in the clear.** They are hashed
  (SHA-256) before use in idempotency keys, rate-limit keys, and op-logs.
- **Anonymous onboarding.** A Silo deployment registers itself with, at most,
  an opaque `deployment_id`. No server URL, server name, users, or profiles are
  involved.

Suggested user-facing disclosure:

> If you enable push notifications, your Silo Server sends a content-free
> request to Silo's push relay so Silo can deliver notifications through Apple
> Push Notification service. The relay does not receive notification titles,
> message bodies, media names, user names, profile names, or your server URL. It
> does process technical metadata needed to deliver and operate the service,
> including an opaque deployment identifier, push delivery timing, request
> status, app topic, the IP address your self-hosted Silo Server uses to contact
> the relay, and a hashed device push token. Apple may also process standard
> APNs delivery metadata. Push notifications are generic; the app fetches
> private content directly from your Silo Server after receiving the push.

## How it works

```
Self-hosted Silo server                  silo-push-relay                 Apple / Google
────────────────────────                 ───────────────                 ──────────────
  POST /v1/apple/send        ─────────▶   auth (rk_ key)
   { token, environment,                  rate limit + quota
     topic, mode,                         allowlist check (topic)
     server_device_id,                    idempotency lock
     delivery_id, badge? }                build generic payload  ──────▶  APNs (ES256)
                             ◀─────────    { request_id, apns_id }
```

1. **Register once.** A Silo deployment calls `POST /v1/deployments/register`
   (optionally with an opaque `deployment_id`) and receives a per-deployment
   API key (`rk_…`) exactly once. The relay stores only the key's hash and
   allowlists the app's APNs topic(s) for that deployment.
2. **Send.** For each notification, the Silo server calls `POST /v1/apple/send`
   with a bearer `rk_` key, an `Idempotency-Key` header, the device token, the
   APNs topic, a delivery mode, and opaque IDs.
3. **The relay validates, meters, and signs.** Bearer auth (constant-time,
   with a decoy compare on miss) → per-account + daily-quota + per-device rate
   limiting → topic allowlist → fail-closed idempotency (so a retried send is
   delivered at most once) → generic payload construction → **ES256
   provider-token** signed delivery to APNs, routed to sandbox or production.
4. **The relay returns an opaque result** (`request_id`, `apns_id`, status) and
   writes a redacted op-log entry (hashed token, no content, no identity).

Delivery modes:

- `private_alert` — a generic, content-free visible alert. The app fetches the
  real content over its own authenticated channel.
- `background_wake` — a silent push that wakes the app to sync.

## API surface

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/deployments/register` | Anonymously mint/rotate a per-deployment `rk_` API key; allowlists configured APNs topics. |
| `POST /v1/apple/send` | Sign and forward an APNs push. **Live.** |
| `POST /v1/fcm/send` | FCM shape reservation. **Fail-closed stub** — validates, meters, and allowlist-checks, then returns `501 not_implemented`; no real FCM delivery yet. |
| `GET /healthz` | Liveness — always `200`. |
| `GET /readyz` | Readiness — `503` until PostgreSQL (and Redis) are reachable. |

## Architecture

- **Go service**, stateless on the request path; PostgreSQL for accounts, API
  keys, allowlists, and op-logs, and Redis for rate limiting and idempotency.
- **API keys** are hashed with `HMAC-SHA256(pepper)`; the raw key is shown only
  once at issue/registration time.
- **Rate limiting** is a Redis token bucket (per-account + daily quota + coarse
  per-device) with a bounded in-process fail-open fallback.
- **Idempotency** is fail-closed: an `Idempotency-Key` acquires an NX lock with
  an ownership nonce; replays return the stored response, in-flight duplicates
  get `409`, and a key reused with a different payload gets `422`.
- **`relayctl`** is the admin CLI (account / key / allowlist / migrate); there
  is no public admin HTTP API. Admin actions are audited.
- **Migrations** are embedded Goose SQL migrations.

## Status

**Apple (APNs) delivery and self-service deployment registration are complete.**

- Service skeleton — boots, `/healthz` + `/readyz`, config load/validate
  (hard-fails on bad values), structured JSON logging, graceful shutdown, the
  §5.5 error envelope, ULID request IDs.
- Storage + admin — PostgreSQL schema via embedded Goose migrations; the
  `accounts` data-access layer with `HMAC-SHA256(pepper)` API-key hashing; the
  `relayctl` admin CLI with audited admin actions.
- Request pipeline — bearer auth (constant-time compare with a decoy on miss;
  revoked/expired/disabled → 401; Redis-throttled `last_used_at`; soft per-IP
  brute-force cap; trusted-proxy client-IP resolution); Redis token-bucket rate
  limiting; strict decode + field validation + allowlist enforcement;
  fail-closed idempotency.
- **Apple upstream** — real APNs delivery on `POST /v1/apple/send` with ES256
  provider-token auth, sandbox/production routing, generic content-private
  alert/wake payloads, APNs response mapping, and redacted op logs.
- **Deployment registration** — `POST /v1/deployments/register` mints/rotates a
  per-deployment `rk_` key, stores only the hash, and allowlists the configured
  APNs topics.

**Not yet done:**

- Real **FCM (Android)** upstream delivery. Deferred with it: the shared
  FCM-project circuit breaker (§9.5) and anti-spike smoothing.
- Metrics and the production deploy pipeline.
- `relay_op_logs` partitioning (Decision 6) lands as a dedicated later migration.

## Develop

Commands assume the repository root is the cwd. Requires Go 1.25+ and Docker for
local datastores.

```sh
docker compose up -d   # local PostgreSQL + Redis
export RELAY_DATABASE_URL="postgres://relay:relay@localhost:5432/relay?sslmode=disable"
export RELAY_REDIS_URL="redis://localhost:6379/0"
export RELAY_API_KEY_PEPPER="$(openssl rand -hex 32)"
export RELAY_APNS_TEAM_ID="<Apple Team ID>"
export RELAY_APNS_KEY_ID="<Apple APNs key ID>"
export RELAY_APNS_KEY_PATH="/run/secrets/AuthKey_<key id>.p8"
# optional: export RELAY_APNS_EXPIRATION_TTL="15m"
# optional: export RELAY_REGISTRATION_APNS_TOPICS="org.siloserver.silo"
# optional: export RELAY_TRUSTED_PROXIES="10.0.0.0/8"  # LB CIDRs for client-IP resolution

make build        # compile bin/relay and bin/relayctl
make migrate-up   # apply migrations
make test         # unit + contract tests
make run          # run the relay locally

# admin (writes directly to PostgreSQL; no public admin HTTP API)
./bin/relayctl account create --name "Home Server"
./bin/relayctl key issue --account <id>           # prints the rk_ token once
./bin/relayctl allowlist apns set --account <id> --topics org.siloserver.silo
```

Silo Server can use `Admin -> Settings -> Notifications -> Apple Push ->
Register relay` to mint a per-deployment key. The registration request sends
only an optional opaque `deployment_id`; it does not include the server URL,
server name, users, profiles, or notification content. The relay returns the raw
API key only to that request; subsequent registrations for the same deployment
rotate by issuing a fresh key.

DB-backed tests run only when `RELAY_TEST_DATABASE_URL` is set (skipped
otherwise). `/healthz` is liveness (always 200); `/readyz` reports 503 until
PostgreSQL is reachable. APNs credentials are read from environment/path at
startup; keep `.p8` files out of Git and outside the container image.
