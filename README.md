# Silo Push Relay

Silo Push Relay lets a self-hosted Silo Server wake the Silo app when something
needs its attention. It provides the small piece of shared infrastructure needed
to reach platform push services without putting Silo's provider credentials on
every self-hosted server.

The relay is not a store for notifications and does not carry your notification
content. Your library activity, media names, notification titles and bodies,
user names, profile names, and server address stay between your Silo Server and
your devices.

## How it works

1. A Silo Server registers with the relay and receives an opaque deployment ID
   and a signed, expiring capability.
2. When the app needs to be notified, the server sends an authenticated,
   content-free delivery request. The relay accepts only the fields required to
   route and safely deduplicate that request.
3. The relay validates and rate-limits the request, constructs a fixed generic
   push, and forwards it to Apple Push Notification service (APNs).
4. APNs delivers either a generic **New notification available** alert or a
   background wake. The actual notification content is never sent through the
   relay.

Delivery requests are idempotent. This allows a Silo Server to retry safely
without intentionally sending the same push more than once, including when an
upstream response is uncertain.

## Privacy by design

The relay is intentionally unable to accept arbitrary notification payloads.
Unknown fields are rejected, so a server cannot accidentally include a title,
message body, media name, user identity, or server URL.

To deliver a push, the relay briefly processes:

- the IP address the self-hosted Silo Server uses to contact the relay, for
  abuse prevention and rate limiting;
- an opaque deployment ID and signed capability;
- the APNs device token, environment, and app topic;
- opaque device and delivery IDs; and
- the delivery mode and optional badge or collapse identifier.

The APNs device token and raw delivery request are used only while handling the
request. The relay application does not persist or log them. The server IP is
not placed in relay application storage or application logs.

The relay persists only the minimum state needed to operate safely:

- an opaque deployment's active or revoked status and credential generation;
- short-lived idempotency and credential-rotation records; and
- a one-way hash of each delivery request plus its redacted delivery outcome.

Short-lived coordination records have a 24-hour retention period and are then
automatically deleted. Operational events may contain a random request ID, an
opaque deployment ID, an error category, or a rate-limit result, but not device
tokens or notification content.

The relay does not have Silo user accounts, does not know who a device belongs
to, and does not use relay traffic for advertising, profiling, or analytics.
APNs necessarily receives the device token and fixed generic payload in order to
deliver the push; Cloudflare processes relay traffic at the network edge where
the service runs.
