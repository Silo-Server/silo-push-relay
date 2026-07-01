-- +goose Up

-- relay_accounts: one per opt-in self-hosted installation.
CREATE TABLE relay_accounts (
    id          text        PRIMARY KEY,                 -- ULID
    name        text        NOT NULL,                    -- operator-facing label
    status      text        NOT NULL DEFAULT 'active'
                CHECK (status IN ('active','disabled')),
    note        text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

-- relay_api_keys: revocable bearer keys (rk_ prefix). Secret never stored.
CREATE TABLE relay_api_keys (
    id            text        PRIMARY KEY,               -- ULID
    account_id    text        NOT NULL REFERENCES relay_accounts(id) ON DELETE CASCADE,
    key_prefix    text        NOT NULL,                  -- non-secret, indexed lookup handle (e.g. rk_live_3Qw9XYZ)
    key_hash      bytea       NOT NULL,                  -- HMAC-SHA256(pepper, secret), 32 bytes
    env           text        NOT NULL DEFAULT 'live'
                  CHECK (env IN ('live','test')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at  timestamptz,                           -- throttled write (<= 1/min)
    expires_at    timestamptz,                           -- optional
    revoked_at    timestamptz                            -- non-null = revoked
);
CREATE UNIQUE INDEX relay_api_keys_prefix_uidx ON relay_api_keys (key_prefix);
CREATE INDEX        relay_api_keys_account_idx  ON relay_api_keys (account_id);

-- relay_apns_allowlist: which APNs topics an account may push to.
CREATE TABLE relay_apns_allowlist (
    account_id  text        NOT NULL REFERENCES relay_accounts(id) ON DELETE CASCADE,
    topic       text        NOT NULL,                    -- e.g. com.continuum.app.ios
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, topic)
);

-- relay_fcm_allowlist: which (project, package) pairs an account may push to.
CREATE TABLE relay_fcm_allowlist (
    account_id    text        NOT NULL REFERENCES relay_accounts(id) ON DELETE CASCADE,
    project_id    text        NOT NULL,                  -- e.g. continuum-prod-android
    package_name  text        NOT NULL,                  -- e.g. com.continuum.app.android
    created_at    timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, project_id, package_name)
);

-- relay_op_logs: redacted operational/audit log. No tokens, no content.
-- `actor` is added vs spec §8.1's column list to satisfy §5.6 (relayctl
-- operations are audited "with the operator identity"). Decision 6 (daily RANGE
-- partitioning + partition-drop retention) lands as a dedicated later migration;
-- v1 ships this plain table so migrations run on stock PostgreSQL.
CREATE TABLE relay_op_logs (
    id              bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    account_id      text        REFERENCES relay_accounts(id) ON DELETE SET NULL,
    request_id      text,                                -- ULID echoed to caller
    event           text        NOT NULL,                -- e.g. send.apns, auth.reject, admin.key_issue
    actor           text,                                -- operator identity for admin.* events
    provider        text,                                -- 'apns' | 'fcm' | null
    outcome         text,                                -- 'accepted' | 'rejected' | 'upstream_error' | ...
    status_code     int,                                 -- caller-facing HTTP status
    error_code      text,                                -- caller-facing error.code
    upstream_reason text,                                -- APNs reason / FCM status (non-sensitive)
    token_hash      text,                                -- SHA-256(token) hex, NOT the raw token
    egress_ip       inet,                                -- caller egress IP
    latency_ms      int
);
CREATE INDEX relay_op_logs_account_time_idx ON relay_op_logs (account_id, occurred_at DESC);
CREATE INDEX relay_op_logs_time_idx         ON relay_op_logs (occurred_at DESC);

-- +goose Down
DROP TABLE relay_op_logs;
DROP TABLE relay_fcm_allowlist;
DROP TABLE relay_apns_allowlist;
DROP TABLE relay_api_keys;
DROP TABLE relay_accounts;
