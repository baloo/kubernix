-- Capability-token HMAC secrets -- PLAN.md Phase 14.
--
-- Global, not per-tenant: any frontend replica must be able to verify a token
-- another replica minted, so every replica needs to agree on the same set of
-- secrets rather than each holding its own. `kid` (the row's own serial) is
-- what a token names to select which row it was signed with, so rotating --
-- inserting a new row -- never invalidates a token signed under an older,
-- still-retained one.
--
-- `rotated_out_at` is why retention counts from the moment a secret stops
-- being current, not from when it was minted: the current secret (NULL) is
-- never eligible for deletion no matter how old it is, and once a rotation
-- retires it, it gets its own full retention window from that moment. Aging
-- retention off `created_at` instead would mean a rotator that missed several
-- cycles -- was down, lost its lock, whatever -- could delete the very secret
-- that had been current (and signing real tokens) the whole time, the instant
-- it finally got superseded.
CREATE TABLE capability_secrets (
    kid            BIGSERIAL PRIMARY KEY,
    secret         BYTEA NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_out_at TIMESTAMPTZ
);
