-- A per-tenant tightening knob: refuse an AddToStoreNar push outright when
-- it carries no content address, instead of accepting it into
-- Tier::Quarantined. Defaults to TRUE — quarantine is a narrow
-- accommodation (round-tripping an input-addressed build closure through
-- `nix copy`), not the baseline expectation, so a tenant opts into it
-- rather than out of the stricter behavior.
ALTER TABLE tenants
    ADD COLUMN reject_unverified_pushes BOOLEAN NOT NULL DEFAULT TRUE;
