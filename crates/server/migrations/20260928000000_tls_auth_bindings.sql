-- Allow `tls` bindings: a row describes a trusted client CA, keyed by its
-- Subject Key Identifier (lowercase hex), with the DER certificate in
-- `key_value`. `kubernix-mtlsd` builds its client trust store from these rows.
ALTER TABLE tenant_auth_bindings
    DROP CONSTRAINT IF EXISTS tenant_auth_bindings_key_type_check;
ALTER TABLE tenant_auth_bindings
    ADD CONSTRAINT tenant_auth_bindings_key_type_check
    CHECK (key_type IN ('ssh', 'tls'));
