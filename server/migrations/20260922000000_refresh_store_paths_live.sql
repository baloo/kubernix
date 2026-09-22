-- Fixes a real bug in 20260921000000_trusted_substituters.sql: Postgres
-- expands a view's `SELECT *` into an explicit column list at `CREATE VIEW`
-- time, not dynamically -- so `store_paths_live` (created by
-- `20260814_retention_and_gc.sql`, well before `substituted_from_url`/
-- `substituted_from_key` existed) never picked up those two columns when
-- that migration added them to `store_paths` via `ALTER TABLE`. Every read
-- in `server/src/postgres_store.rs` goes through this view (see its own
-- comment on why), so `find_substituted_by_hash_part_db`/
-- `substituted_source_db` were reading rows with no such column at all --
-- `row.get("substituted_from_url")` doesn't fail gracefully, it panics
-- (`ColumnNotFound`), taking down whichever database-actor task handled
-- that one request.
--
-- `CREATE OR REPLACE VIEW` re-expands `SELECT *` against the table's
-- *current* columns, and Postgres explicitly allows a replacement view to
-- add new trailing columns as long as every existing one keeps its name,
-- order and type -- both true here, since `ALTER TABLE ADD COLUMN` only
-- ever appends. This preserves the view's OID, its grants
-- (`GRANT SELECT ON store_paths_live ...`), and RLS-relevant behavior
-- without needing to re-issue any of that -- only `security_invoker` is
-- re-asserted below, out of caution rather than known necessity.
CREATE OR REPLACE VIEW store_paths_live AS
    SELECT * FROM store_paths WHERE state = 'live';

ALTER VIEW store_paths_live SET (security_invoker = true);
