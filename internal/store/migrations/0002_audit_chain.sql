-- Tamper-evident hash chain (AUD-2).
--
-- Each row records the previous row's hash and its own hash =
-- sha256(prev_hash | field values). Deleting or editing any row breaks the
-- chain, which `git audit --verify` detects. Rows written before this migration
-- have NULL hashes and are treated as legacy (unverifiable) by the verifier.

ALTER TABLE audit_log ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_log ADD COLUMN row_hash  TEXT;
