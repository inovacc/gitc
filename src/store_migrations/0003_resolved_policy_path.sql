-- SEC-2: record the enforcement policy path that was in effect for each audited
-- invocation, so a policy relocation (e.g. an agent pointing gitc at a weaker
-- per-user policy) is forensically visible in the log. Metadata only — not part
-- of the tamper-evident hash chain yet (that folds into the H-36 HMAC rework).
ALTER TABLE audit_log ADD COLUMN resolved_policy_path TEXT;
