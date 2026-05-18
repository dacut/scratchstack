-- Denormalize the "most recent version's created_at" onto the managed_policies row so list/get
-- queries don't need a per-row sub-query against managed_policy_versions.
ALTER TABLE iam.managed_policies
    ADD COLUMN update_date TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP;
COMMENT ON COLUMN iam.managed_policies.update_date IS
    'Timestamp of the most recent policy version''s creation. Maintained by CreatePolicy, '
    'CreatePolicyVersion, and (when the deleted version was the latest) DeletePolicyVersion.';

UPDATE iam.managed_policies mp
SET update_date = COALESCE(
    (SELECT MAX(created_at) FROM iam.managed_policy_versions WHERE managed_policy_id = mp.managed_policy_id),
    mp.created_at);
