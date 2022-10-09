-- Remove PKs from history tables
ALTER TABLE iam.deleted_iam_group
DROP CONSTRAINT IF EXISTS pk_deleted_iam_group;

ALTER TABLE iam.deleted_iam_role
DROP CONSTRAINT IF EXISTS pk_deleted_iam_role;

ALTER TABLE iam.deleted_iam_user
DROP CONSTRAINT IF EXISTS pk_deleted_iam_user;

ALTER TABLE iam.deleted_managed_policy_version
DROP CONSTRAINT IF EXISTS pk_deleted_managed_policy_version;

ALTER TABLE iam.deleted_managed_policy
DROP CONSTRAINT IF EXISTS pk_deleted_managed_policy;

ALTER TABLE iam.managed_policy
DROP COLUMN IF EXISTS last_version;

DROP TRIGGER IF EXISTS trig_delete_managed_policy_version ON iam.managed_policy_version;
DROP FUNCTION IF EXISTS iam.on_delete_managed_policy_version;
DROP TABLE IF EXISTS iam.deleted_managed_policy_version;
DROP TABLE IF EXISTS iam.managed_policy_version;
