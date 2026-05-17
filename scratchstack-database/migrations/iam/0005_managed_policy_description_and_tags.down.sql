DROP TABLE IF EXISTS iam.managed_policy_tags;
ALTER TABLE iam.managed_policies DROP COLUMN IF EXISTS description;
