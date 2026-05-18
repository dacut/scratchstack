-- iam.users.permissions_boundary_managed_policy_id was incorrectly declared as CHAR(17), which
-- physically pads stored values with trailing spaces. The referenced
-- iam.managed_policies.managed_policy_id is VARCHAR(32); align this column to the same type and
-- strip any pre-existing trailing whitespace introduced by the CHAR(n) storage.
ALTER TABLE iam.users
    ALTER COLUMN permissions_boundary_managed_policy_id TYPE VARCHAR(32)
        USING RTRIM(permissions_boundary_managed_policy_id);
