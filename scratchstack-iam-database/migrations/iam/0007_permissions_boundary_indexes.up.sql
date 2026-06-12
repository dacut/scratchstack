-- Indexes on the permissions-boundary columns. The PermissionsBoundary filter in ListPolicies
-- runs `managed_policy_id IN (SELECT permissions_boundary_managed_policy_id FROM iam.users/roles
-- WHERE account_id = ? AND permissions_boundary_managed_policy_id IS NOT NULL)`, which scans these
-- columns. Partial indexes keep the index small since most users/roles don't have a permissions
-- boundary.
CREATE INDEX ix_iu_pbmp ON iam.users(account_id, permissions_boundary_managed_policy_id)
    WHERE permissions_boundary_managed_policy_id IS NOT NULL;

CREATE INDEX ix_irole_pbmp ON iam.roles(account_id, permissions_boundary_managed_policy_id)
    WHERE permissions_boundary_managed_policy_id IS NOT NULL;
