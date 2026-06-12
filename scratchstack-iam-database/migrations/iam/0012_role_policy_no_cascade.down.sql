-- Restore ON DELETE CASCADE on the role_id foreign keys for role_attached_policies and
-- role_inline_policies.
ALTER TABLE iam.role_attached_policies
    DROP CONSTRAINT role_attached_policies_role_id_fkey;
ALTER TABLE iam.role_attached_policies
    ADD CONSTRAINT role_attached_policies_role_id_fkey
        FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE;

ALTER TABLE iam.role_inline_policies
    DROP CONSTRAINT role_inline_policies_role_id_fkey;
ALTER TABLE iam.role_inline_policies
    ADD CONSTRAINT role_inline_policies_role_id_fkey
        FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE;
