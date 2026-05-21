-- Drop ON DELETE CASCADE on the role_id foreign keys for role_attached_policies and
-- role_inline_policies. With CASCADE in place, a plain `DELETE FROM iam.roles` silently strips
-- attachments and inline policies; AWS DeleteRole must instead fail when any of those are still
-- present. After this migration, the DELETE fails with a FK violation (SQLSTATE 23503), which
-- delete_role surfaces as a DeleteConflictException. This mirrors the user-side FK behavior
-- (user_attached_policies / user_inline_policies have never cascaded on user_id).
ALTER TABLE iam.role_attached_policies
    DROP CONSTRAINT role_attached_policies_role_id_fkey;
ALTER TABLE iam.role_attached_policies
    ADD CONSTRAINT role_attached_policies_role_id_fkey
        FOREIGN KEY (role_id) REFERENCES iam.roles(role_id);

ALTER TABLE iam.role_inline_policies
    DROP CONSTRAINT role_inline_policies_role_id_fkey;
ALTER TABLE iam.role_inline_policies
    ADD CONSTRAINT role_inline_policies_role_id_fkey
        FOREIGN KEY (role_id) REFERENCES iam.roles(role_id);
