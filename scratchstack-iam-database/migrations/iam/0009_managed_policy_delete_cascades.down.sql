ALTER TABLE iam.role_attached_policies
    DROP CONSTRAINT role_attached_policies_managed_policy_id_fkey;
ALTER TABLE iam.role_attached_policies
    ADD CONSTRAINT role_attached_policies_managed_policy_id_fkey
        FOREIGN KEY (managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id)
        ON DELETE CASCADE;

ALTER TABLE iam.managed_policy_versions
    DROP CONSTRAINT fk_mpv_mp_id;
ALTER TABLE iam.managed_policy_versions
    ADD CONSTRAINT fk_mpv_mp_id
        FOREIGN KEY (managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id);
