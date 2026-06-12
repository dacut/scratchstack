-- Adjust foreign-key cascade behavior on managed_policies references so that DeletePolicy can
-- proceed exactly as AWS IAM specifies it.
--
-- (1) iam.managed_policy_versions(managed_policy_id) was created without ON DELETE CASCADE. AWS
-- DeletePolicy implicitly removes the (only) remaining version along with the policy, so the FK
-- needs to cascade in order for a single DELETE on iam.managed_policies to take everything with it.
--
-- (2) iam.role_attached_policies(managed_policy_id) was created with ON DELETE CASCADE, which would
-- silently strip role attachments when a policy is deleted. AWS DeletePolicy must instead fail
-- when the policy is attached to any role/user/group, so the FK is rebuilt without CASCADE to act
-- as a backstop alongside the explicit attachment check. (The role_id FK retains ON DELETE
-- CASCADE: deleting a role still drops its attachment rows.)
ALTER TABLE iam.managed_policy_versions
    DROP CONSTRAINT fk_mpv_mp_id;
ALTER TABLE iam.managed_policy_versions
    ADD CONSTRAINT fk_mpv_mp_id
        FOREIGN KEY (managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id)
        ON DELETE CASCADE;

ALTER TABLE iam.role_attached_policies
    DROP CONSTRAINT role_attached_policies_managed_policy_id_fkey;
ALTER TABLE iam.role_attached_policies
    ADD CONSTRAINT role_attached_policies_managed_policy_id_fkey
        FOREIGN KEY (managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id);
