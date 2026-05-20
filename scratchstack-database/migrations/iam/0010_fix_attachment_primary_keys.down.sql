ALTER TABLE iam.group_attached_policies
    DROP CONSTRAINT group_attached_policies_pkey;

ALTER TABLE iam.user_attached_policies
    DROP CONSTRAINT user_attached_policies_pkey;
ALTER TABLE iam.user_attached_policies
    ADD CONSTRAINT user_attached_policies_pkey
        PRIMARY KEY (user_id);
