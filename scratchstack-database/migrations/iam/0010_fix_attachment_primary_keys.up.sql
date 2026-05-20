-- Fix primary keys on attachment tables so each entity can have multiple managed policies
-- attached to it.
--
-- (1) iam.user_attached_policies had (user_id) as PRIMARY KEY, which limited each user to exactly
-- one attached policy. Replace with a composite PK on (user_id, managed_policy_id).
--
-- (2) iam.group_attached_policies had no primary key at all, so duplicate attachments were
-- possible. Add a composite PK on (group_id, managed_policy_id).
ALTER TABLE iam.user_attached_policies
    DROP CONSTRAINT user_attached_policies_pkey;
ALTER TABLE iam.user_attached_policies
    ADD CONSTRAINT user_attached_policies_pkey
        PRIMARY KEY (user_id, managed_policy_id);

ALTER TABLE iam.group_attached_policies
    ADD CONSTRAINT group_attached_policies_pkey
        PRIMARY KEY (group_id, managed_policy_id);
