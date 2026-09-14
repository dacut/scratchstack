-- The authorization path (authz::get_policies_for_user) probes iam.group_memberships by
-- user_id, but the primary key leads with group_id, so that probe would be a sequential
-- scan. Add a covering index led by user_id.
CREATE INDEX ix_igm_userid ON iam.group_memberships(user_id, group_id);
