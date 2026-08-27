//! Tests for the IAM database model and related functionality.
//!
//! The body of each test lives in a submodule under [tests/iam_database/](iam_database/); this
//! file orchestrates a single end-to-end run because the test database is stateful between calls.
#![cfg(feature = "utils")]
#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

use {
    scratchstack_iam_database::{migrate::MIGRATOR, utils::TempDatabase},
    sqlx::{PgPool, raw_sql},
};

#[path = "iam_database/account.rs"]
mod account;
#[path = "iam_database/authz.rs"]
mod authz;
#[path = "iam_database/common.rs"]
mod common;
#[path = "iam_database/group.rs"]
mod group;
#[path = "iam_database/gsk.rs"]
mod gsk;
#[path = "iam_database/partition.rs"]
mod partition;
#[path = "iam_database/policy_attachment.rs"]
mod policy_attachment;
#[path = "iam_database/policy_crud.rs"]
mod policy_crud;
#[path = "iam_database/policy_delete.rs"]
mod policy_delete;
#[path = "iam_database/policy_query.rs"]
mod policy_query;
#[path = "iam_database/role.rs"]
mod role;
#[path = "iam_database/user.rs"]
mod user;

const IAM_DATA: &str = include_str!("iam_database.sql");

/// Test all of the features of the database.
///
/// We do this instead of more granular testing because the database we're running against is typically
/// stateful. Each commented section of the old monolithic test body is now its own subtest function,
/// awaited in order. Besides readability, the split keeps each async function's poll frame small: in
/// debug builds the compiler reserves a stack slot for every awaited future in a function, and the
/// hundreds of sqlx futures here overflow the test thread's stack when awaited from a single function.
#[test_log::test(tokio::test)]
async fn test_database() {
    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    raw_sql(IAM_DATA).execute(&mut *c).await.expect("Failed to load IAM data into database");

    subtest_current_partition(&pool).await;
    subtest_authz(&pool).await;
    subtest_create_account(&pool).await;
    subtest_account_aliases(&pool).await;
    subtest_create_user(&pool).await;
    subtest_tag_untag_user(&pool).await;
    subtest_get_user(&pool).await;
    subtest_list_users(&pool).await;
    subtest_update_user(&pool).await;
    subtest_delete_user_permissions_boundary(&pool).await;
    subtest_put_user_permissions_boundary(&pool).await;
    subtest_put_user_policy(&pool).await;
    subtest_get_user_policy(&pool).await;
    subtest_list_user_policies(&pool).await;
    subtest_delete_user_policy(&pool).await;
    subtest_delete_user_conflicts(&pool).await;
    subtest_create_access_key(&pool).await;
    subtest_list_access_keys(&pool).await;
    subtest_update_access_key(&pool).await;
    subtest_delete_access_key(&pool).await;
    subtest_get_signing_key(&pool).await;
    subtest_create_role(&pool).await;
    subtest_assume_role(&pool).await;
    subtest_create_group(&pool).await;
    subtest_get_group(&pool).await;
    subtest_list_groups(&pool).await;
    subtest_update_group(&pool).await;
    subtest_group_membership(&pool).await;
    subtest_put_group_policy(&pool).await;
    subtest_get_group_policy(&pool).await;
    subtest_list_group_policies(&pool).await;
    subtest_delete_group_policy(&pool).await;
    subtest_delete_group_conflicts(&pool).await;
    subtest_attach_policy(&pool).await;
    subtest_detach_policy(&pool).await;
    subtest_list_attached_policies(&pool).await;
    subtest_create_policy(&pool).await;
    subtest_create_policy_version(&pool).await;
    subtest_delete_policy_version(&pool).await;
    subtest_policy_update_date(&pool).await;
    subtest_get_policy(&pool).await;
    subtest_set_default_policy_version(&pool).await;
    subtest_tag_untag_policy(&pool).await;
    subtest_list_policy_tags(&pool).await;
    subtest_list_policy_versions(&pool).await;
    subtest_list_policies(&pool).await;
    subtest_list_entities_for_policy(&pool).await;
    subtest_delete_policy(&pool).await;
    subtest_delete_group(&pool).await;
    subtest_delete_role(&pool).await;
    subtest_delete_role_permissions_boundary(&pool).await;
    subtest_get_role(&pool).await;
    subtest_list_roles(&pool).await;
    subtest_list_role_tags(&pool).await;
    subtest_tag_untag_role(&pool).await;
    subtest_update_role(&pool).await;
    subtest_put_role_permissions_boundary(&pool).await;
    subtest_put_role_policy(&pool).await;
    subtest_get_role_policy(&pool).await;
    subtest_list_role_policies(&pool).await;
    subtest_delete_role_policy(&pool).await;

    MIGRATOR.undo(&mut *c, 0).await.expect("Failed to undo database migrations");
}

/// SetCurrentPartition and GetCurrentPartition
async fn subtest_current_partition(pool: &PgPool) {
    partition::test_invalid_set_current_partition(pool).await;
    partition::test_set_current_partition(pool).await;
    partition::test_get_current_partition(pool).await;
}

/// authz::get_policies_for_user / authz::get_policies_for_role + aspen authorize against seeded
/// data. Runs directly after the partition is set so the seed data is still pristine; mutating
/// cases roll back their transactions.
async fn subtest_authz(pool: &PgPool) {
    authz::test_get_policies_by_ids(pool).await;
    authz::test_get_policies_by_ids_unresolvable(pool).await;
    authz::test_get_policies_for_role_direct(pool).await;
    authz::test_get_policies_for_role_nonexistent(pool).await;
    authz::test_get_policies_for_user_direct(pool).await;
    authz::test_get_policies_for_user_via_group(pool).await;
    authz::test_get_policies_for_user_nonexistent(pool).await;
    authz::test_authorize_allow_via_group_attached(pool).await;
    authz::test_authorize_assumed_role(pool).await;
    authz::test_authorize_boundary_deny(pool).await;
    authz::test_authorize_default_deny_no_policy(pool).await;
    authz::test_authorize_explicit_deny(pool).await;
    authz::test_authorize_condition_keys(pool).await;
}

/// CreateAccountRequest
async fn subtest_create_account(pool: &PgPool) {
    account::test_create_account_specific_id(pool).await;
    account::test_create_account_with_email_and_alias(pool).await;
    account::test_create_account_random_id(pool).await;
    account::test_create_account_duplicate_id(pool).await;
    account::test_create_account_invalid_id(pool).await;
    account::test_create_account_invalid_alias_leading_dash(pool).await;
    account::test_create_account_alias_too_short(pool).await;
    account::test_create_account_organization_id_unsupported(pool).await;
    account::test_list_accounts_explicit(pool).await;
    account::test_create_350_accounts(pool).await;
    account::test_list_350_accounts(pool).await;
    account::test_list_accounts_filter_single_account_id(pool).await;
    account::test_list_accounts_filter_multiple_account_ids(pool).await;
    account::test_list_accounts_filter_by_email(pool).await;
    account::test_list_accounts_filter_by_alias(pool).await;
    account::test_list_accounts_filter_combined_match(pool).await;
    account::test_list_accounts_filter_combined_no_match(pool).await;
    account::test_list_accounts_filter_nonexistent(pool).await;
}

/// ListAccountAliasesInternalRequest / CreateAccountAliasInternalRequest
async fn subtest_account_aliases(pool: &PgPool) {
    account::test_list_account_aliases_with_alias(pool).await;
    account::test_list_account_aliases_without_alias(pool).await;
    account::test_list_account_aliases_nonexistent_account(pool).await;
    account::test_list_account_aliases_invalid_account_id();
    account::test_create_account_alias_simple(pool).await;
    account::test_create_account_alias_replaces(pool).await;
    account::test_create_account_alias_nonexistent_account(pool).await;
    account::test_create_account_alias_invalid_alias();
    account::test_create_account_alias_invalid_account_id();
}

/// CreateUserRequestInternal
async fn subtest_create_user(pool: &PgPool) {
    user::test_create_user_simple(pool).await;
    user::test_create_user_with_path(pool).await;
    user::test_create_user_with_tags(pool).await;
    user::test_create_user_with_permissions_boundary(pool).await;
    user::test_create_user_duplicate_name(pool).await;
    user::test_create_user_duplicate_name_different_case(pool).await;
    user::test_create_user_id_collision_reports_a_different_constraint(pool).await;
    user::test_create_user_duplicate_tag_keys(pool).await;
    user::test_create_user_duplicate_tag_keys_different_case(pool).await;
    user::test_create_user_distinct_tag_keys_are_accepted(pool).await;
    user::test_create_user_invalid_name();
    user::test_create_user_nonexistent_account(pool).await;
    user::test_create_user_nonexistent_permissions_boundary(pool).await;
}

/// TagUserInternalRequest / UntagUserInternalRequest
async fn subtest_tag_untag_user(pool: &PgPool) {
    user::test_tag_user(pool).await;
    user::test_tag_user_upsert(pool).await;
    user::test_tag_user_empty_tags(pool).await;
    user::test_tag_user_nonexistent_user(pool).await;
    user::test_tag_user_duplicate_keys(pool).await;
    user::test_untag_user(pool).await;
    user::test_untag_user_empty_keys(pool).await;
    user::test_untag_user_nonexistent_key(pool).await;
    user::test_untag_user_nonexistent_user(pool).await;
}

/// GetUserInternalRequest
async fn subtest_get_user(pool: &PgPool) {
    user::test_get_user_simple(pool).await;
    user::test_get_user_with_tags(pool).await;
    user::test_get_user_nonexistent(pool).await;
    user::test_get_user_no_user_name(pool).await;
    user::test_user_aws_managed_permissions_boundary(pool).await;
}

/// ListUsersInternalRequest
async fn subtest_list_users(pool: &PgPool) {
    user::test_list_users_reports_path_in_arn(pool).await;
}

/// UpdateUserInternalRequest
async fn subtest_update_user(pool: &PgPool) {
    user::test_update_user_rename(pool).await;
    user::test_update_user_change_path(pool).await;
    user::test_update_user_no_changes(pool).await;
    user::test_update_user_rename_case_only(pool).await;
    user::test_update_user_duplicate_name(pool).await;
    user::test_update_user_nonexistent(pool).await;
}

/// DeleteUserPermissionsBoundaryInternalRequest
async fn subtest_delete_user_permissions_boundary(pool: &PgPool) {
    user::test_delete_user_permissions_boundary_simple(pool).await;
    user::test_delete_user_permissions_boundary_no_boundary(pool).await;
    user::test_delete_user_permissions_boundary_nonexistent(pool).await;
    user::test_delete_user_permissions_boundary_invalid_name();
}

/// PutUserPermissionsBoundaryInternalRequest
async fn subtest_put_user_permissions_boundary(pool: &PgPool) {
    user::test_put_user_permissions_boundary_simple(pool).await;
    user::test_put_user_permissions_boundary_nonexistent_user(pool).await;
    user::test_put_user_permissions_boundary_nonexistent_policy(pool).await;
    user::test_put_user_permissions_boundary_invalid_arn(pool).await;
    user::test_put_user_permissions_boundary_invalid_name();
}

/// PutUserPolicyInternalRequest
async fn subtest_put_user_policy(pool: &PgPool) {
    user::test_put_user_policy_simple(pool).await;
    user::test_put_user_policy_replaces(pool).await;
    user::test_put_user_policy_additional_policy(pool).await;
    user::test_put_user_policy_invalid_principal_accepted(pool).await;
    user::test_put_user_policy_invalid_document(pool).await;
    user::test_put_user_policy_nonexistent_user(pool).await;
    user::test_put_user_policy_invalid_name();
}

/// GetUserPolicyInternalRequest
async fn subtest_get_user_policy(pool: &PgPool) {
    user::test_get_user_policy_simple(pool).await;
    user::test_get_user_policy_case_insensitive_lookup(pool).await;
    user::test_get_user_policy_nonexistent_policy(pool).await;
    user::test_get_user_policy_nonexistent_user(pool).await;
    user::test_get_user_policy_invalid_name();
}

/// ListUserPoliciesInternalRequest
async fn subtest_list_user_policies(pool: &PgPool) {
    user::test_list_user_policies_simple(pool).await;
    user::test_list_user_policies_empty(pool).await;
    user::test_list_user_policies_pagination(pool).await;
    user::test_list_user_policies_nonexistent_user(pool).await;
    user::test_list_user_policies_foreign_marker(pool).await;
    user::test_list_user_policies_invalid_name();
}

/// DeleteUserPolicyInternalRequest
async fn subtest_delete_user_policy(pool: &PgPool) {
    user::test_delete_user_policy_simple(pool).await;
    user::test_delete_user_policy_nonexistent_policy(pool).await;
    user::test_delete_user_policy_nonexistent_user(pool).await;
    user::test_delete_user_policy_invalid_name();
}

/// DeleteUserInternalRequest
async fn subtest_delete_user_conflicts(pool: &PgPool) {
    user::test_delete_user_attached_policy_fails(pool).await;
    user::test_delete_user_inline_policy_fails(pool).await;
}

/// CreateAccessKeyInternalRequest
async fn subtest_create_access_key(pool: &PgPool) {
    user::test_create_access_key_simple(pool).await;
    user::test_create_access_key_second(pool).await;
    user::test_create_access_key_no_user_name(pool).await;
    user::test_create_access_key_nonexistent_user(pool).await;
    user::test_create_access_key_invalid_user_name();
}

/// ListAccessKeysInternalRequest
async fn subtest_list_access_keys(pool: &PgPool) {
    user::test_list_access_keys_simple(pool).await;
    user::test_list_access_keys_seeded(pool).await;
    user::test_list_access_keys_empty(pool).await;
    user::test_list_access_keys_pagination(pool).await;
    user::test_list_access_keys_no_user_name(pool).await;
    user::test_list_access_keys_nonexistent_user(pool).await;
}

/// UpdateAccessKeyInternalRequest
async fn subtest_update_access_key(pool: &PgPool) {
    user::test_update_access_key_status_roundtrip(pool).await;
    user::test_update_access_key_expired_status_rejected(pool).await;
    user::test_update_access_key_mismatched_user(pool).await;
    user::test_update_access_key_nonexistent(pool).await;
    user::test_update_access_key_bad_prefix(pool).await;
}

/// DeleteAccessKeyInternalRequest
async fn subtest_delete_access_key(pool: &PgPool) {
    user::test_delete_access_key_simple(pool).await;
    user::test_delete_access_key_without_user_name(pool).await;
    user::test_delete_access_key_mismatched_user(pool).await;
    user::test_delete_access_key_nonexistent(pool).await;
    user::test_delete_access_key_bad_prefix(pool).await;
}

/// GetSigningKeyRequest against the database
async fn subtest_get_signing_key(pool: &PgPool) {
    gsk::test_get_signing_key_long_term(pool).await;
    gsk::test_get_signing_key_long_term_with_session_token(pool).await;
    gsk::test_get_signing_key_short_access_key(pool).await;
    gsk::test_get_signing_key_unknown_prefix(pool).await;
    gsk::test_get_signing_key_nonexistent(pool).await;
}

/// CreateRoleInternalRequest
async fn subtest_create_role(pool: &PgPool) {
    role::test_create_role_simple(pool).await;
    role::test_create_role_with_path(pool).await;
    role::test_create_role_with_description_and_duration(pool).await;
    role::test_create_role_with_tags(pool).await;
    role::test_create_role_with_permissions_boundary(pool).await;
    role::test_create_role_duplicate_name(pool).await;
    role::test_create_role_duplicate_name_different_case(pool).await;
    role::test_create_role_duplicate_name_other_account(pool).await;
    role::test_create_role_malformed_trust_policy(pool).await;
    role::test_create_role_invalid_name();
    role::test_create_role_invalid_max_session_duration();
    role::test_create_role_nonexistent_account(pool).await;
    role::test_create_role_nonexistent_permissions_boundary(pool).await;
}

/// AssumeRoleRequest
async fn subtest_assume_role(pool: &PgPool) {
    role::test_assume_role(pool).await;
    role::test_assume_role_session_policy_cross_account_rejected(pool).await;
    role::test_assume_role_with_session_policies(pool).await;
    role::test_assume_role_nonexistent_role(pool).await;
    role::test_assume_role_invalid_arn(pool).await;
    role::test_assume_role_malformed_policy(pool).await;
}

/// CreateGroupInternalRequest
async fn subtest_create_group(pool: &PgPool) {
    group::test_create_group_simple(pool).await;
    group::test_create_group_with_path(pool).await;
    group::test_create_group_duplicate_name(pool).await;
    group::test_create_group_nonexistent_account(pool).await;
    group::test_create_group_max_length_name(pool).await;
}

/// GetGroupInternalRequest
async fn subtest_get_group(pool: &PgPool) {
    group::test_get_group_simple(pool).await;
    group::test_get_group_with_path(pool).await;
    group::test_get_group_nonexistent(pool).await;
}

/// ListGroupsInternalRequest
async fn subtest_list_groups(pool: &PgPool) {
    group::test_list_groups(pool).await;
    group::test_list_groups_with_path_prefix(pool).await;
}

/// UpdateGroupInternalRequest
async fn subtest_update_group(pool: &PgPool) {
    group::test_update_group_rename(pool).await;
    group::test_update_group_change_path(pool).await;
    group::test_update_group_nonexistent(pool).await;
}

/// AddUserToGroupInternalRequest / RemoveUserFromGroupInternalRequest
async fn subtest_group_membership(pool: &PgPool) {
    group::test_add_user_to_group(pool).await;
    group::test_add_user_to_group_idempotent(pool).await;
    group::test_add_user_to_group_nonexistent_group(pool).await;
    group::test_add_user_to_group_nonexistent_user(pool).await;
    group::test_list_groups_for_user(pool).await;
    group::test_list_groups_for_user_nonexistent_user(pool).await;
    group::test_remove_user_from_group(pool).await;
    group::test_remove_user_from_group_not_member(pool).await;
    group::test_remove_user_from_group_nonexistent_group(pool).await;
}

/// PutGroupPolicyInternalRequest
async fn subtest_put_group_policy(pool: &PgPool) {
    group::test_put_group_policy_simple(pool).await;
    group::test_put_group_policy_replaces(pool).await;
    group::test_put_group_policy_invalid_principal_accepted(pool).await;
    group::test_put_group_policy_invalid_document(pool).await;
    group::test_put_group_policy_nonexistent_group(pool).await;
    group::test_put_group_policy_invalid_name();
}

/// GetGroupPolicyInternalRequest
async fn subtest_get_group_policy(pool: &PgPool) {
    group::test_get_group_policy_simple(pool).await;
    group::test_get_group_policy_case_insensitive_lookup(pool).await;
    group::test_get_group_policy_nonexistent_policy(pool).await;
    group::test_get_group_policy_nonexistent_group(pool).await;
    group::test_get_group_policy_invalid_name();
}

/// ListGroupPoliciesInternalRequest
async fn subtest_list_group_policies(pool: &PgPool) {
    group::test_list_group_policies_simple(pool).await;
    group::test_list_group_policies_empty(pool).await;
    group::test_list_group_policies_pagination(pool).await;
    group::test_list_group_policies_nonexistent_group(pool).await;
    group::test_list_group_policies_invalid_name();
}

/// DeleteGroupPolicyInternalRequest
async fn subtest_delete_group_policy(pool: &PgPool) {
    group::test_delete_group_policy_simple(pool).await;
    group::test_delete_group_policy_nonexistent_policy(pool).await;
    group::test_delete_group_policy_nonexistent_group(pool).await;
    group::test_delete_group_policy_invalid_name();
}

/// DeleteGroupInternalRequest delete-conflict cases
async fn subtest_delete_group_conflicts(pool: &PgPool) {
    group::test_delete_group_attached_policy_fails(pool).await;
    group::test_delete_group_inline_policy_fails(pool).await;
}

/// AttachUserPolicyInternalRequest / AttachGroupPolicyInternalRequest / AttachRolePolicyInternalRequest
async fn subtest_attach_policy(pool: &PgPool) {
    policy_attachment::test_attach_user_policy_simple(pool).await;
    policy_attachment::test_attach_user_policy_idempotent(pool).await;
    policy_attachment::test_attach_user_policy_nonexistent_policy(pool).await;
    policy_attachment::test_attach_user_policy_nonexistent_user(pool).await;
    policy_attachment::test_attach_group_policy_simple(pool).await;
    policy_attachment::test_attach_group_policy_idempotent(pool).await;
    policy_attachment::test_attach_group_policy_nonexistent_policy(pool).await;
    policy_attachment::test_attach_group_policy_nonexistent_group(pool).await;
    policy_attachment::test_attach_role_policy_simple(pool).await;
    policy_attachment::test_attach_role_policy_idempotent(pool).await;
    policy_attachment::test_attach_role_policy_nonexistent_policy(pool).await;
    policy_attachment::test_attach_role_policy_nonexistent_role(pool).await;
}

/// DetachUserPolicyInternalRequest / DetachGroupPolicyInternalRequest / DetachRolePolicyInternalRequest
async fn subtest_detach_policy(pool: &PgPool) {
    policy_attachment::test_detach_user_policy_simple(pool).await;
    policy_attachment::test_detach_user_policy_not_attached(pool).await;
    policy_attachment::test_detach_user_policy_nonexistent_policy(pool).await;
    policy_attachment::test_detach_user_policy_nonexistent_user(pool).await;
    policy_attachment::test_detach_group_policy_simple(pool).await;
    policy_attachment::test_detach_group_policy_not_attached(pool).await;
    policy_attachment::test_detach_group_policy_nonexistent_policy(pool).await;
    policy_attachment::test_detach_group_policy_nonexistent_group(pool).await;
    policy_attachment::test_detach_role_policy_simple(pool).await;
    policy_attachment::test_detach_role_policy_not_attached(pool).await;
    policy_attachment::test_detach_role_policy_nonexistent_policy(pool).await;
    policy_attachment::test_detach_role_policy_nonexistent_role(pool).await;
    policy_attachment::test_attach_policy_cross_account_rejected(pool).await;
    policy_attachment::test_detach_policy_cross_account_rejected(pool).await;
    policy_attachment::test_attach_policy_aws_managed_either_spelling(pool).await;
}

/// ListAttachedUserPoliciesInternalRequest / ListAttachedGroupPoliciesInternalRequest / ListAttachedRolePoliciesInternalRequest
async fn subtest_list_attached_policies(pool: &PgPool) {
    policy_attachment::test_list_attached_user_policies_seed(pool).await;
    policy_attachment::test_list_attached_user_policies_empty(pool).await;
    policy_attachment::test_list_attached_user_policies_nonexistent_user(pool).await;
    policy_attachment::test_list_attached_user_policies_path_prefix(pool).await;
    policy_attachment::test_list_attached_user_policies_pagination(pool).await;
    policy_attachment::test_list_attached_group_policies_seed(pool).await;
    policy_attachment::test_list_attached_group_policies_nonexistent_group(pool).await;
    policy_attachment::test_list_attached_role_policies_seed(pool).await;
    policy_attachment::test_list_attached_role_policies_nonexistent_role(pool).await;
}

/// CreatePolicyInternalRequest
async fn subtest_create_policy(pool: &PgPool) {
    policy_crud::test_create_policy_simple(pool).await;
    policy_crud::test_create_policy_with_path(pool).await;
    policy_crud::test_create_policy_with_description(pool).await;
    policy_crud::test_create_policy_with_tags(pool).await;
    policy_crud::test_create_policy_duplicate_name(pool).await;
    policy_crud::test_create_policy_duplicate_name_different_case(pool).await;
    policy_crud::test_create_policy_duplicate_name_other_account(pool).await;
    policy_crud::test_create_policy_invalid_document(pool).await;
    policy_crud::test_create_policy_valid_json_invalid_aspen(pool).await;
    policy_crud::test_create_policy_nonexistent_account(pool).await;
}

/// CreatePolicyVersionRequest
async fn subtest_create_policy_version(pool: &PgPool) {
    policy_crud::test_create_policy_version_simple(pool).await;
    policy_crud::test_create_policy_version_set_as_default(pool).await;
    policy_crud::test_create_policy_version_not_default(pool).await;
    policy_crud::test_create_policy_version_limit_exceeded(pool).await;
    policy_crud::test_create_policy_version_mismatched_path(pool).await;
    policy_crud::test_create_policy_version_nonexistent_policy(pool).await;
    policy_crud::test_create_policy_version_invalid_document(pool).await;
    policy_crud::test_create_policy_version_invalid_arn(pool).await;
}

/// DeletePolicyVersionRequest
async fn subtest_delete_policy_version(pool: &PgPool) {
    policy_crud::test_delete_policy_version_simple(pool).await;
    policy_crud::test_delete_policy_version_default_fails(pool).await;
    policy_crud::test_delete_policy_version_with_path(pool).await;
    policy_crud::test_delete_policy_version_mismatched_path(pool).await;
    policy_crud::test_delete_policy_version_nonexistent_policy(pool).await;
    policy_crud::test_delete_policy_version_nonexistent_version(pool).await;
    policy_crud::test_delete_policy_version_invalid_arn(pool).await;
    policy_crud::test_delete_policy_version_aws_account(pool).await;
}

/// update_date denormalization
async fn subtest_policy_update_date(pool: &PgPool) {
    policy_crud::test_policy_update_date_lifecycle(pool).await;
}

/// GetPolicyRequest / GetPolicyVersionRequest
async fn subtest_get_policy(pool: &PgPool) {
    policy_query::test_get_policy_simple(pool).await;
    policy_query::test_get_policy_with_path(pool).await;
    policy_query::test_get_policy_aws_account(pool).await;
    policy_query::test_get_policy_attachment_counts_are_per_account(pool).await;
    policy_query::test_get_policy_mismatched_path(pool).await;
    policy_query::test_get_policy_nonexistent(pool).await;
    policy_query::test_get_policy_version_simple(pool).await;
    policy_query::test_get_policy_version_nonexistent_version(pool).await;
    policy_query::test_get_policy_version_mismatched_path(pool).await;
}

/// SetDefaultPolicyVersionRequest
async fn subtest_set_default_policy_version(pool: &PgPool) {
    policy_crud::test_set_default_policy_version_simple(pool).await;
    policy_crud::test_set_default_policy_version_nonexistent_version(pool).await;
    policy_crud::test_set_default_policy_version_nonexistent_policy(pool).await;
    policy_crud::test_set_default_policy_version_mismatched_path(pool).await;
    policy_crud::test_set_default_policy_version_aws_account(pool).await;
}

/// TagPolicyRequest / UntagPolicyRequest
async fn subtest_tag_untag_policy(pool: &PgPool) {
    policy_crud::test_tag_policy_simple(pool).await;
    policy_crud::test_tag_policy_upsert(pool).await;
    policy_crud::test_tag_policy_duplicate_keys(pool).await;
    policy_crud::test_tag_policy_empty(pool).await;
    policy_crud::test_tag_policy_nonexistent(pool).await;
    policy_crud::test_untag_policy_simple(pool).await;
    policy_crud::test_untag_policy_empty(pool).await;
    policy_crud::test_untag_policy_nonexistent(pool).await;
}

/// ListPolicyTagsRequest
async fn subtest_list_policy_tags(pool: &PgPool) {
    policy_query::test_list_policy_tags_simple(pool).await;
    policy_query::test_list_policy_tags_empty(pool).await;
    policy_query::test_list_policy_tags_nonexistent(pool).await;
    policy_query::test_list_policy_tags_invalid_arn(pool).await;
    policy_query::test_list_policy_tags_builder_arn_too_short();
    policy_query::test_list_policy_tags_pagination(pool).await;
}

/// ListPolicyVersionsRequest
async fn subtest_list_policy_versions(pool: &PgPool) {
    policy_query::test_list_policy_versions_simple(pool).await;
    policy_query::test_list_policy_versions_nonexistent(pool).await;
    policy_query::test_list_policy_versions_pagination(pool).await;
}

/// ListPoliciesInternalRequest
async fn subtest_list_policies(pool: &PgPool) {
    policy_query::test_list_policies_local(pool).await;
    policy_query::test_list_policies_aws(pool).await;
    policy_query::test_list_policies_all(pool).await;
    policy_query::test_list_policies_path_prefix(pool).await;
    policy_query::test_list_policies_only_attached(pool).await;
    policy_query::test_list_policies_usage_filter_pb(pool).await;
    policy_query::test_list_policies_usage_filter_permissions_policy(pool).await;
    policy_query::test_list_policies_pagination(pool).await;
}

/// ListEntitiesForPolicyRequest
async fn subtest_list_entities_for_policy(pool: &PgPool) {
    policy_query::test_list_entities_for_policy_default(pool).await;
    policy_query::test_list_entities_for_policy_user_filter(pool).await;
    policy_query::test_list_entities_for_policy_group_filter(pool).await;
    policy_query::test_list_entities_for_policy_role_filter(pool).await;
    policy_query::test_list_entities_for_policy_pb_filter(pool).await;
    policy_query::test_list_entities_for_policy_pagination(pool).await;
    policy_query::test_list_entities_for_policy_nonexistent_policy(pool).await;
    policy_query::test_list_entities_for_policy_path_prefix(pool).await;
    policy_query::test_list_entities_for_policy_invalid_filter(pool).await;
    policy_query::test_list_entities_for_policy_cross_account_attachment(pool).await;
    policy_query::test_list_entities_for_policy_within_section_pagination(pool).await;
}

/// DeletePolicyRequest
async fn subtest_delete_policy(pool: &PgPool) {
    policy_delete::test_delete_policy_simple(pool).await;
    policy_delete::test_delete_policy_cascade_tags_and_default_version(pool).await;
    policy_delete::test_delete_policy_attached_to_user_fails(pool).await;
    policy_delete::test_delete_policy_attached_to_group_fails(pool).await;
    policy_delete::test_delete_policy_attached_to_role_fails(pool).await;
    policy_delete::test_delete_policy_user_permissions_boundary_fails(pool).await;
    policy_delete::test_delete_policy_role_permissions_boundary_fails(pool).await;
    policy_delete::test_delete_policy_with_non_default_versions_fails(pool).await;
    policy_delete::test_delete_policy_nonexistent(pool).await;
    policy_delete::test_delete_policy_mismatched_path(pool).await;
    policy_delete::test_delete_policy_invalid_arn(pool).await;
    policy_delete::test_delete_policy_aws_account(pool).await;
}

/// DeleteGroupInternalRequest
async fn subtest_delete_group(pool: &PgPool) {
    group::test_delete_group_max_length_name(pool).await;
    group::test_delete_group(pool).await;
    group::test_delete_group_nonexistent(pool).await;
}

/// DeleteRoleInternalRequest
async fn subtest_delete_role(pool: &PgPool) {
    role::test_delete_role_simple(pool).await;
    role::test_delete_role_cascades_tags(pool).await;
    role::test_delete_role_attached_policy_fails(pool).await;
    role::test_delete_role_inline_policy_fails(pool).await;
    role::test_delete_role_nonexistent(pool).await;
    role::test_delete_role_invalid_name();
}

/// DeleteRolePermissionsBoundaryInternalRequest
async fn subtest_delete_role_permissions_boundary(pool: &PgPool) {
    role::test_delete_role_permissions_boundary_simple(pool).await;
    role::test_delete_role_permissions_boundary_no_boundary(pool).await;
    role::test_delete_role_permissions_boundary_nonexistent(pool).await;
    role::test_delete_role_permissions_boundary_invalid_name();
}

/// GetRoleInternalRequest
async fn subtest_get_role(pool: &PgPool) {
    role::test_get_role_simple(pool).await;
    role::test_get_role_with_path(pool).await;
    role::test_get_role_with_tags(pool).await;
    role::test_get_role_with_permissions_boundary(pool).await;
    role::test_role_aws_managed_permissions_boundary(pool).await;
    role::test_get_role_nonexistent(pool).await;
    role::test_get_role_invalid_name();
}

/// ListRolesInternalRequest
async fn subtest_list_roles(pool: &PgPool) {
    role::test_list_roles(pool).await;
    role::test_list_roles_with_path_prefix(pool).await;
    role::test_list_roles_path_prefix_no_match(pool).await;
    role::test_list_roles_empty_account(pool).await;
    role::test_list_roles_pagination(pool).await;
    role::test_list_roles_invalid_path_prefix();
}

/// ListRoleTagsInternalRequest
async fn subtest_list_role_tags(pool: &PgPool) {
    role::test_list_role_tags(pool).await;
    role::test_list_role_tags_empty(pool).await;
    role::test_list_role_tags_pagination(pool).await;
    role::test_list_role_tags_nonexistent(pool).await;
    role::test_list_role_tags_invalid_name();
}

/// TagRoleInternalRequest / UntagRoleInternalRequest
async fn subtest_tag_untag_role(pool: &PgPool) {
    role::test_tag_role(pool).await;
    role::test_tag_role_upsert(pool).await;
    role::test_tag_role_empty_tags(pool).await;
    role::test_tag_role_duplicate_keys(pool).await;
    role::test_tag_role_nonexistent_role(pool).await;
    role::test_untag_role(pool).await;
    role::test_untag_role_empty_keys(pool).await;
    role::test_untag_role_nonexistent_key(pool).await;
    role::test_untag_role_nonexistent_role(pool).await;
}

/// UpdateRoleInternalRequest / UpdateRoleDescriptionInternalRequest
async fn subtest_update_role(pool: &PgPool) {
    role::test_update_role_description_only(pool).await;
    role::test_update_role_max_session_duration_only(pool).await;
    role::test_update_role_both_fields(pool).await;
    role::test_update_role_no_fields(pool).await;
    role::test_update_role_nonexistent(pool).await;
    role::test_update_role_invalid_max_session_duration();
    role::test_update_role_invalid_name();
    role::test_update_role_description_simple(pool).await;
    role::test_update_role_description_empty(pool).await;
    role::test_update_role_description_nonexistent(pool).await;
    role::test_update_role_description_invalid_name();
}

/// PutRolePermissionsBoundaryInternalRequest
async fn subtest_put_role_permissions_boundary(pool: &PgPool) {
    role::test_put_role_permissions_boundary_simple(pool).await;
    role::test_put_role_permissions_boundary_nonexistent_role(pool).await;
    role::test_put_role_permissions_boundary_nonexistent_policy(pool).await;
    role::test_put_role_permissions_boundary_invalid_arn(pool).await;
    role::test_put_role_permissions_boundary_invalid_name();
}

/// PutRolePolicyInternalRequest
async fn subtest_put_role_policy(pool: &PgPool) {
    role::test_put_role_policy_simple(pool).await;
    role::test_put_role_policy_replaces(pool).await;
    role::test_put_role_policy_invalid_principal_accepted(pool).await;
    role::test_put_role_policy_invalid_document(pool).await;
    role::test_put_role_policy_nonexistent_role(pool).await;
    role::test_put_role_policy_invalid_name();
}

/// GetRolePolicyInternalRequest
async fn subtest_get_role_policy(pool: &PgPool) {
    role::test_get_role_policy_simple(pool).await;
    role::test_get_role_policy_case_insensitive_lookup(pool).await;
    role::test_get_role_policy_nonexistent_policy(pool).await;
    role::test_get_role_policy_nonexistent_role(pool).await;
    role::test_get_role_policy_invalid_name();
}

/// ListRolePoliciesInternalRequest
async fn subtest_list_role_policies(pool: &PgPool) {
    role::test_list_role_policies_simple(pool).await;
    role::test_list_role_policies_empty(pool).await;
    role::test_list_role_policies_pagination(pool).await;
    role::test_list_role_policies_nonexistent_role(pool).await;
    role::test_list_role_policies_invalid_name();
}

/// DeleteRolePolicyInternalRequest
async fn subtest_delete_role_policy(pool: &PgPool) {
    role::test_delete_role_policy_simple(pool).await;
    role::test_delete_role_policy_nonexistent_policy(pool).await;
    role::test_delete_role_policy_nonexistent_role(pool).await;
    role::test_delete_role_policy_invalid_name();
}
