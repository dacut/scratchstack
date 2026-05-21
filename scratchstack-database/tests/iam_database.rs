//! Tests for the IAM database model and related functionality.
//!
//! The body of each test lives in a submodule under [tests/iam_database/](iam_database/); this
//! file orchestrates a single end-to-end run because the test database is stateful between calls.
#![cfg(all(feature = "iam", feature = "utils"))]
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
    pretty_assertions::{assert_eq, assert_ne},
    scratchstack_database::{Loadable, model::iam, utils::TempDatabase},
};

#[path = "iam_database/account.rs"]
mod account;
#[path = "iam_database/common.rs"]
mod common;
#[path = "iam_database/group.rs"]
mod group;
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

/// Test all of the features of the database.
///
/// We do this instead of more granular testing because the database we're running against is typically stateful.
#[test_log::test(tokio::test)]
async fn test_database() {
    let iam_data: iam::Database =
        serde_json::from_str(TEST_DATA).expect("Failed to deserialize test data into IAM database model");

    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    iam::MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    let rows_affected = iam_data.load_into(&mut c).await.expect("Failed to load IAM data into database");
    eprintln!("Loaded {rows_affected} rows of IAM data into database");

    // -- SetCurrentPartition and GetCurrentPartition --------------------------
    partition::test_invalid_set_current_partition(&pool).await;
    partition::test_set_current_partition(&pool).await;
    partition::test_get_current_partition(&pool).await;

    let iam_dump = iam::Database::dump_from(&mut c).await.expect("Failed to dump IAM data from database");
    assert_ne!(iam_data, iam_dump, "Dumped IAM data should not be equal to original IAM data due to created_at fields");
    let iam_dump2 =
        iam::Database::dump_from(&mut c).await.expect("Failed to dump IAM data from database a second time");
    assert_eq!(iam_dump, iam_dump2, "Dumped IAM data should be equal across multiple dumps");

    // -- CreateAccountRequest -------------------------------------------------
    account::test_create_account_specific_id(&pool).await;
    account::test_create_account_with_email_and_alias(&pool).await;
    account::test_create_account_random_id(&pool).await;
    account::test_create_account_duplicate_id(&pool).await;
    account::test_create_account_invalid_id(&pool).await;
    account::test_create_account_invalid_alias_leading_dash(&pool).await;
    account::test_create_account_alias_too_short(&pool).await;
    account::test_create_account_organization_id_unsupported(&pool).await;
    account::test_list_accounts_explicit(&pool).await;
    account::test_create_350_accounts(&pool).await;
    account::test_list_350_accounts(&pool).await;
    account::test_list_accounts_filter_single_account_id(&pool).await;
    account::test_list_accounts_filter_multiple_account_ids(&pool).await;
    account::test_list_accounts_filter_by_email(&pool).await;
    account::test_list_accounts_filter_by_alias(&pool).await;
    account::test_list_accounts_filter_combined_match(&pool).await;
    account::test_list_accounts_filter_combined_no_match(&pool).await;
    account::test_list_accounts_filter_nonexistent(&pool).await;

    // -- CreateUserRequestInternal --------------------------------------------
    user::test_create_user_simple(&pool).await;
    user::test_create_user_with_path(&pool).await;
    user::test_create_user_with_tags(&pool).await;
    user::test_create_user_with_permissions_boundary(&pool).await;
    user::test_create_user_duplicate_name(&pool).await;
    user::test_create_user_invalid_name();
    user::test_create_user_nonexistent_account(&pool).await;
    user::test_create_user_nonexistent_permissions_boundary(&pool).await;

    // -- TagUserInternalRequest / UntagUserInternalRequest --------------------
    user::test_tag_user(&pool).await;
    user::test_tag_user_upsert(&pool).await;
    user::test_tag_user_empty_tags(&pool).await;
    user::test_tag_user_nonexistent_user(&pool).await;
    user::test_untag_user(&pool).await;
    user::test_untag_user_empty_keys(&pool).await;
    user::test_untag_user_nonexistent_key(&pool).await;
    user::test_untag_user_nonexistent_user(&pool).await;

    // -- GetUserInternalRequest -----------------------------------------------
    user::test_get_user_simple(&pool).await;
    user::test_get_user_with_tags(&pool).await;
    user::test_get_user_nonexistent(&pool).await;
    user::test_get_user_no_user_name(&pool).await;

    // -- CreateRoleInternalRequest --------------------------------------------
    role::test_create_role_simple(&pool).await;
    role::test_create_role_with_path(&pool).await;
    role::test_create_role_with_description_and_duration(&pool).await;
    role::test_create_role_with_tags(&pool).await;
    role::test_create_role_with_permissions_boundary(&pool).await;
    role::test_create_role_duplicate_name(&pool).await;
    role::test_create_role_invalid_name();
    role::test_create_role_invalid_max_session_duration();
    role::test_create_role_nonexistent_account(&pool).await;
    role::test_create_role_nonexistent_permissions_boundary(&pool).await;

    // -- CreateGroupInternalRequest -------------------------------------------
    group::test_create_group_simple(&pool).await;
    group::test_create_group_with_path(&pool).await;
    group::test_create_group_duplicate_name(&pool).await;
    group::test_create_group_nonexistent_account(&pool).await;
    group::test_create_group_max_length_name(&pool).await;

    // -- GetGroupInternalRequest ----------------------------------------------
    group::test_get_group_simple(&pool).await;
    group::test_get_group_with_path(&pool).await;
    group::test_get_group_nonexistent(&pool).await;

    // -- ListGroupsInternalRequest --------------------------------------------
    group::test_list_groups(&pool).await;
    group::test_list_groups_with_path_prefix(&pool).await;

    // -- UpdateGroupInternalRequest -------------------------------------------
    group::test_update_group_rename(&pool).await;
    group::test_update_group_change_path(&pool).await;
    group::test_update_group_nonexistent(&pool).await;

    // -- AddUserToGroupInternalRequest / RemoveUserFromGroupInternalRequest ---
    group::test_add_user_to_group(&pool).await;
    group::test_add_user_to_group_idempotent(&pool).await;
    group::test_add_user_to_group_nonexistent_group(&pool).await;
    group::test_add_user_to_group_nonexistent_user(&pool).await;
    group::test_list_groups_for_user(&pool).await;
    group::test_list_groups_for_user_nonexistent_user(&pool).await;
    group::test_remove_user_from_group(&pool).await;
    group::test_remove_user_from_group_not_member(&pool).await;
    group::test_remove_user_from_group_nonexistent_group(&pool).await;

    // -- AttachUserPolicyInternalRequest / AttachGroupPolicyInternalRequest / AttachRolePolicyInternalRequest ---
    policy_attachment::test_attach_user_policy_simple(&pool).await;
    policy_attachment::test_attach_user_policy_idempotent(&pool).await;
    policy_attachment::test_attach_user_policy_nonexistent_policy(&pool).await;
    policy_attachment::test_attach_user_policy_nonexistent_user(&pool).await;
    policy_attachment::test_attach_group_policy_simple(&pool).await;
    policy_attachment::test_attach_group_policy_idempotent(&pool).await;
    policy_attachment::test_attach_group_policy_nonexistent_policy(&pool).await;
    policy_attachment::test_attach_group_policy_nonexistent_group(&pool).await;
    policy_attachment::test_attach_role_policy_simple(&pool).await;
    policy_attachment::test_attach_role_policy_idempotent(&pool).await;
    policy_attachment::test_attach_role_policy_nonexistent_policy(&pool).await;
    policy_attachment::test_attach_role_policy_nonexistent_role(&pool).await;

    // -- DetachUserPolicyInternalRequest / DetachGroupPolicyInternalRequest / DetachRolePolicyInternalRequest ---
    policy_attachment::test_detach_user_policy_simple(&pool).await;
    policy_attachment::test_detach_user_policy_not_attached(&pool).await;
    policy_attachment::test_detach_user_policy_nonexistent_policy(&pool).await;
    policy_attachment::test_detach_user_policy_nonexistent_user(&pool).await;
    policy_attachment::test_detach_group_policy_simple(&pool).await;
    policy_attachment::test_detach_group_policy_not_attached(&pool).await;
    policy_attachment::test_detach_group_policy_nonexistent_policy(&pool).await;
    policy_attachment::test_detach_group_policy_nonexistent_group(&pool).await;
    policy_attachment::test_detach_role_policy_simple(&pool).await;
    policy_attachment::test_detach_role_policy_not_attached(&pool).await;
    policy_attachment::test_detach_role_policy_nonexistent_policy(&pool).await;
    policy_attachment::test_detach_role_policy_nonexistent_role(&pool).await;

    // -- ListAttachedUserPoliciesInternalRequest / ListAttachedGroupPoliciesInternalRequest / ListAttachedRolePoliciesInternalRequest ---
    policy_attachment::test_list_attached_user_policies_seed(&pool).await;
    policy_attachment::test_list_attached_user_policies_empty(&pool).await;
    policy_attachment::test_list_attached_user_policies_nonexistent_user(&pool).await;
    policy_attachment::test_list_attached_user_policies_path_prefix(&pool).await;
    policy_attachment::test_list_attached_user_policies_pagination(&pool).await;
    policy_attachment::test_list_attached_group_policies_seed(&pool).await;
    policy_attachment::test_list_attached_group_policies_nonexistent_group(&pool).await;
    policy_attachment::test_list_attached_role_policies_seed(&pool).await;
    policy_attachment::test_list_attached_role_policies_nonexistent_role(&pool).await;

    // -- CreatePolicyInternalRequest ------------------------------------------
    policy_crud::test_create_policy_simple(&pool).await;
    policy_crud::test_create_policy_with_path(&pool).await;
    policy_crud::test_create_policy_with_description(&pool).await;
    policy_crud::test_create_policy_with_tags(&pool).await;
    policy_crud::test_create_policy_duplicate_name(&pool).await;
    policy_crud::test_create_policy_invalid_document(&pool).await;
    policy_crud::test_create_policy_valid_json_invalid_aspen(&pool).await;
    policy_crud::test_create_policy_nonexistent_account(&pool).await;

    // -- CreatePolicyVersionRequest -------------------------------------------
    policy_crud::test_create_policy_version_simple(&pool).await;
    policy_crud::test_create_policy_version_set_as_default(&pool).await;
    policy_crud::test_create_policy_version_not_default(&pool).await;
    policy_crud::test_create_policy_version_limit_exceeded(&pool).await;
    policy_crud::test_create_policy_version_mismatched_path(&pool).await;
    policy_crud::test_create_policy_version_nonexistent_policy(&pool).await;
    policy_crud::test_create_policy_version_invalid_document(&pool).await;
    policy_crud::test_create_policy_version_invalid_arn(&pool).await;

    // -- DeletePolicyVersionRequest -------------------------------------------
    policy_crud::test_delete_policy_version_simple(&pool).await;
    policy_crud::test_delete_policy_version_default_fails(&pool).await;
    policy_crud::test_delete_policy_version_with_path(&pool).await;
    policy_crud::test_delete_policy_version_mismatched_path(&pool).await;
    policy_crud::test_delete_policy_version_nonexistent_policy(&pool).await;
    policy_crud::test_delete_policy_version_nonexistent_version(&pool).await;
    policy_crud::test_delete_policy_version_invalid_arn(&pool).await;
    policy_crud::test_delete_policy_version_aws_account(&pool).await;

    // -- update_date denormalization ------------------------------------------
    policy_crud::test_policy_update_date_lifecycle(&pool).await;

    // -- GetPolicyRequest / GetPolicyVersionRequest ---------------------------
    policy_query::test_get_policy_simple(&pool).await;
    policy_query::test_get_policy_with_path(&pool).await;
    policy_query::test_get_policy_aws_account(&pool).await;
    policy_query::test_get_policy_mismatched_path(&pool).await;
    policy_query::test_get_policy_nonexistent(&pool).await;
    policy_query::test_get_policy_version_simple(&pool).await;
    policy_query::test_get_policy_version_nonexistent_version(&pool).await;
    policy_query::test_get_policy_version_mismatched_path(&pool).await;

    // -- SetDefaultPolicyVersionRequest ---------------------------------------
    policy_crud::test_set_default_policy_version_simple(&pool).await;
    policy_crud::test_set_default_policy_version_nonexistent_version(&pool).await;
    policy_crud::test_set_default_policy_version_nonexistent_policy(&pool).await;
    policy_crud::test_set_default_policy_version_mismatched_path(&pool).await;
    policy_crud::test_set_default_policy_version_aws_account(&pool).await;

    // -- TagPolicyRequest / UntagPolicyRequest --------------------------------
    policy_crud::test_tag_policy_simple(&pool).await;
    policy_crud::test_tag_policy_upsert(&pool).await;
    policy_crud::test_tag_policy_empty(&pool).await;
    policy_crud::test_tag_policy_nonexistent(&pool).await;
    policy_crud::test_untag_policy_simple(&pool).await;
    policy_crud::test_untag_policy_empty(&pool).await;
    policy_crud::test_untag_policy_nonexistent(&pool).await;

    // -- ListPolicyVersionsRequest --------------------------------------------
    policy_query::test_list_policy_versions_simple(&pool).await;
    policy_query::test_list_policy_versions_nonexistent(&pool).await;
    policy_query::test_list_policy_versions_pagination(&pool).await;

    // -- ListPoliciesInternalRequest ------------------------------------------
    policy_query::test_list_policies_local(&pool).await;
    policy_query::test_list_policies_aws(&pool).await;
    policy_query::test_list_policies_all(&pool).await;
    policy_query::test_list_policies_path_prefix(&pool).await;
    policy_query::test_list_policies_only_attached(&pool).await;
    policy_query::test_list_policies_usage_filter_pb(&pool).await;
    policy_query::test_list_policies_usage_filter_permissions_policy(&pool).await;
    policy_query::test_list_policies_pagination(&pool).await;

    // -- ListEntitiesForPolicyRequest -----------------------------------------
    policy_query::test_list_entities_for_policy_default(&pool).await;
    policy_query::test_list_entities_for_policy_user_filter(&pool).await;
    policy_query::test_list_entities_for_policy_group_filter(&pool).await;
    policy_query::test_list_entities_for_policy_role_filter(&pool).await;
    policy_query::test_list_entities_for_policy_pb_filter(&pool).await;
    policy_query::test_list_entities_for_policy_pagination(&pool).await;
    policy_query::test_list_entities_for_policy_nonexistent_policy(&pool).await;
    policy_query::test_list_entities_for_policy_path_prefix(&pool).await;
    policy_query::test_list_entities_for_policy_invalid_filter(&pool).await;
    policy_query::test_list_entities_for_policy_cross_account_attachment(&pool).await;
    policy_query::test_list_entities_for_policy_within_section_pagination(&pool).await;

    // -- DeletePolicyRequest --------------------------------------------------
    policy_delete::test_delete_policy_simple(&pool).await;
    policy_delete::test_delete_policy_cascade_tags_and_default_version(&pool).await;
    policy_delete::test_delete_policy_attached_to_user_fails(&pool).await;
    policy_delete::test_delete_policy_attached_to_group_fails(&pool).await;
    policy_delete::test_delete_policy_attached_to_role_fails(&pool).await;
    policy_delete::test_delete_policy_user_permissions_boundary_fails(&pool).await;
    policy_delete::test_delete_policy_role_permissions_boundary_fails(&pool).await;
    policy_delete::test_delete_policy_with_non_default_versions_fails(&pool).await;
    policy_delete::test_delete_policy_nonexistent(&pool).await;
    policy_delete::test_delete_policy_mismatched_path(&pool).await;
    policy_delete::test_delete_policy_invalid_arn(&pool).await;
    policy_delete::test_delete_policy_aws_account(&pool).await;

    // -- DeleteGroupInternalRequest -------------------------------------------
    group::test_delete_group_max_length_name(&pool).await;
    group::test_delete_group(&pool).await;
    group::test_delete_group_nonexistent(&pool).await;

    // -- DeleteRoleInternalRequest --------------------------------------------
    role::test_delete_role_simple(&pool).await;
    role::test_delete_role_cascades_tags(&pool).await;
    role::test_delete_role_attached_policy_fails(&pool).await;
    role::test_delete_role_inline_policy_fails(&pool).await;
    role::test_delete_role_nonexistent(&pool).await;
    role::test_delete_role_invalid_name();

    // -- DeleteRolePermissionsBoundaryInternalRequest -------------------------
    role::test_delete_role_permissions_boundary_simple(&pool).await;
    role::test_delete_role_permissions_boundary_no_boundary(&pool).await;
    role::test_delete_role_permissions_boundary_nonexistent(&pool).await;
    role::test_delete_role_permissions_boundary_invalid_name();

    // -- GetRoleInternalRequest -----------------------------------------------
    role::test_get_role_simple(&pool).await;
    role::test_get_role_with_path(&pool).await;
    role::test_get_role_with_tags(&pool).await;
    role::test_get_role_with_permissions_boundary(&pool).await;
    role::test_get_role_nonexistent(&pool).await;
    role::test_get_role_invalid_name();

    // -- ListRolesInternalRequest ---------------------------------------------
    role::test_list_roles(&pool).await;
    role::test_list_roles_with_path_prefix(&pool).await;
    role::test_list_roles_path_prefix_no_match(&pool).await;
    role::test_list_roles_empty_account(&pool).await;
    role::test_list_roles_pagination(&pool).await;
    role::test_list_roles_invalid_path_prefix();

    iam::MIGRATOR.undo(&mut *c, 0).await.expect("Failed to undo database migrations");
}

const TEST_DATA: &str = include_str!("iam_database.json");
