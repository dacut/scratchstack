//! Group test suite, including group membership tests.
use {
    pretty_assertions::assert_eq,
    scratchstack_database::ops::RequestExecutor,
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AddUserToGroupInternalRequest, CreateGroupInternalRequest, DeleteGroupInternalRequest,
            DeleteGroupPolicyInternalRequest, GetGroupInternalRequest, GetGroupPolicyInternalRequest,
            ListGroupPoliciesInternalRequest, ListGroupsForUserInternalRequest, ListGroupsInternalRequest,
            PutGroupPolicyInternalRequest, RemoveUserFromGroupInternalRequest, UpdateGroupInternalRequest,
        },
    },
};

/// Create a group with only a name and account — all other fields take defaults.
pub async fn test_create_group_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create group");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.group.group_name, "Admins");
    assert_eq!(resp.group.path, "/");
    assert!(resp.group.group_id.starts_with("AGPA"), "Group ID must start with AGPA prefix");
    assert!(resp.group.arn.ends_with(":group/Admins"), "ARN must end with :group/Admins, got {}", resp.group.arn);
}

/// Create a group at a non-default path.
pub async fn test_create_group_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create group with path");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.group.group_name, "Developers");
    assert_eq!(resp.group.path, "/engineering/");
    assert!(
        resp.group.arn.ends_with(":group/engineering/Developers"),
        "ARN must end with :group/engineering/Developers, got {}",
        resp.group.arn
    );
}

/// Attempting to create a group whose (lowercased) name already exists in the account must fail.
pub async fn test_create_group_duplicate_name(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate group name must fail");
}

/// Creating a group in an account that does not exist must fail.
pub async fn test_create_group_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateGroupInternalRequest::builder()
        .group_name("TestGroup".to_string())
        .account_id("999999999999".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a group in a nonexistent account must fail");
}

/// Create a group with a 128-character name (the maximum allowed by AWS IAM).
pub async fn test_create_group_max_length_name(pool: &sqlx::PgPool) {
    // 128 characters: valid characters are [\w+=,.@-]
    let long_name = "A".repeat(128);
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateGroupInternalRequest::builder()
        .group_name(long_name.clone())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create group with 128-character name");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.group.group_name, long_name);
    assert_eq!(resp.group.path, "/");
    assert!(resp.group.group_id.starts_with("AGPA"), "Group ID must start with AGPA prefix");

    // Verify we can retrieve the group.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name(long_name.clone())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group with 128-character name");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, long_name);
}

/// Get a group that exists with default path.
pub async fn test_get_group_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, "Admins");
    assert_eq!(resp.group.path, "/");
    assert!(resp.group.group_id.starts_with("AGPA"), "Group ID must start with AGPA prefix");
    assert!(resp.group.arn.ends_with(":group/Admins"), "ARN must end with :group/Admins, got {}", resp.group.arn);
}

/// Get a group at a non-default path.
pub async fn test_get_group_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, "Developers");
    assert_eq!(resp.group.path, "/engineering/");
    assert!(
        resp.group.arn.ends_with(":group/engineering/Developers"),
        "ARN must end with :group/engineering/Developers, got {}",
        resp.group.arn
    );
}

/// Getting a nonexistent group must fail.
pub async fn test_get_group_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = GetGroupInternalRequest::builder()
        .group_name("NonexistentGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Getting a nonexistent group must fail");
}

/// List groups in an account.
pub async fn test_list_groups(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsInternalRequest::builder()
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListGroupsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert!(resp.groups.len() >= 2, "Expected at least 2 groups, got {}", resp.groups.len());
    // Groups are sorted by name (lowercased).
    let names: Vec<&str> = resp.groups.iter().map(|g| g.group_name.as_str()).collect();
    assert!(names.contains(&"Admins"), "Expected Admins in group list");
    assert!(names.contains(&"Developers"), "Expected Developers in group list");
}

/// List groups with a path prefix filter.
pub async fn test_list_groups_with_path_prefix(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsInternalRequest::builder()
        .account_id("123456789012".to_string())
        .path_prefix(Some("/engineering/".to_string()))
        .build()
        .expect("Failed to build ListGroupsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups with path prefix");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.groups.len(), 1, "Expected exactly 1 group under /engineering/");
    assert_eq!(resp.groups[0].group_name, "Developers");
}

/// Rename a group.
pub async fn test_update_group_rename(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .new_group_name(Some("Administrators".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build UpdateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to rename group");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the rename took effect.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get renamed group");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, "Administrators");
}

/// Change the path of a group.
pub async fn test_update_group_change_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateGroupInternalRequest::builder()
        .group_name("Administrators".to_string())
        .new_path(Some("/admin/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build UpdateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to update group path");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the path change took effect.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group after path change");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.path, "/admin/");
}

/// Updating a nonexistent group must fail.
pub async fn test_update_group_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = UpdateGroupInternalRequest::builder()
        .group_name("NonexistentGroup".to_string())
        .new_group_name(Some("NewName".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build UpdateGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Updating a nonexistent group must fail");
}

/// Delete the group with the maximum-length (128-character) name.
pub async fn test_delete_group_max_length_name(pool: &sqlx::PgPool) {
    let long_name = "A".repeat(128);
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteGroupInternalRequest::builder()
        .group_name(long_name)
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete group with 128-character name");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Delete a group that exists.
pub async fn test_delete_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete group");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the group is gone.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = GetGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Getting a deleted group must fail");
}

/// Deleting a nonexistent group must fail.
pub async fn test_delete_group_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = DeleteGroupInternalRequest::builder()
        .group_name("NonexistentGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Deleting a nonexistent group must fail");
}

// -- Group membership tests --------------------------------------------------

/// Add a user to a group. Uses alice (account 123456789012) and Administrators (renamed earlier).
pub async fn test_add_user_to_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to add user to group");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Adding the same user to the same group again should succeed (idempotent).
pub async fn test_add_user_to_group_idempotent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Adding user to group again should succeed (idempotent)");
    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Adding a user to a nonexistent group must fail.
pub async fn test_add_user_to_group_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("NonexistentGroup".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Adding user to nonexistent group must fail");
}

/// Adding a nonexistent user to a group must fail.
pub async fn test_add_user_to_group_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("nonexistent".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Adding nonexistent user to group must fail");
}

/// List groups for a user who is a member of at least one group.
pub async fn test_list_groups_for_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsForUserInternalRequest::builder()
        .account_id("123456789012".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build ListGroupsForUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups for user");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.groups.len(), 1, "Expected 1 group for alice");
    assert_eq!(resp.groups[0].group_name, "Administrators");
}

/// Listing groups for a nonexistent user must fail.
pub async fn test_list_groups_for_user_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = ListGroupsForUserInternalRequest::builder()
        .account_id("123456789012".to_string())
        .user_name("nonexistent".to_string())
        .build()
        .expect("Failed to build ListGroupsForUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Listing groups for nonexistent user must fail");
}

/// Remove a user from a group.
pub async fn test_remove_user_from_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    RemoveUserFromGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build RemoveUserFromGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to remove user from group");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify alice is no longer in the group.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsForUserInternalRequest::builder()
        .account_id("123456789012".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build ListGroupsForUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups for user after removal");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.groups.len(), 0, "Expected 0 groups for alice after removal");
}

/// Removing a user who is not a member of a group must fail.
pub async fn test_remove_user_from_group_not_member(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = RemoveUserFromGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build RemoveUserFromGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Removing user who is not a group member must fail");
}

/// Removing a user from a nonexistent group must fail.
pub async fn test_remove_user_from_group_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = RemoveUserFromGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("NonexistentGroup".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build RemoveUserFromGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Removing user from nonexistent group must fail");
}

const INLINE_GROUP_POLICY_S3: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
const INLINE_GROUP_POLICY_EC2: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:Describe*","Resource":"*"}]}"#;
const INLINE_GROUP_POLICY_UNKNOWN_PRINCIPAL: &str = r#"{
        "Version":"2012-10-17",
        "Statement":[{
            "Effect":"Allow",
            "Principal":{"AWS":"arn:aws:iam::999999999999:user/nonexistent"},
            "Action":"sts:AssumeRole",
            "Resource":"*"
        }]
    }"#;

/// PutGroupPolicy attaches an inline policy to an existing group.
pub async fn test_put_group_policy_simple(pool: &sqlx::PgPool) {
    // "Administrators" was renamed from "Admins" in test_update_group_rename and survives.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutGroupPolicyInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineRead".to_string())
        .policy_document(INLINE_GROUP_POLICY_S3.to_string())
        .build()
        .expect("Failed to build PutGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to put inline policy on Administrators");
    tx.commit().await.expect("Failed to commit transaction");

    let doc: String = sqlx::query_scalar(
        "SELECT policy_document FROM iam.group_inline_policies \
         WHERE group_id = (SELECT group_id FROM iam.groups WHERE account_id = $1 AND group_name_lower = $2) \
         AND policy_name_lower = $3",
    )
    .bind("123456789012")
    .bind("administrators")
    .bind("inlineread")
    .fetch_one(pool)
    .await
    .expect("Failed to fetch Administrators inline policy");
    assert_eq!(doc, INLINE_GROUP_POLICY_S3);
}

/// PutGroupPolicy with the same policy name replaces the document on the same row.
pub async fn test_put_group_policy_replaces(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutGroupPolicyInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineRead".to_string())
        .policy_document(INLINE_GROUP_POLICY_EC2.to_string())
        .build()
        .expect("Failed to build PutGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to replace inline policy on Administrators");
    tx.commit().await.expect("Failed to commit transaction");

    let doc: String = sqlx::query_scalar(
        "SELECT policy_document FROM iam.group_inline_policies \
         WHERE group_id = (SELECT group_id FROM iam.groups WHERE account_id = $1 AND group_name_lower = $2) \
         AND policy_name_lower = $3",
    )
    .bind("123456789012")
    .bind("administrators")
    .bind("inlineread")
    .fetch_one(pool)
    .await
    .expect("Failed to fetch Administrators inline policy after replace");
    assert_eq!(doc, INLINE_GROUP_POLICY_EC2);

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam.group_inline_policies \
         WHERE group_id = (SELECT group_id FROM iam.groups WHERE account_id = $1 AND group_name_lower = $2)",
    )
    .bind("123456789012")
    .bind("administrators")
    .fetch_one(pool)
    .await
    .expect("Failed to count Administrators inline policies");
    assert_eq!(count, 1, "Replacing must not create a new row");
}

/// A syntactically valid principal that references a non-existent account/user is still accepted.
pub async fn test_put_group_policy_invalid_principal_accepted(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    PutGroupPolicyInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineWithMissingPrincipal".to_string())
        .policy_document(INLINE_GROUP_POLICY_UNKNOWN_PRINCIPAL.to_string())
        .build()
        .expect("Failed to build PutGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Policies referring to non-existent principals must still be accepted");
    tx.commit().await.expect("Failed to commit transaction");
}

/// A non-JSON / unparseable policy document must fail with MalformedPolicyDocument.
pub async fn test_put_group_policy_invalid_document(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutGroupPolicyInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineBroken".to_string())
        .policy_document("{ not valid aspen json }".to_string())
        .build()
        .expect("Failed to build PutGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("PutGroupPolicy with malformed JSON must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(
        matches!(err, IamError::MalformedPolicyDocumentException(_)),
        "Expected MalformedPolicyDocumentException, got: {err:?}"
    );
}

/// PutGroupPolicy on a nonexistent group must fail with NoSuchEntity.
pub async fn test_put_group_policy_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = PutGroupPolicyInternalRequest::builder()
        .group_name("NoSuchPutPolicyGroup".to_string())
        .account_id("123456789012".to_string())
        .policy_name("AnyName".to_string())
        .policy_document(INLINE_GROUP_POLICY_S3.to_string())
        .build()
        .expect("Failed to build PutGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("PutGroupPolicy on a nonexistent group must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a PutGroupPolicy request with an invalid group name must fail before touching the
/// database.
pub fn test_put_group_policy_invalid_name() {
    let result = PutGroupPolicyInternalRequest::builder()
        .group_name("bad name!".to_string())
        .account_id("123456789012".to_string())
        .policy_name("AnyName".to_string())
        .policy_document(INLINE_GROUP_POLICY_S3.to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid group name must fail");
}

/// GetGroupPolicy returns the policy document set via PutGroupPolicy.
pub async fn test_get_group_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupPolicyInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineRead".to_string())
        .build()
        .expect("Failed to build GetGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get inline policy on Administrators");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group_name, "Administrators");
    assert_eq!(resp.policy_name, "InlineRead");
    assert_eq!(resp.policy_document, INLINE_GROUP_POLICY_EC2);
}

/// GetGroupPolicy returns the document under the original case for the policy name even when
/// looked up using a different case.
pub async fn test_get_group_policy_case_insensitive_lookup(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupPolicyInternalRequest::builder()
        .group_name("administrators".to_string())
        .account_id("123456789012".to_string())
        .policy_name("inlineread".to_string())
        .build()
        .expect("Failed to build GetGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get inline policy via case-insensitive lookup");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.group_name, "Administrators");
    assert_eq!(resp.policy_name, "InlineRead");
}

/// GetGroupPolicy on a nonexistent inline policy must fail with NoSuchEntity.
pub async fn test_get_group_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetGroupPolicyInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .policy_name("NotAttached".to_string())
        .build()
        .expect("Failed to build GetGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("GetGroupPolicy with no matching policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// GetGroupPolicy on a nonexistent group must fail with NoSuchEntity.
pub async fn test_get_group_policy_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetGroupPolicyInternalRequest::builder()
        .group_name("NoSuchGetPolicyGroup".to_string())
        .account_id("123456789012".to_string())
        .policy_name("AnyName".to_string())
        .build()
        .expect("Failed to build GetGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("GetGroupPolicy on a nonexistent group must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a GetGroupPolicy request with an invalid group name must fail before touching the
/// database.
pub fn test_get_group_policy_invalid_name() {
    let result = GetGroupPolicyInternalRequest::builder()
        .group_name("bad name!".to_string())
        .account_id("123456789012".to_string())
        .policy_name("AnyName".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid group name must fail");
}

/// ListGroupPolicies returns the policy names attached to a group in sorted (case-insensitive)
/// order.
pub async fn test_list_group_policies_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupPoliciesInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListGroupPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list inline policies on Administrators");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.policy_names, vec!["InlineRead".to_string(), "InlineWithMissingPrincipal".to_string()]);
    assert_eq!(resp.is_truncated, None);
    assert_eq!(resp.marker, None);
}

/// ListGroupPolicies returns an empty list when the group has no inline policies attached.
pub async fn test_list_group_policies_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateGroupInternalRequest::builder()
        .group_name("ListPoliciesEmptyGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create ListPoliciesEmptyGroup");
    let resp = ListGroupPoliciesInternalRequest::builder()
        .group_name("ListPoliciesEmptyGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListGroupPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list inline policies on empty group");
    assert!(resp.policy_names.is_empty(), "Expected no inline policies, got: {:?}", resp.policy_names);
    assert_eq!(resp.is_truncated, None);

    DeleteGroupInternalRequest::builder()
        .group_name("ListPoliciesEmptyGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete ListPoliciesEmptyGroup");
    tx.commit().await.expect("Failed to commit transaction");
}

/// ListGroupPolicies honors `max_items` and emits a usable marker for the next page.
pub async fn test_list_group_policies_pagination(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let page1 = ListGroupPoliciesInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .max_items(Some(1))
        .build()
        .expect("Failed to build ListGroupPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list inline policies on Administrators (page 1)");
    assert_eq!(page1.policy_names, vec!["InlineRead".to_string()]);
    assert_eq!(page1.is_truncated, Some(true));
    let marker = page1.marker.clone().expect("Expected a pagination marker");

    let page2 = ListGroupPoliciesInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .max_items(Some(1))
        .marker(Some(marker))
        .build()
        .expect("Failed to build ListGroupPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list inline policies on Administrators (page 2)");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(page2.policy_names, vec!["InlineWithMissingPrincipal".to_string()]);
    assert_eq!(page2.is_truncated, None);
    assert_eq!(page2.marker, None);
}

/// ListGroupPolicies on a nonexistent group must fail with NoSuchEntity.
pub async fn test_list_group_policies_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListGroupPoliciesInternalRequest::builder()
        .group_name("NoSuchListPoliciesGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListGroupPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("ListGroupPolicies on a nonexistent group must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a ListGroupPolicies request with an invalid group name must fail before touching the
/// database.
pub fn test_list_group_policies_invalid_name() {
    let result = ListGroupPoliciesInternalRequest::builder()
        .group_name("bad name!".to_string())
        .account_id("123456789012".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid group name must fail");
}

/// DeleteGroupPolicy removes an inline policy previously attached via PutGroupPolicy.
pub async fn test_delete_group_policy_simple(pool: &sqlx::PgPool) {
    // The "InlineWithMissingPrincipal" inline policy was added in test_put_group_policy_invalid_principal_accepted.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteGroupPolicyInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .policy_name("InlineWithMissingPrincipal".to_string())
        .build()
        .expect("Failed to build DeleteGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete inline policy on Administrators");
    tx.commit().await.expect("Failed to commit transaction");

    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam.group_inline_policies \
         WHERE group_id = (SELECT group_id FROM iam.groups WHERE account_id = $1 AND group_name_lower = $2) \
         AND policy_name_lower = $3",
    )
    .bind("123456789012")
    .bind("administrators")
    .bind("inlinewithmissingprincipal")
    .fetch_one(pool)
    .await
    .expect("Failed to count Administrators inline policy after delete");
    assert_eq!(count, 0, "Deleted inline policy must be gone");

    // The other policy ("InlineRead") must still be present.
    let remaining: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM iam.group_inline_policies \
         WHERE group_id = (SELECT group_id FROM iam.groups WHERE account_id = $1 AND group_name_lower = $2)",
    )
    .bind("123456789012")
    .bind("administrators")
    .fetch_one(pool)
    .await
    .expect("Failed to count remaining Administrators inline policies");
    assert_eq!(remaining, 1, "Only the targeted inline policy must be removed");
}

/// DeleteGroupPolicy with a policy name that is not attached must fail with NoSuchEntity.
pub async fn test_delete_group_policy_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteGroupPolicyInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .policy_name("NotAttached".to_string())
        .build()
        .expect("Failed to build DeleteGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("DeleteGroupPolicy with no matching policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// DeleteGroupPolicy on a nonexistent group must fail with NoSuchEntity.
pub async fn test_delete_group_policy_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteGroupPolicyInternalRequest::builder()
        .group_name("NoSuchDeletePolicyGroup".to_string())
        .account_id("123456789012".to_string())
        .policy_name("AnyName".to_string())
        .build()
        .expect("Failed to build DeleteGroupPolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("DeleteGroupPolicy on a nonexistent group must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Building a DeleteGroupPolicy request with an invalid group name must fail before touching the
/// database.
pub fn test_delete_group_policy_invalid_name() {
    let result = DeleteGroupPolicyInternalRequest::builder()
        .group_name("bad name!".to_string())
        .account_id("123456789012".to_string())
        .policy_name("AnyName".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid group name must fail");
}

/// A group with an attached managed policy (and nothing else) must not be deletable.
pub async fn test_delete_group_attached_policy_fails(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateGroupInternalRequest::builder()
        .group_name("DeleteMeAttachedGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeAttachedGroup");
    let group_id: String =
        sqlx::query_scalar("SELECT group_id FROM iam.groups WHERE account_id = $1 AND group_name_lower = $2")
            .bind("123456789012")
            .bind("deletemeattachedgroup")
            .fetch_one(tx.as_mut())
            .await
            .expect("Failed to fetch DeleteMeAttachedGroup group_id");
    // AAAABBBBCCCCDDDD is the seeded Example-Managed-Policy-1.
    sqlx::query("INSERT INTO iam.group_attached_policies(group_id, managed_policy_id) VALUES ($1, $2)")
        .bind(&group_id)
        .bind("AAAABBBBCCCCDDDD")
        .execute(tx.as_mut())
        .await
        .expect("Failed to attach Example-Managed-Policy-1 to DeleteMeAttachedGroup");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteGroupInternalRequest::builder()
        .group_name("DeleteMeAttachedGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a group with an attached managed policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");

    // Clean up: detach the policy, confirm DeleteGroup now succeeds.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    sqlx::query("DELETE FROM iam.group_attached_policies WHERE group_id = $1")
        .bind(&group_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to detach managed policy");
    DeleteGroupInternalRequest::builder()
        .group_name("DeleteMeAttachedGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeAttachedGroup after detaching policy");
    tx.commit().await.expect("Failed to commit transaction");
}

/// A group with inline policies must not be deletable.
pub async fn test_delete_group_inline_policy_fails(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreateGroupInternalRequest::builder()
        .group_name("DeleteMeInlineGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create DeleteMeInlineGroup");
    let group_id: String =
        sqlx::query_scalar("SELECT group_id FROM iam.groups WHERE account_id = $1 AND group_name_lower = $2")
            .bind("123456789012")
            .bind("deletemeinlinegroup")
            .fetch_one(tx.as_mut())
            .await
            .expect("Failed to fetch DeleteMeInlineGroup group_id");
    sqlx::query(
        "INSERT INTO iam.group_inline_policies(group_id, policy_name_lower, policy_name_cased, policy_document) VALUES ($1, $2, $3, $4)",
    )
    .bind(&group_id)
    .bind("inline-blocker")
    .bind("inline-blocker")
    .bind(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#)
    .execute(tx.as_mut())
    .await
    .expect("Failed to insert inline policy for DeleteMeInlineGroup");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeleteGroupInternalRequest::builder()
        .group_name("DeleteMeInlineGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a group with an inline policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");

    // Clean up: remove the inline policy and confirm DeleteGroup then succeeds.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    sqlx::query("DELETE FROM iam.group_inline_policies WHERE group_id = $1")
        .bind(&group_id)
        .execute(tx.as_mut())
        .await
        .expect("Failed to remove inline policy");
    DeleteGroupInternalRequest::builder()
        .group_name("DeleteMeInlineGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete DeleteMeInlineGroup after removing inline policy");
    tx.commit().await.expect("Failed to commit transaction");
}
